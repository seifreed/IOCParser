from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import TypeVar, cast
from urllib.parse import ParseResult, urljoin, urlparse

import requests
from requests.exceptions import RequestException, Timeout
from requests.models import PreparedRequest
from urllib3.connectionpool import ConnectionPool

from iocparser.domain.sources import normalize_url_value
from iocparser.errors import (
    BlockedURLError,
    DownloadError,
    DownloadSizeError,
    FileSizeError,
    InvalidURLError,
    IOCTimeoutError,
)
from iocparser.infrastructure.logger import get_logger
from iocparser.interfaces.ports import URLDownloader
from iocparser.shared_utils import lazy_singleton

MAX_URL_SIZE = 50 * 1024 * 1024
INVALID_CONTENT_LENGTH_ERROR = "Invalid Content-Length header: {value!r}"
INVALID_MAX_INPUT_SIZE_ERROR = "Invalid max_input_size_bytes: {value!r}"
REQUEST_TIMEOUT = 30
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = float(REQUEST_TIMEOUT)
MAX_DOWNLOAD_REDIRECTS = 10
ALLOW_PRIVATE_URLS_ENV = "IOCPARSER_ALLOW_PRIVATE_URLS"
TimeoutValue = int | float | tuple[float, float]
logger = get_logger(__name__)


def _env_allows_private_urls() -> bool:
    return os.environ.get(ALLOW_PRIVATE_URLS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _address_is_blocked(ip_text: str) -> bool:
    """Return True for addresses an SSRF guard must refuse (private/loopback/etc.)."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _resolve_pinned_ip(host: str, port: int | None) -> str:
    """Resolve *host*, refuse if ANY address is blocked, and return one to pin.

    Validating and selecting the address in a single resolution closes the
    validate-then-reconnect DNS-rebinding window: the caller connects to exactly
    the address vetted here, so a low-TTL rebind cannot swap in a private target.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    addresses = [str(info[4][0]) for info in infos]
    if not addresses or any(_address_is_blocked(address) for address in addresses):
        raise BlockedURLError(host)
    return addresses[0]


class _PinnedIPAdapter(requests.adapters.HTTPAdapter):
    """Pin each HTTP(S) connection to a pre-validated IP (SSRF DNS-rebind guard).

    The connection pool is built against the validated IP while the request keeps
    its original hostname (so the Host header is correct) and, for HTTPS, the TLS
    SNI and certificate hostname are pinned to the original host. The address the
    socket connects to is therefore identical to the one the guard vetted, closing
    the validate-then-reconnect rebinding window.
    """

    def __init__(self, *, allow_private: bool) -> None:
        self._allow_private = allow_private
        super().__init__()

    def get_connection_with_tls_context(
        self,
        request: PreparedRequest,
        verify: bool | str | None,
        proxies: Mapping[str, str] | None = None,
        cert: tuple[str, str] | str | None = None,
    ) -> ConnectionPool:
        if self._allow_private or _env_allows_private_urls() or proxies:
            return super().get_connection_with_tls_context(request, verify, proxies, cert)
        host = urlparse(request.url or "").hostname
        if not host:
            return super().get_connection_with_tls_context(request, verify, proxies, cert)
        if _is_ip_literal(host):
            if _address_is_blocked(host.strip("[]")):
                raise BlockedURLError(request.url or host)
            return super().get_connection_with_tls_context(request, verify, proxies, cert)
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(
            request, verify if verify is not None else True, cert
        )
        pinned_kwargs: dict[str, object] = dict(pool_kwargs)
        if host_params["scheme"] == "https":
            pinned_kwargs["server_hostname"] = host
            pinned_kwargs["assert_hostname"] = host
        return cast(
            "ConnectionPool",
            self.poolmanager.connection_from_host(
                host=_resolve_pinned_ip(host, host_params["port"]),
                port=host_params["port"],
                scheme=host_params["scheme"],
                pool_kwargs=pinned_kwargs,
            ),
        )


_DEFAULT_DOWNLOADER_HOLDER: list[RequestsURLDownloader] = []
_DEFAULT_DOWNLOADER_LOCK = Lock()


def _default_downloader() -> RequestsURLDownloader:
    return lazy_singleton(
        _DEFAULT_DOWNLOADER_HOLDER, _DEFAULT_DOWNLOADER_LOCK, RequestsURLDownloader
    )


@dataclass(frozen=True)
class HTTPTransportConfig:
    """Reusable HTTP transport settings for the download adapter."""

    timeout: TimeoutValue = REQUEST_TIMEOUT
    retries: int = 0
    backoff: float = 0.0
    rate_limit_delay: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    user_agent: str = "IOCParser/5.0"
    proxies: dict[str, str] = field(default_factory=dict)
    allow_redirects: bool = True
    verify: bool | str = True
    cert: str | None = None
    allow_private_networks: bool = False
    # User-configured download cap (--max-input-size-mb). Only tightens the hard
    # MAX_URL_SIZE ceiling; None leaves the default ceiling in place.
    max_input_size_bytes: int | None = None


def _positive_timeout(value: int | float, default: float) -> float:
    return float(value) if value > 0 else default


def _sanitize_timeout(timeout: TimeoutValue) -> TimeoutValue:
    if isinstance(timeout, tuple):
        connect_timeout, read_timeout = timeout
        return (
            _positive_timeout(connect_timeout, DEFAULT_CONNECT_TIMEOUT),
            _positive_timeout(read_timeout, DEFAULT_READ_TIMEOUT),
        )
    return _positive_timeout(timeout, float(REQUEST_TIMEOUT))


class RequestsURLDownloader(URLDownloader):
    """HTTP download adapter backed by requests."""

    _UNSET: object = object()

    def __init__(  # noqa: PLR0913
        self,
        *,
        config: HTTPTransportConfig | None = None,
        timeout: TimeoutValue | None = None,
        retries: int | None = None,
        backoff: float | None = None,
        rate_limit_delay: float | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        user_agent: str | None = None,
        proxies: dict[str, str] | None = None,
        allow_redirects: bool | None = None,
        verify: bool | str | None = None,
        cert: object = _UNSET,
        allow_private_networks: bool | None = None,
        max_input_size_bytes: int | None = None,
        **kwargs: object,
    ) -> None:
        cfg = config or HTTPTransportConfig()
        self.timeout: TimeoutValue = _sanitize_timeout(
            timeout if timeout is not None else cfg.timeout
        )
        self.retries = max(0, retries if retries is not None else cfg.retries)
        self.backoff = max(0.0, backoff if backoff is not None else cfg.backoff)
        self.rate_limit_delay = max(
            0.0, rate_limit_delay if rate_limit_delay is not None else cfg.rate_limit_delay
        )
        self.headers = dict(headers if headers is not None else cfg.headers)
        self.cookies = dict(cookies if cookies is not None else cfg.cookies)
        self.user_agent = user_agent if user_agent is not None else cfg.user_agent
        self.proxies = dict(proxies if proxies is not None else cfg.proxies)
        self.allow_redirects = (
            allow_redirects if allow_redirects is not None else cfg.allow_redirects
        )
        self.verify: bool | str = verify if verify is not None else cfg.verify
        self.cert: str | None = cast("str | None", cert) if cert is not self._UNSET else cfg.cert
        self.allow_private_networks = (
            allow_private_networks
            if allow_private_networks is not None
            else cfg.allow_private_networks
        )
        configured_max_input_size = (
            max_input_size_bytes
            if max_input_size_bytes is not None
            else cfg.max_input_size_bytes
        )
        if configured_max_input_size is not None and configured_max_input_size < 0:
            raise ValueError(INVALID_MAX_INPUT_SIZE_ERROR.format(value=configured_max_input_size))
        self.max_input_size_bytes = configured_max_input_size
        self._rate_limit_lock = Lock()
        self._last_request_started = 0.0
        self.last_download_metadata: dict[str, object] | None = None

    def with_policy(self, **overrides: object) -> RequestsURLDownloader:
        """Return a downloader with the same policy plus overrides."""
        _T = TypeVar("_T")

        def _pick(key: str, default: _T, *, allow_none: bool = False) -> _T:
            if key not in overrides:
                return default
            result = overrides[key]
            if result is None and not allow_none:
                return default
            return cast("_T", result)

        return RequestsURLDownloader(
            timeout=_pick("timeout", self.timeout),
            retries=_pick("retries", self.retries),
            backoff=_pick("backoff", self.backoff),
            rate_limit_delay=_pick("rate_limit_delay", self.rate_limit_delay),
            headers=_pick("headers", self.headers),
            cookies=_pick("cookies", self.cookies),
            user_agent=_pick("user_agent", self.user_agent),
            proxies=_pick("proxies", self.proxies),
            allow_redirects=_pick("allow_redirects", self.allow_redirects),
            verify=_pick("verify", self.verify),
            cert=_pick("cert", self.cert, allow_none=True),
            allow_private_networks=_pick("allow_private_networks", self.allow_private_networks),
            max_input_size_bytes=_pick(
                "max_input_size_bytes", self.max_input_size_bytes, allow_none=True
            ),
        )

    def download_metadata(self) -> dict[str, object]:
        """Return normalized metadata captured during the last download."""
        if self.last_download_metadata is None:
            return {}
        return {str(name): value for name, value in self.last_download_metadata.items()}

    def _respect_rate_limit(self) -> None:
        if self.rate_limit_delay <= 0:
            return
        with self._rate_limit_lock:
            elapsed = time.monotonic() - self._last_request_started
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
            self._last_request_started = time.monotonic()

    @staticmethod
    def default_timeout() -> int:
        """Return the default single-value timeout."""
        return REQUEST_TIMEOUT

    @staticmethod
    def default_connect_timeout() -> float:
        """Return the default connect timeout."""
        return DEFAULT_CONNECT_TIMEOUT

    @staticmethod
    def default_read_timeout() -> float:
        """Return the default read timeout."""
        return DEFAULT_READ_TIMEOUT

    def validate_url(self, url: str) -> ParseResult:
        """Validate URL format and return parsed URL."""
        try:
            parsed_url = urlparse(url)
            _ = parsed_url.port
        except ValueError as exc:
            raise InvalidURLError(url) from exc
        if not parsed_url.scheme or not parsed_url.netloc:
            raise InvalidURLError(url)
        if parsed_url.scheme.lower() not in {"http", "https"}:
            raise InvalidURLError(url)
        return parsed_url

    def _effective_max_size(self) -> int:
        """Hard MAX_URL_SIZE ceiling, further tightened by --max-input-size-mb."""
        if self.max_input_size_bytes is None:
            return MAX_URL_SIZE
        return min(MAX_URL_SIZE, self.max_input_size_bytes)

    def check_content_size(self, content_length: str | None) -> None:
        """Check if content size exceeds limit."""
        if not content_length:
            return
        try:
            length = int(content_length)
        except ValueError as exc:
            raise ValueError(INVALID_CONTENT_LENGTH_ERROR.format(value=content_length)) from exc
        if length < 0:
            raise ValueError(INVALID_CONTENT_LENGTH_ERROR.format(value=content_length))
        max_size = self._effective_max_size()
        if length > max_size:
            raise FileSizeError(
                length / 1024 / 1024,
                max_size / 1024 / 1024,
                "URL content",
            )

    def generate_temp_filename(self, parsed_url: ParseResult, content_type: str) -> str:
        """Generate filename with appropriate extension, unique per download."""
        base_name = Path(parsed_url.path).name or parsed_url.netloc.replace(".", "_")
        lowercase_base_name = base_name.lower()
        if "application/pdf" in content_type and not lowercase_base_name.endswith(".pdf"):
            base_name += ".pdf"
        elif "text/html" in content_type and not lowercase_base_name.endswith((".html", ".htm")):
            base_name += ".html"
        stem = Path(base_name).stem
        suffix = Path(base_name).suffix
        return f"{stem}_{uuid.uuid4().hex[:8]}{suffix}"

    def download_with_size_check(
        self,
        response: requests.Response,
        temp_file: Path,
        max_size: int,
    ) -> int:
        """Download content with size checking."""
        downloaded_size = 0
        exceeded_size_limit = False
        try:
            with temp_file.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    downloaded_size += len(chunk)
                    if downloaded_size > max_size:
                        exceeded_size_limit = True
                        break
                    handle.write(chunk)
        except Exception:
            try:
                temp_file.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to remove partial download after write error", exc_info=True)
            raise
        if exceeded_size_limit:
            try:
                temp_file.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to remove oversized download", exc_info=True)
            raise DownloadSizeError(max_size / 1024 / 1024)
        return downloaded_size

    def download(self, url: str) -> str:
        """Download URL content into a temp file and return the path."""
        import tempfile

        self.last_download_metadata = None
        parsed_url = self.validate_url(url)
        temp_dir = Path(tempfile.gettempdir()) / "iocparser"
        temp_dir.mkdir(parents=True, exist_ok=True)

        for attempt in range(self.retries + 1):
            try:
                return self._download_once(url, parsed_url, temp_dir, attempt + 1)
            except Timeout as exc:
                if attempt < self.retries:
                    logger.warning(
                        "Timeout downloading %s, retry %s/%s", url, attempt + 1, self.retries
                    )
                    if self.backoff:
                        timeout_delay: float = self.backoff * (2.0**attempt)
                        time.sleep(timeout_delay)
                    continue
                raise IOCTimeoutError("Download", url) from exc
            except RequestException as exc:
                if attempt < self.retries:
                    logger.warning(
                        "Request error downloading %s, retry %s/%s", url, attempt + 1, self.retries
                    )
                    if self.backoff:
                        retry_delay: float = self.backoff * (2.0**attempt)
                        time.sleep(retry_delay)
                    continue
                raise DownloadError(url, str(exc)) from exc
            except (OSError, ValueError, RuntimeError) as exc:
                raise DownloadError(url, str(exc), error_type="unexpected") from exc
        raise DownloadError(url, "Unreachable download state", error_type="unexpected")

    def _assert_host_allowed(self, parsed_url: ParseResult) -> None:
        """Reject URLs resolving to private/loopback/reserved addresses (SSRF guard).

        The env var is honoured at call time (not just construction) so it overrides
        even module-level downloaders built before it was set.
        """
        if self.allow_private_networks or _env_allows_private_urls():
            return
        host = parsed_url.hostname
        if not host:
            raise InvalidURLError(parsed_url.geturl())
        for info in socket.getaddrinfo(host, parsed_url.port, proto=socket.IPPROTO_TCP):
            if _address_is_blocked(str(info[4][0])):
                raise BlockedURLError(parsed_url.geturl())

    def _guard_active(self) -> bool:
        return not (self.allow_private_networks or _env_allows_private_urls())

    def _open_validated(
        self, url: str, request_headers: dict[str, str], session: requests.Session
    ) -> tuple[requests.Response, str]:
        """Open the URL, re-validating each redirect hop against the SSRF guard."""
        if self._guard_active() and self.proxies:
            # The guard resolves and pins the IP locally, but a proxy resolves and
            # connects on its own side, so the pin cannot be enforced through it.
            # Refuse rather than offer protection we cannot deliver.
            raise BlockedURLError(url)
        current = url
        for _ in range(MAX_DOWNLOAD_REDIRECTS + 1):
            self._assert_host_allowed(self.validate_url(current))
            response = session.get(
                current,
                timeout=self.timeout,
                stream=True,
                headers=request_headers,
                cookies=self.cookies or None,
                proxies=self.proxies or None,
                allow_redirects=False,
                verify=self.verify,
                cert=self.cert,
            )
            if self.allow_redirects and response.is_redirect:
                location = response.headers.get("Location", "")
                response.close()
                if not location:
                    raise DownloadError(url, "redirect missing Location header")
                current = urljoin(current, location)
                continue
            return response, str(response.url)
        raise DownloadError(url, "exceeded redirect limit")

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        adapter = _PinnedIPAdapter(allow_private=self.allow_private_networks)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _download_once(
        self, url: str, parsed_url: ParseResult, temp_dir: Path, attempt_count: int
    ) -> str:
        self._respect_rate_limit()
        logger.info("Downloading content from %s", url)
        started_at = time.perf_counter()
        request_headers = dict(self.headers)
        request_headers.setdefault("User-Agent", self.user_agent)
        session = self._build_session()
        primary_exc: Exception | None = None
        try:
            response, response_url = self._open_validated(url, request_headers, session)
            with response:
                response.raise_for_status()
                self.check_content_size(response.headers.get("Content-Length"))

                content_type = str(response.headers.get("Content-Type", "")).lower()
                temp_file = temp_dir / self.generate_temp_filename(parsed_url, content_type)
                downloaded_size = self.download_with_size_check(
                    response, temp_file, self._effective_max_size()
                )
        except Exception as exc:
            primary_exc = exc
            raise
        finally:
            try:
                session.close()
            except Exception:
                if primary_exc is None:
                    raise
                logger.warning("Failed to close download session after error", exc_info=True)
        content_hash = hashlib.sha256(temp_file.read_bytes()).hexdigest()
        self.last_download_metadata = {
            "original_url": url,
            "normalized_url": normalize_url_value(response_url),
            "mime_type": content_type or None,
            "input_size": downloaded_size,
            "attempt_count": attempt_count,
            "elapsed_ms": int((time.perf_counter() - started_at) * 1000),
            "content_hash": content_hash,
            "fingerprint": content_hash[:16],
            "response_url": response_url,
            "cookies": dict(self.cookies),
        }
        logger.info("Downloaded %.2fKB to %s", downloaded_size / 1024, temp_file)
        return str(temp_file)


def validate_url(url: str) -> ParseResult:
    """Module-level convenience wrapper for URL validation."""
    return _default_downloader().validate_url(url)


def check_content_size(content_length: str | None) -> None:
    """Module-level convenience wrapper for content-length validation."""
    _default_downloader().check_content_size(content_length)


def generate_temp_filename(parsed_url: ParseResult, content_type: str) -> str:
    """Module-level convenience wrapper for filename generation."""
    return _default_downloader().generate_temp_filename(parsed_url, content_type)


def download_with_size_check(
    response: requests.Response,
    temp_file: Path,
    max_size: int,
) -> int:
    """Module-level convenience wrapper for guarded downloads."""
    return _default_downloader().download_with_size_check(response, temp_file, max_size)


def download_url_to_temp(url: str, timeout: int = REQUEST_TIMEOUT) -> str:
    """Module-level convenience wrapper for downloading URLs.

    Delegates to RequestsURLDownloader so the SSRF guard and redirect
    re-validation apply here too, instead of an unguarded requests.get.
    """
    return RequestsURLDownloader(timeout=timeout).download(url)
