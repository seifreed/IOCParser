from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import TypeVar, cast
from urllib.parse import ParseResult, urlparse

import requests
from requests.exceptions import RequestException, Timeout

from iocparser.domain.sources import normalize_url_value
from iocparser.errors import (
    DownloadError,
    DownloadSizeError,
    FileSizeError,
    InvalidURLError,
    IOCTimeoutError,
)
from iocparser.infrastructure.logger import get_logger
from iocparser.interfaces.ports import URLDownloader

MAX_URL_SIZE = 50 * 1024 * 1024
REQUEST_TIMEOUT = 30
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = float(REQUEST_TIMEOUT)
logger = get_logger(__name__)


_DEFAULT_DOWNLOADER_HOLDER: list[RequestsURLDownloader] = []
_DEFAULT_DOWNLOADER_LOCK = Lock()


def _default_downloader() -> RequestsURLDownloader:
    if not _DEFAULT_DOWNLOADER_HOLDER:
        with _DEFAULT_DOWNLOADER_LOCK:
            if not _DEFAULT_DOWNLOADER_HOLDER:
                _DEFAULT_DOWNLOADER_HOLDER.append(RequestsURLDownloader())
    return _DEFAULT_DOWNLOADER_HOLDER[0]


@dataclass(frozen=True)
class HTTPTransportConfig:
    """Reusable HTTP transport settings for the download adapter."""

    timeout: int | tuple[float, float] = REQUEST_TIMEOUT
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


class RequestsURLDownloader(URLDownloader):
    """HTTP download adapter backed by requests."""

    _UNSET: object = object()

    def __init__(  # noqa: PLR0913
        self,
        *,
        config: HTTPTransportConfig | None = None,
        timeout: int | tuple[float, float] | None = None,
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
        **kwargs: object,
    ) -> None:
        cfg = config or HTTPTransportConfig()
        self.timeout: int | tuple[float, float] = timeout if timeout is not None else cfg.timeout
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
        self._rate_limit_lock = Lock()
        self._last_request_started = 0.0
        self.last_download_metadata: dict[str, object] | None = None

    def with_policy(self, **overrides: object) -> RequestsURLDownloader:
        """Return a downloader with the same policy plus overrides."""
        _T = TypeVar("_T")

        def _pick(key: str, default: _T) -> _T:
            result = overrides.get(key, default)
            if result is None:
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
            cert=_pick("cert", self.cert),
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
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise InvalidURLError(url)
        return parsed_url

    def check_content_size(self, content_length: str | None) -> None:
        """Check if content size exceeds limit."""
        if not content_length:
            return
        try:
            length = int(content_length)
        except ValueError as exc:
            raise ValueError(f"Invalid Content-Length header: {content_length!r}") from exc
        if length > MAX_URL_SIZE:
            raise FileSizeError(
                length / 1024 / 1024,
                MAX_URL_SIZE / 1024 / 1024,
                "URL content",
            )

    def generate_temp_filename(self, parsed_url: ParseResult, content_type: str) -> str:
        """Generate filename with appropriate extension, unique per download."""
        base_name = Path(parsed_url.path).name or parsed_url.netloc.replace(".", "_")
        if "application/pdf" in content_type and not base_name.endswith(".pdf"):
            base_name += ".pdf"
        elif "text/html" in content_type and not base_name.endswith((".html", ".htm")):
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
        with temp_file.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                downloaded_size += len(chunk)
                if downloaded_size > max_size:
                    exceeded_size_limit = True
                    break
                handle.write(chunk)
        if exceeded_size_limit:
            temp_file.unlink(missing_ok=True)
            raise DownloadSizeError(max_size / 1024 / 1024)
        return downloaded_size

    def download(self, url: str) -> str:
        """Download URL content into a temp file and return the path."""
        import tempfile

        parsed_url = self.validate_url(url)
        temp_dir = Path(tempfile.gettempdir()) / "iocparser"
        temp_dir.mkdir(exist_ok=True)

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

    def _download_once(
        self, url: str, parsed_url: ParseResult, temp_dir: Path, attempt_count: int
    ) -> str:
        self._respect_rate_limit()
        logger.info("Downloading content from %s", url)
        started_at = time.perf_counter()
        request_headers = dict(self.headers)
        request_headers.setdefault("User-Agent", self.user_agent)
        response_url = ""
        with requests.get(
            url,
            timeout=self.timeout,
            stream=True,
            headers=request_headers,
            cookies=self.cookies or None,
            proxies=self.proxies or None,
            allow_redirects=self.allow_redirects,
            verify=self.verify,
            cert=self.cert,
        ) as response:
            response.raise_for_status()
            self.check_content_size(response.headers.get("Content-Length"))

            content_type = str(response.headers.get("Content-Type", "")).lower()
            response_url = str(response.url)
            temp_file = temp_dir / self.generate_temp_filename(parsed_url, content_type)
            downloaded_size = self.download_with_size_check(response, temp_file, MAX_URL_SIZE)
        content_hash = hashlib.sha256(temp_file.read_bytes()).hexdigest()
        self.last_download_metadata = {
            "original_url": url,
            "normalized_url": normalize_url_value(parsed_url.geturl()),
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
    """Module-level convenience wrapper for downloading URLs."""
    try:
        parsed_url = validate_url(url)
        with requests.get(url, timeout=timeout, stream=True) as response:
            response.raise_for_status()
            check_content_size(response.headers.get("Content-Length"))
            import tempfile

            temp_dir = Path(tempfile.gettempdir()) / "iocparser"
            temp_dir.mkdir(exist_ok=True)
            content_type = str(response.headers.get("Content-Type", "")).lower()
            temp_file = temp_dir / generate_temp_filename(parsed_url, content_type)
            download_with_size_check(response, temp_file, MAX_URL_SIZE)
            return str(temp_file)
    except requests.Timeout as exc:
        from iocparser.errors import IOCTimeoutError

        raise IOCTimeoutError("Download", url) from exc
    except requests.RequestException as exc:
        from iocparser.errors import DownloadError

        raise DownloadError(url, str(exc)) from exc
    except (OSError, ValueError, RuntimeError) as exc:
        from iocparser.errors import DownloadError

        raise DownloadError(url, str(exc), error_type="unexpected") from exc
