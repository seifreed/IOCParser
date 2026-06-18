from __future__ import annotations

import contextlib
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requests

from iocparser.errors import (
    BlockedURLError,
    DownloadError,
    DownloadSizeError,
    FileSizeError,
    InvalidURLError,
    IOCTimeoutError,
)
from iocparser.infrastructure.http_download import (
    MAX_URL_SIZE,
    REQUEST_TIMEOUT,
    RequestsURLDownloader,
    _address_is_blocked,
    check_content_size,
    download_url_to_temp,
    download_with_size_check,
    generate_temp_filename,
    validate_url,
)
from tests.http_server_helpers import ThreadedHTTPServer


class StaticResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def iter_content(self, chunk_size: int = 8192):
        del chunk_size
        for chunk in self._chunks:
            yield chunk


class LocalHTTPServer(ThreadedHTTPServer):
    path = "/sample"

    def __init__(
        self,
        *,
        body: bytes,
        content_type: str = "text/plain",
        content_length: str | None = None,
        delay: float = 0.0,
        status: int = 200,
    ) -> None:
        self.body = body
        self.content_type = content_type
        self.content_length = content_length
        self.delay = delay
        self.status = status

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        body = self.body
        content_type = self.content_type
        content_length = self.content_length
        delay = self.delay
        status = self.status

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if delay:
                    time.sleep(delay)
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                header_value = content_length if content_length is not None else str(len(body))
                self.send_header("Content-Length", header_value)
                self.end_headers()
                if body:
                    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                        self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:
                del format, args

        return Handler


def test_validate_url_accepts_valid_url() -> None:
    parsed = validate_url("https://example.test/path")

    assert parsed.scheme == "https"
    assert parsed.netloc == "example.test"
    assert parsed.path == "/path"


def test_validate_url_rejects_invalid_url() -> None:
    with pytest.raises(InvalidURLError):
        validate_url("not-a-url")
    with pytest.raises(InvalidURLError):
        validate_url("ftp://example.test/file.txt")
    with pytest.raises(InvalidURLError):
        validate_url("http://[::1")
    with pytest.raises(InvalidURLError):
        validate_url("https://example.test:99999/path")


def test_requests_url_downloader_sanitizes_non_positive_timeouts() -> None:
    scalar_timeout = RequestsURLDownloader(timeout=-1)
    tuple_timeout = RequestsURLDownloader(timeout=(-1.0, 0.0))

    assert scalar_timeout.timeout == float(REQUEST_TIMEOUT)
    assert tuple_timeout.timeout == (
        RequestsURLDownloader.default_connect_timeout(),
        RequestsURLDownloader.default_read_timeout(),
    )


def test_requests_url_downloader_with_policy_can_clear_client_cert() -> None:
    downloader = RequestsURLDownloader(cert="/tmp/client.pem")

    derived = downloader.with_policy(cert=None)

    assert derived.cert is None


def test_check_content_size_accepts_empty_and_small_values() -> None:
    check_content_size(None)
    check_content_size("1024")


def test_check_content_size_rejects_negative_value() -> None:
    with pytest.raises(ValueError, match="Content-Length"):
        check_content_size("-1")


def test_check_content_size_rejects_oversized_value() -> None:
    with pytest.raises(FileSizeError):
        check_content_size(str(MAX_URL_SIZE + 1))


def test_configured_max_input_size_tightens_content_check() -> None:
    """Regression: --max-input-size-mb was ignored on the URL path; check_content_size
    compared against the hardcoded MAX_URL_SIZE ceiling only. A configured limit must
    further restrict it (and never raise it above the ceiling)."""
    downloader = RequestsURLDownloader(max_input_size_bytes=1024 * 1024)
    downloader.check_content_size(str(512 * 1024))  # under 1MB: allowed
    with pytest.raises(FileSizeError):
        downloader.check_content_size(str(2 * 1024 * 1024))  # over 1MB but under 50MB
    # with_policy carries the limit through clones (used per-URL in batch fan-out).
    assert downloader.with_policy().max_input_size_bytes == 1024 * 1024


def test_negative_max_input_size_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_input_size_bytes"):
        RequestsURLDownloader(max_input_size_bytes=-1)


def test_generate_temp_filename_appends_pdf_and_html_extensions() -> None:
    parsed_pdf = urlparse("https://example.test/report")
    parsed_html = urlparse("https://example.test/index")
    parsed_named = urlparse("https://example.test/page.html")

    pdf_name = generate_temp_filename(parsed_pdf, "application/pdf")
    assert pdf_name.startswith("report_")
    assert pdf_name.endswith(".pdf")
    html_name = generate_temp_filename(parsed_html, "text/html; charset=utf-8")
    assert html_name.startswith("index_")
    assert html_name.endswith(".html")
    named_name = generate_temp_filename(parsed_named, "text/html")
    assert named_name.startswith("page_")
    assert named_name.endswith(".html")
    uppercase_pdf_name = generate_temp_filename(
        urlparse("https://example.test/REPORT.PDF"), "application/pdf"
    )
    assert Path(uppercase_pdf_name).suffix == ".PDF"


def test_download_with_size_check_writes_content_and_rejects_oversize(tmp_path: Path) -> None:
    output_file = tmp_path / "download.bin"
    size = download_with_size_check(StaticResponse([b"abc", b"", b"def"]), output_file, 10)
    assert size == 6
    assert output_file.read_bytes() == b"abcdef"

    oversized_file = tmp_path / "oversized.bin"
    with pytest.raises(DownloadSizeError):
        download_with_size_check(StaticResponse([b"1234", b"5678"]), oversized_file, 6)
    assert not oversized_file.exists()


def test_download_with_size_check_removes_partial_file_on_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_file = tmp_path / "partial.bin"
    original_open = Path.open

    class FailingWriteHandle:
        def __init__(self, path: Path) -> None:
            self.path = path
            self.handle = None

        def __enter__(self):
            self.handle = original_open(self.path, "wb")
            return self

        def __exit__(self, exc_type, exc, tb):
            del exc_type, exc, tb
            assert self.handle is not None
            self.handle.close()

        def write(self, data: bytes) -> int:
            assert self.handle is not None
            self.handle.write(data)
            raise OSError("disk full")

    def failing_open(path: Path, mode: str = "r", *args, **kwargs):
        if path == output_file and mode == "wb":
            return FailingWriteHandle(path)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)

    with pytest.raises(OSError, match="disk full"):
        download_with_size_check(StaticResponse([b"abc"]), output_file, 10)
    assert not output_file.exists()


def test_requests_url_downloader_downloads_pdf_and_html_files() -> None:
    downloader = RequestsURLDownloader()

    with LocalHTTPServer(body=b"%PDF-1.4 content", content_type="application/pdf") as pdf_url:
        pdf_path = Path(downloader.download(pdf_url))
        try:
            assert pdf_path.suffix == ".pdf"
            assert pdf_path.read_bytes() == b"%PDF-1.4 content"
        finally:
            pdf_path.unlink(missing_ok=True)

    with LocalHTTPServer(body=b"<html>ok</html>", content_type="text/html") as html_url:
        html_path = Path(download_url_to_temp(html_url, timeout=5))
        try:
            assert html_path.suffix == ".html"
            assert html_path.read_text(encoding="utf-8") == "<html>ok</html>"
        finally:
            html_path.unlink(missing_ok=True)


def test_download_creates_nested_temp_dir(monkeypatch, tmp_path) -> None:
    """download() must create the iocparser temp dir even when its parent is missing.

    Regression: temp_dir.mkdir(exist_ok=True) raised FileNotFoundError when
    tempfile.gettempdir() pointed at a not-yet-existing nested path (e.g. a
    sandboxed TMPDIR), aborting every download. parents=True fixes it.
    """
    nested_tmp = tmp_path / "does" / "not" / "exist"
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(nested_tmp))
    downloader = RequestsURLDownloader()
    with LocalHTTPServer(body=b"<html>ok</html>", content_type="text/html") as html_url:
        path = Path(downloader.download(html_url))
        try:
            assert path.read_text(encoding="utf-8") == "<html>ok</html>"
        finally:
            path.unlink(missing_ok=True)


def test_download_url_to_temp_reports_timeout_and_network_errors(monkeypatch) -> None:
    with LocalHTTPServer(body=b"slow", delay=0.02) as slow_url, pytest.raises(IOCTimeoutError):
        download_url_to_temp(slow_url, timeout=0.001)

    def raise_connection_error(*args, **kwargs):
        del args, kwargs
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(requests.Session, "get", raise_connection_error)
    with pytest.raises(DownloadError):
        download_url_to_temp("http://127.0.0.1/missing", timeout=1)


def test_download_url_to_temp_reports_file_size_and_unexpected_errors() -> None:
    with LocalHTTPServer(body=b"", content_length=str(MAX_URL_SIZE + 1)) as oversized_url:
        with pytest.raises(FileSizeError):
            download_url_to_temp(oversized_url, timeout=5)

    with LocalHTTPServer(body=b"abc", content_length="not-an-int") as broken_url:
        with pytest.raises(DownloadError) as exc_info:
            download_url_to_temp(broken_url, timeout=5)
    assert exc_info.value.error_type == "unexpected"


def test_download_url_to_temp_uses_manual_path_for_default_timeout(monkeypatch) -> None:
    """Regression: timeout == REQUEST_TIMEOUT must not bypass the manual path."""
    get_calls = []

    def fake_get(self, url, *, timeout=None, stream=False, **_kwargs):
        del self
        get_calls.append((url, timeout, stream))
        return type(
            "FakeResponse",
            (),
            {
                "raise_for_status": lambda _self=None: None,
                "headers": {"Content-Length": "2", "Content-Type": "text/plain"},
                "iter_content": lambda _self, chunk_size=8192: [b"ok"],
                "is_redirect": False,
                "url": url,
                "close": lambda _self=None: None,
                "__enter__": lambda s: s,
                "__exit__": lambda *args: None,
            },
        )()

    monkeypatch.setattr(requests.Session, "get", fake_get)
    monkeypatch.setattr(
        "iocparser.infrastructure.http_download.download_with_size_check",
        lambda response, temp_file, max_size: temp_file.write_text("ok"),
    )
    with LocalHTTPServer(body=b"ok") as url:
        download_url_to_temp(url, timeout=30)
    assert len(get_calls) == 1
    assert get_calls[0][1] == 30


def test_requests_url_downloader_reports_unexpected_errors() -> None:
    downloader = RequestsURLDownloader()

    with LocalHTTPServer(body=b"abc", content_length="not-an-int") as broken_url:
        with pytest.raises(DownloadError) as exc_info:
            downloader.download(broken_url)
    assert exc_info.value.error_type == "unexpected"


def test_requests_url_downloader_clears_metadata_before_failed_download() -> None:
    downloader = RequestsURLDownloader()

    with LocalHTTPServer(body=b"ok") as success_url:
        downloaded = Path(downloader.download(success_url))
        try:
            assert downloader.download_metadata()["input_size"] == 2
        finally:
            downloaded.unlink(missing_ok=True)

    with LocalHTTPServer(body=b"abc", content_length="not-an-int") as broken_url:
        with pytest.raises(DownloadError):
            downloader.download(broken_url)

    assert downloader.download_metadata() == {}


def test_requests_url_downloader_rate_limit_sleep_path_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downloader = RequestsURLDownloader(rate_limit_delay=0.5)
    downloader._last_request_started = 9.75
    monotonic_values = iter([10.0, 10.5])
    sleeps: list[float] = []

    monkeypatch.setattr(
        "iocparser.infrastructure.http_download.time.monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr(
        "iocparser.infrastructure.http_download.time.sleep",
        sleeps.append,
    )

    downloader._respect_rate_limit()

    assert sleeps == [pytest.approx(0.25)]
    assert downloader._last_request_started == 10.5


class _FakeRedirectResponse:
    def __init__(self, *, is_redirect=False, location=None, url="http://example.com/"):
        self.is_redirect = is_redirect
        self.headers = {"Location": location} if location else {}
        self.url = url
        self.closed = False

    def close(self):
        self.closed = True

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=8192):
        del chunk_size
        return [b"ok"]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def test_address_is_blocked_classifies_addresses() -> None:
    assert _address_is_blocked("8.8.8.8") is False
    assert _address_is_blocked("127.0.0.1") is True
    assert _address_is_blocked("169.254.169.254") is True  # cloud metadata
    assert _address_is_blocked("10.0.0.1") is True
    assert _address_is_blocked("::1") is True
    assert _address_is_blocked("not-an-ip") is True


def test_download_blocks_private_and_metadata_urls(monkeypatch) -> None:
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    downloader = RequestsURLDownloader()
    for blocked in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:1/x"):
        with pytest.raises(BlockedURLError):
            downloader.download(blocked)


def test_allow_private_networks_opt_out_skips_guard(monkeypatch) -> None:
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    downloader = RequestsURLDownloader(allow_private_networks=True)
    # Guard is disabled, so the loopback URL is attempted and fails to connect
    # (DownloadError) rather than being refused up front (BlockedURLError).
    with pytest.raises(DownloadError):
        downloader.download("http://127.0.0.1:1/x")


def test_redirect_to_private_host_is_revalidated_and_blocked(monkeypatch) -> None:
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)

    def fake_get(self, url, **_kwargs):
        del self
        return _FakeRedirectResponse(is_redirect=True, location="http://127.0.0.1/internal", url=url)

    monkeypatch.setattr(requests.Session, "get", fake_get)
    with pytest.raises(BlockedURLError):
        RequestsURLDownloader().download("http://93.184.216.34/start")


def test_redirect_without_location_is_rejected(monkeypatch) -> None:
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    monkeypatch.setattr(
        requests.Session,
        "get",
        lambda self, url, **_kwargs: _FakeRedirectResponse(
            is_redirect=True, location=None, url=url
        ),
    )
    with pytest.raises(DownloadError, match="Location"):
        RequestsURLDownloader().download("http://93.184.216.34/start")


def test_redirect_limit_is_enforced(monkeypatch) -> None:
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    monkeypatch.setattr(
        requests.Session,
        "get",
        lambda self, url, **_kwargs: _FakeRedirectResponse(
            is_redirect=True, location="http://93.184.216.34/loop", url=url
        ),
    )
    with pytest.raises(DownloadError, match="redirect limit"):
        RequestsURLDownloader().download("http://93.184.216.34/start")


def test_redirect_to_public_host_is_followed(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    responses = [
        _FakeRedirectResponse(is_redirect=True, location="http://93.184.216.34/final"),
        _FakeRedirectResponse(is_redirect=False, url="http://93.184.216.34/final"),
    ]
    monkeypatch.setattr(
        requests.Session,
        "get",
        lambda self, url, **_kwargs: responses.pop(0),
    )
    downloader = RequestsURLDownloader()
    path = downloader.download("http://93.184.216.34/start")
    assert Path(path).read_text(encoding="utf-8") == "ok"
    assert downloader.download_metadata()["normalized_url"] == "http://93.184.216.34/final"
    assert downloader.download_metadata()["response_url"] == "http://93.184.216.34/final"


def test_assert_host_allowed_rejects_missing_hostname(monkeypatch) -> None:
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    with pytest.raises(InvalidURLError):
        RequestsURLDownloader()._assert_host_allowed(urlparse("http://@/path"))


def test_resolve_pinned_ip_returns_public_and_rejects_blocked(monkeypatch) -> None:
    """The resolver returns a vetted address and refuses if ANY resolved IP is private."""
    from iocparser.infrastructure import http_download as hd

    monkeypatch.setattr(
        hd.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80))],
    )
    assert hd._resolve_pinned_ip("example.com", 80) == "93.184.216.34"

    monkeypatch.setattr(
        hd.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80)), (2, 1, 6, "", ("127.0.0.1", 80))],
    )
    with pytest.raises(BlockedURLError):
        hd._resolve_pinned_ip("example.com", 80)


def test_pinned_adapter_pins_connection_to_validated_ip(monkeypatch) -> None:
    """The adapter connects to the validated IP while keeping the hostname for SNI."""
    from requests.models import PreparedRequest

    from iocparser.infrastructure import http_download as hd

    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    monkeypatch.setattr(hd, "_resolve_pinned_ip", lambda host, port: "93.184.216.34")
    adapter = hd._PinnedIPAdapter(allow_private=False)

    https_req = PreparedRequest()
    https_req.prepare(method="GET", url="https://example.com/path")
    https_pool = adapter.get_connection_with_tls_context(https_req, True)
    assert https_pool.host == "93.184.216.34"
    assert https_pool.conn_kw.get("server_hostname") == "example.com"

    http_req = PreparedRequest()
    http_req.prepare(method="GET", url="http://example.com/path")
    http_pool = adapter.get_connection_with_tls_context(http_req, True)
    assert http_pool.host == "93.184.216.34"


def test_pinned_adapter_skips_pinning_when_guard_disabled(monkeypatch) -> None:
    """With the guard off the adapter behaves like the stock one (no pin)."""
    from requests.models import PreparedRequest

    from iocparser.infrastructure import http_download as hd

    monkeypatch.setenv("IOCPARSER_ALLOW_PRIVATE_URLS", "1")
    adapter = hd._PinnedIPAdapter(allow_private=False)
    req = PreparedRequest()
    req.prepare(method="GET", url="http://example.com/path")
    pool = adapter.get_connection_with_tls_context(req, True)
    assert pool.host == "example.com"


def test_pinned_adapter_rejects_blocked_ip_literal(monkeypatch) -> None:
    """A literal private IP target is refused at connection build time."""
    from requests.models import PreparedRequest

    from iocparser.infrastructure import http_download as hd

    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    adapter = hd._PinnedIPAdapter(allow_private=False)
    req = PreparedRequest()
    req.prepare(method="GET", url="http://127.0.0.1/x")
    with pytest.raises(BlockedURLError):
        adapter.get_connection_with_tls_context(req, True)


def test_pinned_adapter_allows_public_ip_literal(monkeypatch) -> None:
    """A literal public IP is allowed through (no rebinding risk to pin)."""
    from requests.models import PreparedRequest

    from iocparser.infrastructure import http_download as hd

    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    adapter = hd._PinnedIPAdapter(allow_private=False)
    req = PreparedRequest()
    req.prepare(method="GET", url="http://93.184.216.34/x")
    pool = adapter.get_connection_with_tls_context(req, True)
    assert pool.host == "93.184.216.34"


def test_download_through_proxy_is_refused_when_guard_active(monkeypatch) -> None:
    """The guard can't be enforced through a proxy, so a proxied download is refused."""
    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    downloader = RequestsURLDownloader(proxies={"http": "http://proxy:3128"})
    with pytest.raises(BlockedURLError):
        downloader.download("http://93.184.216.34/x")


def test_pinned_adapter_delegates_hostless_url(monkeypatch) -> None:
    """A URL with no hostname is left to the stock adapter (which rejects it)."""
    from requests.models import PreparedRequest
    from urllib3.exceptions import LocationValueError

    from iocparser.infrastructure import http_download as hd

    monkeypatch.delenv("IOCPARSER_ALLOW_PRIVATE_URLS", raising=False)
    adapter = hd._PinnedIPAdapter(allow_private=False)
    req = PreparedRequest()
    req.url = "http:///nopath"
    req.headers = {}
    with pytest.raises(LocationValueError):
        adapter.get_connection_with_tls_context(req, True)
