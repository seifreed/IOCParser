from __future__ import annotations

import contextlib
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requests

from iocparser.errors import (
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


def test_check_content_size_rejects_oversized_value() -> None:
    with pytest.raises(FileSizeError):
        check_content_size(str(MAX_URL_SIZE + 1))


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

    monkeypatch.setattr(
        "iocparser.infrastructure.http_download.requests.get",
        raise_connection_error,
    )
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

    def fake_get(url, *, timeout=None, stream=False, **_kwargs):
        get_calls.append((url, timeout, stream))
        return type(
            "FakeResponse",
            (),
            {
                "raise_for_status": lambda _self=None: None,
                "headers": {"Content-Length": "2", "Content-Type": "text/plain"},
                "iter_content": lambda chunk_size: [b"ok"],
                "__enter__": lambda s: s,
                "__exit__": lambda *args: None,
            },
        )()

    monkeypatch.setattr("iocparser.infrastructure.http_download.requests.get", fake_get)
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
