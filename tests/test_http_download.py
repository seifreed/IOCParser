from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

from iocparser.errors import (
    DownloadError,
    DownloadSizeError,
    FileSizeError,
    InvalidURLError,
    IOCTimeoutError,
)
from iocparser.infrastructure.http_download import (
    MAX_URL_SIZE,
    RequestsURLDownloader,
    check_content_size,
    download_url_to_temp,
    download_with_size_check,
    generate_temp_filename,
    validate_url,
)


class StaticResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def iter_content(self, chunk_size: int = 8192):
        del chunk_size
        for chunk in self._chunks:
            yield chunk


class LocalHTTPServer:
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
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
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
                    self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:
                del format, args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.01),
            daemon=True,
        )
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/sample"

    def __exit__(self, exc_type, exc, tb) -> None:
        del exc_type, exc, tb
        assert self.server is not None
        assert self.thread is not None
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_validate_url_accepts_valid_url() -> None:
    parsed = validate_url("https://example.test/path")

    assert parsed.scheme == "https"
    assert parsed.netloc == "example.test"
    assert parsed.path == "/path"


def test_validate_url_rejects_invalid_url() -> None:
    with pytest.raises(InvalidURLError):
        validate_url("not-a-url")


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


def test_download_with_size_check_writes_content_and_rejects_oversize(tmp_path: Path) -> None:
    output_file = tmp_path / "download.bin"
    size = download_with_size_check(StaticResponse([b"abc", b"", b"def"]), output_file, 10)
    assert size == 6
    assert output_file.read_bytes() == b"abcdef"

    oversized_file = tmp_path / "oversized.bin"
    with pytest.raises(DownloadSizeError):
        download_with_size_check(StaticResponse([b"1234", b"5678"]), oversized_file, 6)
    assert not oversized_file.exists()


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


def test_download_url_to_temp_reports_timeout_and_network_errors() -> None:
    with LocalHTTPServer(body=b"slow", delay=0.02) as slow_url, pytest.raises(IOCTimeoutError):
        download_url_to_temp(slow_url, timeout=0.001)

    port = unused_port()
    with pytest.raises(DownloadError):
        download_url_to_temp(f"http://127.0.0.1:{port}/missing", timeout=1)


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
