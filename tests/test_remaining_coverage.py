from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from iocparser.adapters.renderers import STIXOutputRenderer
from iocparser.domain.enums import IOCType
from iocparser.domain.models import IOC, ExtractionResult
from iocparser.errors import IOCTimeoutError
from iocparser.infrastructure.extraction import IOCExtractor
from iocparser.infrastructure.file_readers import MagicTextSourceReader
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.streaming import ParallelStreamingExtractor, StreamingIOCExtractor
from iocparser.infrastructure.warninglists_diagnostics import WarningListDiagnosticsMixin


class PlainTextHtmlReader(MagicTextSourceReader):
    def detect_file_type_by_mime(self, file_type: str) -> str | None:
        if file_type.lower() == "text/plain":
            return None
        return super().detect_file_type_by_mime(file_type)


class TimeoutDownloader(RequestsURLDownloader):
    def download_with_size_check(self, response, temp_file: Path, max_size: int) -> int:
        del response, temp_file, max_size
        from requests.exceptions import Timeout

        raise Timeout("simulated timeout")


class StaticHTTPServer:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        body = self.body

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args) -> None:
                del fmt, args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.01),
            daemon=True,
        )
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/sample.txt"

    def __exit__(self, exc_type, exc, tb) -> None:
        del exc_type, exc, tb
        assert self.server is not None
        assert self.thread is not None
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class DiagnosticProbe(WarningListDiagnosticsMixin):
    TYPE_KEYWORDS = {"domains": ["domain"], "ips": ["ip"]}

    def __init__(self) -> None:
        self.warning_lists = {}

    def _check_value_in_list(self, value: str, values: list[object], list_type: str) -> bool:
        del list_type
        return value in values

    def _clean_defanged_value(self, value: str) -> str:
        return value

    def check_value(self, value: str, ioc_type: str) -> tuple[bool, dict[str, str] | None]:
        del value, ioc_type
        return False, None


def test_file_reader_treats_plain_text_html_extension_as_html(tmp_path: Path) -> None:
    sample = tmp_path / "sample.html"
    sample.write_text("plain text content", encoding="utf-8")

    detected = PlainTextHtmlReader().detect_file_type(sample)

    assert detected == "html"


def test_http_downloader_wraps_timeout_from_download_phase() -> None:
    with StaticHTTPServer(b"IOC URL: https://timeout.example/path\n") as url:
        with_path = TimeoutDownloader()
        try:
            with_path.download(url)
        except IOCTimeoutError:
            pass
        else:
            raise AssertionError


def test_warninglist_diagnostics_returns_empty_values_for_non_list() -> None:
    probe = DiagnosticProbe()

    assert probe._get_warning_list_values({"list": "not-a-list"}) == []


def test_network_extractor_covers_url_error_and_host_filtering() -> None:
    class WeirdExtractor(IOCExtractor):
        def _clean_defanged(self, value: str) -> str:  # type: ignore[override]
            if value == "http://broken.example":
                raise ValueError("broken")
            return super()._clean_defanged(value)

        def extract_domains(self, text: str) -> list[str]:  # type: ignore[override]
            del text
            return ["localhost", "good.example", "view"]

    extractor = WeirdExtractor(defang=False)

    urls = extractor.extract_urls("http://broken.example")
    hosts = extractor.extract_hosts("ignored")

    assert urls == ["http://broken.example"]
    assert hosts == ["good.example"]


def test_base_extractor_covers_unknown_pattern_hash_fallback_and_bad_url_parse() -> None:
    class BaseCoverageExtractor(IOCExtractor):
        def _extract_pattern(self, text: str, pattern_name: str) -> list[str]:  # type: ignore[override]
            if pattern_name == "urls":
                return ["http://[::1", "https://evil-example.com/path"]
            return super()._extract_pattern(text, pattern_name)

    extractor = BaseCoverageExtractor(defang=False)
    non_hex_hash = "ghijklmnopqrstuvwxyz" * 3

    assert extractor._extract_pattern("anything", "not-defined") == []
    assert extractor._is_valid_hash_pattern(non_hex_hash[:64]) is True
    assert "evil-example.com" in extractor._extract_domains_from_urls("ignored")


def test_artifact_extractors_cover_remaining_validation_paths() -> None:
    class ArtifactCoverageExtractor(IOCExtractor):
        def _extract_pattern(self, text: str, pattern_name: str) -> list[str]:  # type: ignore[override]
            if pattern_name == "yara":
                return ['rule demo { strings: $a = "x" condition: true']
            return super()._extract_pattern(text, pattern_name)

    extractor = ArtifactCoverageExtractor(defang=False)

    bitcoin = extractor.extract_bitcoin(
        "0123456789abcdef0123456789abcdef 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    )
    macs = extractor.extract_mac_addresses("bad aa:bb:cc:dd:ee:ff aa:bb:cc:dd:ee")
    yara = extractor.extract_yara_rules("ignored")

    assert bitcoin == ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
    assert "aa:bb:cc:dd:ee:ff" in macs
    assert any(rule.endswith("\n}") for rule in yara)

    class ArtifactEdgeExtractor(IOCExtractor):
        def _extract_pattern(self, text: str, pattern_name: str) -> list[str]:  # type: ignore[override]
            if pattern_name == "bitcoin":
                return ["0123456789abcdef0123456789abcdef", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
            if pattern_name == "mac_addresses":
                return ["aa:bb:cc:dd:ee"]
            return super()._extract_pattern(text, pattern_name)

    edge_extractor = ArtifactEdgeExtractor(defang=False)
    assert edge_extractor.extract_bitcoin("ignored") == ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
    assert edge_extractor.extract_mac_addresses("ignored") == []


def test_streaming_extractors_cover_buffer_and_parallel_fallbacks(tmp_path: Path) -> None:
    text_file = tmp_path / "sample.txt"
    text_file.write_text("IOC URL: https://stream.example/path\n", encoding="utf-8")

    extractor = StreamingIOCExtractor(chunk_size=64, overlap=2, defang=False)
    with text_file.open(encoding="utf-8") as handle:
        chunks = list(extractor._read_chunks(handle, is_text=False))
    assert chunks

    with text_file.open(encoding="utf-8") as handle:
        yielded = list(extractor.extract_from_stream(handle, is_text=False))
    assert yielded

    progress_values: list[int] = []
    parallel = ParallelStreamingExtractor(max_workers=1, chunk_size=8, defang=False)

    class BrokenPath:
        def __init__(self) -> None:
            self.calls = 0

        def __str__(self) -> str:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError
            return "broken-path"

    results = parallel.extract_from_files(
        [text_file, BrokenPath()],
        progress_callback=progress_values.append,
    )

    assert "https://stream.example/path" in results[str(text_file)]["urls"]
    assert "_errors" in results["broken-path"]
    assert progress_values == [50]


def test_network_and_base_edge_paths_cover_remaining_branches() -> None:
    class NetworkEdgeExtractor(IOCExtractor):
        def _extract_pattern(self, text: str, pattern_name: str) -> list[str]:  # type: ignore[override]
            if pattern_name == "ips":
                return ["1.2.3", "a.2.3.4", "01.2.3.4"]
            if pattern_name == "ipv6":
                return ["not::ip", "2001:db8::1"]
            if pattern_name == "domains":
                return ["document.cookie", "evil-example.com"]
            return super()._extract_pattern(text, pattern_name)

    extractor = NetworkEdgeExtractor(defang=False)
    assert extractor.extract_ips("ignored") == []
    assert extractor.extract_ipv6("ignored") == ["2001:db8::1"]
    assert extractor.extract_hosts("ignored") == ["evil-example.com"]

    dynamic_extractor_cls = type("DynamicExtractor", (IOCExtractor,), {"__module__": "missing.module"})
    dynamic = dynamic_extractor_cls(defang=False)
    assert dynamic.reference_data.data_dir.name == "data"

    non_hex_hash = ("ghijklmnopqrstuvwxyz" * 3) + "wxyz"
    assert dynamic._is_valid_hash_pattern(non_hex_hash) is True


def test_stix_renderer_covers_unsupported_builder_and_write_path(tmp_path: Path) -> None:
    renderer = STIXOutputRenderer()
    assert renderer._build_indicator(IOCType.JWT, "header.payload.signature", None) is None

    original_builders = dict(STIXOutputRenderer.PATTERN_BUILDERS)
    STIXOutputRenderer.PATTERN_BUILDERS.pop(IOCType.DOMAIN, None)
    try:
        assert renderer._build_indicator(IOCType.DOMAIN, "example.com", None) is None
    finally:
        STIXOutputRenderer.PATTERN_BUILDERS = original_builders

    output_file = tmp_path / "stix" / "bundle.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        renderer.render(ExtractionResult(iocs=(IOC.from_raw("domains", "example.com"),))),
        encoding="utf-8",
    )
    assert output_file.exists()
