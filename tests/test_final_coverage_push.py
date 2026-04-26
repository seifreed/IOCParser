from __future__ import annotations

import io
from pathlib import Path

import pytest

import iocparser.infrastructure.warninglists_service as warninglists_service_module
from iocparser.application.use_cases import _build_evidence, _build_result_from_raw_iocs
from iocparser.cli_args import get_output_filename
from iocparser.domain.models import IOC, ExtractionResult, IOCType, PersistOptions, classify_ioc
from iocparser.infrastructure.persistence.query import SQLAlchemyPersistenceService
from iocparser.infrastructure.streaming import StreamingIOCExtractor


class NoSeekBytesIO(io.BytesIO):
    def seek(self, *args, **kwargs):  # type: ignore[override]
        raise io.UnsupportedOperation("seek disabled")


class WrappedTextIO(io.TextIOWrapper):
    @property
    def buffer(self):  # type: ignore[override]
        return io.BytesIO(b"https://evil.example/path")


class ServiceBackedWarningListsWithFallback:
    def __init__(self, *, force_update: bool = False) -> None:
        self.force_update = force_update

    def separate_iocs_by_warnings(self, grouped_iocs):
        del grouped_iocs
        return (
            {"domains": ["fresh.example"]},
            {
                "domains": [
                    {"value": ""},
                    {"value": "normal.example", "warning_list": "Matched", "description": "existing"},
                    {"value": "warning.example", "warning_list": "Known", "description": ""},
                ]
            },
        )


def test_use_case_helpers_cover_empty_duplicates_and_truncation() -> None:
    assert _build_evidence("anything", "") == ()

    evidence = _build_evidence(
        "https://evil.example/path\nhttps://evil.example/path\nhttps://evil.example/path\nhttps://evil.example/path\n",
        "https://evil.example/path",
    )
    assert len(evidence) == 3
    assert _build_evidence("https://evil.example/path\n \nhttps://evil.example/path\n", "https://evil.example/path")
    assert _build_evidence("xxxhttps://evil.example/pathyyy", "https://evil.example/path")

    result = _build_result_from_raw_iocs({"urls": ["https://evil.example/path", ""]}, "https://evil.example/path")
    assert result.grouped_iocs() == {"urls": ["https://evil.example/path"]}


def test_classify_high_severity_and_cli_filename_formats() -> None:
    severity, tags = classify_ioc(IOCType.CVE)
    assert severity == "high"
    assert "behavioral" in tags

    assert get_output_filename("sample", output_format="jsonl").endswith(".jsonl")
    assert get_output_filename("sample", output_format="csv").endswith(".csv")


def test_persistence_queries_cover_warning_and_missing_run(tmp_path: Path) -> None:
    service = SQLAlchemyPersistenceService(f"sqlite:///{tmp_path / 'runs.sqlite'}")
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "warning.txt",
                ExtractionResult.from_grouped_payload(
                    {"domains": ["normal.example"]},
                    {
                        "domains": [
                            {
                                "value": "warning.example",
                                "warning_list": "Known",
                                "description": "",
                            }
                        ]
                    },
                ),
            )
        ],
        tool_version="1.0.0",
        options=PersistOptions(
            defang=False,
            check_warnings=False,
            force_update=False,
            output_format="json",
        ),
    )
    export = service.export_run(run_id=run_ids[0])
    assert export.result.warnings
    with pytest.raises(ValueError, match="Run not found: 99999"):
        service.export_run(run_id=99999)


def test_warninglist_service_fallback_and_empty_warning_value() -> None:
    original = warninglists_service_module.MISPWarningLists
    warninglists_service_module.MISPWarningLists = ServiceBackedWarningListsWithFallback
    try:
        result = warninglists_service_module.MISPWarningListService().separate(
            (IOC.from_raw("domains", "normal.example"),),
            force_update=True,
        )
    finally:
        warninglists_service_module.MISPWarningLists = original

    assert result.grouped_iocs() == {"domains": ["fresh.example"]}
    assert result.grouped_warnings() == {
        "domains": [
            {"value": "normal.example", "warning_list": "Matched", "description": "existing"},
            {"value": "warning.example", "warning_list": "Known", "description": ""},
        ],
    }


def test_streaming_private_helpers_cover_remaining_branches(tmp_path: Path) -> None:
    extractor = StreamingIOCExtractor(chunk_size=16, overlap=8, defang=False)

    chunks = list(extractor._read_chunks_with_prefix(NoSeekBytesIO(b"https://evil.example/path"), is_text=False))
    assert chunks
    wrapped = WrappedTextIO(io.BytesIO(b"placeholder"), encoding="utf-8")
    assert list(extractor._read_chunks_with_prefix(wrapped, is_text=False))

    assert extractor._is_valid_match_boundary("urls", "xhttps://evil.example/path", 1, 26) is False
    assert extractor._is_valid_match_boundary("emails", "xuser@example.comy", 1, 17) is False
    assert extractor._is_valid_match_boundary("emails", "prefix user@example.comx", 7, 23) is False
    assert extractor._should_keep_ioc("domains", "evil.example", "", 2) is False
    assert extractor._should_keep_ioc("domains", "evil.example", "evil.example", 0) is True

    sample = tmp_path / "stream.txt"
    sample.write_text("IOC URL: https://evil.example/path\n", encoding="utf-8")
    full_extractor = StreamingIOCExtractor(chunk_size=1024, overlap=16, defang=False)
    assert "https://evil.example/path" in full_extractor.extract_from_file(sample)["urls"]
