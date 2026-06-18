from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from iocparser.adapters.renderers import (
    CSVOutputRenderer,
    JSONLinesOutputRenderer,
    JSONOutputRenderer,
    STIXOutputRenderer,
)
from iocparser.api_pipeline import (
    BATCH_REPORT_SCHEMA_VERSION,
    PipelineJobRequest,
    PipelineWorker,
    ResourceLimits,
)
from iocparser.cli_output import print_batch_report
from iocparser.cli_processing import process_url_file_input_with_report
from iocparser.cli_runtime import apply_config_defaults
from iocparser.config import load_config
from iocparser.domain.models import IOC, ExtractionResult
from iocparser.domain.persisted import PersistedRunExport, PersistedRunSummary
from iocparser.domain.pipeline import RESULT_SCHEMA_VERSION, PipelineErrorInfo, PipelineJobResult
from iocparser.errors import (
    DownloadError,
    FileExistenceError,
    FileProcessingError,
    FileSizeError,
    InvalidURLError,
    IOCTimeoutError,
    UnsupportedFileTypeError,
    ValidationError,
)
from iocparser.infrastructure.file_readers import MagicTextSourceReader
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
from iocparser.infrastructure.persistence_schema import RunModel, SQLAlchemyUnitOfWork
from iocparser.pipeline_errors import classify_pipeline_exception


def _result() -> ExtractionResult:
    return ExtractionResult(iocs=(IOC.from_raw("domains", "evil.example"),))


def test_renderers_include_schema_version() -> None:
    result = _result()

    json_payload = json.loads(JSONOutputRenderer(include_context=True).render(result))
    assert json_payload["schema_version"] == RESULT_SCHEMA_VERSION
    assert json_payload["format"] == "json"

    jsonl_line = JSONLinesOutputRenderer().render(result).splitlines()[0]
    assert json.loads(jsonl_line)["schema_version"] == RESULT_SCHEMA_VERSION

    csv_lines = CSVOutputRenderer().render(result).splitlines()
    assert csv_lines[0].startswith("schema_version,")
    assert RESULT_SCHEMA_VERSION in csv_lines[1]

    stix_payload = json.loads(STIXOutputRenderer().render(result))
    assert stix_payload["x_iocparser_schema_version"] == RESULT_SCHEMA_VERSION
    assert stix_payload["x_iocparser_format"] == "stix"


def test_batch_report_is_versioned_and_classified(tmp_path: Path) -> None:
    url_file = tmp_path / "urls.txt"
    url_file.write_text("not-a-url\n", encoding="utf-8")
    args = type(
        "Args",
        (),
        {
            "url_file": str(url_file),
            "retry_failed_from": None,
            "retry_batch_job": None,
            "retry_error_type": None,
            "retry_error_contains": None,
            "url_workers": 1,
            "streaming": False,
            "chunk_size": 1024 * 1024,
            "overlap": 1024,
            "type": None,
            "no_defang": False,
            "no_check_warnings": True,
            "force_update": False,
            "only": None,
            "exclude": None,
            "extractor": None,
            "postprocessor": None,
            "enricher": None,
            "job_id": "job-1",
            "correlation_id": "corr-1",
        },
    )()
    _, _, _, _, report = process_url_file_input_with_report(
        args,
        reader=MagicTextSourceReader(),
        warning_service=None,
        downloader=RequestsURLDownloader(),
        db_uri=None,
    )
    assert report["schema_version"] == BATCH_REPORT_SCHEMA_VERSION
    assert report["job_id"] == "job-1"
    assert report["correlation_id"] == "corr-1"
    assert report["status"] == "failed"
    item = report["items"][0]
    assert item["error_code"] == "INVALID_URL"
    assert item["error_category"] == "malformed_input"
    assert item["retryable"] is False


def test_pipeline_worker_persists_and_skips_processed(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'pipeline.db'}"
    worker = PipelineWorker(limits=ResourceLimits(skip_processed=True))
    request = PipelineJobRequest(
        input_kind="text",
        source_value="IOC hxxp://evil.example",
        persist=True,
        db_uri=db_uri,
        check_warnings=False,
    )

    first = worker.process(request)
    second = worker.process(request)

    assert first.status == "success"
    assert first.run_id is not None
    assert second.status == "skipped"
    assert second.skipped is True
    assert second.run_id == first.run_id

    runs = SQLAlchemyPersistenceService(db_uri).list_runs(limit=10)
    assert len(runs) == 1


def test_pipeline_worker_enforces_size_limit() -> None:
    worker = PipelineWorker(limits=ResourceLimits(max_input_size_bytes=8))
    result = worker.process(
        PipelineJobRequest(
            input_kind="text",
            source_value="this input is too large",
            check_warnings=False,
        ),
    )
    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "VALIDATION_FAILED"
    assert result.error.retryable is False


def test_resource_limits_ignore_negative_operational_limits() -> None:
    limits = ResourceLimits(
        max_input_size_bytes=-1,
        max_input_seconds=-1.0,
        max_workers=0,
        max_queue_size=0,
    )

    assert limits.max_input_size_bytes is None
    assert limits.max_input_seconds is None
    assert limits.max_workers == 1
    assert limits.max_queue_size == 64
    result = PipelineWorker(limits=limits).process(
        PipelineJobRequest(
            input_kind="text",
            source_value="see hxxp://evil.example",
            check_warnings=False,
        ),
    )
    assert result.status == "success"


def test_pipeline_worker_classifies_missing_file_as_input_not_found() -> None:
    result = PipelineWorker().process(
        PipelineJobRequest(
            input_kind="file",
            source_value="/tmp/iocparser-missing-file-nope.txt",
            check_warnings=False,
        ),
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "INPUT_NOT_FOUND"


def test_pipeline_worker_checks_file_size_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = tmp_path / "oversized.txt"
    file_path.write_text("too large", encoding="utf-8")

    def fail_read_bytes(self: Path) -> bytes:
        raise AssertionError(f"read_bytes should not be called for {self}")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)
    result = PipelineWorker(limits=ResourceLimits(max_input_size_bytes=1)).process(
        PipelineJobRequest(input_kind="file", source_value=str(file_path), check_warnings=False),
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "VALIDATION_FAILED"


def test_pipeline_worker_ignores_missing_temp_file_during_url_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    temp_file = tmp_path / "downloaded.txt"
    temp_file.write_text("cached input", encoding="utf-8")

    class FakeDownloader:
        last_download_metadata = {"input_size": temp_file.stat().st_size}

        def download(self, url: str) -> str:
            assert url == "https://example.test/report"
            return str(temp_file)

    class FakeClient:
        downloader = FakeDownloader()

        def extract_result_from_text(self, text_content: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("text extraction should not run")

        def extract_result_from_file(self, file_path: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("file extraction should not run")

    def fail_limit(*args: object, **kwargs: object) -> None:
        del args, kwargs
        temp_file.unlink()
        raise ValidationError("too big")

    monkeypatch.setattr("iocparser.pipeline_worker_support.enforce_size_limit", fail_limit)

    result = PipelineWorker(client=FakeClient()).process(
        PipelineJobRequest(
            input_kind="url",
            source_value="https://example.test/report",
            check_warnings=False,
        )
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "VALIDATION_FAILED"


def test_pipeline_worker_cleans_downloaded_url_when_runtime_size_limit_fails(
    tmp_path: Path,
) -> None:
    temp_file = tmp_path / "downloaded.txt"
    temp_file.write_text("too large", encoding="utf-8")

    class FakeDownloader:
        last_download_metadata = {"input_size": 9}

        def download(self, url: str) -> str:
            assert url == "https://example.test/report"
            return str(temp_file)

    class FakeClient:
        downloader = FakeDownloader()

        def extract_result_from_text(self, text_content: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("text extraction should not run")

        def extract_result_from_file(self, file_path: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("file extraction should not run")

    result = PipelineWorker(
        client=FakeClient(),
        limits=ResourceLimits(max_input_size_bytes=1),
    ).process(
        PipelineJobRequest(
            input_kind="url",
            source_value="https://example.test/report",
            check_warnings=False,
        )
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "VALIDATION_FAILED"
    assert not temp_file.exists()


def test_pipeline_worker_enforces_downloaded_file_size_when_url_metadata_omits_size(
    tmp_path: Path,
) -> None:
    temp_file = tmp_path / "downloaded.txt"
    temp_file.write_text("too large", encoding="utf-8")

    class FakeDownloader:
        last_download_metadata: dict[str, object] | None = {}

        def download(self, url: str) -> str:
            assert url == "https://example.test/report"
            return str(temp_file)

    class FakeClient:
        downloader = FakeDownloader()

        def extract_result_from_text(self, text_content: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("text extraction should not run")

        def extract_result_from_file(self, file_path: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("oversized URL extraction should not run")

    result = PipelineWorker(
        client=FakeClient(),
        limits=ResourceLimits(max_input_size_bytes=1),
    ).process(
        PipelineJobRequest(
            input_kind="url",
            source_value="https://example.test/report",
            check_warnings=False,
        )
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "VALIDATION_FAILED"
    assert not temp_file.exists()


def test_pipeline_worker_cleans_downloaded_url_when_processed_run_is_skipped(
    tmp_path: Path,
) -> None:
    temp_file = tmp_path / "downloaded.txt"
    temp_file.write_text("cached input", encoding="utf-8")
    content_hash = "a" * 64
    fingerprint = "a" * 16
    now = datetime.now(UTC)
    summary = PersistedRunSummary(
        run_id=17,
        source_kind="url",
        source_value="https://example.test/report",
        tool_version="5.0.0",
        started_at=now,
        finished_at=now,
        content_hash=content_hash,
        fingerprint=fingerprint,
    )

    class FakeDownloader:
        last_download_metadata = {
            "input_size": temp_file.stat().st_size,
            "content_hash": content_hash,
            "fingerprint": fingerprint,
        }

        def download(self, url: str) -> str:
            assert url == "https://example.test/report"
            return str(temp_file)

    class FakeClient:
        downloader = FakeDownloader()

        def extract_result_from_text(self, text_content: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("text extraction should not run")

        def extract_result_from_file(self, file_path: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("file extraction should not run for skipped inputs")

    class FakeProcessedRunLookup:
        def find_existing_run(
            self,
            *,
            fingerprint: str | None = None,
            content_hash: str | None = None,
            status: str = "success",
        ) -> PersistedRunSummary | None:
            assert fingerprint == "a" * 16
            assert content_hash == "a" * 64
            assert status == "success"
            return summary

        def export_run(self, *, run_id: int) -> PersistedRunExport:
            assert run_id == 17
            return PersistedRunExport(summary=summary, result=_result())

    result = PipelineWorker(
        client=FakeClient(),
        limits=ResourceLimits(skip_processed=True),
        processed_run_lookup=FakeProcessedRunLookup(),
    ).process(
        PipelineJobRequest(
            input_kind="url",
            source_value="https://example.test/report",
            check_warnings=False,
        )
    )

    assert result.status == "skipped"
    assert result.skipped is True
    assert result.run_id == 17
    assert not temp_file.exists()


def test_pipeline_worker_raises_when_success_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    temp_file = tmp_path / "downloaded.txt"
    temp_file.write_text("cached input", encoding="utf-8")

    class FakeDownloader:
        last_download_metadata = {"input_size": temp_file.stat().st_size}

        def download(self, url: str) -> str:
            assert url == "https://example.test/report"
            return str(temp_file)

    class FakeClient:
        downloader = FakeDownloader()

        def extract_result_from_text(self, text_content: str, **kwargs: object) -> ExtractionResult:
            raise AssertionError("text extraction should not run")

        def extract_result_from_file(self, file_path: str, **kwargs: object) -> ExtractionResult:
            assert file_path == str(temp_file)
            return _result()

    def failing_unlink(*_args: object, **_kwargs: object) -> None:
        raise OSError("cleanup failed")

    monkeypatch.setattr("iocparser.pipeline_worker_support.Path.unlink", failing_unlink)

    with pytest.raises(OSError, match="cleanup failed"):
        PipelineWorker(client=FakeClient()).process(
            PipelineJobRequest(
                input_kind="url",
                source_value="https://example.test/report",
                check_warnings=False,
            )
        )


def test_pipeline_worker_enforces_time_limit_and_invalid_kind() -> None:
    timed = PipelineWorker(limits=ResourceLimits(max_input_seconds=0.0))
    timed_result = timed.process(
        PipelineJobRequest(
            input_kind="text", source_value="ioc hxxp://evil.example", check_warnings=False
        ),
    )
    assert timed_result.status == "failed"
    assert timed_result.error is not None
    assert timed_result.error.code == "INPUT_TIMEOUT"

    invalid = PipelineWorker().process(
        PipelineJobRequest(input_kind="unknown", source_value="x", check_warnings=False),
    )
    assert invalid.status == "failed"
    assert invalid.error is not None
    assert invalid.error.code == "UNEXPECTED_FAILURE"


def test_load_config_exposes_pipeline_limits(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[network]\n"
        "max_input_size_mb = 12.5\n"
        "max_input_seconds = 4.5\n"
        "max_queue_size = 7\n"
        "skip_processed = true\n",
        encoding="utf-8",
    )
    config = load_config(None, None, str(config_path))
    assert config.max_input_size_mb == 12.5
    assert config.max_input_seconds == 4.5
    assert config.max_queue_size == 7
    assert config.skip_processed is True


def test_apply_config_defaults_sets_pipeline_limit_values(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[network]\nmax_input_size_mb = 2.0\nmax_input_seconds = 3.0\nmax_queue_size = 9\nskip_processed = true\n",
        encoding="utf-8",
    )
    config = load_config(None, None, str(config_path))
    args = SimpleNamespace(
        only=None,
        exclude=None,
        stix_types=None,
        severity=None,
        tag=None,
        headers_json=None,
        cookies_json=None,
        with_context=False,
        streaming=False,
        summary=False,
        skip_processed=False,
        json=False,
        jsonl=False,
        csv=False,
        stix=False,
        output_format=None,
        url_workers=None,
        url_retries=None,
        url_backoff=None,
        rate_limit=None,
        parallel=None,
        chunk_size=None,
        overlap=None,
        max_queue_size=None,
        max_input_size_mb=None,
        max_input_seconds=None,
        diff_only=None,
        user_agent=None,
        proxy=None,
        tls_cert=None,
        ca_bundle=None,
        connect_timeout=None,
        read_timeout=None,
        allow_redirects=True,
        tls_verify=True,
    )
    apply_config_defaults(args, config)
    assert args.skip_processed is True
    assert args.max_input_size_mb == 2.0
    assert args.max_input_seconds == 3.0
    assert args.max_queue_size == 9


def test_apply_config_defaults_keeps_zero_network_timeouts(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[network]\nconnect_timeout = 0.0\nread_timeout = 0.0\n",
        encoding="utf-8",
    )
    config = load_config(None, None, str(config_path))
    args = SimpleNamespace(
        only=None,
        exclude=None,
        stix_types=None,
        severity=None,
        tag=None,
        headers_json=None,
        cookies_json=None,
        with_context=False,
        streaming=False,
        summary=False,
        skip_processed=False,
        json=False,
        jsonl=False,
        csv=False,
        stix=False,
        output_format=None,
        url_workers=None,
        url_retries=None,
        url_backoff=None,
        rate_limit=None,
        parallel=None,
        chunk_size=None,
        overlap=None,
        max_queue_size=None,
        max_input_size_mb=None,
        max_input_seconds=None,
        diff_only=None,
        user_agent=None,
        proxy=None,
        tls_cert=None,
        ca_bundle=None,
        connect_timeout=None,
        read_timeout=None,
        allow_redirects=True,
        tls_verify=True,
    )
    apply_config_defaults(args, config)
    assert args.connect_timeout == 0.0
    assert args.read_timeout == 0.0


@pytest.mark.parametrize(
    ("config_text", "message"),
    [
        ("[defaults]\nchunk_size = 0\n", "chunk_size"),
        ("[defaults]\noverlap = -1\n", "overlap"),
    ],
)
def test_apply_config_defaults_rejects_invalid_streaming_sizes_from_config(
    tmp_path: Path, config_text: str, message: str
) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(config_text, encoding="utf-8")
    config = load_config(None, None, str(config_path))
    args = SimpleNamespace(chunk_size=None, overlap=None)

    with pytest.raises(ValidationError, match=message):
        apply_config_defaults(args, config)


def test_apply_config_defaults_rejects_invalid_output_format_config(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[defaults]\noutput_format = jsno\n", encoding="utf-8")
    config = load_config(None, None, str(config_path))
    args = SimpleNamespace(json=False, jsonl=False, csv=False, stix=False)

    with pytest.raises(ValidationError, match="output_format"):
        apply_config_defaults(args, config)


def test_apply_config_defaults_accepts_text_output_format_config(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[defaults]\noutput_format = text\n", encoding="utf-8")
    config = load_config(None, None, str(config_path))
    args = SimpleNamespace(json=False, jsonl=False, csv=False, stix=False)

    apply_config_defaults(args, config)

    assert args.json is False
    assert args.jsonl is False
    assert args.csv is False
    assert args.stix is False


def test_apply_config_defaults_rejects_invalid_diff_only_config(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[defaults]\ndiff_only = bogus\n", encoding="utf-8")
    config = load_config(None, None, str(config_path))
    args = SimpleNamespace(diff_only=None)

    with pytest.raises(ValidationError, match="Invalid diff_only"):
        apply_config_defaults(args, config)


def test_pipeline_error_classification_covers_stable_codes() -> None:
    cases = [
        (FileExistenceError("missing.txt"), "INPUT_NOT_FOUND"),
        (InvalidURLError("notaurl"), "INVALID_URL"),
        (UnsupportedFileTypeError("bad.bin"), "UNSUPPORTED_INPUT_TYPE"),
        (FileSizeError(3.0, 1.0), "INPUT_TOO_LARGE"),
        (IOCTimeoutError("Download", "https://x"), "INPUT_TIMEOUT"),
        (DownloadError("https://x", "boom"), "DOWNLOAD_FAILED"),
        (FileProcessingError("sample.txt", "bad parse"), "PARSER_FAILED"),
        (ValidationError("bad"), "VALIDATION_FAILED"),
        (RuntimeError("boom"), "UNEXPECTED_FAILURE"),
    ]
    assert [classify_pipeline_exception(exc).code for exc, _ in cases] == [
        code for _, code in cases
    ]


def test_pipeline_job_result_and_error_info_to_record() -> None:
    error = PipelineErrorInfo(
        code="INPUT_TIMEOUT",
        category="transport_failure",
        retryable=True,
        status="failed",
        message="timeout",
    )
    result = PipelineJobResult(
        input_kind="text",
        source_value="demo",
        status="failed",
        result=ExtractionResult(),
        correlation_id="corr",
        job_id="job",
        error=error,
    )
    record = result.to_record()
    assert record["schema_version"] == "1.0"
    assert record["error"]["code"] == "INPUT_TIMEOUT"
    assert record["result"]["schema_version"] == "1.0"


def test_pipeline_worker_handles_file_url_and_backpressure(tmp_path: Path, capsys) -> None:
    file_path = tmp_path / "ioc.txt"
    file_path.write_text("Visit hxxp://evil.example", encoding="utf-8")
    worker = PipelineWorker(limits=ResourceLimits(max_queue_size=1))

    file_result = worker.process(
        PipelineJobRequest(input_kind="file", source_value=str(file_path), check_warnings=False),
    )
    assert file_result.status == "success"

    class _Downloader:
        def __init__(self, source: Path) -> None:
            self.source = source
            self.last_download_metadata = {
                "input_size": source.stat().st_size,
                "content_hash": "abc123",
                "fingerprint": "abc12345",
                "original_url": "https://example.test/feed.txt",
                "normalized_url": "https://example.test/feed.txt",
            }

        def download(self, url: str) -> str:
            del url
            target = self.source.parent / "downloaded.txt"
            target.write_bytes(self.source.read_bytes())
            return str(target)

    url_worker = PipelineWorker()
    url_worker.client.downloader = _Downloader(file_path)
    url_result = url_worker.process(
        PipelineJobRequest(
            input_kind="url", source_value="https://example.test/feed.txt", check_warnings=False
        ),
    )
    assert url_result.status == "success"
    assert not (file_path.parent / "downloaded.txt").exists()

    worker._inflight = 1
    with pytest.raises(RuntimeError, match="at capacity"):
        worker.process(
            PipelineJobRequest(input_kind="text", source_value="x", check_warnings=False)
        )
    worker._inflight = 0

    print_batch_report(
        {"schema_version": BATCH_REPORT_SCHEMA_VERSION, "total": 1, "successful": 1, "failed": 0}
    )
    assert "Batch report schema" in capsys.readouterr().out


def test_find_existing_run_without_keys_returns_none(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'empty.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    assert service.find_existing_run() is None


def test_find_existing_run_uses_newest_run_id_as_timestamp_tiebreaker(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'dedupe-tiebreak.db'}"
    worker = PipelineWorker()
    request = PipelineJobRequest(
        input_kind="text",
        source_value="IOC hxxp://evil.example",
        persist=True,
        db_uri=db_uri,
        check_warnings=False,
    )
    first = worker.process(request)
    second = worker.process(request)
    same_started_at = datetime(2026, 1, 1, tzinfo=UTC)
    unit = SQLAlchemyUnitOfWork(db_uri)
    try:
        for run_id in (first.run_id, second.run_id):
            run = unit.session.get(RunModel, run_id)
            assert run is not None
            run.started_at = same_started_at
        unit.commit()
    finally:
        unit.close()

    found = SQLAlchemyPersistenceService(db_uri).find_existing_run(
        fingerprint=second.fingerprint,
        content_hash=second.content_hash,
    )

    assert found is not None
    assert found.run_id == second.run_id
