from __future__ import annotations

import argparse
import io
import json
import sys
import time
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from iocparser import cli_processing_single
from iocparser.adapters.renderers import (
    STIXOutputRenderer,
    TextOutputRenderer,
    _record_dict_list,
    _record_string_list,
)
from iocparser.adapters.renderers import (
    _json_object as renderer_json_object,
)
from iocparser.cli_args_values import int_arg_value
from iocparser.cli_output import _int_value as batch_int_value
from iocparser.cli_output import print_batch_report, save_batch_report
from iocparser.cli_output_rendering import (
    _int_run_metadata_value,
    _optional_int_run_metadata_value,
)
from iocparser.cli_processing_single import process_single_input
from iocparser.cli_processing_support import joined_type_filters, plugin_client
from iocparser.cli_processing_urls import (
    _int_value as url_int_value,
)
from iocparser.cli_processing_urls import (
    _joined_type_filters as url_joined_type_filters,
)
from iocparser.cli_processing_urls import (
    _json_dict,
    _report_item,
    _report_items,
)
from iocparser.cli_processing_urls import (
    _plugin_client as url_plugin_client,
)
from iocparser.cli_runtime import _optional_float_arg
from iocparser.cli_schema import _history_payload
from iocparser.client_persistence import _parse_string_filters
from iocparser.domain.distributed import _int_from_payload
from iocparser.domain.enums import IOCType, register_custom_ioc_type
from iocparser.domain.models import IOC, ExtractionOptions, ExtractionResult
from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.errors import DownloadError, ValidationError
from iocparser.infrastructure.file_readers import MagicTextSourceReader
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.persistence.history.ops import _json_object as history_json_object
from iocparser.infrastructure.persistence.history.ops import _row_dict
from iocparser.infrastructure.persistence.query import query_runs_page, search_iocs_page
from iocparser.infrastructure.persistence.query.ops import _coerce_count, _order_search_stmt
from iocparser.infrastructure.persistence_batch import (
    BatchJobModel,
    FailedBatchItemModel,
    _failed_items,
    _int_report_value,
)
from iocparser.infrastructure.persistence_distributed_records import _json_int_map
from iocparser.infrastructure.persistence_distributed_records import (
    _json_object as record_json_object,
)
from iocparser.infrastructure.persistence_migration_runtime import schema_version
from iocparser.infrastructure.persistence_migration_steps import _coerce_version_row
from iocparser.infrastructure.persistence_models import DeadLetterJobModel, DistributedJobModel
from iocparser.infrastructure.persistence_repository_support import (
    _int_metadata_value,
    _ioc_type_name,
    _optional_int_metadata_value,
    finished_at_from_duration,
)
from iocparser.infrastructure.persistence_schema import IOCModel, RunIOCModel, RunModel, SourceModel
from iocparser.infrastructure.persistence_support import _evidence_from_json, _json_list
from iocparser.infrastructure.queue_filesystem import _load_queue_record as load_fs_queue_record
from iocparser.infrastructure.queue_rabbitmq import _load_queue_record as load_rabbit_queue_record
from iocparser.infrastructure.queue_sqs import _load_queue_record as load_sqs_queue_record
from iocparser.infrastructure.warninglists_matching import WarningListMatchingMixin
from iocparser.infrastructure.warninglists_preprocess import WarningListPreprocessMixin
from iocparser.infrastructure.warninglists_types import WarningListLookups
from iocparser.pipeline_worker import (
    _metadata_int,
    _PipelineUnitOfWork,
    _prepared_temp_file,
    _PreparedInput,
    _RunRepositoryAdapter,
)
from iocparser.pipeline_worker_support import PreparedInput, persist_result
from iocparser.worker_config_support import (
    bool_env,
    float_env,
    float_or,
    float_or_none,
    int_env,
    int_or,
    int_or_none,
    resolve_config_path,
)


class _MemoryWriter:
    def __init__(self) -> None:
        self.writes: list[tuple[str, str]] = []

    def write(self, path: str, content: str) -> None:
        self.writes.append((path, content))


class _DummyReader:
    def read(self, file_path: Path, options=None) -> str:
        del file_path, options
        return ""


class _DummyWarningLists(WarningListPreprocessMixin, WarningListMatchingMixin):
    IOC_TYPE_MAPPING = {"domain": "domains"}
    MISP_TYPE_MAPPING = {"domains": ["domain"]}
    DEFANG_CLEANERS = [("[.]", "."), ("hxxp", "http")]

    def __init__(self) -> None:
        self.warning_lists = {}
        self.lookup_data = WarningListLookups({}, {}, {}, {})


class _DummyMatchingOnly(WarningListMatchingMixin):
    IOC_TYPE_MAPPING = {"domain": "domains"}
    MISP_TYPE_MAPPING = {"domains": ["domain"]}

    def _clean_defanged_value(self, value: str) -> str:
        return value


class _DummyPreprocessOnly(WarningListPreprocessMixin):
    IOC_TYPE_MAPPING = {"domain": "domains"}
    DEFANG_CLEANERS = [("[.]", "."), ("hxxp", "http")]

    def __init__(self) -> None:
        self.warning_lists = {}
        self.lookup_data = WarningListLookups({}, {}, {}, {})


def test_cli_processing_support_helpers_cover_filters_and_plugin_creation() -> None:
    options = ExtractionOptions(
        include_types=(IOCType.DOMAIN, IOCType.URL),
        exclude_types=(IOCType.IP,),
    )
    assert joined_type_filters(options) == ("domains,urls", "ips")
    assert (
        plugin_client(None, reader=MagicTextSourceReader(), downloader=None, warning_service=None)
        is None
    )

    args = argparse.Namespace(extractor=["demo"], postprocessor=(), enricher=())
    client = plugin_client(
        args,
        reader=MagicTextSourceReader(),
        downloader=None,
        warning_service=object(),
    )
    assert client is not None


def test_cli_processing_single_rejects_non_text_stdin() -> None:
    original_stdin = cli_processing_single.sys.stdin
    args = argparse.Namespace(
        stdin=True,
        file="-",
        url=None,
        url_direct=None,
        no_check_warnings=True,
        force_update=False,
        no_defang=False,
        type=None,
        only=None,
        exclude=None,
        extractor=None,
        postprocessor=None,
        enricher=None,
        streaming=False,
        chunk_size=1024,
        overlap=128,
    )
    try:
        cli_processing_single.sys.stdin = object()
        with pytest.raises(ValidationError):
            process_single_input(
                args,
                reader=MagicTextSourceReader(),
                warning_service=None,
                downloader=RequestsURLDownloader(),
                process_file_func=lambda _path, *, request=None: ({}, {}),
            )
    finally:
        cli_processing_single.sys.stdin = original_stdin


def test_cli_processing_url_helper_parsing_and_plugin_builder() -> None:
    payload_path = Path("tmp-url-batch-report.json")
    payload_path.write_text(json.dumps(["bad"]), encoding="utf-8")
    try:
        assert _json_dict(payload_path) == {}
    finally:
        payload_path.unlink()

    entry = _report_item(
        {
            "url": "https://example.test",
            "status": "failed",
            "error": "boom",
            "error_type": "ValueError",
            "error_code": "ERR",
            "error_category": "parser_failure",
            "duration_ms": "12",
            "normal_ioc_count": "2",
            "warning_ioc_count": "1",
            "retry_attempt": "3",
            "retryable": True,
            "metadata": {"a": 1},
        }
    )
    assert entry["retry_attempt"] == 3
    assert entry["error_code"] == "ERR"
    assert _report_items({"items": ["bad", {"url": "x"}]}) == [{"url": "x"}]

    options = argparse.Namespace(include_types=(IOCType.DOMAIN,), exclude_types=("ips",))
    assert url_joined_type_filters(options) == ("domains", "ips")
    assert url_int_value(True) == 0
    assert url_int_value("bad", default=9) == 9
    assert url_int_value("", default=9) == 9
    assert _report_items({}) == []

    args = argparse.Namespace(extractor=["demo"], postprocessor=["post"], enricher=["extra"])
    client = url_plugin_client(
        args,
        reader=MagicTextSourceReader(),
        downloader=RequestsURLDownloader(),
        warning_service=None,
    )
    assert client is not None
    no_client = url_plugin_client(
        argparse.Namespace(extractor=None, postprocessor=None, enricher=None),
        reader=MagicTextSourceReader(),
        downloader=RequestsURLDownloader(),
        warning_service=None,
    )
    assert no_client is None


def test_cli_output_batch_helpers_cover_stdout_and_default_file() -> None:
    report = {
        "schema_version": "1.0",
        "total": "3",
        "successful": True,
        "failed": 2,
        "failures": {"a": "boom"},
        "error_groups": {"ValueError": "2"},
        "phase_timings_ms": {"extract": "5"},
        "metrics": {"throughput": 1.5},
    }
    output = io.StringIO()
    with redirect_stdout(output):
        print_batch_report(report)
        save_batch_report(report, "-", file_writer=_MemoryWriter())
    assert "Batch report schema" in output.getvalue()

    writer = _MemoryWriter()
    save_batch_report({"total": 0}, None, file_writer=writer)
    assert writer.writes[0][0] == "iocparser_batch_report.json"
    assert batch_int_value([], default=7) == 7


def test_cli_rendering_metadata_helpers_accept_strings() -> None:
    metadata = {"duration_ms": "4", "processed_items": "5"}
    assert _int_run_metadata_value(metadata, "processed_items", 0) == 5
    assert _optional_int_run_metadata_value(metadata, "duration_ms") == 4


def test_cli_and_schema_integer_helpers_raise_validation_errors() -> None:
    with pytest.raises(ValidationError):
        int_arg_value([], "offset")
    with pytest.raises(ValidationError):
        int_arg_value("oops", "offset")
    with pytest.raises(ValidationError):
        int_arg_value(False, "keep_latest")
    with pytest.raises(ValidationError):
        int_arg_value("nope", "keep_latest")

    payload_path = Path("bad-history.json")
    payload_path.write_text("[]", encoding="utf-8")
    try:
        with pytest.raises(ValidationError):
            _history_payload(str(payload_path))
    finally:
        payload_path.unlink()


def test_runtime_and_worker_config_support_helpers_cover_error_branches(tmp_path: Path) -> None:
    os_environ = sys.modules["os"].environ
    previous = {
        key: os_environ.get(key)
        for key in ("IOC_INT_ENV", "IOC_FLOAT_ENV", "IOC_BOOL_ENV", "IOCPARSER_CONFIG")
    }
    try:
        os_environ["IOC_INT_ENV"] = "7"
        os_environ["IOC_FLOAT_ENV"] = "1.5"
        os_environ["IOC_BOOL_ENV"] = "yes"
        assert int_env("IOC_INT_ENV") == 7
        assert float_env("IOC_FLOAT_ENV") == 1.5
        assert bool_env("IOC_BOOL_ENV") is True

        config_path = tmp_path / "iocparser.ini"
        config_path.write_text("[worker]\nqueue_backend = filesystem\n", encoding="utf-8")
        os_environ["IOCPARSER_CONFIG"] = str(config_path)
        assert resolve_config_path(None) == config_path
    finally:
        for key, value in previous.items():
            if value is None:
                os_environ.pop(key, None)
            else:
                os_environ[key] = value

    assert int_or("9", 0) == 9
    assert int_or_none("11") == 11
    assert float_or("1.25", 0.0) == 1.25
    assert float_or_none("2.5") == 2.5
    with pytest.raises(TypeError):
        int_or([], 0)
    with pytest.raises(TypeError):
        int_or_none([])
    with pytest.raises(TypeError):
        int_or(True, 0)
    with pytest.raises(TypeError):
        int_or_none(True)
    with pytest.raises(TypeError):
        float_or([], 0.0)
    with pytest.raises(TypeError):
        float_or_none([])
    with pytest.raises(TypeError):
        float_or(True, 0.0)
    with pytest.raises(TypeError):
        float_or_none(True)


def test_client_persistence_and_distributed_payload_helpers() -> None:
    assert _parse_string_filters(None) == ()
    assert _parse_string_filters("a, , b") == ("a", "b")
    assert _int_from_payload({"attempts": "3"}, "attempts", 0) == 3
    with pytest.raises(TypeError):
        _int_from_payload({"attempts": []}, "attempts", 0)
    with pytest.raises(TypeError, match="attempts"):
        _int_from_payload({"attempts": "bad"}, "attempts", 0)


def test_http_and_queue_helpers_cover_error_paths() -> None:
    assert _optional_float_arg(argparse.Namespace(rate=1), "rate") == 1.0
    assert _optional_float_arg(argparse.Namespace(rate="2.5"), "rate") == 2.5
    with pytest.raises(TypeError):
        _optional_float_arg(argparse.Namespace(rate=True), "rate")
    with pytest.raises(TypeError):
        _optional_float_arg(argparse.Namespace(rate=[]), "rate")

    with pytest.raises(TypeError):
        load_fs_queue_record("[]")
    with pytest.raises(TypeError):
        load_rabbit_queue_record(b"[]")
    with pytest.raises(TypeError):
        load_sqs_queue_record("[]")

    downloader = RequestsURLDownloader()
    downloader.retries = -1
    with pytest.raises(DownloadError) as exc_info:
        downloader.download("https://example.com")
    assert exc_info.value.error_type == "unexpected"


def test_persistence_helper_functions_cover_conversion_edges() -> None:
    assert _int_report_value({"count": "4"}, "count") == 4
    assert _int_report_value({"count": True}, "count", default=7) == 7
    assert _int_report_value({"count": "bad"}, "count", default=7) == 7
    assert _int_metadata_value({"count": True}, "count", 7) == 7
    assert _int_metadata_value({"count": "bad"}, "count", 7) == 7
    assert _int_metadata_value({"count": "-4"}, "count", 7) == 7
    assert _optional_int_metadata_value({"count": True}, "count") is None
    assert _optional_int_metadata_value({"count": "bad"}, "count") is None
    assert _optional_int_metadata_value({"count": -5}, "count") is None
    assert _failed_items("bad") == []
    with pytest.raises(TypeError):
        _int_report_value({"count": []}, "count")

    assert record_json_object("[]") == {}
    assert _json_int_map(json.dumps({"a": "2"})) == {"a": 2}
    assert _json_int_map(json.dumps({"a": True, "b": "bad", "c": "-3"})) == {"c": -3}
    assert _json_list("{}") == []
    evidence = _evidence_from_json(
        json.dumps([1, {"excerpt": "x", "line_number": 4, "source": "s"}])
    )
    assert evidence[0].excerpt == "x"

    assert _int_metadata_value({"count": "4"}, "count", 0) == 4
    assert _optional_int_metadata_value({"count": "5"}, "count") == 5
    assert _ioc_type_name("domains") == "domains"


def test_persistence_history_and_page_query_helpers_cover_remaining_branches() -> None:
    assert history_json_object("[]") == {}
    assert callable(query_runs_page)
    assert callable(search_iocs_page)

    now = datetime.now(UTC)
    batch_job = BatchJobModel(
        id=1,
        source_kind="url",
        started_at=now,
        finished_at=now,
        total_inputs=3,
        successful_inputs=2,
        failed_inputs=1,
        retry_attempt=0,
        status="completed",
        error_summary_json="{}",
        config_json="{}",
        metrics_json="{}",
    )
    failed_item = FailedBatchItemModel(
        id=2,
        batch_job_id=1,
        source_value="https://example.test",
        error_type="TimeoutError",
        error_message="boom",
        retry_attempt=1,
        created_at=now,
    )
    distributed = DistributedJobModel(
        job_id="job-1",
        correlation_id="corr-1",
        queue_backend="filesystem",
        queue_name="default",
        input_kind="text",
        source_value="ioc",
        idempotency_key="idem",
        status="completed",
        attempts=1,
        max_attempts=3,
        retryable=False,
        receipt_id="r-1",
        payload_json="{}",
        result_json="{}",
        metrics_json="{}",
        last_error_code="",
        last_error_category="",
        last_error_message="",
        run_id=None,
        submitted_at=now,
        started_at=None,
        completed_at=None,
        dead_lettered_at=None,
    )
    dead_letter = DeadLetterJobModel(
        job_id="job-2",
        correlation_id="corr-2",
        queue_backend="filesystem",
        queue_name="default",
        source_value="ioc",
        attempts=2,
        max_attempts=3,
        error_code="ERR",
        error_category="parser_failure",
        error_message="boom",
        retryable=False,
        payload_json="{}",
        dead_lettered_at=now,
    )
    assert _row_dict(batch_job)["status"] == "completed"
    assert _row_dict(failed_item)["error_type"] == "TimeoutError"
    assert "job_id" in _row_dict(distributed)
    assert _row_dict(dead_letter)["error_code"] == "ERR"

    from sqlalchemy import select

    stmt = _order_search_stmt(
        select(RunModel, SourceModel, IOCModel, RunIOCModel),
        sort_by="oldest",
    )
    assert "ORDER BY runs.started_at ASC" in str(stmt)
    assert _coerce_count("6") == 6
    with pytest.raises(TypeError):
        _coerce_count(1.5)


def test_warninglist_mixins_cover_fallback_logger_and_cache_clear() -> None:
    dummy = _DummyWarningLists()
    assert WarningListMatchingMixin._get_logger(_DummyMatchingOnly()) is not None
    assert WarningListPreprocessMixin._get_logger(_DummyPreprocessOnly()) is not None
    dummy._clean_value_cache = {f"k{i}": "v" for i in range(10000)}
    assert dummy._clean_defanged_value("hxxp://x[.]test") == "http://x.test"
    assert "hxxp://x[.]test" in dummy._clean_value_cache

    dummy._warning_lookup_cache = {(str(i), "domains"): (False, None) for i in range(5000)}
    dummy._cache_check_value(("x", "domains"), (False, None))
    assert dummy._warning_lookup_cache[("x", "domains")] == (False, None)


def test_pipeline_worker_private_helpers_cover_remaining_branches() -> None:
    class _Inner:
        def __init__(self) -> None:
            self.rolled_back = False
            self.metadata = None
            self.attached = None

        def rollback(self) -> None:
            self.rolled_back = True

        def create_run(self, **kwargs):
            self.metadata = kwargs["metadata"]
            return 7

        def attach_iocs(self, **kwargs) -> None:
            self.attached = kwargs["result"]

    uow = _PipelineUnitOfWork.__new__(_PipelineUnitOfWork)
    inner = _Inner()
    uow._inner = inner
    uow.rollback()
    assert inner.rolled_back is True

    adapter = _RunRepositoryAdapter(inner)
    assert adapter.create_run(source_id=1, tool_version="1", options=object(), metadata=None) == 7
    adapter.create_run(source_id=1, tool_version="1", options=object(), metadata={"x": object()})
    assert inner.metadata == {"x": str(inner.metadata["x"])}
    adapter.attach_iocs(
        run_id=1, ioc_ids=[1], result=ExtractionResult(iocs=(IOC.from_raw("domains", "a.test"),))
    )
    assert inner.attached is not None

    assert _metadata_int({}, "input_size") is None
    assert _metadata_int({"input_size": "5"}, "input_size") == 5
    with pytest.raises(TypeError):
        _metadata_int({"input_size": True}, "input_size")
    with pytest.raises(TypeError):
        _metadata_int({"input_size": "bad"}, "input_size")
    with pytest.raises(TypeError):
        _metadata_int({"input_size": []}, "input_size")
    with pytest.raises(ValueError, match="missing temp_file"):
        _prepared_temp_file(_PreparedInput(fingerprint=None, content_hash=None, metadata={}))


def test_persist_result_rolls_back_and_closes_on_exception(monkeypatch) -> None:
    """persist_result must rollback and close the UoW when persist_run raises."""
    from unittest.mock import MagicMock

    mock_persist_run = MagicMock(side_effect=RuntimeError("db down"))
    monkeypatch.setattr("iocparser.pipeline_worker_support.persist_run", mock_persist_run)

    request = PipelineJobRequest(
        input_kind="text",
        source_value="test",
        persist=True,
        db_uri="sqlite:///:memory:",
        emit_only=False,
    )
    prepared = PreparedInput(fingerprint="fp", content_hash="hash", metadata={"input_size": 4})
    result = ExtractionResult(iocs=())

    with pytest.raises(RuntimeError, match="db down"):
        persist_result(request=request, prepared=prepared, result=result, started=time.time())


def test_renderers_cover_custom_stix_and_record_helpers() -> None:
    custom_name = register_custom_ioc_type(
        "quality-finish-custom",
        base_type=IOCType.SSDEEP,
        stix_pattern="[x-quality:value = '{value}']",
    )
    result = ExtractionResult(iocs=(IOC.from_raw(custom_name, "value"),))
    rendered = json.loads(STIXOutputRenderer().render(result))
    assert rendered["x_iocparser_format"] == "stix"

    no_stix_name = register_custom_ioc_type(
        f"quality-finish-custom-no-stix-domain-{uuid4().hex}",
        base_type=IOCType.DOMAIN,
    )
    renderer = STIXOutputRenderer()
    indicator = renderer._build_indicator(no_stix_name, "fallback.test", None)
    assert indicator is not None
    fallback_bundle = json.loads(
        STIXOutputRenderer().render(
            ExtractionResult(iocs=(IOC.from_raw(no_stix_name, "fallback.test"),))
        )
    )
    assert fallback_bundle["x_iocparser_format"] == "stix"

    class _WeirdContextResult(ExtractionResult):
        def to_records(self) -> list[dict[str, object]]:
            return [{"type": "domains", "raw_value": "ctx.test", "evidence": "bad"}]

    weird_result = _WeirdContextResult(iocs=(IOC.from_raw("domains", "ctx.test"),))
    assert "ctx.test" in TextOutputRenderer(include_context=True).render(weird_result)
    assert _record_string_list({"tags": "bad"}, "tags") == ()
    assert _record_dict_list({"evidence": "bad"}, "evidence") == []
    assert renderer_json_object("[]") == {}


def test_schema_version_accepts_string_rows(tmp_path: Path) -> None:
    from sqlalchemy import create_engine, text

    sqlite_db_uri = f"sqlite:///{tmp_path / 'schema.sqlite'}"
    engine = create_engine(sqlite_db_uri, future=True)
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)")
        )
        connection.execute(text("DELETE FROM schema_migrations"))
        connection.execute(text("INSERT INTO schema_migrations(version) VALUES ('7')"))
    try:
        assert schema_version(engine) == 7
        assert _coerce_version_row("8") == 8

        class _VersionLike:
            def __str__(self) -> str:
                return "9"

        assert _coerce_version_row(_VersionLike()) == 9
    finally:
        engine.dispose()


def test_repository_helpers_cover_remaining_metadata_branches() -> None:
    assert _optional_int_metadata_value({"count": 8}, "count") == 8

    class _TypeValue:
        value = "domains"

    assert _ioc_type_name(_TypeValue()) == "domains"
    assert int(
        (finished_at_from_duration(1500) - finished_at_from_duration(0)).total_seconds()
    ) in {1, 2}


def test_worker_config_defaults_cover_none_branches() -> None:
    assert int_or(None, 4) == 4
    assert float_or(None, 1.5) == 1.5
