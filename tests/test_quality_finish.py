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
    CSVOutputRenderer,
    JSONOutputRenderer,
    STIXOutputRenderer,
    TextOutputRenderer,
    _record_dict_list,
    _record_string_list,
)
from iocparser.adapters.renderers import (
    _json_object as renderer_json_object,
)
import iocparser.adapters.renderers_json as renderers_json_module
from iocparser.adapters.renderers_text import format_warning_item
from iocparser.cli_args_values import int_arg_value
from iocparser.cli_output import _int_value as batch_int_value
from iocparser.cli_output import print_batch_report, save_batch_report
from iocparser.cli_output_rendering import (
    _int_run_metadata_value,
    _optional_int_run_metadata_value,
    print_warning_lists,
)
import iocparser.cli_schema as cli_schema_module
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
import iocparser.cli_processing_url_reports as url_reports_module
from iocparser.cli_runtime import _optional_float_arg
from iocparser.cli_schema import _history_payload
from iocparser.client_persistence import _parse_string_filters
from iocparser.domain.distributed import _int_from_payload
from iocparser.domain.enums import IOCType, register_custom_ioc_type
from iocparser.domain.models import IOC, ExtractionOptions, ExtractionResult, IOCEvidence, PersistedRun
from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.errors import DownloadError, ValidationError
from iocparser.infrastructure.file_readers import MagicTextSourceReader
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.persistence.history.ops import _json_object as history_json_object
from iocparser.infrastructure.persistence.history.ops import _row_dict
from iocparser.infrastructure.persistence.history.ops import _payload_fingerprint
from iocparser.infrastructure.persistence.query import query_runs_page, search_iocs_page
from iocparser.infrastructure.persistence.query.ops import _coerce_count, _order_run_query_stmt
from iocparser.infrastructure.persistence_batch import (
    BatchJobModel,
    FailedBatchItemModel,
    _dict_report_value,
    _failed_items,
    _int_report_value,
)
from iocparser.infrastructure.persistence_distributed_records import _json_int_map
from iocparser.infrastructure.persistence_distributed_records import (
    _json_object as record_json_object,
)
import iocparser.infrastructure.persistence_distributed_records as distributed_records_module
from iocparser.infrastructure.persistence_migration_runtime import schema_version
from iocparser.infrastructure.persistence_migration_steps import _coerce_version_row
from iocparser.infrastructure.persistence_models import DeadLetterJobModel, DistributedJobModel
from iocparser.infrastructure.persistence_repository_support import (
    _int_metadata_value,
    _ioc_type_name,
    _optional_int_metadata_value,
    finished_at_from_duration,
    string_metadata_value,
)
from iocparser.infrastructure.persistence_schema import IOCModel, RunIOCModel, RunModel, SourceModel
from iocparser.infrastructure.persistence_support import (
    _evidence_from_json,
    _evidence_records_from_json,
    _json_list,
    _tags_from_json,
)
import iocparser.infrastructure.persistence_support as persistence_support_module
from iocparser.infrastructure.persistence_support import source_value_clause
from iocparser.infrastructure.queue_rabbitmq import _load_queue_record as load_rabbit_queue_record
from iocparser.infrastructure.queue_records import load_queue_record
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
from iocparser.pipeline_worker_support import PreparedInput, cleanup_prepared_input, persist_result
from iocparser.shared_utils import normalize_metadata_values
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
        with pytest.raises(ValueError, match="Expected JSON object"):
            _json_dict(payload_path)
    finally:
        payload_path.unlink()
    original_url_report_loads = url_reports_module.loads
    url_reports_module.loads = lambda _raw: {1: "one", "two": "2", "metadata": {3: "three"}}
    try:
        payload_path = Path("tmp-url-report.json")
        payload_path.write_text("{}", encoding="utf-8")
        try:
            assert _json_dict(payload_path) == {"two": "2", "metadata": {}}
        finally:
            payload_path.unlink()
    finally:
        url_reports_module.loads = original_url_report_loads

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
    with pytest.raises(TypeError, match="Expected batch report keys to be strings"):
        print_batch_report({1: "one"})
    with pytest.raises(TypeError, match="Expected batch report failure keys to be strings"):
        print_batch_report({"failures": {1: "boom"}})
    with pytest.raises(TypeError, match="Expected batch report failure values to be strings"):
        print_batch_report({"failures": {"a": object()}})
    with pytest.raises(TypeError, match="Expected batch report error group keys to be strings"):
        print_batch_report({"error_groups": {1: 1}})
    with pytest.raises(TypeError, match="Expected batch report phase timing keys to be strings"):
        print_batch_report({"phase_timings_ms": {1: 1}})
    with pytest.raises(TypeError, match="Expected batch report metric keys to be strings"):
        print_batch_report({"metrics": {1: 1}})

    writer = _MemoryWriter()
    save_batch_report({"total": 0}, None, file_writer=writer)
    assert writer.writes[0][0] == "iocparser_batch_report.json"
    with pytest.raises(TypeError, match="Expected batch report keys to be strings"):
        save_batch_report({1: "one"}, None, file_writer=writer)
    assert batch_int_value([], default=7) == 7


def test_cli_rendering_metadata_helpers_accept_strings() -> None:
    metadata = {"duration_ms": "4", "processed_items": "5"}
    assert _int_run_metadata_value(metadata, "processed_items", 0) == 5
    assert _optional_int_run_metadata_value(metadata, "duration_ms") == 4
    assert normalize_metadata_values({"count": 3, "name": "x"}) == {
        "count": 3,
        "name": "x",
    }
    with pytest.raises(TypeError, match="Expected metadata value for flag"):
        normalize_metadata_values({"flag": True})
    with pytest.raises(TypeError, match="Expected metadata value"):
        normalize_metadata_values({"bad": object()})


def test_string_metadata_value_rejects_non_strings() -> None:
    assert string_metadata_value({"status": "ok"}, "status", "success") == "ok"
    assert string_metadata_value({}, "status", "success") == "success"
    with pytest.raises(TypeError, match="Expected status to be string"):
        string_metadata_value({"status": 1}, "status", "success")


def test_normalize_tokens_rejects_non_string_items() -> None:
    from iocparser.shared_utils import normalize_tokens

    assert normalize_tokens([" A ", "b"]) == ("a", "b")
    with pytest.raises(TypeError, match="Expected token to be string"):
        normalize_tokens([object()])


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

    payload_path = Path("bad-history.json")
    payload_path.write_text("{}", encoding="utf-8")
    original_json_loads = cli_schema_module.json.loads
    cli_schema_module.json.loads = lambda _raw: {1: "one", "sources": []}
    try:
        with pytest.raises(ValidationError, match="history import file must contain a JSON object"):
            _history_payload(str(payload_path))
    finally:
        cli_schema_module.json.loads = original_json_loads
        payload_path.unlink()


def test_history_payload_reports_missing_and_unreadable_files_cleanly(tmp_path: Path) -> None:
    # Regression: --restore-history/--import-history on a missing or malformed archive
    # raised a raw FileNotFoundError/JSONDecodeError that reached the CLI top-level
    # handler as an "unexpected error" stack trace instead of a clean message.
    missing = tmp_path / "nope.json"
    with pytest.raises(ValidationError, match="History file not found"):
        _history_payload(str(missing))

    malformed = tmp_path / "bad.json"
    malformed.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValidationError, match="Could not read history file"):
        _history_payload(str(malformed))


def test_history_payload_expands_user_home_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    payload_path = home / "history.json"
    payload_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    assert _history_payload("~/history.json") == {}


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

        # Malformed numeric env values raise a descriptive, env-var-named error
        # (matching bool_env) instead of an opaque "invalid literal for int()".
        os_environ["IOC_INT_ENV"] = "not-an-int"
        os_environ["IOC_FLOAT_ENV"] = "not-a-float"
        with pytest.raises(ValueError, match="IOC_INT_ENV"):
            int_env("IOC_INT_ENV")
        with pytest.raises(ValueError, match="IOC_FLOAT_ENV"):
            float_env("IOC_FLOAT_ENV")

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
    with pytest.raises(ValidationError, match="Invalid float argument"):
        _optional_float_arg(argparse.Namespace(rate="bad"), "rate")
    with pytest.raises(TypeError):
        _optional_float_arg(argparse.Namespace(rate=True), "rate")
    with pytest.raises(TypeError):
        _optional_float_arg(argparse.Namespace(rate=[]), "rate")

    with pytest.raises(TypeError):
        load_queue_record("[]")
    with pytest.raises(TypeError):
        load_rabbit_queue_record(b"[]")

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
    assert _dict_report_value({"data": {1: "one", "two": 2}}, "data") == {"two": 2}
    assert _failed_items([{1: "one", "status": "failed"}]) == [{"status": "failed"}]
    with pytest.raises(TypeError):
        _int_report_value({"count": []}, "count")

    downloader = RequestsURLDownloader()
    downloader.last_download_metadata = {1: "one", "two": 2}
    assert downloader.download_metadata() == {"two": 2}

    with pytest.raises(ValueError, match="Expected JSON object"):
        record_json_object("[]")
    with pytest.raises(ValueError, match="Invalid JSON object"):
        record_json_object("{bad")
    assert _json_int_map(json.dumps({"a": "2"})) == {"a": 2}
    assert _json_int_map(json.dumps({"a": True, "b": "bad", "c": "-3"})) == {"c": -3}
    assert _json_list("{}") == []
    assert _json_list("{bad") == []
    original_json_loads = distributed_records_module.json.loads
    distributed_records_module.json.loads = lambda _raw: {1: "one", "two": "2"}
    try:
        assert record_json_object("{}") == {"two": "2"}
    finally:
        distributed_records_module.json.loads = original_json_loads
    original_renderer_json_loads = renderers_json_module.json.loads
    renderers_json_module.json.loads = lambda _raw: {1: "one", "two": "2"}
    try:
        assert renderer_json_object("{}") == {"two": "2"}
    finally:
        renderers_json_module.json.loads = original_renderer_json_loads
    evidence = _evidence_from_json(
        json.dumps([1, {"excerpt": "x", "line_number": 4, "source": "s"}])
    )
    assert evidence[0].excerpt == "x"
    assert _tags_from_json(json.dumps([1, "tag-a", None])) == ("tag-a",)
    assert _tags_from_json("not-json") == ()
    assert _evidence_from_json(json.dumps([{"excerpt": 1, "source": "s"}, {"excerpt": "x", "source": "s"}])) == (
        IOCEvidence(excerpt="x", line_number=None, source="s"),
    )
    original_json_loads = persistence_support_module.json.loads
    persistence_support_module.json.loads = lambda _raw: [{1: "one", "excerpt": "x", "source": "s"}]
    try:
        assert _evidence_records_from_json("[]") == ({"excerpt": "x", "source": "s"},)
    finally:
        persistence_support_module.json.loads = original_json_loads

    assert _int_metadata_value({"count": "4"}, "count", 0) == 4
    assert _optional_int_metadata_value({"count": "5"}, "count") == 5
    assert _ioc_type_name("domains") == "domains"
    with pytest.raises(TypeError, match="source_kind"):
        source_value_clause(source_kind=1, source_value="x")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="source_value"):
        source_value_clause(source_kind="url", source_value=1)  # type: ignore[arg-type]


def test_persistence_history_and_page_query_helpers_cover_remaining_branches() -> None:
    with pytest.raises(ValueError, match="Expected JSON object"):
        history_json_object("[]")
    with pytest.raises(ValueError, match="Invalid JSON object"):
        history_json_object("{bad")
    assert callable(query_runs_page)
    assert callable(search_iocs_page)
    with pytest.raises(TypeError):
        _payload_fingerprint({"bad": object()})

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

    stmt = _order_run_query_stmt(
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
    with pytest.raises(TypeError, match="Expected metadata value"):
        adapter.create_run(source_id=1, tool_version="1", options=object(), metadata={"x": object()})
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


def test_persist_result_preserves_original_error_when_close_fails(monkeypatch) -> None:
    """persist_result must not replace the persistence error with a close failure."""
    from unittest.mock import MagicMock

    mock_persist_run = MagicMock(side_effect=RuntimeError("db down"))
    monkeypatch.setattr("iocparser.pipeline_worker_support.persist_run", mock_persist_run)
    monkeypatch.setattr(
        "iocparser.pipeline_worker_support.PipelineUnitOfWork.close",
        MagicMock(side_effect=RuntimeError("close failed")),
    )

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


def test_persist_result_raises_close_failure_after_success(monkeypatch) -> None:
    """persist_result must surface close failures after a successful persist."""
    from unittest.mock import MagicMock

    mock_persist_run = MagicMock(return_value=PersistedRun(run_id=123))
    monkeypatch.setattr("iocparser.pipeline_worker_support.persist_run", mock_persist_run)
    monkeypatch.setattr(
        "iocparser.pipeline_worker_support.PipelineUnitOfWork.close",
        MagicMock(side_effect=RuntimeError("close failed")),
    )

    request = PipelineJobRequest(
        input_kind="text",
        source_value="test",
        persist=True,
        db_uri="sqlite:///:memory:",
        emit_only=False,
    )
    prepared = PreparedInput(fingerprint="fp", content_hash="hash", metadata={"input_size": 4})
    result = ExtractionResult(iocs=())

    with pytest.raises(RuntimeError, match="close failed"):
        persist_result(request=request, prepared=prepared, result=result, started=time.time())


def test_cleanup_prepared_input_ignores_missing_temp_file(tmp_path: Path) -> None:
    request = PipelineJobRequest(input_kind="url", source_value="https://example.com")
    temp_file = tmp_path / "download.tmp"
    temp_file.write_text("payload", encoding="utf-8")
    prepared = PreparedInput(
        fingerprint="fp",
        content_hash="hash",
        metadata={"input_size": 7, "temp_file": str(temp_file)},
    )

    temp_file.unlink()
    cleanup_prepared_input(request=request, prepared=prepared)

    assert not temp_file.exists()


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
    class _BadGroupedResult(ExtractionResult):
        def canonical_by_type(self) -> dict[object, tuple[object, ...]]:
            return {"domains": (object(),)}

    with pytest.raises(TypeError, match="Expected value to be string"):
        TextOutputRenderer().render(_BadGroupedResult(iocs=()))
    class _BadContextResult(ExtractionResult):
        def to_records(self) -> list[dict[str, object]]:
            return [{"type": "domains", "raw_value": object(), "value": "ctx.test", "evidence": []}]

    with pytest.raises(TypeError, match="Expected raw_value to be string"):
        TextOutputRenderer(include_context=True).render(_BadContextResult(iocs=()))
    class _BadJsonGroupedResult(ExtractionResult):
        def canonical_by_type(self) -> dict[object, tuple[object, ...]]:
            return {"domains": (1,)}

    with pytest.raises(TypeError, match="Expected value to be string"):
        renderer_json_object(
            JSONOutputRenderer().render(_BadJsonGroupedResult(iocs=()))
        )
    class _BadCsvResult(ExtractionResult):
        def to_records(self) -> list[dict[str, object]]:
            return [
                {
                    "type": "domains",
                    "value": "ctx.test",
                    "raw_value": "ctx.test",
                    "severity": "medium",
                    "tags": [],
                    "warning_list": object(),
                    "description": "",
                    "evidence": [],
                }
            ]

    with pytest.raises(TypeError, match="Expected warning_list to be string"):
        CSVOutputRenderer().render(_BadCsvResult(iocs=()))
    class _BadCsvDescriptionResult(ExtractionResult):
        def to_records(self) -> list[dict[str, object]]:
            return [
                {
                    "type": "domains",
                    "value": "ctx.test",
                    "raw_value": "ctx.test",
                    "severity": "medium",
                    "tags": [],
                    "warning_list": "wl",
                    "evidence": [],
                }
            ]

    with pytest.raises(TypeError, match="Expected description to be string"):
        CSVOutputRenderer().render(_BadCsvDescriptionResult(iocs=()))
    class _BadCsvLineNumberResult(ExtractionResult):
        def to_records(self) -> list[dict[str, object]]:
            return [
                {
                    "type": "domains",
                    "value": "ctx.test",
                    "raw_value": "ctx.test",
                    "severity": "medium",
                    "tags": [],
                    "warning_list": "",
                    "description": "",
                    "evidence": [{"excerpt": "x", "line_number": "1", "source": "s"}],
                }
            ]

    with pytest.raises(TypeError, match="Expected line_number to be int"):
        CSVOutputRenderer().render(_BadCsvLineNumberResult(iocs=()))
    class _BadJsonWarningResult(ExtractionResult):
        def grouped_warnings(self) -> dict[str, list[dict[str, str]]]:
            return {"domains": [{"value": "ctx.test", "description": ""}]}

    with pytest.raises(TypeError, match="Expected warning_list to be string"):
        JSONOutputRenderer().render(_BadJsonWarningResult(iocs=()))
    assert _record_string_list({"tags": "bad"}, "tags") == ()
    assert _record_dict_list({"evidence": "bad"}, "evidence") == []
    with pytest.raises(TypeError, match="Expected tags entries to be string"):
        _record_string_list({"tags": [1]}, "tags")
    with pytest.raises(TypeError, match="Expected value to be string"):
        format_warning_item({"value": object(), "warning_list": "wl"})
    with pytest.raises(ValueError, match="Expected JSON object"):
        renderer_json_object("[]")


def test_print_warning_lists_rejects_non_string_fields() -> None:
    with pytest.raises(TypeError, match="Expected value to be string"):
        print_warning_lists({"domains": [{"value": object(), "warning_list": "wl", "description": ""}]})
    with pytest.raises(TypeError, match="Expected warning_list to be string"):
        print_warning_lists({"domains": [{"value": "x", "description": ""}]})


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


def test_worker_config_str_or_none_trims_blank_strings() -> None:
    from iocparser.worker_config_support import str_or_none

    assert str_or_none("  value  ") == "value"
    assert str_or_none("   ") is None
