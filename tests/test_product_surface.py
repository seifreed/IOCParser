from __future__ import annotations

import argparse
import json
import sqlite3
import threading
import time
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler
from io import StringIO
from pathlib import Path

import pytest

import iocparser.plugins as plugins_module
from iocparser import cli_processing, cli_queries
from iocparser.api_extraction import (
    extract_result_from_file,
    extract_result_from_text,
    extract_result_from_url,
)
from iocparser.api_persistence import (
    PersistedDiffFilters,
    PersistedExportFilters,
    PersistedRenderOptions,
    delete_persisted_run,
    diff_persisted_runs,
    diff_run_against_previous_source,
    export_persisted_run,
    export_structured_persisted_diff,
    list_persisted_runs,
    prune_persisted_runs,
    query_persisted_iocs,
    query_persisted_runs,
    render_persisted_diff,
    render_persisted_run,
    search_persisted_iocs,
)
from iocparser.api_persistence_query import (
    coerce_diff_filters,
    coerce_export_filters,
    coerce_render_options,
)
from iocparser.cli_args import create_argument_parser, parse_string_filters
from iocparser.cli_output import (
    PersistResultsRequest,
    persist_results,
    print_batch_report,
    print_maintenance_result,
    render_result,
    save_batch_report,
    save_diff_output,
)
from iocparser.cli_persistence import (
    persist_batch_job,
    persist_failed_batch_items,
    persist_many_results,
)
from iocparser.cli_processing import process_url_file_input_with_report
from iocparser.cli_processing_files import merge_batch_results
from iocparser.cli_processing_support import BatchResultsCollection, batch_item_keys
from iocparser.cli_processing_urls import (
    _failed_urls_from_report,
    _report_item,
    build_batch_report,
    public_batch_report,
)
from iocparser.cli_runtime import (
    _parse_http_mapping,
    apply_config_defaults,
    downloader_for_args,
    mb_to_bytes,
    warning_service_for_args,
)
from iocparser.config import AppConfig, load_config
from iocparser.domain.models import (
    IOC,
    ExtractionResult,
    IOCEvidence,
    PersistOptions,
    WarningMatch,
)
from iocparser.errors import FileExistenceError, IOCTimeoutError, ValidationError
from iocparser.infrastructure import persistence_migrations as migrations
from iocparser.infrastructure.file_readers import MagicTextSourceReader
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.persistence import (
    SQLAlchemyPersistenceService,
    SQLAlchemyUnitOfWork,
)
from iocparser.infrastructure.warninglists_service import CompositeWarningListService
from iocparser.plugins import (
    enricher_names,
    get_enricher,
    get_renderer,
    register_enricher,
    register_renderer,
    renderer_names,
)
from tests.http_server_helpers import LocalHTTPFileServer, ThreadedHTTPServer


def _args(**overrides: object) -> argparse.Namespace:
    base = {
        "json": False,
        "jsonl": False,
        "csv": False,
        "stix": False,
        "stix_types": None,
        "with_context": False,
        "summary": False,
        "severity": None,
        "tag": None,
        "only_warnings": False,
        "only_normal": False,
        "sort_by": "type",
        "max_evidence": None,
        "diff_only": "all",
        "output": "-",
        "parallel": 1,
        "chunk_size": 1024 * 1024,
        "overlap": 1024,
        "user_agent": None,
        "header": None,
        "headers_json": None,
        "cookie": None,
        "cookies_json": None,
        "proxy": None,
        "allow_redirects": True,
        "tls_verify": True,
        "tls_cert": None,
        "ca_bundle": None,
        "connect_timeout": None,
        "read_timeout": None,
        "batch_report_json": None,
        "renderer": None,
        "enricher": None,
        "retry_failed_from": None,
        "offset": 0,
        "query_limit": 50,
        "query_sort": "newest",
        "exclude_tag": None,
        "tag_mode": "all",
        "min_severity": None,
        "delete_run": None,
        "prune_before": None,
        "keep_latest": 0,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_numeric_defaults_let_cli_override_invalid_config_chunk_size() -> None:
    """An explicit --chunk-size must win over a bad INI/env value (CLI > env > INI).

    Regression: _apply_numeric_defaults validated config.chunk_size/overlap
    unconditionally, before applying the CLI override, so a valid --chunk-size 100
    still aborted with 'Invalid chunk_size: 0' when the INI carried chunk_size = 0.
    """
    import dataclasses

    from iocparser.cli_runtime_defaults import _apply_numeric_defaults

    config = dataclasses.replace(
        load_config(cli_persist=False, cli_db_uri=None, cli_config_path=None),
        chunk_size=0,
        overlap=-5,
    )
    shared = {
        "overlap": None,
        "url_workers": None,
        "url_retries": None,
        "url_backoff": None,
        "rate_limit": None,
        "parallel": None,
        "max_queue_size": None,
        "max_input_size_mb": None,
        "max_input_seconds": None,
    }

    overridden = argparse.Namespace(**{**shared, "chunk_size": 100, "overlap": 10})
    _apply_numeric_defaults(overridden, config)
    assert overridden.chunk_size == 100
    assert overridden.overlap == 10

    # No CLI override: the bad config value is still rejected.
    not_overridden = argparse.Namespace(**{**shared, "chunk_size": None})
    with pytest.raises(ValidationError, match="chunk_size"):
        _apply_numeric_defaults(not_overridden, config)


def test_resolve_tls_options_rejects_missing_paths_cleanly(tmp_path: object) -> None:
    """Regression: a missing --ca-bundle/--tls-cert path used to surface mid-download
    as a generic "Unexpected error download <url>"; validate it up front instead."""
    from iocparser.cli_runtime_defaults import resolve_tls_options

    real = tmp_path / "ca.pem"  # type: ignore[operator]
    real.write_text("x", encoding="utf-8")
    verify, cert = resolve_tls_options(
        argparse.Namespace(tls_verify=True, ca_bundle=str(real), tls_cert=None)
    )
    assert verify == str(real)
    assert cert is None

    with pytest.raises(ValidationError, match="--ca-bundle file does not exist"):
        resolve_tls_options(
            argparse.Namespace(tls_verify=True, ca_bundle="/no/such.pem", tls_cert=None)
        )
    with pytest.raises(ValidationError, match="--tls-cert file does not exist"):
        resolve_tls_options(
            argparse.Namespace(tls_verify=True, ca_bundle=None, tls_cert="/no/such.pem")
        )


def test_resolve_tls_options_expands_user_home_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from iocparser.cli_runtime_defaults import resolve_tls_options

    home = tmp_path / "home"
    home.mkdir()
    cert = home / "cert.pem"
    ca_bundle = home / "ca.pem"
    cert.write_text("cert", encoding="utf-8")
    ca_bundle.write_text("ca", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    verify, resolved_cert = resolve_tls_options(
        argparse.Namespace(tls_verify=True, ca_bundle="~/ca.pem", tls_cert="~/cert.pem")
    )

    assert verify == str(ca_bundle)
    assert resolved_cert == str(cert)


def test_persisted_option_overrides_parse_bool_strings() -> None:
    render_options = coerce_render_options(None, {"with_context": "false"})
    export_filters = coerce_export_filters(None, {"only_warnings": "false", "only_normal": "0"})
    diff_filters = coerce_diff_filters(
        None,
        {"only_warnings": "false", "only_normal": "0", "diff_only": "all"},
    )

    assert render_options.with_context is False
    assert export_filters.only_warnings is False
    assert export_filters.only_normal is False
    assert diff_filters.only_warnings is False
    assert diff_filters.only_normal is False

    with pytest.raises(ValidationError, match="Invalid boolean option"):
        coerce_render_options(None, {"with_context": "maybe"})
    with pytest.raises(ValidationError, match="Invalid boolean option"):
        coerce_export_filters(None, {"only_warnings": ["yes"]})


def test_batch_report_item_parses_retryable_bool_strings() -> None:
    disabled = _report_item({"url": "https://a.example", "retryable": "false"})
    enabled = _report_item({"url": "https://b.example", "retryable": "yes"})
    invalid_ints = _report_item(
        {"url": "https://e.example", "duration_ms": True, "retry_attempt": "bad"}
    )

    assert disabled["retryable"] is False
    assert enabled["retryable"] is True
    assert invalid_ints["duration_ms"] == 0
    assert invalid_ints["retry_attempt"] == 0


def test_batch_report_item_rejects_unknown_retryable_string() -> None:
    with pytest.raises(TypeError, match="Expected boolean-compatible value"):
        _report_item({"url": "https://c.example", "retryable": "maybe"})


def test_batch_report_item_rejects_non_boolean_retryable_lists() -> None:
    with pytest.raises(TypeError, match="Expected boolean-compatible value"):
        _report_item({"url": "https://d.example", "retryable": ["yes"]})


def test_batch_report_item_rejects_non_boolean_retryable_objects() -> None:
    with pytest.raises(TypeError, match="Expected boolean-compatible value"):
        _report_item({"url": "https://f.example", "retryable": object()})


def test_batch_report_item_rejects_non_string_error_fields() -> None:
    with pytest.raises(TypeError, match="Expected status to be string"):
        _report_item({"url": "https://bad.example", "status": object()})


def test_batch_report_item_ignores_non_string_keys() -> None:
    item = _report_item({1: "one", "url": "https://ok.example", "status": "failed"})
    assert item == {"url": "https://ok.example", "status": "failed"}


def test_retry_report_ignores_non_string_urls(tmp_path: Path) -> None:
    report_path = tmp_path / "bad-url-report.json"
    report_path.write_text(
        json.dumps({"items": [{"url": None, "status": "failed", "error": "timeout"}]}),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="No failed URLs found"):
        _failed_urls_from_report(report_path)


def test_public_batch_report_ignores_non_string_failed_urls() -> None:
    report = public_batch_report(
        {
            "items": [{"url": None, "status": "failed", "error": "timeout"}],
            "failures": {},
        }
    )

    assert report["failures"] == {}


class _Writer:
    def write(self, path: str, content: str) -> None:
        Path(path).write_text(content, encoding="utf-8")


class FlakyLocalHTTPServer(ThreadedHTTPServer):
    path = "/feed.txt"

    def __init__(self) -> None:
        self.calls = 0

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.calls += 1
                if outer.calls == 1:
                    self.send_response(500)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", "5")
                    self.end_headers()
                    self.wfile.write(b"error")
                    return
                body = b"IOC URL: https://retry.example/path"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args) -> None:
                del fmt, args

        return Handler


class SlowLocalHTTPServer(ThreadedHTTPServer):
    path = "/slow.txt"

    def __init__(self, *, delay: float) -> None:
        self.delay = delay

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        delay = self.delay

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                time.sleep(delay)
                body = b"slow"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args) -> None:
                del fmt, args

        return Handler


def test_public_query_api_and_diff_previous_source(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'queries.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "alpha.txt",
                ExtractionResult.from_grouped_payload({"domains": ["alpha.example"]}, {}),
            ),
            (
                "file",
                "alpha.txt",
                ExtractionResult.from_grouped_payload({"domains": ["beta.example"]}, {}),
            ),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    runs = list_persisted_runs(
        db_uri=db_uri,
        limit=10,
        offset=0,
        source_kind="file",
        source_value="alpha.txt",
        sort_by="source",
    )
    assert runs[0].counts_by_type
    assert runs[0].normal_ioc_count == 1

    hits = search_persisted_iocs(
        db_uri=db_uri,
        value="beta",
        limit=10,
        offset=0,
        source_kind="file",
        source_value="alpha.txt",
        ioc_type="domains",
        sort_by="source",
    )
    assert hits[0].value == "beta.example"

    exported = export_persisted_run(db_uri=db_uri, run_id=run_ids[0])
    assert exported.summary.source_value == "alpha.txt"

    direct_diff = diff_persisted_runs(
        db_uri=db_uri, left_run_id=run_ids[0], right_run_id=run_ids[1]
    )
    assert direct_diff.added.grouped_iocs() == {"domains": ["beta.example"]}

    diff = diff_run_against_previous_source(db_uri=db_uri, run_id=run_ids[1])
    assert diff.compared_to_previous_source_run_id == run_ids[0]
    assert diff.added.grouped_iocs() == {"domains": ["beta.example"]}

    run_page = query_persisted_runs(db_uri=db_uri, limit=1, offset=0, source_kind="file")
    assert run_page.total == 2
    assert run_page.has_next is True
    assert run_page.page == 1

    hit_page = query_persisted_iocs(
        db_uri=db_uri, value=".example", limit=1, offset=1, sort_by="source"
    )
    assert hit_page.total == 2
    assert hit_page.offset == 1
    assert len(hit_page.items) == 1
    assert run_page.to_record()["has_next"] is True
    assert hit_page.to_record()["page"] == 2


def test_diff_previous_source_skips_partial_prior_runs(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'partial-diff-source.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="alpha.txt",
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={"status": "success"},
        )
    )
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="alpha.txt",
            normal_iocs={"domains": ["beta.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={
                "status": "partial",
                "partial_error_count": 1,
                "failed_items": 0,
                "successful_items": 1,
            },
        )
    )
    latest_run_id = persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="alpha.txt",
            normal_iocs={"domains": ["gamma.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={"status": "success"},
        )
    )
    assert latest_run_id is not None

    diff = diff_run_against_previous_source(db_uri=db_uri, run_id=latest_run_id)
    exported = export_persisted_run(
        db_uri=db_uri, run_id=diff.compared_to_previous_source_run_id or 0
    )
    assert exported.result.grouped_iocs() == {"domains": ["alpha.example"]}


def test_persist_results_defaults_invalid_numeric_run_metadata(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'invalid-run-metadata.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    run_id = persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="invalid-metadata.txt",
            normal_iocs={"domains": ["bad-metadata.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            source_metadata={"input_size": True},
            run_metadata={
                "failed_items": True,
                "partial_error_count": "bad",
                "successful_items": "bad",
            },
        )
    )

    assert run_id is not None
    runs = query_persisted_runs(db_uri=db_uri, limit=10)
    assert runs.items[0].failed_items == 0
    assert runs.items[0].partial_error_count == 0
    assert runs.items[0].successful_items == 1
    exported = export_persisted_run(db_uri=db_uri, run_id=run_id)
    assert exported.summary.input_size is None


def test_url_batch_preserves_duplicate_inputs_through_report_and_persistence(
    tmp_path: Path,
) -> None:
    from iocparser import cli_dispatch_workflow as workflow

    db_uri = f"sqlite:///{tmp_path / 'duplicate-urls.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    url_file = tmp_path / "urls.txt"
    with LocalHTTPFileServer(body=b"IOC URL: https://duplicate.example/path") as url:
        url_file.write_text(f"{url}\n{url}\n", encoding="utf-8")
        args = _args(url_file=str(url_file), url_workers=2, persist=True)
        _normal_iocs, warning_iocs, _label, results, report = process_url_file_input_with_report(
            args,
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
            db_uri=db_uri,
        )

    assert warning_iocs == {}
    assert len(results) == 2
    assert report["successful"] == 2
    assert len(report["items"]) == 2
    assert report["failed"] == 0
    assert all("item_key" in item for item in report["items"])
    assert all("item_key" not in item for item in public_batch_report(report)["items"])
    assert [item["url"] for item in report["items"]] == [url, url]
    workflow.persist_batch_results(
        args,
        config,
        PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="text"
        ),
        results,
        report,
    )
    runs = SQLAlchemyPersistenceService(db_uri).list_runs(limit=10)
    duplicate_runs = [run for run in runs if run.source_value == url]
    assert len(duplicate_runs) == 2
    assert url not in results
    duplicate_entries = [entry for entry in results.entries if entry.source_value == url]
    assert len(duplicate_entries) == 2
    assert len({entry.item_key for entry in duplicate_entries}) == 2
    assert all(not entry.item_key.startswith("\0") for entry in duplicate_entries)
    assert all(
        entry.normal_iocs["urls"] == ["hxxps://duplicate[.]example/path"]
        for entry in duplicate_entries
    )


def test_parallel_url_batch_keeps_downloader_metadata_per_url(tmp_path: Path) -> None:
    url_file = tmp_path / "urls.txt"
    first_url = "https://metadata-one.example/feed"
    second_url = "https://metadata-two.example/feed"
    url_file.write_text(f"{first_url}\n{second_url}\n", encoding="utf-8")
    second_downloaded = threading.Event()

    class RaceDownloader:
        def __init__(self) -> None:
            self.last_download_metadata: dict[str, object] | None = None

        def with_policy(self, **overrides: object) -> RaceDownloader:
            del overrides
            return RaceDownloader()

        def download(self, url: str) -> str:
            marker = "one" if url == first_url else "two"
            target = tmp_path / f"{marker}.txt"
            target.write_text(f"IOC URL: https://{marker}.example/path", encoding="utf-8")
            self.last_download_metadata = {"marker": marker, "input_size": target.stat().st_size}
            if marker == "two":
                second_downloaded.set()
            else:
                assert second_downloaded.wait(timeout=5)
            return str(target)

        def download_metadata(self) -> dict[str, object]:
            return dict(self.last_download_metadata or {})

    class TextReader:
        def read(self, source_path: str, options) -> str:
            del options
            return Path(source_path).read_text(encoding="utf-8")

    args = _args(url_file=str(url_file), url_workers=2)

    _, _, _, _, report = process_url_file_input_with_report(
        args,
        reader=TextReader(),
        warning_service=None,
        downloader=RaceDownloader(),
    )

    metadata_by_url = {item["url"]: item["metadata"] for item in report["items"]}
    assert metadata_by_url[first_url]["marker"] == "one"
    assert metadata_by_url[second_url]["marker"] == "two"


def test_successful_retry_uses_original_batch_url_for_retry_history_when_completed_url_changes(
    tmp_path: Path,
) -> None:
    from iocparser import cli_dispatch_workflow
    from iocparser import cli_url_batch_workflow as workflow

    class RedirectingDownloader:
        def __init__(self, temp_path: Path) -> None:
            self.temp_path = temp_path
            self._metadata = {"final_url": "https://redirected.example/path", "input_size": 0}

        def download(self, url: str) -> str:
            del url
            content = "IOC URL: https://redirected.example/path"
            self.temp_path.write_text(content, encoding="utf-8")
            self._metadata = {
                "final_url": "https://redirected.example/path",
                "input_size": len(content),
            }
            return str(self.temp_path)

        def download_metadata(self) -> dict[str, object]:
            return dict(self._metadata)

    class RedirectingReader:
        def read(self, source_path: str, options) -> str:
            del options
            return Path(source_path).read_text(encoding="utf-8")

    report_path = tmp_path / "retry-report.json"
    original_url = "https://original.example/feed"
    report_path.write_text(
        json.dumps(
            {
                "items": [
                    {"url": original_url, "status": "failed", "retry_attempt": 2},
                ]
            }
        ),
        encoding="utf-8",
    )

    args = _args(retry_failed_from=str(report_path), url_workers=1)
    _, _, _, results, report = workflow.run_url_batch_workflow(
        workflow.URLBatchWorkflowRequest(
            args=args,
            reader=RedirectingReader(),
            warning_service=None,
            downloader=RedirectingDownloader(tmp_path / "redirected.txt"),
            db_uri=None,
        )
    )

    assert len(results.entries) == 1
    assert results.entries[0].source_value == original_url
    assert report["items"][0]["url"] == original_url
    assert report["items"][0]["retry_attempt"] == 3
    assert report["source_metadata_map"][results.entries[0].item_key]["input_value"] == original_url
    assert report["items"][0]["metadata"]["final_url"] == "https://redirected.example/path"

    cli_dispatch_workflow.persist_batch_results(
        args,
        load_config(
            cli_persist=True,
            cli_db_uri=f"sqlite:///{tmp_path / 'redirect-retry.sqlite'}",
            cli_config_path=None,
        ),
        PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
        results,
        report,
    )
    runs = SQLAlchemyPersistenceService(
        f"sqlite:///{tmp_path / 'redirect-retry.sqlite'}"
    ).list_runs(limit=10)
    assert len(runs) == 1
    assert runs[0].source_value == original_url


def test_retry_report_attempts_follow_filtered_failed_items(tmp_path: Path) -> None:
    report_path = tmp_path / "filtered-retry-report.json"
    with LocalHTTPFileServer(body=b"IOC URL: https://filtered-retry.example/path") as url:
        report_path.write_text(
            json.dumps(
                {
                    "items": [
                        {
                            "url": url,
                            "status": "failed",
                            "error": "timeout waiting",
                            "error_type": "IOCTimeoutError",
                            "retry_attempt": 1,
                        },
                        {
                            "url": url,
                            "status": "failed",
                            "error": "tls verify failed",
                            "error_type": "NetworkDownloadError",
                            "retry_attempt": 5,
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        args = _args(
            retry_failed_from=str(report_path),
            retry_error_type="NetworkDownloadError",
            url_workers=1,
        )
        _normal_iocs, _warning_iocs, _label, _results, report = process_url_file_input_with_report(
            args,
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
        )

    assert report["successful"] == 1
    assert report["items"][0]["retry_attempt"] == 6


def test_retry_report_expands_user_home_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report_path = tmp_path / "home" / "report.json"
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "url": "https://retry-home.example/path",
                        "status": "failed",
                        "error": "timeout waiting",
                        "error_type": "IOCTimeoutError",
                        "retry_attempt": 2,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(report_path.parent))

    urls = _failed_urls_from_report(Path("~/report.json"))

    assert urls == ["https://retry-home.example/path"]


def test_retry_batch_job_attempts_follow_filtered_failed_items(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'filtered-retry-batch.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    with LocalHTTPFileServer(body=b"IOC URL: https://filtered-batch.example/path") as url:
        batch_job_id = persist_batch_job(
            {
                "total": 2,
                "successful": 0,
                "failed": 2,
                "status": "failed",
                "items": [
                    {
                        "url": url,
                        "status": "failed",
                        "error": "timeout waiting",
                        "error_type": "IOCTimeoutError",
                        "retry_attempt": 1,
                    },
                    {
                        "url": url,
                        "status": "failed",
                        "error": "tls verify failed",
                        "error_type": "NetworkDownloadError",
                        "retry_attempt": 5,
                    },
                ],
            },
            config=config,
            source_kind="url",
            run_ids=(),
            effective_config={},
        )
        assert batch_job_id is not None
        args = _args(
            retry_batch_job=batch_job_id,
            retry_error_type="NetworkDownloadError",
            url_workers=1,
        )
        _normal_iocs, _warning_iocs, _label, _results, report = process_url_file_input_with_report(
            args,
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
            db_uri=db_uri,
        )

    assert report["successful"] == 1
    assert report["items"][0]["retry_attempt"] == 6


def test_retry_batch_job_rejects_non_integer_value() -> None:
    from iocparser import cli_url_batch_workflow as workflow

    with pytest.raises(ValidationError, match=r"Invalid retry_batch_job"):
        workflow.run_url_batch_workflow(
            workflow.URLBatchWorkflowRequest(
                args=_args(retry_batch_job=[]),  # type: ignore[arg-type]
                reader=MagicTextSourceReader(),
                warning_service=None,
                downloader=RequestsURLDownloader(),
                db_uri=None,
            )
        )


@pytest.mark.parametrize("value", [[], "bad"])
def test_url_batch_workers_rejects_non_integer_value(tmp_path: Path, value: object) -> None:
    from iocparser import cli_url_batch_workflow as workflow

    class NoopDownloader:
        def with_policy(self, **overrides: object) -> NoopDownloader:
            del overrides
            return self

        def download(self, url: str) -> str:
            raise AssertionError(f"download should not be called for {url}")

        def download_metadata(self) -> dict[str, object]:
            return {}

    url_file = tmp_path / "urls.txt"
    url_file.write_text("https://workers.example/path\n", encoding="utf-8")

    with pytest.raises(ValidationError, match=r"Invalid url_workers"):
        workflow.run_url_batch_workflow(
            workflow.URLBatchWorkflowRequest(
                args=_args(url_file=str(url_file), url_workers=value),
                reader=MagicTextSourceReader(),
                warning_service=None,
                downloader=NoopDownloader(),
                db_uri=None,
            )
        )


def test_source_value_file_filter_preserves_case_sensitive_identity(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'case-sensitive-source-filter.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="Report-A.txt",
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="report-a.txt",
            normal_iocs={"domains": ["beta.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )

    queried_runs = query_persisted_runs(
        db_uri=db_uri, limit=10, source_kind="file", source_value="Report-A.txt"
    )
    assert queried_runs.total == 1
    assert queried_runs.items[0].source_value == "Report-A.txt"

    queried_hits = query_persisted_iocs(
        db_uri=db_uri,
        value=".example",
        source_kind="file",
        source_value="Report-A.txt",
    )
    assert queried_hits.total == 1
    assert queried_hits.items[0].source_value == "Report-A.txt"

    assert (
        prune_persisted_runs(
            db_uri=db_uri,
            before="2999-01-01T00:00:00",
            source_kind="file",
            source_value="Report-A.txt",
        )
        == 1
    )
    remaining = query_persisted_runs(db_uri=db_uri, limit=10)
    assert remaining.total == 1
    assert remaining.items[0].source_value == "report-a.txt"


def test_multiple_files_preserve_duplicate_paths_through_results_and_persistence(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "duplicate.txt"
    file_path.write_text("IOC URL: https://files.example/path", encoding="utf-8")
    args = _args(multiple=[str(file_path), str(file_path)], persist=True)

    normal_iocs, warning_iocs, input_display, results = cli_processing.process_multiple_files_input(
        args,
        reader=MagicTextSourceReader(),
        warning_service=None,
    )

    assert warning_iocs == {}
    assert input_display == "2 files"
    assert len(results) == 2
    assert normal_iocs["urls"] == ["hxxps://files[.]example/path"]

    db_uri = f"sqlite:///{tmp_path / 'duplicate-files.sqlite'}"
    persist_many_results(
        results,
        config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="text"
        ),
        source_kind="file",
    )
    runs = SQLAlchemyPersistenceService(db_uri).list_runs(limit=10)
    duplicate_runs = [run for run in runs if run.source_value == str(file_path)]
    assert len(duplicate_runs) == 2
    assert str(file_path) not in results
    duplicate_entries = [entry for entry in results.entries if entry.source_value == str(file_path)]
    assert len(duplicate_entries) == 2
    assert len({entry.item_key for entry in duplicate_entries}) == 2
    assert all(
        entry.normal_iocs["urls"] == ["hxxps://files[.]example/path"] for entry in duplicate_entries
    )


def test_equivalent_urls_reuse_same_persisted_source_for_previous_source_diff(
    tmp_path: Path,
) -> None:
    db_uri = f"sqlite:///{tmp_path / 'normalized-source.sqlite'}"
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="url",
            source_value="HTTPS://Example.TEST/report",
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            source_metadata={"normalized_url": "https://example.test/report"},
        )
    )
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="url",
            source_value="https://example.test/report",
            normal_iocs={"domains": ["beta.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            source_metadata={"normalized_url": "https://example.test/report"},
        )
    )

    service = SQLAlchemyPersistenceService(db_uri)
    runs = service.list_runs(limit=10)
    diff = diff_run_against_previous_source(db_uri=db_uri, run_id=runs[0].run_id)
    assert diff.compared_to_previous_source_run_id == runs[1].run_id
    assert diff.added.grouped_iocs() == {"domains": ["beta.example"]}
    queried_runs = query_persisted_runs(
        db_uri=db_uri, limit=10, source_kind="url", source_value="https://example.test/report/"
    )
    assert queried_runs.total == 2
    queried_hits = query_persisted_iocs(
        db_uri=db_uri,
        value=".example",
        source_kind="url",
        source_value="https://example.test/report/",
    )
    assert queried_hits.total == 2


def test_source_value_url_filter_matches_exact_canonical_source(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'exact-source-filter.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="url",
            source_value="https://example.test/report",
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="url",
            source_value="https://example.test/report-old",
            normal_iocs={"domains": ["beta.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )

    queried_runs = query_persisted_runs(
        db_uri=db_uri, limit=10, source_kind="url", source_value="https://example.test/report"
    )
    assert queried_runs.total == 1
    assert queried_runs.items[0].source_value == "https://example.test/report"

    queried_hits = query_persisted_iocs(
        db_uri=db_uri,
        value=".example",
        source_kind="url",
        source_value="https://example.test/report",
    )
    assert queried_hits.total == 1
    assert queried_hits.items[0].source_value == "https://example.test/report"

    assert (
        prune_persisted_runs(
            db_uri=db_uri,
            before="2999-01-01T00:00:00",
            source_kind="url",
            source_value="https://example.test/report",
        )
        == 1
    )


def test_source_value_url_like_string_does_not_auto_promote_without_url_source_kind(
    tmp_path: Path,
) -> None:
    db_uri = f"sqlite:///{tmp_path / 'literal-url-like-source-filter.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="https://example.test/report",
            normal_iocs={"domains": ["literal.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )
    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="url",
            source_value="HTTPS://Example.TEST/report",
            normal_iocs={"domains": ["canonical.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            source_metadata={"normalized_url": "https://example.test/report"},
        )
    )

    file_runs = query_persisted_runs(
        db_uri=db_uri, limit=10, source_value="https://example.test/report"
    )
    file_hits = query_persisted_iocs(
        db_uri=db_uri, value=".example", source_value="https://example.test/report"
    )

    assert file_runs.total == 1
    assert file_runs.items[0].source_kind == "file"
    assert file_hits.total == 1
    assert file_hits.items[0].source_kind == "file"


def test_url_sources_reuse_same_identity_across_direct_and_downloader_style_normalization(
    tmp_path: Path,
) -> None:
    db_uri = f"sqlite:///{tmp_path / 'normalized-source-producers.sqlite'}"
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="url",
            source_value="https://example.test/report",
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            source_metadata={"normalized_url": "HTTPS://Example.TEST/report#frag"},
        )
    )
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="url",
            source_value="https://example.test/report",
            normal_iocs={"domains": ["beta.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )

    service = SQLAlchemyPersistenceService(db_uri)
    runs = service.list_runs(limit=10)
    diff = diff_run_against_previous_source(db_uri=db_uri, run_id=runs[0].run_id)
    assert diff.compared_to_previous_source_run_id == runs[1].run_id


def test_persist_multiple_runs_reuses_canonical_url_identity(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'normalized-source-bulk.sqlite'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            (
                "url",
                "HTTPS://Example.TEST/report#frag",
                ExtractionResult.from_grouped_payload({"domains": ["alpha.example"]}, {}),
            ),
            (
                "url",
                "https://example.test/report",
                ExtractionResult.from_grouped_payload({"domains": ["beta.example"]}, {}),
            ),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    compared = service.diff_run_against_previous_source(run_id=run_ids[1])
    assert compared.compared_to_previous_source_run_id == run_ids[0]
    queried_runs = query_persisted_runs(
        db_uri=db_uri, limit=10, source_kind="url", source_value="https://example.test/report/"
    )
    assert queried_runs.total == 2


def test_merge_batch_results_preserves_entries_when_item_key_matches_other_source_value() -> None:
    results = BatchResultsCollection()
    results.add(
        item_key="batch-item:1",
        source_value="https://dup.example",
        normal_iocs={"domains": ["alpha.example"]},
        warning_iocs={},
    )
    results.add(
        item_key="other-entry",
        source_value="batch-item:1",
        normal_iocs={"domains": ["beta.example"]},
        warning_iocs={},
    )

    merged = merge_batch_results(results)
    assert merged.grouped_iocs()["domains"] == ["alpha.example", "beta.example"]


def test_batch_with_context_merges_evidence_across_items() -> None:
    """Regression: batch --with-context rendered empty evidence because the per-item
    rich results were dropped at the grouped-dict conversion. merge_batch_results now
    dedups by canonical value and aggregates evidence from each item's retained result,
    and resolve_input_payload threads that merged result only when --with-context is set.
    """
    from iocparser.cli_dispatch_workflow import resolve_input_payload

    def item(source: str, line: int) -> ExtractionResult:
        ioc = IOC.from_raw(
            "domains",
            "shared.example.com",
            evidence=(IOCEvidence(excerpt=f"seen in {source}", line_number=line, source=source),),
        )
        return ExtractionResult(iocs=(ioc,))

    results = BatchResultsCollection()
    for source, line in (("a.txt", 1), ("b.txt", 9)):
        result = item(source, line)
        results.add(
            item_key=source,
            source_value=source,
            normal_iocs=result.grouped_iocs(),
            warning_iocs={},
            result=result,
        )

    merged = merge_batch_results(results)
    domain_iocs = [ioc for ioc in merged.iocs if ioc.value.canonical() == "shared.example.com"]
    assert len(domain_iocs) == 1  # deduped to a single IOC
    assert len(domain_iocs[0].evidence) == 2  # evidence aggregated across both items
    assert merged.grouped_iocs()["domains"] == ["shared.example.com"]

    def multi(_args: argparse.Namespace) -> tuple[dict, dict, str, BatchResultsCollection]:
        return merged.grouped_iocs(), {}, "2 files", results

    base = {"directory": None, "url_file": None, "retry_failed_from": None, "retry_batch_job": None}
    with_ctx = resolve_input_payload(
        argparse.Namespace(multiple=["a.txt", "b.txt"], with_context=True, **base),
        process_multiple_files_input=multi,
        process_single_input=lambda _a: ({}, {}, "x", None),
    )
    assert with_ctx.result is not None
    assert with_ctx.result.grouped_iocs() == with_ctx.normal_iocs

    without_ctx = resolve_input_payload(
        argparse.Namespace(multiple=["a.txt", "b.txt"], with_context=False, **base),
        process_multiple_files_input=multi,
        process_single_input=lambda _a: ({}, {}, "x", None),
    )
    assert without_ctx.result is None


def test_batch_json_counts_match_deduped_arrays() -> None:
    """Regression: total_count/counts_by_type counted raw (un-deduped) iocs while the
    per-type arrays were deduped, so batch JSON reported totals larger than the arrays.
    merge_batch_results now dedups, so the summary numbers match the array lengths.
    """
    from iocparser.adapters.renderers_json import JSONOutputRenderer

    results = BatchResultsCollection()
    for source in ("a.txt", "b.txt", "c.txt"):
        result = ExtractionResult(iocs=(IOC.from_raw("domains", "repeated.example.com"),))
        results.add(
            item_key=source,
            source_value=source,
            normal_iocs=result.grouped_iocs(),
            warning_iocs={},
            result=result,
        )

    merged = merge_batch_results(results)
    payload = json.loads(JSONOutputRenderer().render(merged))

    reserved = {
        "schema_version",
        "format",
        "records",
        "counts_by_type",
        "total_count",
        "warning_list_matches",
    }
    array_total = sum(
        len(value)
        for key, value in payload.items()
        if key not in reserved and isinstance(value, list)
    )
    assert payload["total_count"] == len(payload["records"]) == array_total == 1


def test_public_batch_report_uses_urls_and_hides_internal_batch_maps() -> None:
    report = public_batch_report(
        {
            "schema_version": "1.0",
            "report_type": "url_batch",
            "job_id": "job-1",
            "correlation_id": "corr-1",
            "status": "partial",
            "failure_cause": "ValueError",
            "total": 2,
            "successful": 1,
            "failed": 1,
            "failures": {"batch-item:1": "boom"},
            "error_groups": {"ValueError": 1},
            "items": [
                {
                    "url": "https://bad.example",
                    "status": "failed",
                    "error": "boom",
                    "item_key": "batch-item:1",
                },
                {"url": "https://ok.example", "status": "ok", "item_key": "batch-item:2"},
            ],
            "source_metadata_map": {"batch-item:1": {"input_value": "https://bad.example"}},
            "run_metadata_map": {"batch-item:1": {"status": "failed"}},
            "duration_ms": 10,
            "phase_timings_ms": {"execution": 10},
            "phase_timestamps": {
                "started_at": "2026-01-01T00:00:00",
                "finished_at": "2026-01-01T00:00:10",
            },
            "metrics": {"throughput_items_per_second": 2.0},
        }
    )

    assert report["failures"] == {"https://bad.example": "boom"}
    assert "source_metadata_map" not in report
    assert "run_metadata_map" not in report
    assert all("item_key" not in item for item in report["items"])


def test_public_batch_report_preserves_duplicate_failed_urls_in_summary() -> None:
    report = public_batch_report(
        {
            "schema_version": "1.0",
            "report_type": "url_batch",
            "job_id": "job-1",
            "correlation_id": "corr-1",
            "status": "failed",
            "failure_cause": "ValueError",
            "total": 2,
            "successful": 0,
            "failed": 2,
            "failures": {"batch-item:1": "boom", "batch-item:2": "boom-again"},
            "error_groups": {"ValueError": 2},
            "items": [
                {
                    "url": "https://bad.example",
                    "status": "failed",
                    "error": "boom",
                    "item_key": "batch-item:1",
                },
                {
                    "url": "https://bad.example",
                    "status": "failed",
                    "error": "boom-again",
                    "item_key": "batch-item:2",
                },
            ],
            "source_metadata_map": {"batch-item:1": {"input_value": "https://bad.example"}},
            "run_metadata_map": {"batch-item:1": {"status": "failed"}},
            "duration_ms": 10,
            "phase_timings_ms": {"execution": 10},
            "phase_timestamps": {
                "started_at": "2026-01-01T00:00:00",
                "finished_at": "2026-01-01T00:00:10",
            },
            "metrics": {"throughput_items_per_second": 2.0},
        }
    )

    assert report["failures"] == {
        "https://bad.example [1]": "boom",
        "https://bad.example [2]": "boom-again",
    }


def test_public_batch_report_lists_failed_url_with_empty_error_message() -> None:
    """Regression: a failed URL whose exception had no message (str(exc) == "") is still
    counted in report['failed'], so it must appear in the public failures summary too --
    gating on a non-empty error string dropped it and skewed the count vs listing."""
    report = public_batch_report(
        {
            "schema_version": "1.0",
            "report_type": "url_batch",
            "job_id": "job-1",
            "correlation_id": "corr-1",
            "status": "failed",
            "failure_cause": "ValueError",
            "total": 1,
            "successful": 0,
            "failed": 1,
            "failures": {"batch-item:1": ""},
            "error_groups": {"ValueError": 1},
            "items": [
                {
                    "url": "https://silent.example",
                    "status": "failed",
                    "error": "",
                    "item_key": "batch-item:1",
                },
            ],
            "duration_ms": 5,
        }
    )

    assert report["failed"] == 1
    assert len(report["failures"]) == 1
    assert report["failures"] == {"https://silent.example": "unknown error"}


def test_batch_item_keys_avoid_collision_with_real_source_values() -> None:
    assert batch_item_keys(["dup", "dup", "batch-item:2"]) == [
        ("batch-item:1", "dup"),
        ("batch-item:2:1", "dup"),
        ("batch-item:2", "batch-item:2"),
    ]


def test_public_batch_report_preserves_input_order_for_duplicate_failed_urls() -> None:
    report = build_batch_report(
        {
            "urls": ["https://bad.example", "https://bad.example"],
            "results": BatchResultsCollection(),
            "failures": {"batch-item:2": "second", "batch-item:1": "first"},
            "item_reports": [
                {
                    "url": "https://bad.example",
                    "status": "failed",
                    "error": "second",
                    "item_key": "batch-item:2",
                    "input_index": 2,
                },
                {
                    "url": "https://bad.example",
                    "status": "failed",
                    "error": "first",
                    "item_key": "batch-item:1",
                    "input_index": 1,
                },
            ],
            "source_metadata_map": {"batch-item:1": {"input_value": "https://bad.example"}},
            "run_metadata_map": {"batch-item:1": {"status": "failed"}},
            "job_id": "job-1",
            "correlation_id": "corr-1",
            "input_load_ms": 0,
            "batch_started": time.perf_counter(),
            "batch_started_wall": time.time(),
        }
    )

    assert [item["error"] for item in report["items"]] == ["first", "second"]


def test_batch_results_collection_rejects_ambiguous_key_between_internal_item_key_and_source_value() -> (
    None
):
    results = BatchResultsCollection()
    results.add(
        item_key="batch-item:1",
        source_value="https://dup.example",
        normal_iocs={"domains": ["alpha.example"]},
        warning_iocs={},
    )
    results.add(
        item_key="other-entry",
        source_value="batch-item:1",
        normal_iocs={"domains": ["beta.example"]},
        warning_iocs={},
    )

    assert "batch-item:1" not in results
    with pytest.raises(KeyError):
        _ = results["batch-item:1"]


def test_public_rich_extraction_api(tmp_path: Path) -> None:
    with pytest.raises(FileExistenceError):
        extract_result_from_file(str(tmp_path / "missing.txt"))

    sample = tmp_path / "sample.txt"
    sample.write_text("See https://evil.example/path and alpha.example\n", encoding="utf-8")

    file_result = extract_result_from_file(str(sample))
    assert any(ioc.ioc_type.value == "urls" for ioc in file_result.iocs)
    assert any(ioc.tags for ioc in file_result.iocs)

    text_result = extract_result_from_text("beta.example 198.51.100.10", check_warnings=False)
    assert "ips" in {ioc.ioc_type.value for ioc in text_result.iocs}
    assert text_result.iocs


def test_public_rich_extraction_api_expands_user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    sample = home / "sample.txt"
    sample.write_text("See https://evil.example/path and alpha.example\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    file_result = extract_result_from_file("~/sample.txt")
    assert any(ioc.ioc_type.value == "urls" for ioc in file_result.iocs)
    assert any(ioc.tags for ioc in file_result.iocs)

    class OneShotServer(ThreadedHTTPServer):
        path = "/report.txt"

        def build_handler(self) -> type[BaseHTTPRequestHandler]:
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    body = b"gamma.example https://gamma.example/x"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, fmt: str, *args) -> None:
                    del fmt, args

            return Handler

    with OneShotServer() as url:
        url_result = extract_result_from_url(url)
    assert any(ioc.ioc_type.value == "urls" for ioc in url_result.iocs)


def test_render_result_supports_summary_and_analyst_filters() -> None:
    result = ExtractionResult(
        iocs=(
            IOC.from_raw("domains", "alpha.example"),
            IOC.from_raw("cves", "CVE-2024-9999"),
            IOC.from_raw("urls", "https://evil.example/path"),
        ),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw(
                    "ips", "198.51.100.10", severity="informational", tags=("warning-list-match",)
                ),
                warning_list="Known Benign",
                description="Resolver",
            ),
        ),
    )

    summary_text, label, fmt = render_result(_args(summary=True), result)
    assert label == "summary"
    assert fmt == "text"
    assert "IOC Summary" in summary_text
    assert "urls" in summary_text
    assert "1" in summary_text
    assert "Warning Matches" in summary_text

    warnings_only, _, _ = render_result(_args(json=True, only_warnings=True), result)
    assert "Known Benign" in warnings_only
    assert "alpha.example" not in warnings_only

    high_first = result.filter_analyst_view(sort_by="severity")
    assert high_first.iocs[0].ioc_type.value == "cves"

    with pytest.raises(ValueError, match="Invalid sort_by"):
        result.filter_analyst_view(sort_by="bogus")

    with pytest.raises(ValidationError, match="Invalid severity"):
        render_result(_args(json=True, severity="critical"), result)
    with pytest.raises(ValidationError, match="max_evidence"):
        render_result(_args(json=True, max_evidence=[]), result)  # type: ignore[arg-type]

    trimmed = result.filter_analyst_view(max_evidence=0, sort_by="value", severities=("high",))
    assert len(trimmed.iocs) == 1
    assert trimmed.iocs[0].evidence == ()
    by_value = result.filter_analyst_view(sort_by="value")
    assert by_value.iocs[0].canonical_value() == "CVE-2024-9999"
    assert result.filter_analyst_view(tags=("nonexistent",)).iocs == ()


def test_save_diff_output_supports_counts_and_selective_sections(tmp_path: Path) -> None:
    diff = SQLAlchemyPersistenceService(f"sqlite:///{tmp_path / 'diff.db'}")
    run_ids = diff.persist_multiple_runs(
        [
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload({"domains": ["old.example"]}, {}),
            ),
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload({"domains": ["new.example"]}, {}),
            ),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="text"
        ),
    )
    compared = diff.diff_run_against_previous_source(run_id=run_ids[1])
    buffer = StringIO()
    with redirect_stdout(buffer):
        save_diff_output(_args(diff_only="added"), compared, file_writer=_Writer())
    output = buffer.getvalue()
    assert "Added Counts" in output
    assert "new.example" in output
    assert "old.example" not in output

    buffer = StringIO()
    with redirect_stdout(buffer):
        save_diff_output(_args(diff_only="removed"), compared, file_writer=_Writer())
    assert "Removed Counts" in buffer.getvalue()


def test_diff_previous_source_uses_run_id_to_break_started_at_ties(tmp_path: Path) -> None:
    from iocparser.infrastructure.persistence import RunModel

    db_uri = f"sqlite:///{tmp_path / 'diff-started-at-tie.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload({"domains": ["old.example"]}, {}),
            ),
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload({"domains": ["new.example"]}, {}),
            ),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="text"
        ),
    )

    unit = SQLAlchemyUnitOfWork(db_uri)
    try:
        first = unit.session.get(RunModel, run_ids[0])
        second = unit.session.get(RunModel, run_ids[1])
        assert first is not None
        assert second is not None
        second.started_at = first.started_at
        unit.commit()
    finally:
        unit.close()

    compared = service.diff_run_against_previous_source(run_id=run_ids[1])
    assert compared.compared_to_previous_source_run_id == run_ids[0]


def test_load_config_supports_extended_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    client_pem = tmp_path / "client.pem"
    client_pem.write_text("cert", encoding="utf-8")
    ca_pem = tmp_path / "ca.pem"
    ca_pem.write_text("ca", encoding="utf-8")
    config_path.write_text(
        (
            "[database]\n"
            "persist=true\n"
            "uri=sqlite:///iocparser.db\n"
            "[defaults]\n"
            "only=urls,domains\n"
            "stix_types=domains\n"
            "output_format=json\n"
            "with_context=true\n"
            "streaming=true\n"
            "summary=true\n"
            "severity=medium\n"
            "tag=network\n"
            "[network]\n"
            "url_workers=8\n"
            "url_retries=2\n"
            "url_backoff=0.01\n"
            "rate_limit=0.02\n"
            "user_agent=IOCParser-Test/1.0\n"
            'headers_json={"X-Test": "1"}\n'
            'cookies_json={"session": "cookie"}\n'
            "proxy=http://127.0.0.1:8080\n"
            "allow_redirects=false\n"
            "tls_verify=false\n"
            f"tls_cert={client_pem}\n"
            f"ca_bundle={ca_pem}\n"
            "connect_timeout=1.5\n"
            "read_timeout=3.5\n"
        ),
        encoding="utf-8",
    )

    config = load_config(cli_persist=None, cli_db_uri=None, cli_config_path=str(config_path))
    assert config.output_format == "json"
    assert config.only == "urls,domains"
    assert config.with_context is True
    assert config.url_workers == 8
    assert config.rate_limit == 0.02
    assert config.user_agent == "IOCParser-Test/1.0"
    assert config.headers_json == '{"X-Test": "1"}'
    assert config.cookies_json == '{"session": "cookie"}'
    assert config.proxy == "http://127.0.0.1:8080"
    assert config.allow_redirects is False
    assert config.tls_verify is False
    assert config.tls_cert == str(client_pem)
    assert config.ca_bundle == str(ca_pem)
    assert config.connect_timeout == 1.5
    assert config.read_timeout == 3.5

    args = _args()
    args.only = None
    args.exclude = None
    args.stix_types = None
    args.severity = None
    args.tag = None
    args.streaming = False
    args.url_workers = None
    args.url_retries = None
    args.url_backoff = None
    args.rate_limit = None
    args.parallel = None
    args.chunk_size = None
    args.overlap = None
    args.diff_only = None
    args.user_agent = None
    args.headers_json = None
    args.cookies_json = None
    args.proxy = None
    args.allow_redirects = None
    args.tls_verify = None
    args.tls_cert = None
    args.ca_bundle = None
    args.connect_timeout = None
    args.read_timeout = None
    apply_config_defaults(args, config)
    assert args.only == "urls,domains"
    assert args.json is True
    assert args.streaming is True
    assert args.url_workers == 8
    assert args.user_agent == "IOCParser-Test/1.0"
    assert args.headers_json == '{"X-Test": "1"}'
    assert args.cookies_json == '{"session": "cookie"}'
    assert args.proxy == "http://127.0.0.1:8080"
    assert args.allow_redirects is False
    assert args.tls_verify is False
    assert args.tls_cert == str(client_pem)
    assert args.ca_bundle == str(ca_pem)
    assert args.connect_timeout == 1.5
    assert args.read_timeout == 3.5

    config_with_diff = AppConfig(
        persist=False,
        db_uri="sqlite:///iocparser.db",
        config_path=None,
        diff_only="added",
    )
    diff_args = _args()
    diff_args.diff_only = None
    apply_config_defaults(diff_args, config_with_diff)
    assert diff_args.diff_only == "added"

    configured_downloader = downloader_for_args(args)
    assert configured_downloader.retries == 2
    assert configured_downloader.rate_limit_delay == 0.02
    assert configured_downloader.user_agent == "IOCParser-Test/1.0"
    assert configured_downloader.headers["X-Test"] == "1"
    assert configured_downloader.cookies["session"] == "cookie"
    assert configured_downloader.proxies["https"] == "http://127.0.0.1:8080"
    assert configured_downloader.allow_redirects is False
    assert configured_downloader.verify is False
    assert configured_downloader.cert == str(client_pem)
    assert configured_downloader.timeout == (1.5, 3.5)

    args.tls_verify = True
    configured_with_ca = downloader_for_args(args)
    assert configured_with_ca.verify == str(ca_pem)


def test_cli_boolean_network_flags_override_false_config() -> None:
    config = AppConfig(
        persist=False,
        db_uri=None,
        config_path=None,
        allow_redirects=False,
        tls_verify=False,
    )
    args = create_argument_parser().parse_args(["--allow-redirects", "--tls-verify"])

    apply_config_defaults(args, config)

    assert args.allow_redirects is True
    assert args.tls_verify is True


def test_config_output_format_is_case_insensitive() -> None:
    """An INI/env output_format must be honored regardless of case.

    The valid set and CLI flags are lowercase, so a config "output_format = JSON" (or
    "  Stix ") was silently ignored and output fell back to text. It is now normalized.
    """
    args = create_argument_parser().parse_args([])
    apply_config_defaults(
        args, AppConfig(persist=False, db_uri=None, config_path=None, output_format="JSON")
    )
    assert args.json is True

    stix_args = create_argument_parser().parse_args([])
    apply_config_defaults(
        stix_args, AppConfig(persist=False, db_uri=None, config_path=None, output_format="  Stix ")
    )
    assert stix_args.stix is True

    invalid_args = create_argument_parser().parse_args([])
    with pytest.raises(ValidationError, match="output_format"):
        apply_config_defaults(
            invalid_args,
            AppConfig(persist=False, db_uri=None, config_path=None, output_format="yaml"),
        )


def test_cli_numeric_defaults_override_config_when_explicit() -> None:
    config = AppConfig(
        persist=False,
        db_uri=None,
        config_path=None,
        url_workers=8,
        url_retries=2,
        url_backoff=0.5,
        rate_limit=0.25,
        parallel=3,
        chunk_size=4096,
        overlap=128,
        max_queue_size=9,
        diff_only="added",
    )
    args = create_argument_parser().parse_args(
        [
            "--url-workers",
            "4",
            "--url-retries",
            "0",
            "--url-backoff",
            "0",
            "--rate-limit",
            "0",
            "--parallel",
            "1",
            "--chunk-size",
            str(1024 * 1024),
            "--overlap",
            "1024",
            "--max-queue-size",
            "64",
            "--diff-only",
            "all",
        ]
    )

    apply_config_defaults(args, config)

    assert args.url_workers == 4
    assert args.url_retries == 0
    assert args.url_backoff == 0
    assert args.rate_limit == 0
    assert args.parallel == 1
    assert args.chunk_size == 1024 * 1024
    assert args.overlap == 1024
    assert args.max_queue_size == 64
    assert args.diff_only == "all"


def test_requests_url_downloader_supports_retries_and_metadata() -> None:
    downloader = RequestsURLDownloader(
        retries=1,
        backoff=0.001,
        headers={"X-Test": "1"},
        cookies={"session": "abc"},
        timeout=(0.5, 0.5),
    )
    with FlakyLocalHTTPServer() as url:
        downloaded = Path(downloader.download(url))
        try:
            assert downloaded.exists()
            assert downloader.last_download_metadata is not None
            assert downloader.last_download_metadata["content_hash"]
            assert downloader.last_download_metadata["fingerprint"]
        finally:
            downloaded.unlink(missing_ok=True)

    derived = downloader.with_policy(rate_limit_delay=0.001)
    assert derived.rate_limit_delay == 0.001
    assert derived.headers["X-Test"] == "1"
    assert derived.cookies["session"] == "abc"


def test_requests_url_downloader_rate_limit_and_timeout_retry() -> None:
    downloader = RequestsURLDownloader(retries=1, backoff=0.001, rate_limit_delay=0.01)
    with FlakyLocalHTTPServer() as url:
        start = time.monotonic()
        first = Path(downloader.download(url))
        second = Path(downloader.download(url))
        elapsed = time.monotonic() - start
        try:
            assert elapsed >= 0.01
        finally:
            first.unlink(missing_ok=True)
            second.unlink(missing_ok=True)

    timeout_downloader = RequestsURLDownloader(timeout=0.001, retries=1, backoff=0.001)
    with SlowLocalHTTPServer(delay=0.02) as slow_url:
        try:
            timeout_downloader.download(slow_url)
        except IOCTimeoutError:
            pass
        else:
            raise AssertionError("Expected timeout for slow URL")


def test_cli_query_and_persist_helpers_cover_new_paths(tmp_path: Path) -> None:
    db_path = tmp_path / "persist.sqlite"
    db_uri = f"sqlite:///{db_path}"
    sample = tmp_path / "sample.txt"
    sample.write_text("IOC domain: alpha.example\n", encoding="utf-8")
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="file",
            source_value=str(sample),
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="url",
            source_value="https://example.test/report",
            normal_iocs={"domains": ["beta.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="url",
            source_value="https://example.test/report",
            normal_iocs={"domains": ["gamma.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )

    service = SQLAlchemyPersistenceService(db_uri)
    runs = service.list_runs(limit=10)
    assert runs[0].original_url == "https://example.test/report"
    assert runs[-1].mime_type == "text"

    query_args = _args(
        diff_latest=runs[0].run_id,
        list_runs=False,
        run_limit=10,
        search_ioc=None,
        diff_runs=None,
        export_run=None,
    )
    query_args.db_uri = db_uri
    query_args.config = None
    assert (
        cli_queries.handle_query_commands(
            query_args, load_config(None, db_uri, None), file_writer=_Writer()
        )
        is True
    )

    unreadable = tmp_path / "unreadable.txt"
    unreadable.write_text("IOC domain: denied.example\n", encoding="utf-8")
    unreadable.chmod(0)
    try:
        persist_results(
            PersistResultsRequest(
                config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
                source_kind="file",
                source_value=str(unreadable),
                normal_iocs={"domains": ["denied.example"]},
                warning_iocs={},
                options=PersistOptions(
                    defang=False, check_warnings=False, force_update=False, output_format="json"
                ),
                tool_version="5.0.0",
            )
        )
    finally:
        unreadable.chmod(0o644)


def test_parse_string_filters_supports_sequences() -> None:
    assert parse_string_filters(["high,medium", "informational"]) == (
        "high",
        "medium",
        "informational",
    )
    assert parse_string_filters("high,medium") == ("high", "medium")
    with pytest.raises(ValidationError, match="Invalid filter value"):
        parse_string_filters([object()])
    with pytest.raises(ValidationError, match="Invalid filter value"):
        parse_string_filters(123)


def test_persistence_query_service_raises_for_missing_runs(tmp_path: Path) -> None:
    service = SQLAlchemyPersistenceService(f"sqlite:///{tmp_path / 'missing.db'}")
    with pytest.raises(ValueError, match="Run not found"):
        service.diff_run_against_previous_source(run_id=999)

    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "lonely.txt",
                ExtractionResult.from_grouped_payload({"domains": ["solo.example"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    with pytest.raises(ValueError, match="No previous run found"):
        service.diff_run_against_previous_source(run_id=run_ids[0])


def test_public_render_api_and_semantic_diff_filters(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'render.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    initial = ExtractionResult(
        iocs=(
            IOC.from_raw(
                "domains",
                "alpha.example",
                evidence=(IOCEvidence(excerpt="alpha.example", line_number=1, source="alpha.txt"),),
            ),
        ),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw(
                    "ips",
                    "198.51.100.10",
                    evidence=(
                        IOCEvidence(excerpt="198.51.100.10", line_number=4, source="alpha.txt"),
                    ),
                    severity="informational",
                    tags=("warning-list-match", "network"),
                ),
                warning_list="Known Benign",
                description="Resolver",
            ),
        ),
    )
    updated = ExtractionResult(iocs=(IOC.from_raw("urls", "https://beta.example/path"),))
    run_ids = service.persist_multiple_runs(
        [
            ("file", "alpha.txt", initial),
            ("file", "alpha.txt", updated),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=True, force_update=False, output_format="json"
        ),
    )

    rendered_run = render_persisted_run(
        db_uri=db_uri,
        run_id=run_ids[0],
        output_format="json",
        with_context=True,
        severity="informational",
        only_warnings=True,
    )
    assert "Known Benign" in rendered_run
    assert "alpha.example" not in rendered_run
    assert "line_number" in rendered_run
    assert "Known Benign" in render_persisted_run(
        db_uri=db_uri,
        run_id=run_ids[0],
        output_format=" JSON ",
        severity="informational",
        only_warnings=True,
    )

    rendered_jsonl = render_persisted_run(
        db_uri=db_uri,
        run_id=run_ids[0],
        render=PersistedRenderOptions(output_format="jsonl"),
        filters=PersistedExportFilters(only_warnings=True),
    )
    assert "Known Benign" in rendered_jsonl

    rendered_csv = render_persisted_run(
        db_uri=db_uri,
        run_id=run_ids[0],
        render=PersistedRenderOptions(output_format="csv"),
        filters=PersistedExportFilters(only_warnings=True),
    )
    assert "warning_list" in rendered_csv

    rendered_stix = render_persisted_run(
        db_uri=db_uri,
        run_id=run_ids[1],
        render=PersistedRenderOptions(output_format="stix", stix_types="urls"),
    )
    assert "bundle" in rendered_stix.lower()

    rendered_diff = render_persisted_diff(
        db_uri=db_uri,
        left_run_id=run_ids[0],
        right_run_id=run_ids[1],
        output_format="json",
        diff_only="added",
        ioc_type="urls",
    )
    assert "beta.example" in rendered_diff
    assert "alpha.example" not in rendered_diff
    assert "Known Benign" not in rendered_diff

    latest_source_diff = render_persisted_diff(
        db_uri=db_uri,
        run_id=run_ids[1],
        render=PersistedRenderOptions(output_format="text"),
        filters=PersistedDiffFilters(diff_only="all"),
    )
    assert "beta.example" in latest_source_diff
    structured_diff = export_structured_persisted_diff(
        db_uri=db_uri,
        left_run_id=run_ids[0],
        right_run_id=run_ids[1],
    )
    assert structured_diff["added_counts"]["urls"] == 1

    removed_diff = render_persisted_diff(
        db_uri=db_uri,
        left_run_id=run_ids[0],
        right_run_id=run_ids[1],
        output_format="json",
        diff_only="removed",
    )
    assert "alpha.example" in removed_diff

    normal_only_removed_diff = render_persisted_diff(
        db_uri=db_uri,
        left_run_id=run_ids[0],
        right_run_id=run_ids[1],
        output_format="json",
        diff_only="removed",
        only_normal=True,
    )
    assert "alpha.example" in normal_only_removed_diff
    assert "Known Benign" not in normal_only_removed_diff

    normal_only_structured_diff = diff_persisted_runs(
        db_uri=db_uri,
        left_run_id=run_ids[0],
        right_run_id=run_ids[1],
        only_normal=True,
    )
    assert normal_only_structured_diff.removed_warning_counts == {}

    warning_only_diff = diff_persisted_runs(
        db_uri=db_uri, left_run_id=run_ids[1], right_run_id=run_ids[0]
    )
    assert warning_only_diff.added_warning_counts["ips"] == 1
    assert warning_only_diff.removed_warning_counts == {}

    with pytest.raises(ValueError, match="Missing diff target"):
        render_persisted_diff(db_uri=db_uri)
    with pytest.raises(ValueError, match="Missing diff target"):
        export_structured_persisted_diff(db_uri=db_uri)

    structured_latest = export_structured_persisted_diff(db_uri=db_uri, run_id=run_ids[1])
    assert structured_latest["compared_to_previous_source_run_id"] == run_ids[0]


def test_query_filters_and_previous_successful_baseline(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'filters.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    warning_result = ExtractionResult(
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw(
                    "domains",
                    "flagged.example",
                    evidence=(
                        IOCEvidence(excerpt="flagged.example", line_number=2, source="batch"),
                    ),
                    severity="informational",
                    tags=("warning-list-match", "network"),
                ),
                warning_list="Known Benign",
                description="Sample",
            ),
        ),
    )
    service.persist_multiple_runs(
        [("file", "sample.txt", warning_result)],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=True, force_update=False, output_format="json"
        ),
    )
    unit_of_work = SQLAlchemyUnitOfWork(db_uri)
    try:
        source_id = unit_of_work.source_repository.get_or_create(kind="file", value="sample.txt")
        failed_run_id = unit_of_work.run_repository.create_run(
            source_id=source_id,
            tool_version="5.0.0",
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            metadata={
                "normal_ioc_count": 0,
                "warning_ioc_count": 0,
                "processed_items": 1,
                "successful_items": 0,
                "failed_items": 1,
                "partial_error_count": 1,
            },
        )
        success_run_id = unit_of_work.run_repository.create_run(
            source_id=source_id,
            tool_version="5.0.0",
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            metadata={
                "normal_ioc_count": 1,
                "warning_ioc_count": 0,
                "processed_items": 1,
                "successful_items": 1,
                "failed_items": 0,
                "partial_error_count": 0,
            },
        )
        fresh_result = ExtractionResult(iocs=(IOC.from_raw("urls", "https://fresh.example"),))
        ioc_ids = unit_of_work.ioc_repository.get_or_create_normal(fresh_result)
        unit_of_work.run_repository.attach_iocs(
            run_id=success_run_id, ioc_ids=ioc_ids, result=fresh_result
        )
        latest_run_id = unit_of_work.run_repository.create_run(
            source_id=source_id,
            tool_version="5.0.0",
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            metadata={
                "normal_ioc_count": 1,
                "warning_ioc_count": 0,
                "processed_items": 1,
                "successful_items": 1,
                "failed_items": 0,
                "partial_error_count": 0,
            },
        )
        latest_result = ExtractionResult(iocs=(IOC.from_raw("domains", "latest.example"),))
        latest_ids = unit_of_work.ioc_repository.get_or_create_normal(latest_result)
        unit_of_work.run_repository.attach_iocs(
            run_id=latest_run_id, ioc_ids=latest_ids, result=latest_result
        )
        unit_of_work.commit()
    finally:
        unit_of_work.close()

    hits = search_persisted_iocs(
        db_uri=db_uri,
        value="flagged",
    )
    assert hits[0].severity == "informational"
    assert hits[0].tags == ("warning-list-match", "network")
    assert hits[0].evidence[0]["line_number"] == 2

    filtered_hits = service.search_iocs(
        value="flagged",
        limit=10,
        offset=0,
        date_from="2000-01-01T00:00:00",
        date_to="2999-01-01T00:00:00",
        source_kind="file",
        source_value="sample.txt",
        ioc_type="domains",
        severity=("informational",),
        tags=("warning-list-match",),
        exclude_tags=("artifact",),
        min_severity="informational",
        tag_mode="all",
    )
    assert len(filtered_hits) == 1
    assert not service.search_iocs(
        value="flagged",
        tags=("missing",),
        tag_mode="all",
    )
    assert not service.search_iocs(
        value="flagged",
        exclude_tags=("warning-list-match",),
    )

    public_filtered_hits = search_persisted_iocs(
        db_uri=db_uri,
        value="flagged",
        source_kind="file",
        source_value="sample.txt",
        ioc_type="domains",
        severity="informational",
        tag="warning-list-match",
        exclude_tag="artifact",
        min_severity="informational",
        limit=10,
        offset=0,
    )
    assert len(public_filtered_hits) == 1

    date_filtered_runs = service.list_runs(
        limit=5,
        offset=0,
        date_from="2000-01-01T00:00:00",
        date_to="2999-01-01T00:00:00",
        source_kind="file",
        source_value="sample.txt",
        sort_by="source",
    )
    assert date_filtered_runs
    assert service.list_runs(limit=5, sort_by="oldest")
    assert SQLAlchemyPersistenceService._parse_datetime(None) is None

    compared = service.diff_run_against_previous_source(run_id=latest_run_id)
    assert compared.compared_to_previous_source_run_id == success_run_id
    assert compared.left_run_id != failed_run_id


def test_export_run_rehydrates_legacy_warning_tags(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'legacy-warning-tags.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    warning_result = ExtractionResult(
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw(
                    "domains",
                    "legacy-warning.example",
                    severity="informational",
                    tags=("warning-list-match", "network"),
                ),
                warning_list="Legacy List",
                description="legacy row",
            ),
        ),
    )
    (run_id,) = service.persist_multiple_runs(
        [("file", "legacy-warning.txt", warning_result)],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=True, force_update=False, output_format="json"
        ),
    )

    from iocparser.infrastructure.persistence_schema import RunIOCModel

    unit_of_work = SQLAlchemyUnitOfWork(db_uri)
    try:
        run_ioc = unit_of_work.session.query(RunIOCModel).one()
        run_ioc.tags_json = "[]"
        run_ioc.tags_search = ""
        unit_of_work.commit()
    finally:
        unit_of_work.close()

    exported = service.export_run(run_id=run_id)
    warning_tags = exported.result.warnings[0].ioc.tags

    assert "warning-list-match" in warning_tags
    assert exported.result.filter_analyst_view(
        tags=("warning-list-match",), include_normal=False
    ).warnings


def test_version_is_single_sourced_and_consistent(monkeypatch: pytest.MonkeyPatch) -> None:
    """__version__, the CLI --version string, and the distribution metadata must agree.

    Regression: pyproject was bumped to 6.0.0 but iocparser.__version__ (5.0.2) and
    cli_args_parser.VERSION (5.0.0) drifted; now all derive from the installed metadata.
    """
    from importlib.metadata import PackageNotFoundError, version

    import iocparser
    from iocparser import _version
    from iocparser.cli_args_parser import VERSION

    expected = version("iocparser-tool")
    assert iocparser.__version__ == expected
    assert expected == VERSION
    assert _version.resolve_version() == expected

    # Running from a source tree with no installed distribution falls back, never crashes.
    def _raise(_name: str) -> str:
        raise PackageNotFoundError(_name)

    monkeypatch.setattr(_version, "version", _raise)
    assert _version.resolve_version() == "0.0.0+unknown"


def test_batch_report_honors_stream_and_keeps_stdout_clean() -> None:
    """Under -o - the batch summary must go to the given stream (stderr), not stdout,
    so it does not corrupt machine output (JSONL/JSON/CSV/STIX) piped to stdout."""
    summary_stream = StringIO()
    stdout_buffer = StringIO()
    with redirect_stdout(stdout_buffer):
        print_batch_report({"total": 2, "successful": 2, "failed": 0}, stream=summary_stream)
    assert "2/2 successful" in summary_stream.getvalue()
    assert stdout_buffer.getvalue() == ""  # nothing leaked to stdout


def test_batch_report_and_partial_url_failures_are_printed(tmp_path: Path) -> None:
    buffer = StringIO()
    with redirect_stdout(buffer):
        print_batch_report(
            {
                "total": 2,
                "successful": 1,
                "failed": 1,
                "failures": {"https://bad.example": "timeout"},
            },
        )
    output = buffer.getvalue()
    assert "1/2 successful" in output
    assert "FAIL" in output
    with redirect_stdout(buffer):
        print_maintenance_result("delete-run", 1)
    assert "affected_runs=1" in buffer.getvalue()
    report_path = tmp_path / "batch.json"
    save_batch_report(
        {
            "total": 1,
            "successful": 1,
            "failed": 0,
            "items": [{"url": "https://ok", "status": "ok"}],
        },
        str(report_path),
        file_writer=_Writer(),
    )
    assert '"status": "ok"' in report_path.read_text(encoding="utf-8")

    url_file = tmp_path / "urls.txt"
    with FlakyLocalHTTPServer() as good_url:
        url_file.write_text(f"{good_url}\nnot-a-url\n", encoding="utf-8")
        args = _args(url_file=str(url_file), url_workers=2)
        normal_iocs, warning_iocs, label, results, report = process_url_file_input_with_report(
            args,
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(retries=1, backoff=0.001),
        )
    assert label == "2 URLs"
    assert "retry" in str(normal_iocs)
    assert warning_iocs == {}
    assert len(results) == 1
    assert report["failed"] == 1
    assert "not-a-url" in report["failures"]
    assert report["items"]
    assert report["run_metadata_map"]
    stdout_report = StringIO()
    with redirect_stdout(stdout_report):
        save_batch_report({"total": 0}, "-", file_writer=_Writer())
    assert '"total": 0' in stdout_report.getvalue()


def test_schema_migration_status_and_retry_failed_batch(tmp_path: Path) -> None:
    db_path = tmp_path / "migration.sqlite"
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE sources (
                id INTEGER PRIMARY KEY,
                kind VARCHAR(16) NOT NULL,
                value TEXT NOT NULL,
                original_url TEXT,
                normalized_url TEXT,
                mime_type VARCHAR(128),
                input_size INTEGER,
                content_hash VARCHAR(128),
                fingerprint VARCHAR(128),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE runs (
                id INTEGER PRIMARY KEY,
                source_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                tool_version VARCHAR(32) NOT NULL,
                options_json TEXT NOT NULL,
                normal_ioc_count INTEGER NOT NULL DEFAULT 0,
                warning_ioc_count INTEGER NOT NULL DEFAULT 0,
                processed_items INTEGER NOT NULL DEFAULT 1,
                successful_items INTEGER NOT NULL DEFAULT 1,
                failed_items INTEGER NOT NULL DEFAULT 0,
                partial_error_count INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE iocs (
                id INTEGER PRIMARY KEY,
                ioc_type VARCHAR(64) NOT NULL,
                value TEXT NOT NULL,
                is_warning BOOLEAN NOT NULL,
                warning_list TEXT NOT NULL DEFAULT '',
                warning_description TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE run_iocs (
                id INTEGER PRIMARY KEY,
                run_id INTEGER NOT NULL,
                ioc_id INTEGER NOT NULL,
                severity VARCHAR(32) NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                evidence_json TEXT NOT NULL DEFAULT '[]'
            );
            """
        )
        connection.commit()
    finally:
        connection.close()

    db_uri = f"sqlite:///{db_path}"
    persist_results(
        PersistResultsRequest(
            config=load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None),
            source_kind="url",
            source_value="https://failed.example/report",
            normal_iocs={},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={
                "status": "failed",
                "error_message": "timeout",
                "processed_items": 1,
                "successful_items": 0,
                "failed_items": 1,
                "partial_error_count": 1,
            },
        )
    )
    runs = query_persisted_runs(db_uri=db_uri, limit=10)
    assert runs.items[0].status == "failed"
    assert runs.items[0].error_message == "timeout"

    migrated = sqlite3.connect(db_path)
    try:
        columns = {row[1] for row in migrated.execute("PRAGMA table_info(runs)")}
        assert {"status", "error_message"}.issubset(columns)
        versions = list(migrated.execute("SELECT version FROM schema_migrations"))
        assert versions[-1][0] >= 2
    finally:
        migrated.close()

    versioned_db = tmp_path / "versioned.sqlite"
    versioned = sqlite3.connect(versioned_db)
    try:
        versioned.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        versioned.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (1, '2026-01-01T00:00:00+00:00')"
        )
        versioned.executescript(
            """
            CREATE TABLE runs (
                id INTEGER PRIMARY KEY,
                source_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                tool_version VARCHAR(32) NOT NULL,
                options_json TEXT NOT NULL,
                normal_ioc_count INTEGER NOT NULL DEFAULT 0,
                warning_ioc_count INTEGER NOT NULL DEFAULT 0,
                processed_items INTEGER NOT NULL DEFAULT 1,
                successful_items INTEGER NOT NULL DEFAULT 1,
                failed_items INTEGER NOT NULL DEFAULT 0,
                partial_error_count INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE sources (
                id INTEGER PRIMARY KEY,
                kind VARCHAR(16) NOT NULL,
                value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            """
        )
        versioned.commit()
    finally:
        versioned.close()

    versioned_uow = SQLAlchemyUnitOfWork(f"sqlite:///{versioned_db}")
    versioned_uow.close()
    versioned_check = sqlite3.connect(versioned_db)
    try:
        columns = {row[1] for row in versioned_check.execute("PRAGMA table_info(runs)")}
        assert {"status", "error_message"}.issubset(columns)
    finally:
        versioned_check.close()

    current_db = tmp_path / "current.sqlite"
    current_uow = SQLAlchemyUnitOfWork(f"sqlite:///{current_db}")
    current_uow.close()
    current_migration_uow = SQLAlchemyUnitOfWork(f"sqlite:///{current_db}")
    try:
        migrations.migrate_engine(current_migration_uow.engine)
    finally:
        current_migration_uow.close()

    partial_db = tmp_path / "partial.sqlite"
    partial = sqlite3.connect(partial_db)
    try:
        partial.execute("CREATE TABLE demo (id INTEGER PRIMARY KEY)")
        partial.commit()
    finally:
        partial.close()
    partial_migration_uow = SQLAlchemyUnitOfWork(f"sqlite:///{partial_db}")
    try:
        migrations.migrate_engine(partial_migration_uow.engine)
    finally:
        partial_migration_uow.close()

    upgrade_uow = SQLAlchemyUnitOfWork(f"sqlite:///{current_db}")
    try:
        migrations._upgrade_to_v2(upgrade_uow.engine, migrations.inspect(upgrade_uow.engine))
    finally:
        upgrade_uow.close()

    with FlakyLocalHTTPServer() as url:
        report_path = tmp_path / "batch-report.json"
        report_path.write_text(
            f'{{"items": [{{"url": "{url}", "status": "failed", "error": "HTTP 500"}}]}}',
            encoding="utf-8",
        )
        args = _args(
            retry_failed_from=str(report_path), url_workers=1, url_retries=1, url_backoff=0.001
        )
        normal_iocs, warning_iocs, label, _, report = process_url_file_input_with_report(
            args,
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(retries=1, backoff=0.001),
        )
    assert label == "1 retried URLs"
    assert normal_iocs["urls"] == ["hxxps://retry[.]example/path"]
    assert warning_iocs == {}
    assert report["successful"] == 1

    empty_report = tmp_path / "empty-report.json"
    empty_report.write_text('{"items": []}', encoding="utf-8")
    with pytest.raises(ValidationError, match="No failed URLs found"):
        process_url_file_input_with_report(
            _args(retry_failed_from=str(empty_report)),
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
        )
    invalid_report = tmp_path / "invalid-report.json"
    invalid_report.write_text('["bad"]', encoding="utf-8")
    with pytest.raises(ValidationError, match="Invalid batch report"):
        process_url_file_input_with_report(
            _args(retry_failed_from=str(invalid_report)),
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
        )
    malformed_report = tmp_path / "malformed-report.json"
    malformed_report.write_text("{ invalid json }", encoding="utf-8")
    with pytest.raises(ValidationError, match="Invalid batch report"):
        process_url_file_input_with_report(
            _args(retry_failed_from=str(malformed_report)),
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
        )
    invalid_items_report = tmp_path / "invalid-items-report.json"
    invalid_items_report.write_text('{"items": "bad"}', encoding="utf-8")
    with pytest.raises(ValidationError, match="Invalid batch report items"):
        process_url_file_input_with_report(
            _args(retry_failed_from=str(invalid_items_report)),
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
        )
    with pytest.raises(FileExistenceError):
        process_url_file_input_with_report(
            _args(retry_failed_from=str(tmp_path / "missing-report.json")),
            reader=MagicTextSourceReader(),
            warning_service=None,
            downloader=RequestsURLDownloader(),
        )


def test_delete_and_prune_persisted_runs(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'maint.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "one.txt",
                ExtractionResult.from_grouped_payload({"domains": ["one.example"]}, {}),
            ),
            (
                "file",
                "one.txt",
                ExtractionResult.from_grouped_payload({"domains": ["two.example"]}, {}),
            ),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    assert delete_persisted_run(db_uri=db_uri, run_id=run_ids[0]) is True
    assert delete_persisted_run(db_uri=db_uri, run_id=9999) is False
    deleted = prune_persisted_runs(
        db_uri=db_uri,
        before="2999-01-01T00:00:00",
        keep_latest=0,
        source_kind="file",
        source_value="one.txt",
    )
    assert deleted >= 1


def test_prune_persisted_runs_accepts_string_statuses(tmp_path: Path) -> None:
    """Regression: prune_persisted_runs took statuses as a pre-split tuple, so a bare
    string (which retain_persisted_history/list_batch_jobs accept) reached SQLAlchemy's
    .in_() and raised a cryptic ArgumentError. A string must now parse like its siblings.
    """
    db_uri = f"sqlite:///{tmp_path / 'prune-status.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    service.persist_multiple_runs(
        [("file", "s.txt", ExtractionResult.from_grouped_payload({"domains": ["a.example"]}, {}))],
        tool_version="6.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    # A non-matching status string deletes nothing (and does not crash).
    assert (
        prune_persisted_runs(db_uri=db_uri, before="2999-01-01", statuses="failed,dead-lettered")
        == 0
    )
    # The matching status string deletes the run; a tuple stays accepted for compatibility.
    assert prune_persisted_runs(db_uri=db_uri, before="2999-01-01", statuses=("success",)) == 1


def test_prune_persisted_runs_rejects_invalid_keep_latest_type(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'prune-keep-latest.db'}"

    with pytest.raises(ValidationError, match="Invalid keep_latest"):
        prune_persisted_runs(
            db_uri=db_uri,
            before="2999-01-01T00:00:00",
            keep_latest="bad",  # type: ignore[arg-type]
        )


def test_plugin_registry_and_structured_records(tmp_path: Path) -> None:
    parsed = SQLAlchemyPersistenceService._parse_datetime("2026-01-01T00:00:00")
    assert parsed is not None
    assert "text" in renderer_names()
    assert "misp" in enricher_names()
    assert get_enricher("misp")

    register_renderer("demo", lambda _ctx, _stix: get_renderer("text"))
    assert "demo" in renderer_names()
    assert "Indicators of Compromise" in get_renderer("demo").render(ExtractionResult())

    register_enricher("demo", lambda: get_enricher("misp"))
    assert "demo" in enricher_names()
    assert get_enricher("demo")

    db_uri = f"sqlite:///{tmp_path / 'plugins.sqlite'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "one.txt",
                ExtractionResult.from_grouped_payload({"domains": ["one.example"]}, {}),
            ),
            (
                "file",
                "one.txt",
                ExtractionResult.from_grouped_payload({"domains": ["two.example"]}, {}),
            ),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    summary = service.list_runs(limit=1)[0]
    assert summary.to_record()["run_id"] == run_ids[1]
    hit = service.search_iocs(value="two", limit=1)[0]
    assert hit.to_record()["value"] == "two.example"
    exported = service.export_run(run_id=run_ids[1])
    assert exported.to_record()["summary"]["source_value"] == "one.txt"
    diff = service.diff_runs(left_run_id=run_ids[0], right_run_id=run_ids[1])
    assert diff.to_record()["added_counts"]["domains"] == 1

    register_renderer("demo-renderer", lambda _ctx, _stix: get_renderer("json"))
    rendered, label, fmt = render_result(_args(renderer="demo-renderer"), exported.result)
    assert label == "demo-renderer"
    assert fmt == "demo-renderer"
    assert '"domains"' in rendered

    register_enricher("demo-enricher", lambda: get_enricher("misp"))
    service_pipeline = warning_service_for_args(_args(enricher=["misp", "demo-enricher"]))
    assert isinstance(service_pipeline, CompositeWarningListService)
    assert warning_service_for_args(_args(enricher=["misp"])).__class__.__name__.endswith("Service")

    class _EntryPoints:
        @staticmethod
        def select(*, group: str):
            if group == "iocparser.renderers":
                return [
                    type(
                        "EP",
                        (),
                        {
                            "name": "entry-renderer",
                            "load": staticmethod(lambda: lambda _ctx, _stix: get_renderer("json")),
                        },
                    )()
                ]
            if group == "iocparser.enrichers":
                return [
                    type(
                        "EP",
                        (),
                        {
                            "name": "entry-enricher",
                            "load": staticmethod(lambda: lambda: get_enricher("misp")),
                        },
                    )()
                ]
            return []

    plugins_module._plugin_state["entry_points_loaded"] = False
    original_entry_points = plugins_module.entry_points
    try:
        plugins_module.entry_points = _EntryPoints
        assert "entry-renderer" in plugins_module.renderer_names()
        assert "entry-enricher" in plugins_module.enricher_names()
    finally:
        plugins_module.entry_points = original_entry_points
        plugins_module._plugin_state["entry_points_loaded"] = False


def test_entry_point_discovery_runs_once_under_concurrent_first_use() -> None:
    """Lazy entry-point discovery must run exactly once across parallel first callers.

    Regression: _load_entry_point_plugins did an unlocked check-then-act, so concurrent
    resolvers each ran the full discovery + re-register (re-firing override warnings).
    Double-checked locking now loads once.
    """
    import threading

    import iocparser.plugins as plugins_module

    passes = {"count": 0}
    count_lock = threading.Lock()
    original_loader = plugins_module._load_discovered_entry_points

    def counting_loader(entry_points_obj: object) -> None:
        with count_lock:
            passes["count"] += 1
        original_loader(entry_points_obj)  # type: ignore[arg-type]

    plugins_module._load_discovered_entry_points = counting_loader
    plugins_module._plugin_state["entry_points_loaded"] = False
    barrier = threading.Barrier(12)
    try:

        def worker() -> None:
            barrier.wait()
            plugins_module.renderer_names()

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert passes["count"] == 1
    finally:
        plugins_module._load_discovered_entry_points = original_loader
        plugins_module._plugin_state["entry_points_loaded"] = False


def test_ioc_type_plugin_lookup_loads_entry_points() -> None:
    import iocparser.plugins as plugins_module

    class _EntryPoints:
        @staticmethod
        def select(*, group: str):
            if group == "iocparser.ioc_types":
                return [
                    type(
                        "EP",
                        (),
                        {
                            "name": "entry-ioc-type",
                            "load": staticmethod(
                                lambda: (
                                    lambda: {
                                        "name": "entry_ioc_type",
                                        "base_type": "urls",
                                    }
                                )
                            ),
                        },
                    )()
                ]
            return []

    plugins_module._plugin_state["entry_points_loaded"] = False
    plugins_module._ioc_type_registry.pop("entry-ioc-type", None)
    original_entry_points = plugins_module.entry_points
    try:
        plugins_module.entry_points = _EntryPoints
        definition = plugins_module.get_ioc_type_plugin("entry-ioc-type")
        assert definition["name"] == "entry_ioc_type"
    finally:
        plugins_module.entry_points = original_entry_points
        plugins_module._ioc_type_registry.pop("entry-ioc-type", None)
        plugins_module._plugin_state["entry_points_loaded"] = False


def test_internal_http_mapping_and_static_timeout_helpers() -> None:
    class _Header:
        def __str__(self) -> str:
            return "X-Test: ok"

    assert _parse_http_mapping("", separator=":") == {}
    assert _parse_http_mapping('{"X-Test": "1"}', separator=":") == {"X-Test": "1"}
    assert _parse_http_mapping(["A: one", "B: two"], separator=":") == {"A": "one", "B": "two"}
    assert _parse_http_mapping([": bad", "A: ok"], separator=":") == {"A": "ok"}
    assert _parse_http_mapping(123, separator="=") == {}
    with pytest.raises(ValidationError, match="Invalid HTTP mapping item"):
        _parse_http_mapping([_Header()], separator=":")
    with pytest.raises(ValidationError, match="Invalid HTTP mapping item"):
        _parse_http_mapping("MissingSeparator", separator=":")
    with pytest.raises(ValidationError, match="Invalid HTTP mapping item"):
        _parse_http_mapping(["A: ok", "MissingSeparator"], separator=":")
    with pytest.raises(ValidationError, match="Invalid HTTP mapping JSON"):
        _parse_http_mapping("{bad", separator=":")
    with pytest.raises(ValidationError, match="Invalid HTTP mapping JSON"):
        _parse_http_mapping('["bad"]', separator=":")
    assert RequestsURLDownloader.default_timeout() == 30
    assert RequestsURLDownloader.default_connect_timeout() == 10.0
    assert RequestsURLDownloader.default_read_timeout() == 30.0
    assert mb_to_bytes(1.5) == 1572864
    with pytest.raises(ValidationError, match="Invalid max_input_size_mb"):
        mb_to_bytes(-1)
    # nan/inf are accepted by argparse type=float but slip past `< 0`; they must be
    # rejected as a clean ValidationError, not crash int() with an uncaught traceback.
    for non_finite in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError, match="Invalid max_input_size_mb"):
            mb_to_bytes(non_finite)


def test_persist_failed_batch_items_creates_failed_runs(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'failed-batch.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    persist_failed_batch_items(
        {
            "items": [{"url": "https://bad.example", "status": "failed", "error": "timeout"}],
            "run_metadata_map": {
                "https://bad.example": {
                    "status": "failed",
                    "error_message": "timeout",
                    "processed_items": 1,
                    "successful_items": 0,
                    "failed_items": 1,
                    "partial_error_count": 1,
                },
            },
        },
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    runs = query_persisted_runs(db_uri=db_uri, limit=10)
    assert runs.items[0].status == "failed"
    assert runs.items[0].error_message == "timeout"
    persist_failed_batch_items(
        {"items": ["bad-shape"], "run_metadata_map": {}},
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    persist_failed_batch_items(
        {"items": "bad-shape", "run_metadata_map": {}},
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    persist_failed_batch_items(
        {"items": [{"status": "failed", "error": "missing-url"}], "run_metadata_map": {}},
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    persist_failed_batch_items(
        {"items": [{"url": None, "status": "failed", "error": "bad-url"}], "run_metadata_map": {}},
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    persist_failed_batch_items(
        {"items": [{"url": "https://bad2.example", "status": "failed"}], "run_metadata_map": []},
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    assert "None" not in {item.source_value for item in query_persisted_runs(db_uri=db_uri).items}


def test_persist_failed_batch_items_rejects_non_string_error_messages(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'failed-batch-error.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)

    with pytest.raises(TypeError, match="Expected error to be string"):
        persist_failed_batch_items(
            {"items": [{"url": "https://bad.example", "status": "failed", "error": object()}]},
            config=config,
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
        )


def test_persist_failed_batch_items_defaults_invalid_duration_metadata(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'failed-batch-invalid-duration.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    persist_failed_batch_items(
        {
            "items": [
                {
                    "url": "https://bad-duration.example",
                    "status": "failed",
                    "error": "",
                    "duration_ms": True,
                }
            ],
            "run_metadata_map": {
                "https://bad-duration.example": {
                    "duration_ms": "bad",
                    "error_message": " timeout ",
                }
            },
        },
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    runs = query_persisted_runs(db_uri=db_uri, limit=10)
    assert runs.items[0].duration_ms == 0
    assert runs.items[0].error_message == "timeout"


def test_persist_batch_job_skips_non_string_failed_item_urls(tmp_path: Path) -> None:
    from iocparser.infrastructure.persistence.history import list_failed_batch_items

    db_uri = f"sqlite:///{tmp_path / 'batch-job-bad-url.sqlite'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    batch_job_id = persist_batch_job(
        {
            "total": 1,
            "successful": 0,
            "failed": 1,
            "items": [{"url": None, "status": "failed", "error": "timeout"}],
        },
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )

    assert batch_job_id is not None
    assert list_failed_batch_items(db_uri, batch_job_id=batch_job_id) == []


def test_cli_dispatch_workflow_persists_failed_batch_items(tmp_path: Path) -> None:
    from iocparser import cli_dispatch_workflow as workflow
    from iocparser.infrastructure.persistence.history import (
        list_failed_batch_items,
        list_failed_batches,
    )

    db_uri = f"sqlite:///{tmp_path / 'dispatch-failed-batches.db'}"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    args = _args(retry_failed_from=str(tmp_path / "retry-report.json"), persist=True)
    options = PersistOptions(
        defang=False, check_warnings=False, force_update=False, output_format="json"
    )
    results = {
        "https://ok.example": (
            {"urls": ["hxxps://ok[.]example"]},
            {},
        ),
    }
    batch_report = {
        "total": 2,
        "successful": 1,
        "failed": 1,
        "items": [
            {"url": "https://bad.example", "status": "failed", "error": "timeout"},
        ],
        "run_metadata_map": {
            "https://bad.example": {
                "status": "failed",
                "error_message": "timeout",
                "processed_items": 1,
                "successful_items": 0,
                "failed_items": 1,
                "partial_error_count": 1,
            },
        },
        "source_metadata_map": {
            "https://ok.example": {"input_value": "https://ok.example"},
            "https://bad.example": {"input_value": "https://bad.example"},
        },
        "phase_timings_ms": {},
    }

    workflow.persist_batch_results(args, config, options, results, batch_report)

    jobs = list_failed_batches(db_uri, limit=10)
    assert len(jobs) == 1
    failed_items = list_failed_batch_items(db_uri, batch_job_id=jobs[0].batch_job_id)
    assert len(failed_items) == 1
    assert failed_items[0].source_value == "https://bad.example"
    assert failed_items[0].error_message == "timeout"
    service = SQLAlchemyPersistenceService(db_uri)
    runs = service.list_runs(limit=10)
    assert {run.source_kind for run in runs} == {"url"}
    assert runs[0].original_url is not None
    assert "persistence" in batch_report["phase_timings_ms"]


def test_cli_dispatch_workflow_keeps_all_failed_url_batches_in_batch_flow(tmp_path: Path) -> None:
    from iocparser import cli_dispatch_workflow as workflow
    from iocparser.infrastructure.persistence.history import (
        list_failed_batch_items,
        list_failed_batches,
    )

    db_uri = f"sqlite:///{tmp_path / 'dispatch-all-failed-batch.db'}"
    report_path = tmp_path / "all-failed-batch-report.json"
    failed_url = "https://failed.example/feed"
    config = load_config(cli_persist=True, cli_db_uri=db_uri, cli_config_path=None)
    args = _args(
        retry_failed_from=str(tmp_path / "retry-report.json"),
        persist=True,
        batch_report_json=str(report_path),
    )

    workflow.finalize_cli_run(
        args,
        config=config,
        workflow_started=time.perf_counter(),
        normal_iocs={},
        warning_iocs={},
        input_display="0 retried URLs",
        results={},
        batch_report={
            "total": 1,
            "successful": 0,
            "failed": 1,
            "items": [{"url": failed_url, "status": "failed", "error": "timeout"}],
            "run_metadata_map": {
                failed_url: {
                    "status": "failed",
                    "error_message": "timeout",
                    "processed_items": 1,
                    "successful_items": 0,
                    "failed_items": 1,
                    "partial_error_count": 1,
                },
            },
            "phase_timings_ms": {},
        },
        save_output=lambda *_args: None,
    )

    jobs = list_failed_batches(db_uri, limit=10)
    assert len(jobs) == 1
    failed_items = list_failed_batch_items(db_uri, batch_job_id=jobs[0].batch_job_id)
    assert len(failed_items) == 1
    assert failed_items[0].source_value == failed_url

    service = SQLAlchemyPersistenceService(db_uri)
    runs = service.list_runs(limit=10)
    assert len(runs) == 1
    assert runs[0].source_kind == "url"
    assert runs[0].source_value == failed_url

    saved_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved_report["failed"] == 1
    assert "persistence" in saved_report["phase_timings_ms"]


def test_batch_report_to_stdout_keeps_summary_off_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--batch-report-json (defaulting to stdout) must not be corrupted by the summary.

    Regression: the summary was routed to stderr only when -o - was set, so a
    batch report written to stdout via --batch-report-json had the human summary
    (display_results + print_batch_report) prepended to it, producing invalid JSON.
    """
    from iocparser import cli_dispatch_workflow as workflow

    config = load_config(cli_persist=False, cli_db_uri=None, cli_config_path=None)
    args = _args(persist=False, batch_report_json="-")

    workflow.finalize_cli_run(
        args,
        config=config,
        workflow_started=time.perf_counter(),
        normal_iocs={"domains": ["evil.com"]},
        warning_iocs={},
        input_display="2 URLs",
        results={},
        batch_report={
            "total": 1,
            "successful": 0,
            "failed": 1,
            "items": [{"url": "https://bad.example", "status": "failed", "error": "timeout"}],
            "run_metadata_map": {},
            "phase_timings_ms": {},
        },
        save_output=lambda *_args: None,
    )

    captured = capsys.readouterr()
    # stdout must be exactly the JSON report — parseable, no summary lines.
    parsed = json.loads(captured.out)
    assert parsed["failed"] == 1
    assert "Batch summary" in captured.err


def test_composite_warning_service_combines_results() -> None:
    from iocparser.infrastructure.warninglists_service import CompositeWarningListService

    class FirstService:
        def separate(self, iocs, *, force_update: bool = False):
            del force_update
            return ExtractionResult(
                iocs=iocs[1:], warnings=(WarningMatch(ioc=iocs[0], warning_list="first"),)
            )

    class SecondService:
        def separate(self, iocs, *, force_update: bool = False):
            del force_update
            return ExtractionResult(
                iocs=(), warnings=(WarningMatch(ioc=iocs[0], warning_list="second"),)
            )

    original = (
        IOC.from_raw("domains", "alpha.example"),
        IOC.from_raw("domains", "beta.example"),
    )
    combined = CompositeWarningListService((FirstService(), SecondService())).separate(original)
    assert combined.iocs == ()
    assert [warning.warning_list for warning in combined.warnings] == ["first", "second"]
