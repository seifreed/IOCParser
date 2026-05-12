from __future__ import annotations

import io
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from iocparser import (
    api_extraction,
    cli_dispatch,
    cli_output,
    cli_processing,
    cli_queries,
    cli_schema,
)
from iocparser.api_persistence import query_persisted_iocs
from iocparser.api_persistence_history import (
    get_batch_job as get_batch_job_api,
)
from iocparser.api_persistence_history import (
    list_batch_jobs as list_batch_jobs_api,
)
from iocparser.api_persistence_history import (
    list_batch_runs as list_batch_runs_api,
)
from iocparser.application.contracts import (
    BatchJobInput,
    DiffPersistedRunsInput,
    ListBatchJobsInput,
    SearchPersistedIOCsInput,
)
from iocparser.application.query_use_cases import (
    diff_persisted_runs,
    get_batch_job,
    list_batch_jobs,
    list_batch_runs,
    search_persisted_iocs,
)
from iocparser.cli_persistence import (
    persist_batch_job,
    persist_failed_batch_items,
    persist_many_results,
)
from iocparser.client import PersistenceClient
from iocparser.config import load_config
from iocparser.domain.jobs import BatchJobDetail
from iocparser.domain.models import (
    IOC,
    ExtractionResult,
    IOCType,
    PersistedRunDiff,
    PersistOptions,
    indicator_value_for,
    ioc_type_name,
)
from iocparser.domain.results import WarningMatch, classify_ioc
from iocparser.errors import ValidationError
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.migration_revisions import rev_0006_search_indexes
from iocparser.infrastructure.persistence import (
    SQLAlchemyPersistenceService,
    SQLAlchemyUnitOfWork,
)
from iocparser.infrastructure.persistence.history import get_batch_job as get_batch_job_history
from iocparser.infrastructure.persistence.history import list_batch_jobs as list_batch_jobs_history
from iocparser.infrastructure.persistence.history import list_batch_runs as list_batch_runs_history
from iocparser.infrastructure.persistence_fts import build_fts_query, has_fts_table, sync_fts_index
from iocparser.plugins import (
    custom_ioc_types,
    get_ioc_type_plugin,
    get_renderer,
    ioc_type_plugin_names,
    postprocessor_names,
    register_custom_ioc_type,
    register_extractor,
    register_ioc_type_plugin,
    register_postprocessor,
    renderer_names,
)


class _Writer:
    def write(self, path: str, content: str) -> None:
        Path(path).write_text(content, encoding="utf-8")


class _HTTPServer:
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
            target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True
        )
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/feed.txt"

    def __exit__(self, exc_type, exc, tb) -> None:
        del exc_type, exc, tb
        assert self.server is not None
        assert self.thread is not None
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class ExtraExtractor:
    def extract(self, text_content: str, *, defang: bool = True) -> ExtractionResult:
        del text_content, defang
        return ExtractionResult(iocs=(IOC.from_raw("domains", "plugin-added.example"),))


class ExtraPostProcessor:
    def process(self, result: ExtractionResult) -> ExtractionResult:
        return ExtractionResult(
            iocs=(*result.iocs, IOC.from_raw("ips", "203.0.113.200")), warnings=result.warnings
        )


def _setup_batch_history(db_uri: str, *, failed_url: str = "https://fail.example") -> int:
    config = load_config(True, db_uri, None)
    run_ids = persist_many_results(
        {"https://ok.example": ({"domains": ["ok.example"]}, {})},
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
        source_kind="url",
        run_metadata_map={"https://ok.example": {"duration_ms": 11, "status": "success"}},
    )
    failed_ids = persist_failed_batch_items(
        {
            "items": [
                {
                    "url": failed_url,
                    "status": "failed",
                    "error": "timeout",
                    "error_type": "IOCTimeoutError",
                    "retry_attempt": 1,
                },
            ],
            "run_metadata_map": {
                failed_url: {"duration_ms": 0, "status": "failed", "failed_items": 1}
            },
        },
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
        source_kind="url",
    )
    batch_job_id = persist_batch_job(
        {
            "total": 2,
            "successful": 1,
            "failed": 1,
            "duration_ms": 12,
            "items": [
                {
                    "url": "https://ok.example",
                    "status": "ok",
                    "duration_ms": 11,
                    "retry_attempt": 0,
                },
                {
                    "url": failed_url,
                    "status": "failed",
                    "error": "timeout",
                    "error_type": "IOCTimeoutError",
                    "retry_attempt": 1,
                },
            ],
            "metrics": {"average_item_duration_ms": 11},
            "phase_timings_ms": {"execution": 12},
        },
        config=config,
        source_kind="url",
        run_ids=run_ids + failed_ids,
        effective_config={"url_workers": 2, "renderer": "json"},
    )
    assert batch_job_id is not None
    return batch_job_id


def test_custom_ioc_types_fts_and_public_batch_api(tmp_path: Path) -> None:
    register_custom_ioc_type(
        "telegram_handles",
        base_type="urls",
        aliases=("telegram",),
        severity="medium",
        tags=("social",),
        stix_pattern="[url:value = '{value}']",
    )
    register_ioc_type_plugin(
        "wallet-tag",
        lambda: {
            "name": "wallet_tags",
            "base_type": "urls",
            "aliases": ("wallet-tag",),
            "tags": ("wallet",),
        },
    )
    plugin_definition = get_ioc_type_plugin("wallet-tag")
    assert plugin_definition["name"] == "wallet_tags"
    assert "wallet-tag" in ioc_type_plugin_names()
    assert "telegram_handles" in custom_ioc_types()
    telegram = IOC.from_raw("telegram", "hxxps://t.me/evil")
    assert telegram.ioc_type.value == "telegram_handles"
    assert "social" in telegram.tags
    assert (
        indicator_value_for(telegram.ioc_type, "hxxps://t.me/evil").canonical()
        == "https://t.me/evil"
    )
    warning_severity, warning_tags = classify_ioc(telegram.ioc_type, is_warning=True)
    assert warning_severity == "informational"
    assert "warning-list-match" in warning_tags
    with pytest.raises(ValueError, match="cannot be empty"):
        register_custom_ioc_type("", base_type="urls")
    with pytest.raises(TypeError):
        register_custom_ioc_type("bad-base", base_type="telegram_handles")
    with pytest.raises(ValueError, match="not-registered"):
        IOCType.from_name("not-registered")
    assert ioc_type_name("raw-string") == "raw-string"

    stix = get_renderer("stix")
    rendered = stix.render(
        ExtractionResult(
            iocs=(telegram,), warnings=(WarningMatch(ioc=telegram, warning_list="demo"),)
        )
    )
    assert "telegram_handles indicator" in rendered
    register_custom_ioc_type("domain_alias", base_type="domains")
    rendered_domain = stix.render(
        ExtractionResult(iocs=(IOC.from_raw("domain_alias", "evil.example"),), warnings=())
    )
    assert "domain-name:value" in rendered_domain

    db_uri = f"sqlite:///{tmp_path / 'fts.sqlite'}"
    batch_job_id = _setup_batch_history(db_uri)
    api_extraction.extract_result_from_text("noise")  # warm import paths
    service = SQLAlchemyPersistenceService(db_uri)
    page = query_persisted_iocs(db_uri=db_uri, value="ok", search_backend="fts")
    assert page.total >= 1
    uow = SQLAlchemyUnitOfWork(db_uri)
    try:
        assert has_fts_table(uow.engine) is True
        sync_fts_index(uow.session)
    finally:
        uow.close()
    assert build_fts_query("ok example") == 'NEAR("ok" "example", 0)'
    with pytest.raises(ValueError, match="alphanumeric term"):
        service.search_iocs_page(value="!!!", search_backend="fts")
    assert service.search_iocs_page(value="ok", search_backend="like").total >= 1
    empty_uow = SQLAlchemyUnitOfWork(f"sqlite:///{tmp_path / 'nofts.sqlite'}")
    try:
        sync_fts_index(empty_uow.session)
    finally:
        empty_uow.close()

    jobs = list_batch_jobs_api(db_uri=db_uri, limit=5)
    detail = get_batch_job_api(db_uri=db_uri, batch_job_id=batch_job_id)
    runs = list_batch_runs_api(db_uri=db_uri, batch_job_id=batch_job_id)
    assert jobs
    assert detail is not None
    assert runs
    assert detail.to_record()["effective_config"]["renderer"] == "json"
    assert list_batch_jobs(ListBatchJobsInput(limit=5), persistence_query_service=service)
    assert (
        get_batch_job(BatchJobInput(batch_job_id=batch_job_id), persistence_query_service=service)
        is not None
    )
    assert list_batch_runs(
        BatchJobInput(batch_job_id=batch_job_id), persistence_query_service=service
    )
    assert list_batch_jobs_history(db_uri, limit=5)
    assert get_batch_job_history(db_uri, batch_job_id=batch_job_id) is not None
    assert list_batch_runs_history(db_uri, batch_job_id=batch_job_id)
    client = PersistenceClient(db_uri)
    assert client.list_batch_jobs(limit=5)
    assert client.get_batch_job(batch_job_id=batch_job_id) is not None
    assert client.list_batch_runs(batch_job_id=batch_job_id)
    assert list_batch_jobs_history(db_uri, limit=5, statuses=("partial",))
    assert get_batch_job_history(db_uri, batch_job_id=999999) is None


def test_cli_plugin_paths_and_batch_queries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    register_extractor("extra-cli", ExtraExtractor)
    register_postprocessor("extra-post", ExtraPostProcessor)
    file_path = tmp_path / "sample.txt"
    file_path.write_text("Visit hxxps://evil.example and 198.51.100.10", encoding="utf-8")
    common = {
        "type": None,
        "no_defang": False,
        "no_check_warnings": True,
        "force_update": False,
        "only": None,
        "exclude": None,
        "streaming": False,
        "chunk_size": 1024,
        "overlap": 8,
        "extractor": ["extra-cli"],
        "postprocessor": ["extra-post"],
        "enricher": None,
    }
    original_stdin = cli_processing.sys.stdin
    try:
        cli_processing.sys.stdin = io.StringIO("Text input with hxxps://stdin.example")
        stdin_args = SimpleNamespace(stdin=True, file=None, url=None, url_direct=None, **common)
        normal_iocs, _, _ = cli_processing.process_single_input(
            stdin_args,
            reader=api_extraction._reader,
            warning_service=None,
            downloader=RequestsURLDownloader(),
            process_file_func=cli_processing.process_file,
        )
        assert "plugin-added.example" in normal_iocs["domains"]
    finally:
        cli_processing.sys.stdin = original_stdin

    file_args = SimpleNamespace(
        stdin=False, file=str(file_path), url=None, url_direct=None, **common
    )
    normal_iocs, _, _ = cli_processing.process_single_input(
        file_args,
        reader=api_extraction._reader,
        warning_service=None,
        downloader=RequestsURLDownloader(),
        process_file_func=cli_processing.process_file,
    )
    assert "203.0.113.200" in normal_iocs["ips"]

    multiple_args = SimpleNamespace(multiple=[str(file_path)], parallel=1, **common)
    merged_normal, _, _, _ = cli_processing.process_multiple_files_input(
        multiple_args, reader=api_extraction._reader, warning_service=None
    )
    assert "plugin-added.example" in merged_normal["domains"]

    with _HTTPServer(b"Remote hxxps://remote.example") as url:
        url_args = SimpleNamespace(stdin=False, file=None, url=url, url_direct=None, **common)
        normal_iocs, _, _ = cli_processing.process_single_input(
            url_args,
            reader=api_extraction._reader,
            warning_service=None,
            downloader=RequestsURLDownloader(),
            process_file_func=cli_processing.process_file,
        )
        assert "plugin-added.example" in normal_iocs["domains"]
    with pytest.raises(ValidationError, match="configured persistence"):
        cli_processing.process_url_file_input_with_report(
            SimpleNamespace(
                url_file=None,
                retry_failed_from=None,
                retry_batch_job=123,
                retry_error_type=None,
                retry_error_contains=None,
                url_workers=1,
                no_defang=False,
                no_check_warnings=True,
                force_update=False,
                only=None,
                exclude=None,
                extractor=None,
                postprocessor=None,
                enricher=None,
            ),
            reader=api_extraction._reader,
            warning_service=None,
            downloader=RequestsURLDownloader(),
            db_uri=None,
        )

    with _HTTPServer(b"Batch hxxps://batch.example") as url:
        db_uri = f"sqlite:///{tmp_path / 'batch-queries.sqlite'}"
        batch_job_id = _setup_batch_history(db_uri, failed_url=url)
        args = SimpleNamespace(
            url_file=None,
            retry_failed_from=None,
            retry_batch_job=batch_job_id,
            retry_error_type="IOCTimeoutError",
            retry_error_contains="time",
            url_workers=1,
            no_defang=False,
            no_check_warnings=True,
            force_update=False,
            only=None,
            exclude=None,
            extractor=["extra-cli"],
            postprocessor=["extra-post"],
            enricher=None,
        )
        report_path = tmp_path / "urls.txt"
        report_path.write_text(url + "\n", encoding="utf-8")
        args.url_file = str(report_path)
        normal_iocs, _, input_display, _, report = (
            cli_processing.process_url_file_input_with_report(
                args,
                reader=api_extraction._reader,
                warning_service=None,
                downloader=RequestsURLDownloader(),
                db_uri=db_uri,
            )
        )
        assert input_display.startswith(("0 retried batch", "1 retried batch"))
        assert "metrics" in report
        assert "phase_timings_ms" in report
        with pytest.raises(ValidationError, match="No failed URLs found"):
            cli_processing._failed_urls_from_batch(
                db_uri, batch_job_id=batch_job_id, error_type_filter="Other"
            )

    list_plugins_args = SimpleNamespace(init=False, force_update=False, list_plugins=True)
    cli_dispatch.run_cli(
        list_plugins_args,
        handle_misp_init=lambda: None,
        process_multiple_files_input=lambda _args: None,
        process_single_input=lambda _args: ({}, {}, "stdin"),
        save_output=lambda *_args, **_kwargs: None,
    )
    assert "extra-cli" in capsys.readouterr().out

    query_args = SimpleNamespace(
        list_runs=True,
        list_batches=True,
        batch_limit=10,
        prune_status=None,
        json=True,
        batch_job=None,
        batch_runs=None,
        search_ioc=None,
        diff_runs=None,
        diff_latest=None,
        export_run=None,
        delete_run=None,
        prune_before=None,
        keep_latest=0,
        severity=None,
        tag=None,
        exclude_tag=None,
        min_severity=None,
        tag_mode="all",
        query_limit=10,
        offset=0,
        date_from=None,
        date_to=None,
        source_kind=None,
        source_value=None,
        query_sort="newest",
        ioc_type=None,
        diff_only="all",
        diff_warnings_only=False,
        only_warnings=False,
        only_normal=False,
        max_evidence=None,
        sort_by="type",
        output=None,
        stix=False,
        jsonl=False,
        csv=False,
        renderer=None,
        with_context=False,
        stix_types=None,
        search_backend="fts",
    )
    config = load_config(True, db_uri, None)
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    payload = json.loads(capsys.readouterr().out)
    assert payload["items"]
    query_args.json = False
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert "run_id" in capsys.readouterr().out

    query_args.list_runs = False
    query_args.list_batches = True
    query_args.json = True
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert json.loads(capsys.readouterr().out)["items"]
    query_args.json = False
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert "batch_job_id" in capsys.readouterr().out

    query_args.list_batches = False
    query_args.batch_job = batch_job_id
    query_args.json = False
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert "source_kind" in capsys.readouterr().out
    query_args.json = True
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert json.loads(capsys.readouterr().out)["batch_job_id"] == batch_job_id

    query_args.batch_job = None
    query_args.batch_runs = batch_job_id
    query_args.json = False
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert "run_id" in capsys.readouterr().out
    query_args.json = True
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert json.loads(capsys.readouterr().out)["items"]

    query_args.batch_runs = None
    query_args.search_ioc = "ok"
    query_args.json = True
    assert cli_queries.handle_query_commands(query_args, config, file_writer=_Writer()) is True
    assert json.loads(capsys.readouterr().out)["items"]
    query_args.batch_job = 999999
    query_args.search_ioc = None
    with pytest.raises(ValidationError, match="Batch job not found"):
        cli_queries.handle_query_commands(query_args, config, file_writer=_Writer())

    schema_args = SimpleNamespace(
        schema_version=False,
        migrate=False,
        validate_schema=False,
        compact_history=False,
        retain_days=None,
        prune_status=None,
        list_failed_batches=True,
        batch_limit=10,
        export_history=None,
        archive_history=None,
        import_history=None,
        restore_history=None,
        json=True,
    )
    assert cli_schema.handle_schema_commands(schema_args, config, file_writer=_Writer()) is True
    assert json.loads(capsys.readouterr().out)["items"]

    cli_output.print_batch_report(
        {
            "total": 1,
            "successful": 1,
            "failed": 0,
            "phase_timings_ms": {"persist": 5},
            "metrics": {"throughput": 1},
        }
    )
    cli_output.print_batch_job_detail(
        BatchJobDetail(
            batch_job_id=batch_job_id,
            source_kind="url",
            status="partial",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            total_inputs=2,
            successful_inputs=1,
            failed_inputs=1,
            retry_attempt=1,
            error_summary={"IOCTimeoutError": 1},
            effective_config={"url_workers": 1},
            metrics={"duration_ms": 10},
            failed_item_count=1,
        ),
    )
    output = capsys.readouterr().out
    assert "Phase timings (ms)" in output
    assert 'metrics\t{"duration_ms": 10}' in output

    blank_engine = create_engine(f"sqlite:///{tmp_path / 'blank-no-fts.sqlite'}", future=True)
    try:
        with Session(blank_engine) as blank_session:
            sync_fts_index(blank_session)
    finally:
        blank_engine.dispose()


def test_search_index_revision_is_noop_without_known_tables(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.sqlite'}", future=True)
    try:
        rev_0006_search_indexes.apply(engine, inspect(engine))
    finally:
        engine.dispose()


def test_plugin_entry_points_and_query_filter_edges() -> None:
    register_ioc_type_plugin("entry-wallet", lambda: {"name": "entry_wallet", "base_type": "urls"})
    assert "entry-wallet" in ioc_type_plugin_names()
    if "entry_wallet" not in custom_ioc_types():
        register_custom_ioc_type("entry_wallet", base_type="urls")
    assert "entry_wallet" in custom_ioc_types()
    assert "text" in renderer_names()
    assert isinstance(postprocessor_names(), tuple)

    class SearchService:
        def search_iocs(self, **kwargs):
            assert kwargs["search_backend"] == "fts"
            return []

    assert (
        search_persisted_iocs(
            SearchPersistedIOCsInput(value="ok", search_backend="fts"),
            persistence_query_service=SearchService(),
        )
        == []
    )

    diff = PersistedRunDiff(
        left_run_id=1,
        right_run_id=2,
        added=ExtractionResult(iocs=(IOC.from_raw("domains", "evil.example"),)),
        removed=ExtractionResult(iocs=(IOC.from_raw("ips", "203.0.113.5"),)),
    )

    class DiffService:
        def diff_runs(self, *, left_run_id: int, right_run_id: int):
            assert left_run_id == 1
            assert right_run_id == 2
            return diff

    added_only = diff_persisted_runs(
        DiffPersistedRunsInput(
            left_run_id=1, right_run_id=2, ioc_types=("domains",), only_added=True
        ),
        persistence_query_service=DiffService(),
    )
    removed_only = diff_persisted_runs(
        DiffPersistedRunsInput(left_run_id=1, right_run_id=2, only_removed=True),
        persistence_query_service=DiffService(),
    )
    assert added_only.removed.total_count() == 0
    assert removed_only.added.total_count() == 0
