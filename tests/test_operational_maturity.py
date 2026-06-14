from __future__ import annotations

import json
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from iocparser.api_persistence import (
    compact_persisted_history,
    diff_persisted_runs,
    export_persisted_history,
    export_structured_persisted_diff,
    import_persisted_history,
    list_distributed_jobs,
    list_failed_batch_jobs,
    query_persisted_iocs,
    query_persisted_runs,
    render_persisted_diff,
    render_persisted_run,
    retain_persisted_history,
)
from iocparser.application.contracts import PersistRunInput
from iocparser.application.use_cases import persist_run
from iocparser.cli_output import (
    PersistResultsRequest,
    persist_results,
    print_batch_report,
    print_failed_batch_jobs,
    print_text_lines,
    save_batch_report,
)
from iocparser.cli_persistence import (
    persist_batch_job,
    persist_failed_batch_items,
    persist_many_results,
)
from iocparser.cli_processing import _failed_urls_from_report, _retry_attempt_for_url
from iocparser.cli_processing_urls import (
    build_batch_report,
    public_batch_report,
    retry_attempt_for_url,
)
from iocparser.cli_schema import handle_schema_commands, print_schema_revisions
from iocparser.client import IOCParserClient, PersistenceClient, _options
from iocparser.client_extraction import (
    ClientExtractionAdapters,
    ClientExtractionRequest,
    ClientPluginSettings,
    merge_extraction_results,
)
from iocparser.client_extraction import extract_url_result as extract_result_from_url
from iocparser.config import load_config
from iocparser.domain.jobs import (
    BatchDashboard,
    BatchDashboardWindow,
    BatchJobSummary,
    FailedBatchItem,
)
from iocparser.domain.models import (
    IOC,
    ExtractionResult,
    PersistedRunQueryHit,
    PersistOptions,
    PipelineErrorInfo,
    PipelineJobRequest,
    QueueEnvelope,
    Source,
)
from iocparser.domain.results import WarningMatch
from iocparser.errors import ValidationError
from iocparser.infrastructure.persistence import (
    SQLAlchemyPersistenceService,
    SQLAlchemyUnitOfWork,
)
from iocparser.infrastructure.persistence.history import (
    archive_history,
    list_failed_batch_items,
    restore_history,
)
from iocparser.infrastructure.persistence.history import (
    import_history as import_history_raw,
)
from iocparser.infrastructure.persistence_batch import (
    list_failed_batch_jobs as list_failed_batch_jobs_with_session,
)
from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService
from iocparser.infrastructure.persistence_migrations import (
    CURRENT_SCHEMA_VERSION,
    _has_column,
    migrate_db_uri,
    revision_history,
    schema_version,
    validate_schema,
)
from iocparser.infrastructure.persistence_schema import RunIOCModel, RunModel
from iocparser.infrastructure.persistence_support import matches_advanced_filters
from iocparser.plugins import (
    extractor_names,
    get_extractor,
    get_postprocessor,
    postprocessor_names,
    register_extractor,
    register_postprocessor,
)
from tests.http_server_helpers import LocalHTTPFileServer


class _Writer:
    def write(self, path: str, content: str) -> None:
        Path(path).write_text(content, encoding="utf-8")


class DemoExtractor:
    def extract(self, text_content: str, *, defang: bool = True) -> ExtractionResult:
        del text_content, defang
        return ExtractionResult(iocs=(IOC.from_raw("domains", "plugin.example"),))


class DemoPostProcessor:
    def process(self, result: ExtractionResult) -> ExtractionResult:
        return ExtractionResult(
            iocs=(*result.iocs, IOC.from_raw("ips", "203.0.113.55")), warnings=result.warnings
        )


def _persist_result(
    db_uri: str,
    *,
    source_value: str,
    ioc_value: str,
    severity: str = "medium",
    tags: tuple[str, ...] = (),
    status: str = "success",
) -> int:
    unit_of_work = SQLAlchemyUnitOfWork(db_uri)
    try:
        persisted = persist_run(
            PersistRunInput(
                source=Source.from_raw("file", source_value),
                result=ExtractionResult(
                    iocs=(IOC.from_raw("domains", ioc_value, severity=severity, tags=tags),)
                ),
                tool_version="5.0.0",
                options=PersistOptions(
                    defang=False, check_warnings=False, force_update=False, output_format="json"
                ),
                status=status,
                failed_items=1 if status == "failed" else 0,
                successful_items=0 if status == "failed" else 1,
                partial_error_count=1 if status == "partial" else 0,
            ),
            unit_of_work=unit_of_work,
        )
        return persisted.run_id
    except Exception:
        unit_of_work.rollback()
        raise
    finally:
        unit_of_work.close()


def test_search_page_uses_sql_side_filters_and_indexes(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'search.sqlite'}"
    _persist_result(
        db_uri,
        source_value="Report-A.txt",
        ioc_value="Alpha.example",
        severity="high",
        tags=("phishing",),
    )
    _persist_result(
        db_uri, source_value="Other.txt", ioc_value="Beta.example", severity="low", tags=("benign",)
    )

    page = query_persisted_iocs(
        db_uri=db_uri,
        value="alpha",
        source_value="Report-A.txt",
        tag="phishing",
        min_severity="medium",
        limit=10,
        offset=0,
    )
    assert page.total == 1
    assert page.items[0].value == "Alpha.example"

    connection = sqlite3.connect(tmp_path / "search.sqlite")
    source_indexes = {
        row[1] for row in connection.execute("PRAGMA index_list('sources')").fetchall()
    }
    ioc_indexes = {row[1] for row in connection.execute("PRAGMA index_list('iocs')").fetchall()}
    run_ioc_indexes = {
        row[1] for row in connection.execute("PRAGMA index_list('run_iocs')").fetchall()
    }
    assert "ix_sources_kind_value_search" in source_indexes
    assert "ix_iocs_type_value_search" in ioc_indexes
    assert "ix_run_iocs_tags_search" in run_ioc_indexes


def test_persisted_ioc_search_matches_refanged_values(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'refanged-search.sqlite'}"
    unit_of_work = SQLAlchemyUnitOfWork(db_uri)
    try:
        persist_run(
            PersistRunInput(
                source=Source.from_raw("file", "defanged.txt"),
                result=ExtractionResult(iocs=(IOC.from_raw("urls", "hxxps://Example[.]COM/a"),)),
                tool_version="5.0.0",
                options=PersistOptions(
                    defang=False,
                    check_warnings=False,
                    force_update=False,
                    output_format="json",
                ),
            ),
            unit_of_work=unit_of_work,
        )
    finally:
        unit_of_work.close()

    page = query_persisted_iocs(
        db_uri=db_uri,
        value="https://example.com/a",
        search_backend="like",
    )

    assert page.total == 1
    assert page.items[0].value == "hxxps://Example[.]COM/a"


def test_search_page_applies_multiple_exclude_tags(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'exclude-tags.sqlite'}"
    _persist_result(db_uri, source_value="one.txt", ioc_value="one.example", tags=("phishing",))
    _persist_result(db_uri, source_value="two.txt", ioc_value="two.example", tags=("malware",))
    _persist_result(db_uri, source_value="three.txt", ioc_value="three.example", tags=("benign",))

    page = query_persisted_iocs(
        db_uri=db_uri,
        value=".example",
        exclude_tag="phishing,malware",
        limit=10,
        offset=0,
    )

    assert page.total == 1
    assert page.items[0].value == "three.example"


def test_public_query_api_validates_dates_and_min_severity(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'query-validation.sqlite'}"
    first_run_id = _persist_result(
        db_uri, source_value="sample.txt", ioc_value="alpha.example", severity="high"
    )
    second_run_id = _persist_result(
        db_uri, source_value="sample.txt", ioc_value="beta.example", severity="high"
    )

    with pytest.raises(ValidationError, match="Invalid ISO date"):
        query_persisted_runs(db_uri=db_uri, limit=10, offset=0, date_from="not-a-date")

    with pytest.raises(ValidationError, match="Invalid ISO date"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", date_to="still-not-a-date")

    with pytest.raises(ValidationError, match="Invalid min_severity"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", min_severity="critical")

    with pytest.raises(ValidationError, match="Invalid tag_mode"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", tag_mode="bogus")

    with pytest.raises(ValidationError, match="Invalid sort_by"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", sort_by="bogus")

    with pytest.raises(ValidationError, match="Invalid sort_by"):
        query_persisted_runs(db_uri=db_uri, limit=10, sort_by="bogus")

    with pytest.raises(ValidationError, match="Invalid search_backend"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", search_backend="bogus")

    with pytest.raises(ValidationError, match="Invalid diff_only"):
        diff_persisted_runs(
            db_uri=db_uri,
            left_run_id=first_run_id,
            right_run_id=second_run_id,
            diff_only="bogus",
        )

    with pytest.raises(ValidationError, match="Invalid diff_only"):
        render_persisted_diff(
            db_uri=db_uri,
            left_run_id=first_run_id,
            right_run_id=second_run_id,
            diff_only="bogus",
        )

    with pytest.raises(ValidationError, match="Invalid diff_only"):
        export_structured_persisted_diff(
            db_uri=db_uri,
            run_id=second_run_id,
            diff_only="bogus",
        )

    with pytest.raises(ValidationError, match="Invalid FTS query"):
        query_persisted_iocs(db_uri=db_uri, value="!!!", search_backend="fts")

    with pytest.raises(ValidationError, match="Invalid search value"):
        query_persisted_iocs(db_uri=db_uri, value="   ", search_backend="like")

    with pytest.raises(ValidationError, match="Invalid severity"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", severity="HIGH,critical")

    with pytest.raises(ValidationError, match="Invalid severity"):
        render_persisted_run(db_uri=db_uri, run_id=first_run_id, severity="critical")

    with pytest.raises(ValidationError, match="Invalid severity"):
        diff_persisted_runs(
            db_uri=db_uri,
            left_run_id=first_run_id,
            right_run_id=second_run_id,
            severity="critical",
        )

    with pytest.raises(ValidationError, match="Invalid ioc_type"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", ioc_type="bogus")

    with pytest.raises(ValidationError, match="Invalid ioc_type"):
        diff_persisted_runs(
            db_uri=db_uri,
            left_run_id=first_run_id,
            right_run_id=second_run_id,
            ioc_type="bogus",
        )

    with pytest.raises(ValidationError, match="Invalid limit"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", limit=-1)

    with pytest.raises(ValidationError, match="Invalid offset"):
        query_persisted_runs(db_uri=db_uri, offset=-1)

    with pytest.raises(ValidationError, match="Invalid limit"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", limit="abc")

    with pytest.raises(ValidationError, match="Invalid offset"):
        query_persisted_runs(db_uri=db_uri, offset="nan")

    with pytest.raises(ValidationError, match="Invalid limit"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", limit=[])

    with pytest.raises(ValidationError, match="Invalid offset"):
        query_persisted_runs(db_uri=db_uri, offset={})

    with pytest.raises(ValidationError, match="Invalid limit"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", limit=None)

    with pytest.raises(ValidationError, match="Invalid limit"):
        query_persisted_iocs(db_uri=db_uri, value="alpha", limit=True)

    client = PersistenceClient(db_uri)
    with pytest.raises(ValidationError, match="Invalid search_backend"):
        client.search_iocs(value="alpha", search_backend="bogus")

    with pytest.raises(ValidationError, match="Invalid limit"):
        client.search_iocs(value="alpha", limit=True)

    with pytest.raises(ValidationError, match="Invalid sort_by"):
        client.query_runs(sort_by="bogus")

    assert client.query_runs(sort_by=None).total >= 2
    client_search_page = client.search_iocs(
        value="alpha",
        tag_mode=None,
        sort_by=None,
        search_backend=None,
    )
    assert client_search_page.items[0].value == "alpha.example"

    normalized_page = query_persisted_iocs(db_uri=db_uri, value="alpha", severity="HIGH")
    assert normalized_page.total == 1
    alias_page = query_persisted_iocs(db_uri=db_uri, value="alpha", ioc_type="domain")
    assert alias_page.total == 1
    alias_diff = diff_persisted_runs(
        db_uri=db_uri,
        left_run_id=first_run_id,
        right_run_id=second_run_id,
        ioc_type="domain",
    )
    assert alias_diff.added.total_count() == 1
    assert alias_diff.removed.total_count() == 1
    assert client.search_iocs(value="alpha", ioc_type="domain").items[0].value == "alpha.example"


def test_direct_persistence_services_do_not_treat_negative_limits_as_unbounded(
    tmp_path: Path,
) -> None:
    db_uri = f"sqlite:///{tmp_path / 'negative-limit.sqlite'}"
    service = SQLAlchemyPersistenceService(db_uri)
    service.persist_multiple_runs(
        [
            (
                "file",
                "first.txt",
                ExtractionResult(iocs=(IOC.from_raw("domains", "first.example"),)),
            ),
            (
                "file",
                "second.txt",
                ExtractionResult(iocs=(IOC.from_raw("domains", "second.example"),)),
            ),
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    run_page = service.query_runs_page(limit=-1, offset=-10)
    search_page = service.search_iocs_page(value="example", limit=-1, offset=-10)

    assert run_page.total == 2
    assert run_page.items == ()
    assert run_page.limit == 0
    assert run_page.offset == 0
    assert search_page.total == 2
    assert search_page.items == ()
    assert search_page.limit == 0
    assert search_page.offset == 0

    service.persist_batch_job(
        source_kind="url",
        run_ids=(),
        report={
            "total": 1,
            "successful": 0,
            "failed": 1,
            "items": [
                {
                    "status": "failed",
                    "url": "https://failed.example",
                    "error_type": "DownloadError",
                    "error": "failed",
                }
            ],
        },
        config={},
    )
    assert service.list_failed_batches(limit=-1) == []
    assert service.list_batch_jobs(limit=-1) == []

    distributed = SQLAlchemyDistributedJobService(db_uri)
    envelope = QueueEnvelope(
        request=PipelineJobRequest(
            input_kind="text",
            source_value="payload",
            job_id="negative-limit-job",
        ),
        queue_backend="filesystem",
        queue_name="jobs",
    )
    distributed.create_or_get_job(envelope=envelope, receipt_id="receipt-1")
    distributed.mark_dead_lettered(
        job_id="negative-limit-job",
        attempts=1,
        error=PipelineErrorInfo(
            code="VALIDATION_FAILED",
            category="validation",
            retryable=False,
            status="failed",
            message="failed",
        ),
    )

    assert distributed.list_jobs(limit=-1) == []
    assert distributed.list_dead_letters(limit=-1) == []


def test_like_search_treats_percent_and_underscore_as_literals(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'like-literals.sqlite'}"
    _persist_result(db_uri, source_value="first.txt", ioc_value="alpha%beta.example")
    _persist_result(db_uri, source_value="second.txt", ioc_value="alphaxbeta.example")
    _persist_result(db_uri, source_value="third.txt", ioc_value="team_1.example")
    _persist_result(db_uri, source_value="fourth.txt", ioc_value="teama1.example")

    percent_hits = query_persisted_iocs(db_uri=db_uri, value="alpha%beta", search_backend="like")
    underscore_hits = query_persisted_iocs(db_uri=db_uri, value="team_1", search_backend="like")

    assert [hit.value for hit in percent_hits.items] == ["alpha%beta.example"]
    assert [hit.value for hit in underscore_hits.items] == ["team_1.example"]


def test_tag_filters_treat_percent_and_underscore_as_literals(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'tag-like-literals.sqlite'}"
    _persist_result(db_uri, source_value="first.txt", ioc_value="first.example", tags=("tag%prod",))
    _persist_result(
        db_uri, source_value="second.txt", ioc_value="second.example", tags=("tagxprod",)
    )
    _persist_result(db_uri, source_value="third.txt", ioc_value="third.example", tags=("team_1",))
    _persist_result(db_uri, source_value="fourth.txt", ioc_value="fourth.example", tags=("teama1",))

    percent_hits = query_persisted_iocs(db_uri=db_uri, value=".example", tag="tag%prod")
    underscore_hits = query_persisted_iocs(db_uri=db_uri, value=".example", tag="team_1")
    excluded_hits = query_persisted_iocs(db_uri=db_uri, value=".example", exclude_tag="team_1")

    assert [hit.value for hit in percent_hits.items] == ["first.example"]
    assert [hit.value for hit in underscore_hits.items] == ["third.example"]
    assert "third.example" not in [hit.value for hit in excluded_hits.items]
    assert "fourth.example" in [hit.value for hit in excluded_hits.items]


def test_tag_filters_match_whole_tags_not_substrings(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'tag-token-boundaries.sqlite'}"
    _persist_result(db_uri, source_value="exact.txt", ioc_value="exact.example", tags=("network",))
    _persist_result(
        db_uri, source_value="prefix.txt", ioc_value="prefix.example", tags=("networking",)
    )

    tagged_hits = query_persisted_iocs(db_uri=db_uri, value=".example", tag="network")
    excluded_hits = query_persisted_iocs(db_uri=db_uri, value=".example", exclude_tag="network")

    assert [hit.value for hit in tagged_hits.items] == ["exact.example"]
    assert "exact.example" not in [hit.value for hit in excluded_hits.items]
    assert "prefix.example" in [hit.value for hit in excluded_hits.items]


def test_tag_search_backfill_matches_query_format(tmp_path: Path) -> None:
    from sqlalchemy import create_engine, inspect, text

    from iocparser.infrastructure.persistence_migration_steps import upgrade_to_v3

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy-tags.sqlite'}", future=True)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE run_iocs (id INTEGER PRIMARY KEY, run_id INTEGER, ioc_id INTEGER,"
                    " severity TEXT, tags_json TEXT, evidence_json TEXT)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO run_iocs (run_id, ioc_id, severity, tags_json, evidence_json)"
                    " VALUES (1, 1, 'medium', '[\"Foo\", \"bar\"]', '[]')"
                )
            )
        upgrade_to_v3(engine, inspect(engine))
        with engine.connect() as connection:
            tags_search = connection.execute(text("SELECT tags_search FROM run_iocs")).scalar_one()
    finally:
        engine.dispose()

    # The backfill must reproduce the format the runtime writes and the tag query
    # expects: bare, lowercase, single-space-delimited tokens with no JSON punctuation.
    assert '"' not in tags_search
    assert "," not in tags_search
    assert sorted(tags_search.split()) == ["bar", "foo"]


def test_query_pagination_is_stable_when_runs_share_started_at(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'stable-pagination.sqlite'}"
    first_run_id = _persist_result(db_uri, source_value="first.txt", ioc_value="first.example")
    second_run_id = _persist_result(db_uri, source_value="second.txt", ioc_value="second.example")
    third_run_id = _persist_result(db_uri, source_value="third.txt", ioc_value="third.example")

    shared_timestamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    unit_of_work = SQLAlchemyUnitOfWork(db_uri)
    try:
        for run_id in (first_run_id, second_run_id, third_run_id):
            run = unit_of_work.session.get(RunModel, run_id)
            assert run is not None
            run.started_at = shared_timestamp
            run.finished_at = shared_timestamp
        unit_of_work.commit()
    finally:
        unit_of_work.close()

    runs_page_1 = query_persisted_runs(db_uri=db_uri, limit=1, offset=0)
    runs_page_2 = query_persisted_runs(db_uri=db_uri, limit=1, offset=1)
    runs_page_3 = query_persisted_runs(db_uri=db_uri, limit=1, offset=2)
    ioc_page_1 = query_persisted_iocs(db_uri=db_uri, value=".example", limit=1, offset=0)
    ioc_page_2 = query_persisted_iocs(db_uri=db_uri, value=".example", limit=1, offset=1)
    ioc_page_3 = query_persisted_iocs(db_uri=db_uri, value=".example", limit=1, offset=2)

    expected_order = [third_run_id, second_run_id, first_run_id]
    assert [
        runs_page_1.items[0].run_id,
        runs_page_2.items[0].run_id,
        runs_page_3.items[0].run_id,
    ] == expected_order
    assert [
        ioc_page_1.items[0].run_id,
        ioc_page_2.items[0].run_id,
        ioc_page_3.items[0].run_id,
    ] == expected_order


def test_migration_revision_history_and_validation(tmp_path: Path) -> None:
    db_path = tmp_path / "migrate.sqlite"
    version = migrate_db_uri(f"sqlite:///{db_path}")
    assert version == CURRENT_SCHEMA_VERSION
    assert revision_history()[-1].version == CURRENT_SCHEMA_VERSION

    migrated_unit = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    try:
        assert schema_version(migrated_unit.engine) == CURRENT_SCHEMA_VERSION
        assert validate_schema(migrated_unit.engine) == []
    finally:
        migrated_unit.close()
    blank_db = tmp_path / "blank.sqlite"
    blank_db.touch()
    from sqlalchemy import create_engine

    blank_engine = create_engine(f"sqlite:///{blank_db}", future=True)
    try:
        assert schema_version(blank_engine) == 0
        assert any("schema version drift" in problem for problem in validate_schema(blank_engine))
    finally:
        blank_engine.dispose()
    partial_db = tmp_path / "partial-schema.sqlite"
    partial = sqlite3.connect(partial_db)
    partial.execute(
        "CREATE TABLE runs (id INTEGER PRIMARY KEY, source_id INTEGER, started_at TEXT, finished_at TEXT, tool_version TEXT, options_json TEXT, status TEXT, error_message TEXT)"
    )
    partial.commit()
    partial.close()
    assert migrate_db_uri(f"sqlite:///{partial_db}") == CURRENT_SCHEMA_VERSION
    broken_db = tmp_path / "broken.sqlite"
    broken = sqlite3.connect(broken_db)
    broken.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    broken.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (4, 'now')")
    broken.execute(
        "CREATE TABLE runs (id INTEGER PRIMARY KEY, source_id INTEGER, started_at TEXT, finished_at TEXT, tool_version TEXT, options_json TEXT, status TEXT, error_message TEXT)"
    )
    broken.execute(
        "CREATE TABLE sources (id INTEGER PRIMARY KEY, kind TEXT, value TEXT, value_search TEXT, first_seen TEXT, last_seen TEXT)"
    )
    broken.execute(
        "CREATE TABLE iocs (id INTEGER PRIMARY KEY, ioc_type TEXT, value TEXT, value_search TEXT, is_warning INTEGER, warning_list TEXT, warning_description TEXT)"
    )
    broken.execute(
        "CREATE TABLE run_iocs (id INTEGER PRIMARY KEY, run_id INTEGER, ioc_id INTEGER, severity TEXT, tags_json TEXT, evidence_json TEXT)"
    )
    broken.execute(
        "CREATE TABLE batch_jobs (id INTEGER PRIMARY KEY, source_kind TEXT, started_at TEXT, finished_at TEXT, total_inputs INTEGER, successful_inputs INTEGER, failed_inputs INTEGER, retry_attempt INTEGER, status TEXT, config_json TEXT, error_summary_json TEXT)"
    )
    broken.execute(
        "CREATE TABLE failed_batch_items (id INTEGER PRIMARY KEY, batch_job_id INTEGER, source_value TEXT, error_type TEXT, error_message TEXT, retry_attempt INTEGER, created_at TEXT)"
    )
    broken.commit()
    broken.close()
    broken_engine = create_engine(f"sqlite:///{broken_db}", future=True)
    from sqlalchemy import inspect

    try:
        assert any(
            "run_iocs missing column: tags_search" in problem
            for problem in validate_schema(broken_engine)
        )
        assert _has_column(inspect(broken_engine), "missing", "nope") is False
    finally:
        broken_engine.dispose()


def test_history_export_import_compact_and_retain(tmp_path: Path) -> None:
    source_db = f"sqlite:///{tmp_path / 'source.sqlite'}"
    _persist_result(
        source_db, source_value="failed.txt", ioc_value="failed.example", status="failed"
    )
    exported = export_persisted_history(db_uri=source_db)
    assert exported["runs"]

    restored_db = f"sqlite:///{tmp_path / 'restored.sqlite'}"
    imported = import_persisted_history(db_uri=restored_db, payload=exported)
    assert imported["runs"] >= 1
    archive_path = archive_history(restored_db, str(tmp_path / "archive.json"))
    restored_counts = restore_history(
        f"sqlite:///{tmp_path / 'restored_again.sqlite'}", archive_path
    )
    assert restored_counts["runs"] >= 1
    compact_persisted_history(db_uri=restored_db)
    affected = retain_persisted_history(db_uri=restored_db, days=0, statuses="failed")
    assert affected >= 1
    invalid_archive = tmp_path / "invalid.json"
    invalid_archive.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(TypeError):
        restore_history(restored_db, str(invalid_archive))


def test_batch_job_persistence_and_failed_batch_listing(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'batch.sqlite'}"
    config = load_config(True, db_uri, None)
    results = {"https://ok.example": ({"domains": ["ok.example"]}, {})}
    report = {
        "total": 2,
        "successful": 1,
        "failed": 1,
        "duration_ms": 123,
        "items": [
            {"url": "https://ok.example", "status": "ok", "duration_ms": 12, "retry_attempt": 0},
            {
                "url": "https://fail.example",
                "status": "failed",
                "error": "timeout",
                "error_type": "IOCTimeoutError",
                "retry_attempt": 1,
            },
        ],
        "run_metadata_map": {
            "https://ok.example": {
                "duration_ms": 12,
                "successful_items": 1,
                "failed_items": 0,
                "status": "success",
            },
            "https://fail.example": {
                "duration_ms": 0,
                "successful_items": 0,
                "failed_items": 1,
                "status": "failed",
            },
        },
        "source_metadata_map": {},
        "error_groups": {"IOCTimeoutError": 1},
        "failures": {"https://fail.example": "timeout"},
    }
    options = PersistOptions(
        defang=False, check_warnings=False, force_update=False, output_format="json"
    )
    ok_run_ids = persist_many_results(results, config=config, options=options, source_kind="url")
    failed_run_ids = persist_failed_batch_items(
        report, config=config, options=options, source_kind="url"
    )
    batch_job_id = persist_batch_job(
        report,
        config=config,
        source_kind="url",
        run_ids=ok_run_ids + failed_run_ids,
        effective_config={"url_workers": 2},
    )
    assert batch_job_id is not None
    jobs = list_failed_batch_jobs(db_uri=db_uri, limit=10)
    assert jobs[0].batch_job_id == batch_job_id
    assert jobs[0].error_summary == {"IOCTimeoutError": 1}
    failed_items = list_failed_batch_items(db_uri, batch_job_id=batch_job_id)
    assert failed_items[0].retry_attempt == 1
    assert (
        persist_batch_job(
            report,
            config=load_config(False, None, None),
            source_kind="url",
            run_ids=(),
            effective_config={},
        )
        is None
    )


def test_batch_job_persistence_uses_report_status_and_max_retry_attempt(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'batch-status.sqlite'}"
    config = load_config(True, db_uri, None)

    failed_only_report = {
        "total": 2,
        "successful": 0,
        "failed": 2,
        "status": "failed",
        "duration_ms": 50,
        "items": [
            {
                "url": "https://fail-one.example",
                "status": "failed",
                "error": "timeout",
                "retry_attempt": 2,
            },
            {
                "url": "https://fail-two.example",
                "status": "failed",
                "error": "boom",
                "retry_attempt": 1,
            },
        ],
    }
    batch_job_id = persist_batch_job(
        failed_only_report,
        config=config,
        source_kind="url",
        run_ids=(101, 102),
        effective_config={},
    )
    assert batch_job_id is not None

    detail = PersistenceClient(db_uri).get_batch_job(batch_job_id=batch_job_id)
    assert detail is not None
    assert detail.status == "failed"
    assert detail.retry_attempt == 2


def test_batch_job_persistence_uses_report_phase_timestamps(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'batch-timestamps.sqlite'}"
    config = load_config(True, db_uri, None)
    batch_job_id = persist_batch_job(
        {
            "total": 1,
            "successful": 1,
            "failed": 0,
            "duration_ms": 100,
            "items": [{"url": "https://ok.example", "status": "ok"}],
            "phase_timestamps": {
                "started_at": "2026-01-01T00:00:00",
                "finished_at": "2026-01-01T00:00:10",
            },
        },
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert batch_job_id is not None
    detail = PersistenceClient(db_uri).get_batch_job(batch_job_id=batch_job_id)
    assert detail is not None
    assert detail.started_at.isoformat().startswith("2026-01-01T00:00:00")
    assert detail.finished_at.isoformat().startswith("2026-01-01T00:00:10")
    assert list_failed_batch_items(db_uri, batch_job_id=batch_job_id) == []

    successful_retry_report = {
        "total": 1,
        "successful": 1,
        "failed": 0,
        "status": "success",
        "duration_ms": 25,
        "items": [
            {"url": "https://ok.example", "status": "ok", "duration_ms": 12, "retry_attempt": 3},
        ],
    }
    success_job_id = persist_batch_job(
        successful_retry_report,
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert success_job_id is not None
    success_detail = PersistenceClient(db_uri).get_batch_job(batch_job_id=success_job_id)
    assert success_detail is not None
    assert success_detail.status == "success"
    assert success_detail.retry_attempt == 3


def test_failed_batch_items_use_batch_finished_at_timestamp(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'batch-failed-item-timestamps.sqlite'}"
    config = load_config(True, db_uri, None)
    batch_job_id = persist_batch_job(
        {
            "total": 1,
            "successful": 0,
            "failed": 1,
            "duration_ms": 100,
            "items": [{"url": "https://bad.example", "status": "failed", "error": "timeout"}],
            "phase_timestamps": {
                "started_at": "2026-01-01T00:00:00",
                "finished_at": "2026-01-01T00:00:10",
            },
        },
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert batch_job_id is not None
    failed_items = list_failed_batch_items(db_uri, batch_job_id=batch_job_id)
    assert len(failed_items) == 1
    assert failed_items[0].created_at.isoformat().startswith("2026-01-01T00:00:10")


def test_retry_attempt_for_url_uses_failed_batch_history(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'retry-attempt.sqlite'}"
    config = load_config(True, db_uri, None)
    persist_failed_batch_items(
        {
            "items": [
                {
                    "url": "https://retry.example",
                    "status": "failed",
                    "error": "timeout",
                    "error_type": "IOCTimeoutError",
                    "retry_attempt": 2,
                },
            ],
            "run_metadata_map": {"https://retry.example": {"status": "failed", "failed_items": 1}},
        },
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
        source_kind="url",
    )
    batch_job_id = persist_batch_job(
        {
            "total": 1,
            "successful": 0,
            "failed": 1,
            "status": "failed",
            "duration_ms": 10,
            "items": [
                {
                    "url": "https://retry.example",
                    "status": "failed",
                    "error": "timeout",
                    "error_type": "IOCTimeoutError",
                    "retry_attempt": 2,
                },
            ],
        },
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert batch_job_id is not None
    assert (
        retry_attempt_for_url(
            "https://retry.example",
            None,
            retry_batch_job=batch_job_id,
            db_uri=db_uri,
        )
        == 3
    )


def test_cli_schema_commands_and_history_io(tmp_path: Path, capsys) -> None:
    db_uri = f"sqlite:///{tmp_path / 'cli.sqlite'}"
    _persist_result(db_uri, source_value="cli.txt", ioc_value="cli.example")
    config = load_config(True, db_uri, None)
    writer = _Writer()

    assert (
        handle_schema_commands(SimpleNamespace(schema_version=True), config, file_writer=writer)
        is True
    )
    assert "schema_version" in capsys.readouterr().out
    assert (
        handle_schema_commands(
            SimpleNamespace(schema_version=False, migrate=True), config, file_writer=writer
        )
        is True
    )
    assert "migrated_to" in capsys.readouterr().out
    assert (
        handle_schema_commands(
            SimpleNamespace(schema_version=False, migrate=False, validate_schema=True),
            config,
            file_writer=writer,
        )
        is True
    )
    assert "schema_valid" in capsys.readouterr().out
    broken_db = tmp_path / "schema-broken.sqlite"
    broken_db.touch()
    broken_config = load_config(True, f"sqlite:///{broken_db}", None)
    assert (
        handle_schema_commands(
            SimpleNamespace(schema_version=False, migrate=False, validate_schema=True),
            broken_config,
            file_writer=writer,
        )
        is True
    )
    assert "missing table" in capsys.readouterr().out
    assert (
        handle_schema_commands(SimpleNamespace(export_history="-"), config, file_writer=writer)
        is True
    )
    assert '"runs"' in capsys.readouterr().out

    export_path = tmp_path / "history.json"
    args = SimpleNamespace(
        schema_version=False,
        migrate=False,
        validate_schema=False,
        export_history=str(export_path),
        archive_history=None,
        import_history=None,
        restore_history=None,
        compact_history=False,
        retain_days=None,
        prune_status=None,
        list_failed_batches=False,
        batch_limit=20,
    )
    assert handle_schema_commands(args, config, file_writer=writer) is True
    assert export_path.is_file()

    restore_db = f"sqlite:///{tmp_path / 'restore.sqlite'}"
    restore_config = load_config(True, restore_db, None)
    restore_args = SimpleNamespace(
        schema_version=False,
        migrate=False,
        validate_schema=False,
        export_history=None,
        archive_history=None,
        import_history=str(export_path),
        restore_history=None,
        compact_history=False,
        retain_days=None,
        prune_status=None,
        list_failed_batches=False,
        batch_limit=20,
    )
    assert handle_schema_commands(restore_args, restore_config, file_writer=writer) is True
    assert query_persisted_runs(db_uri=restore_db, limit=10).total >= 1
    assert handle_schema_commands(
        SimpleNamespace(
            schema_version=False,
            migrate=False,
            validate_schema=False,
            export_history=None,
            archive_history=None,
            import_history=None,
            restore_history=None,
            compact_history=True,
            retain_days=None,
            prune_status=None,
            list_failed_batches=False,
            batch_limit=20,
        ),
        config,
        file_writer=writer,
    )
    assert handle_schema_commands(
        SimpleNamespace(
            schema_version=False,
            migrate=False,
            validate_schema=False,
            export_history=None,
            archive_history=None,
            import_history=None,
            restore_history=None,
            compact_history=False,
            retain_days=3650,
            prune_status="success",
            list_failed_batches=False,
            batch_limit=20,
        ),
        config,
        file_writer=writer,
    )
    failed_batch_db = f"sqlite:///{tmp_path / 'failed-batches.sqlite'}"
    failed_config = load_config(True, failed_batch_db, None)
    persist_batch_job(
        {
            "total": 1,
            "successful": 0,
            "failed": 1,
            "duration_ms": 1,
            "items": [
                {
                    "url": "https://bad.example",
                    "status": "failed",
                    "error": "boom",
                    "error_type": "Timeout",
                }
            ],
        },
        config=failed_config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert handle_schema_commands(
        SimpleNamespace(
            schema_version=False,
            migrate=False,
            validate_schema=False,
            export_history=None,
            archive_history=None,
            import_history=None,
            restore_history=None,
            compact_history=False,
            retain_days=None,
            prune_status=None,
            list_failed_batches=True,
            batch_limit=20,
        ),
        failed_config,
        file_writer=writer,
    )
    print_schema_revisions()
    assert "baseline" in capsys.readouterr().out


def test_cli_schema_validation_errors_and_noop() -> None:
    writer = _Writer()
    config = load_config(True, None, None)
    from iocparser.errors import ValidationError

    with pytest.raises(ValidationError):
        handle_schema_commands(SimpleNamespace(schema_version=True), config, file_writer=writer)
    with pytest.raises(ValidationError):
        handle_schema_commands(
            SimpleNamespace(schema_version=False, migrate=True), config, file_writer=writer
        )
    with pytest.raises(ValidationError):
        handle_schema_commands(
            SimpleNamespace(schema_version=False, migrate=False, validate_schema=True),
            config,
            file_writer=writer,
        )
    with pytest.raises(ValidationError):
        handle_schema_commands(SimpleNamespace(export_history="-"), config, file_writer=writer)
    assert (
        handle_schema_commands(
            SimpleNamespace(
                schema_version=False,
                migrate=False,
                validate_schema=False,
                export_history=None,
                archive_history=None,
                import_history=None,
                restore_history=None,
                compact_history=False,
                retain_days=None,
                prune_status=None,
                list_failed_batches=False,
                batch_limit=20,
            ),
            config,
            file_writer=writer,
        )
        is False
    )


def test_retry_failed_report_can_filter_by_error_type_and_text(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "url": "https://one.example",
                        "status": "failed",
                        "error": "timeout waiting",
                        "error_type": "IOCTimeoutError",
                    },
                    {
                        "url": "https://two.example",
                        "status": "failed",
                        "error": "tls verify failed",
                        "error_type": "NetworkDownloadError",
                    },
                ],
            },
        ),
        encoding="utf-8",
    )
    assert _failed_urls_from_report(report_path, error_type_filter="IOCTimeoutError") == [
        "https://one.example"
    ]
    assert _failed_urls_from_report(report_path, error_substring="verify") == [
        "https://two.example"
    ]
    assert _failed_urls_from_report(
        report_path,
        error_type_filter="NetworkDownloadError",
        error_substring="verify",
    ) == ["https://two.example"]
    bad_report = tmp_path / "bad.json"
    bad_report.write_text(json.dumps([]), encoding="utf-8")
    from iocparser.errors import ValidationError

    with pytest.raises(ValidationError):
        _failed_urls_from_report(bad_report)
    bad_report.write_text(json.dumps({"items": {}}), encoding="utf-8")
    with pytest.raises(ValidationError):
        _failed_urls_from_report(bad_report)
    from iocparser.errors import FileExistenceError

    missing = tmp_path / "missing.json"
    with pytest.raises(FileExistenceError):
        _failed_urls_from_report(missing)
    assert _retry_attempt_for_url("https://missing.example", str(report_path)) == 0


def test_clients_wrap_reusable_services_and_plugin_pipeline(tmp_path: Path) -> None:
    register_extractor("demo-extractor", DemoExtractor)
    register_postprocessor("demo-post", DemoPostProcessor)
    parser_client = IOCParserClient(
        enrichers=(), extractors=("demo-extractor",), postprocessors=("demo-post",)
    )
    result = parser_client.extract_result_from_text("plain text without IOCs", check_warnings=False)
    assert {ioc.value.raw for ioc in result.iocs} == {"plugin.example", "203.0.113.55"}
    file_path = tmp_path / "client.txt"
    file_path.write_text("client.example", encoding="utf-8")
    assert parser_client.extract_result_from_file(str(file_path), check_warnings=False).iocs
    with LocalHTTPFileServer(b"url.example") as url:
        assert parser_client.extract_result_from_url(url, check_warnings=False).iocs
    assert "demo-extractor" in extractor_names()
    assert "demo-post" in postprocessor_names()
    assert isinstance(get_extractor("demo-extractor"), DemoExtractor)
    assert isinstance(get_postprocessor("demo-post"), DemoPostProcessor)

    class _WarningExtractor:
        def extract(self, *_args, **_kwargs):
            return ExtractionResult(
                warnings=(
                    WarningMatch(ioc=IOC.from_raw("domains", "warn.example"), warning_list="demo"),
                ),
            )

    register_extractor(
        "demo-warning",
        _WarningExtractor,
    )
    assert (
        IOCParserClient(enrichers=(), extractors=("demo-warning",))
        .extract_result_from_text("x", check_warnings=False)
        .warnings
    )

    class PassThroughEnricher:
        def separate(self, iocs, *, force_update: bool = False):
            del force_update
            return ExtractionResult(iocs=iocs)

    from iocparser.plugins import register_enricher

    register_enricher("demo-enricher-a", PassThroughEnricher)
    register_enricher("demo-enricher-b", PassThroughEnricher)
    assert (
        IOCParserClient(enrichers=("demo-enricher-a", "demo-enricher-b"))._warning_service(True)
        is not None
    )

    db_uri = f"sqlite:///{tmp_path / 'client.sqlite'}"
    _persist_result(db_uri, source_value="client.txt", ioc_value="client.example")
    persistence = PersistenceClient(db_uri)
    assert persistence.query_runs(limit=10).total == 1
    assert persistence.search_iocs(value="client").total == 1
    assert persistence.export_history()["runs"]
    assert persistence.export_run(run_id=1).summary.run_id == 1
    assert persistence.diff_runs(left_run_id=1, right_run_id=1).added.total_count() == 0
    assert persistence.import_history(persistence.export_history())["runs"] == 0
    assert persistence.list_failed_batches(limit=5) == []
    assert persistence.retain_history(days=3650) >= 0
    assert SQLAlchemyPersistenceService(db_uri).list_failed_batch_items(batch_job_id=999) == []


def test_merge_extraction_results_deduplicates_canonical_values() -> None:
    base = ExtractionResult(
        iocs=(IOC.from_raw("domains", "Example[.]COM"),),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw("domains", "Warning[.]Example"),
                warning_list="Known Good",
                description="duplicate",
            ),
        ),
    )
    extra = ExtractionResult(
        iocs=(IOC.from_raw("domains", "example.com"),),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw("domains", "warning.example"),
                warning_list="Known Good",
                description="duplicate",
            ),
        ),
    )

    merged = merge_extraction_results(base, extra)

    assert [ioc.canonical_value() for ioc in merged.iocs] == ["example.com"]
    assert [warning.ioc.canonical_value() for warning in merged.warnings] == ["warning.example"]


def test_parser_client_apply_plugins_uses_registered_extractors() -> None:
    register_extractor("demo-apply", DemoExtractor)
    parser_client = IOCParserClient(enrichers=(), extractors=("demo-apply",))
    options = _options(check_warnings=False, force_update=False, defang=True)
    result = parser_client._apply_plugins(
        "plain text without IOCs",
        options,
        ExtractionResult(),
    )
    assert {ioc.value.raw for ioc in result.iocs} == {"plugin.example"}


def test_parser_client_url_without_runtime_adapters_raises() -> None:
    parser_client = IOCParserClient(enrichers=())
    with pytest.raises(ValueError, match="Missing URL adapters"):
        extract_result_from_url(
            url="https://example.test",
            adapters=ClientExtractionAdapters(
                reader=parser_client.reader,
                extractor_engine=parser_client.extractor_engine,
            ),
            plugins=ClientPluginSettings(enrichers=(), extractors=(), postprocessors=()),
            request=ClientExtractionRequest(check_warnings=False),
        )


def test_batch_report_and_filter_helpers(capsys) -> None:
    report = {
        "total": 2,
        "successful": 1,
        "failed": 1,
        "failures": {"https://bad.example": "boom"},
        "error_groups": {"Timeout": 1},
    }
    print_batch_report(report)
    print_text_lines(["alpha", "beta"])
    print_failed_batch_jobs(
        [
            SimpleNamespace(
                batch_job_id=1,
                status="failed",
                source_kind="url",
                total_inputs=2,
                failed_inputs=1,
                retry_attempt=2,
            )
        ],
    )
    save_batch_report(report, "-", file_writer=_Writer())
    save_batch_report(report, None, file_writer=_Writer())
    assert "Failure groups" in capsys.readouterr().out
    assert Path("iocparser_batch_report.json").is_file()
    Path("iocparser_batch_report.json").unlink()

    hit = PersistedRunQueryHit(
        run_id=1,
        source_kind="file",
        source_value="source.txt",
        ioc_type="domains",
        value="alpha.example",
        is_warning=False,
        severity="medium",
        tags=("phishing",),
    )
    assert (
        matches_advanced_filters(
            hit, tags=("phishing",), exclude_tags=(), min_severity="low", tag_mode="all"
        )
        is True
    )
    assert (
        matches_advanced_filters(
            hit, tags=("phishing",), exclude_tags=("phishing",), min_severity=None, tag_mode="all"
        )
        is False
    )
    assert (
        matches_advanced_filters(hit, tags=(), exclude_tags=(), min_severity=None, tag_mode="all")
        is True
    )
    assert (
        BatchJobSummary(
            batch_job_id=1,
            source_kind="url",
            started_at=__import__("datetime").datetime.now(),
            finished_at=__import__("datetime").datetime.now(),
            total_inputs=1,
            successful_inputs=0,
            failed_inputs=1,
            retry_attempt=0,
            status="failed",
            error_summary={"Timeout": 1},
        ).to_record()["batch_job_id"]
        == 1
    )
    assert (
        FailedBatchItem(
            batch_job_id=1,
            source_value="u",
            error_type="Timeout",
            error_message="boom",
            retry_attempt=0,
            created_at=__import__("datetime").datetime.now(),
        ).to_record()["error_type"]
        == "Timeout"
    )
    assert (
        BatchDashboard(
            lookback_hours=24,
            group_by="hour",
            total_jobs=1,
            failed_jobs=1,
            partial_jobs=0,
            failure_rate=1.0,
            alerts=("failure-rate",),
            windows=(
                BatchDashboardWindow(
                    started_at="2026-03-10T10:00:00+00:00",
                    total_jobs=1,
                    failed_jobs=1,
                    partial_jobs=0,
                    failure_rate=1.0,
                    average_duration_ms=10,
                ),
            ),
        ).to_record()["windows"][0]["average_duration_ms"]
        == 10
    )


def test_history_batch_session_plugin_entry_points_and_dispatch_shortcuts(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'entry.sqlite'}"
    assert import_history_raw(db_uri, {"sources": "bad"})["sources"] == 0
    assert import_history_raw(db_uri, {"sources": [1]})["sources"] == 0
    invalid_fk_counts = import_history_raw(
        db_uri,
        {
            "runs": [{"id": 1, "source_id": "bad"}],
            "run_iocs": [{"run_id": "bad", "ioc_id": "bad"}],
            "failed_batch_items": [{"batch_job_id": "bad"}],
        },
    )
    assert invalid_fk_counts["runs"] == 0
    assert invalid_fk_counts["run_iocs"] == 0
    assert invalid_fk_counts["failed_batch_items"] == 0
    invalid_int_counts = import_history_raw(
        db_uri,
        {
            "batch_jobs": [
                {
                    "id": 99,
                    "source_kind": "url",
                    "started_at": "2026-01-01T00:00:00",
                    "finished_at": "2026-01-01T00:00:00",
                    "total_inputs": "bad",
                    "successful_inputs": True,
                    "failed_inputs": "bad",
                    "retry_attempt": "bad",
                    "status": "success",
                    "config_json": "{}",
                    "error_summary_json": "{}",
                    "metrics_json": "{}",
                }
            ],
        },
    )
    assert invalid_int_counts["batch_jobs"] == 1

    batch_job_id = persist_batch_job(
        {
            "total": 1,
            "successful": 0,
            "failed": 1,
            "duration_ms": 1,
            "items": [
                {
                    "url": "https://bad.example",
                    "status": "failed",
                    "error": "boom",
                    "error_type": "Timeout",
                }
            ],
        },
        config=load_config(True, db_uri, None),
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    unit = SQLAlchemyUnitOfWork(db_uri)
    try:
        assert list_failed_batch_jobs_with_session(unit.session, limit=10)[0][0].id == batch_job_id
    finally:
        unit.close()

    register_extractor("ep-extractor", DemoExtractor)
    register_postprocessor("ep-post", DemoPostProcessor)
    assert "ep-extractor" in extractor_names()
    assert "ep-post" in postprocessor_names()

    from iocparser import cli_dispatch_workflow as workflow

    assert (
        workflow.resolve_input_payload(
            SimpleNamespace(multiple=[], directory=None, url_file=None, retry_failed_from=None),
            process_multiple_files_input=lambda _args: None,
            process_single_input=lambda _args: ({}, {}, "stdin"),
        ).results
        is None
    )


def test_import_history_remaps_foreign_keys_on_primary_key_collision(tmp_path: Path) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-target.sqlite'}"

    persist_results(
        PersistResultsRequest(
            config=load_config(True, source_db_uri, None),
            source_kind="file",
            source_value="imported.txt",
            normal_iocs={"domains": ["imported.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )
    persist_results(
        PersistResultsRequest(
            config=load_config(True, target_db_uri, None),
            source_kind="file",
            source_value="existing.txt",
            normal_iocs={"domains": ["existing.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )

    counts = import_history_raw(target_db_uri, export_persisted_history(db_uri=source_db_uri))
    assert counts["sources"] == 1
    assert counts["runs"] == 1

    runs = query_persisted_runs(db_uri=target_db_uri, limit=10)
    assert {run.source_value for run in runs.items} == {"existing.txt", "imported.txt"}
    imported_run = next(run for run in runs.items if run.source_value == "imported.txt")
    exported = PersistenceClient(target_db_uri).export_run(run_id=imported_run.run_id)
    assert exported.result.grouped_iocs() == {"domains": ["imported.example"]}


def test_retry_attempt_for_duplicate_urls_uses_occurrence_order(tmp_path: Path) -> None:
    report_path = tmp_path / "retry-report.json"
    report_path.write_text(
        json.dumps(
            {
                "items": [
                    {"url": "https://dup.example", "status": "failed", "retry_attempt": 1},
                    {"url": "https://dup.example", "status": "failed", "retry_attempt": 3},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert retry_attempt_for_url("https://dup.example", str(report_path), occurrence=1) == 2
    assert retry_attempt_for_url("https://dup.example", str(report_path), occurrence=2) == 4


def test_retry_attempt_for_duplicate_urls_from_batch_job_uses_stable_order(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'duplicate-batch-retry-order.sqlite'}"
    config = load_config(True, db_uri, None)
    batch_job_id = persist_batch_job(
        {
            "total": 2,
            "successful": 0,
            "failed": 2,
            "status": "failed",
            "duration_ms": 10,
            "items": [
                {
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "timeout-1",
                    "retry_attempt": 1,
                },
                {
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "timeout-2",
                    "retry_attempt": 3,
                },
            ],
        },
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert batch_job_id is not None

    assert (
        retry_attempt_for_url(
            "https://dup.example",
            None,
            retry_batch_job=batch_job_id,
            db_uri=db_uri,
            occurrence=1,
        )
        == 2
    )
    assert (
        retry_attempt_for_url(
            "https://dup.example",
            None,
            retry_batch_job=batch_job_id,
            db_uri=db_uri,
            occurrence=2,
        )
        == 4
    )


def test_import_history_keeps_distinct_runs_with_same_metadata_but_different_iocs(
    tmp_path: Path,
) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-same-metadata-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-same-metadata-target.sqlite'}"

    persist_results(
        PersistResultsRequest(
            config=load_config(True, source_db_uri, None),
            source_kind="file",
            source_value="same.txt",
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={"duration_ms": 10},
        )
    )
    persist_results(
        PersistResultsRequest(
            config=load_config(True, source_db_uri, None),
            source_kind="file",
            source_value="same.txt",
            normal_iocs={"domains": ["beta.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={"duration_ms": 10},
        )
    )

    counts = import_history_raw(target_db_uri, export_persisted_history(db_uri=source_db_uri))
    assert counts["runs"] == 2
    runs = query_persisted_runs(db_uri=target_db_uri, limit=10)
    assert len(runs.items) == 2
    exported_values = {
        tuple(
            PersistenceClient(target_db_uri)
            .export_run(run_id=run.run_id)
            .result.grouped_iocs()["domains"]
        )
        for run in runs.items
    }
    assert exported_values == {("alpha.example",), ("beta.example",)}


def test_import_history_same_origin_accepts_string_run_ioc_foreign_keys(
    tmp_path: Path,
) -> None:
    db_uri = f"sqlite:///{tmp_path / 'history-string-run-ioc-fks.sqlite'}"
    persist_results(
        PersistResultsRequest(
            config=load_config(True, db_uri, None),
            source_kind="file",
            source_value="same-origin.txt",
            normal_iocs={"domains": ["alpha.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={"duration_ms": 10},
        )
    )
    payload = export_persisted_history(db_uri=db_uri)
    run_ioc_rows = payload["run_iocs"]
    assert isinstance(run_ioc_rows, list)
    for row in run_ioc_rows:
        assert isinstance(row, dict)
        row["run_id"] = str(row["run_id"])
        row["ioc_id"] = str(row["ioc_id"])

    counts = import_history_raw(db_uri, payload)

    assert counts["runs"] == 0
    assert counts["run_iocs"] == 0


def test_import_history_keeps_distinct_runs_with_same_iocs_but_different_run_ioc_metadata(
    tmp_path: Path,
) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-same-ioc-metadata-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-same-ioc-metadata-target.sqlite'}"
    source_config = load_config(True, source_db_uri, None)

    persist_results(
        PersistResultsRequest(
            config=source_config,
            source_kind="file",
            source_value="same.txt",
            normal_iocs={"domains": ["same.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={"duration_ms": 10},
        )
    )
    persist_results(
        PersistResultsRequest(
            config=source_config,
            source_kind="file",
            source_value="same.txt",
            normal_iocs={"domains": ["same.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
            run_metadata={"duration_ms": 10},
        )
    )

    source_unit = SQLAlchemyUnitOfWork(source_db_uri)
    try:
        runs = source_unit.session.query(RunModel).order_by(RunModel.id.asc()).all()
        assert len(runs) == 2
        first_started = runs[0].started_at
        first_finished = runs[0].finished_at
        runs[1].started_at = first_started
        runs[1].finished_at = first_finished
        run_iocs = source_unit.session.query(RunIOCModel).order_by(RunIOCModel.run_id.asc()).all()
        assert len(run_iocs) == 2
        run_iocs[0].tags_json = '["tag-a"]'
        run_iocs[0].tags_search = "tag-a"
        run_iocs[1].tags_json = '["tag-b"]'
        run_iocs[1].tags_search = "tag-b"
        source_unit.commit()
    finally:
        source_unit.close()

    counts = import_history_raw(target_db_uri, export_persisted_history(db_uri=source_db_uri))
    assert counts["runs"] == 2
    runs = query_persisted_runs(db_uri=target_db_uri, limit=10)
    assert len(runs.items) == 2
    target_unit = SQLAlchemyUnitOfWork(target_db_uri)
    try:
        tags = {row.tags_json for row in target_unit.session.query(RunIOCModel).all()}
        assert tags == {'["tag-a"]', '["tag-b"]'}
    finally:
        target_unit.close()


def test_import_history_preserves_duplicate_failed_batch_items_with_same_payload(
    tmp_path: Path,
) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-failed-items-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-failed-items-target.sqlite'}"
    config = load_config(True, source_db_uri, None)
    batch_job_id = persist_batch_job(
        {
            "total": 2,
            "successful": 0,
            "failed": 2,
            "status": "failed",
            "duration_ms": 10,
            "items": [
                {
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "boom",
                    "error_type": "Timeout",
                    "retry_attempt": 1,
                },
                {
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "boom",
                    "error_type": "Timeout",
                    "retry_attempt": 1,
                },
            ],
        },
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert batch_job_id is not None

    payload = export_persisted_history(db_uri=source_db_uri)
    counts = import_history_raw(target_db_uri, payload)
    assert counts["failed_batch_items"] == 2
    imported_jobs = list_failed_batch_jobs(db_uri=target_db_uri, limit=10)
    assert len(imported_jobs) == 1
    imported_items = list_failed_batch_items(
        target_db_uri, batch_job_id=imported_jobs[0].batch_job_id
    )
    assert len(imported_items) == 2

    repeated = import_history_raw(target_db_uri, payload)
    assert repeated["failed_batch_items"] == 0


def test_import_history_preserves_distinct_batch_jobs_with_identical_aggregate(
    tmp_path: Path,
) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-batch-jobs-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-batch-jobs-target.sqlite'}"
    config = load_config(True, source_db_uri, None)
    report = {
        "total": 1,
        "successful": 0,
        "failed": 1,
        "status": "failed",
        "duration_ms": 10,
        "phase_timestamps": {
            "started_at": "2026-01-02T03:04:05+00:00",
            "finished_at": "2026-01-02T03:04:05.010000+00:00",
        },
        "items": [
            {
                "url": "https://dup.example",
                "status": "failed",
                "error": "boom",
                "error_type": "Timeout",
                "retry_attempt": 1,
            },
        ],
    }
    first_job_id = persist_batch_job(
        report,
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    second_job_id = persist_batch_job(
        report,
        config=config,
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    assert first_job_id is not None
    assert second_job_id is not None
    assert first_job_id != second_job_id

    payload = export_persisted_history(db_uri=source_db_uri)
    counts = import_history_raw(target_db_uri, payload)
    assert counts["batch_jobs"] == 2
    imported_jobs = list_failed_batch_jobs(db_uri=target_db_uri, limit=10)
    assert len(imported_jobs) == 2

    repeated = import_history_raw(target_db_uri, payload)
    assert repeated["batch_jobs"] == 0


def test_import_history_keeps_identical_batch_jobs_from_distinct_payloads_separate(
    tmp_path: Path,
) -> None:
    first_source_db_uri = f"sqlite:///{tmp_path / 'history-batch-jobs-first.sqlite'}"
    second_source_db_uri = f"sqlite:///{tmp_path / 'history-batch-jobs-second.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-batch-jobs-merged.sqlite'}"

    identical_report = {
        "total": 1,
        "successful": 0,
        "failed": 1,
        "status": "failed",
        "duration_ms": 10,
        "phase_timestamps": {
            "started_at": "2026-01-02T03:04:05+00:00",
            "finished_at": "2026-01-02T03:04:05.010000+00:00",
        },
        "items": [
            {
                "url": "https://dup.example",
                "status": "failed",
                "error": "boom",
                "error_type": "Timeout",
                "retry_attempt": 1,
            },
        ],
    }
    persist_batch_job(
        identical_report,
        config=load_config(True, first_source_db_uri, None),
        source_kind="url",
        run_ids=(),
        effective_config={},
    )
    persist_batch_job(
        identical_report,
        config=load_config(True, second_source_db_uri, None),
        source_kind="url",
        run_ids=(),
        effective_config={},
    )

    first_payload = export_persisted_history(db_uri=first_source_db_uri)
    second_payload = export_persisted_history(db_uri=second_source_db_uri)
    assert first_payload["__history_archive_id__"] != second_payload["__history_archive_id__"]
    assert import_history_raw(target_db_uri, first_payload)["batch_jobs"] == 1
    assert import_history_raw(target_db_uri, second_payload)["batch_jobs"] == 1

    imported_jobs = list_failed_batch_jobs(db_uri=target_db_uri, limit=10)
    assert len(imported_jobs) == 2


def test_import_history_keeps_identical_runs_from_distinct_payloads_separate(
    tmp_path: Path,
) -> None:
    first_source_db_uri = f"sqlite:///{tmp_path / 'history-runs-first.sqlite'}"
    second_source_db_uri = f"sqlite:///{tmp_path / 'history-runs-second.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-runs-target.sqlite'}"

    for db_uri in (first_source_db_uri, second_source_db_uri):
        persist_results(
            PersistResultsRequest(
                config=load_config(True, db_uri, None),
                source_kind="file",
                source_value="same.txt",
                normal_iocs={"domains": ["same.example"]},
                warning_iocs={},
                options=PersistOptions(
                    defang=False, check_warnings=False, force_update=False, output_format="json"
                ),
                tool_version="5.0.0",
                run_metadata={"duration_ms": 10},
            )
        )

    first_payload = export_persisted_history(db_uri=first_source_db_uri)
    second_payload = export_persisted_history(db_uri=second_source_db_uri)

    assert import_history_raw(target_db_uri, first_payload)["runs"] == 1
    assert import_history_raw(target_db_uri, second_payload)["runs"] == 1
    assert query_persisted_runs(db_uri=target_db_uri, limit=10).total == 2


def test_export_history_is_idempotent_for_same_snapshot_from_same_db(tmp_path: Path) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-same-db.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-same-db-target.sqlite'}"

    report = {
        "total": 1,
        "successful": 0,
        "failed": 1,
        "status": "failed",
        "duration_ms": 10,
        "phase_timestamps": {
            "started_at": "2026-01-02T03:04:05+00:00",
            "finished_at": "2026-01-02T03:04:05.010000+00:00",
        },
        "items": [
            {
                "url": "https://dup.example",
                "status": "failed",
                "error": "boom",
                "error_type": "Timeout",
                "retry_attempt": 1,
            },
        ],
    }
    persist_batch_job(
        report,
        config=load_config(True, source_db_uri, None),
        source_kind="url",
        run_ids=(),
        effective_config={},
    )

    first_payload = export_persisted_history(db_uri=source_db_uri)
    second_payload = export_persisted_history(db_uri=source_db_uri)
    assert first_payload["__history_origin_id__"] == second_payload["__history_origin_id__"]
    assert first_payload["__history_archive_id__"] == second_payload["__history_archive_id__"]

    assert import_history_raw(target_db_uri, first_payload)["batch_jobs"] == 1
    assert import_history_raw(target_db_uri, second_payload)["batch_jobs"] == 0
    assert len(list_failed_batch_jobs(db_uri=target_db_uri, limit=10)) == 1


def test_import_history_legacy_payload_reimport_is_rejected_as_ambiguous(tmp_path: Path) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-legacy-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-legacy-target.sqlite'}"

    report = {
        "total": 1,
        "successful": 0,
        "failed": 1,
        "status": "failed",
        "duration_ms": 10,
        "phase_timestamps": {
            "started_at": "2026-01-02T03:04:05+00:00",
            "finished_at": "2026-01-02T03:04:05.010000+00:00",
        },
        "items": [
            {
                "url": "https://dup.example",
                "status": "failed",
                "error": "boom",
                "error_type": "Timeout",
                "retry_attempt": 1,
            },
        ],
    }
    persist_batch_job(
        report,
        config=load_config(True, source_db_uri, None),
        source_kind="url",
        run_ids=(),
        effective_config={},
    )

    legacy_payload = export_persisted_history(db_uri=source_db_uri)
    legacy_payload.pop("__history_archive_id__", None)
    legacy_payload.pop("__history_origin_id__", None)

    assert import_history_raw(target_db_uri, legacy_payload)["batch_jobs"] == 1
    with pytest.raises(ValueError, match="ambiguous legacy history archive"):
        import_history_raw(target_db_uri, legacy_payload)
    assert len(list_failed_batch_jobs(db_uri=target_db_uri, limit=10)) == 1


def test_import_history_legacy_run_payload_reimport_is_rejected_as_ambiguous(
    tmp_path: Path,
) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-legacy-run-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-legacy-run-target.sqlite'}"

    persist_results(
        PersistResultsRequest(
            config=load_config(True, source_db_uri, None),
            source_kind="file",
            source_value="legacy.txt",
            normal_iocs={"domains": ["legacy.example"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False, check_warnings=False, force_update=False, output_format="json"
            ),
            tool_version="5.0.0",
        )
    )

    legacy_payload = export_persisted_history(db_uri=source_db_uri)
    legacy_payload.pop("__history_archive_id__", None)
    legacy_payload.pop("__history_origin_id__", None)

    assert import_history_raw(target_db_uri, legacy_payload)["runs"] == 1
    with pytest.raises(ValueError, match="ambiguous legacy history archive"):
        import_history_raw(target_db_uri, legacy_payload)
    assert query_persisted_runs(db_uri=target_db_uri, limit=10).total == 1


def test_import_history_legacy_dead_letter_payload_reimport_is_rejected_as_ambiguous(
    tmp_path: Path,
) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-legacy-dead-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-legacy-dead-target.sqlite'}"
    service = SQLAlchemyDistributedJobService(source_db_uri)
    envelope = QueueEnvelope(
        request=PipelineJobRequest(
            input_kind="url",
            source_value="https://legacy.example/feed",
            job_id="job-legacy",
            correlation_id="corr-legacy",
        ),
        queue_backend="filesystem",
        queue_name="default",
    )
    service.create_or_get_job(envelope=envelope, receipt_id="receipt-1")
    service.mark_dead_lettered(
        job_id="job-legacy",
        attempts=2,
        error=PipelineErrorInfo(
            code="INPUT_TIMEOUT",
            category="timeout",
            retryable=True,
            status="failed",
            message="timeout",
        ),
    )

    legacy_payload = export_persisted_history(db_uri=source_db_uri)
    legacy_payload.pop("__history_archive_id__", None)
    legacy_payload.pop("__history_origin_id__", None)

    assert import_history_raw(target_db_uri, legacy_payload)["dead_letter_jobs"] == 1
    with pytest.raises(ValueError, match="ambiguous legacy history archive"):
        import_history_raw(target_db_uri, legacy_payload)
    assert len(PersistenceClient(target_db_uri).list_dead_letters(limit=10)) == 1


def test_import_history_keeps_identical_distributed_jobs_from_distinct_payloads_separate(
    tmp_path: Path,
) -> None:
    first_source_db_uri = f"sqlite:///{tmp_path / 'history-dist-first.sqlite'}"
    second_source_db_uri = f"sqlite:///{tmp_path / 'history-dist-second.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-dist-target.sqlite'}"

    def _create_job(db_uri: str) -> None:
        service = SQLAlchemyDistributedJobService(db_uri)
        envelope = QueueEnvelope(
            request=PipelineJobRequest(
                input_kind="url",
                source_value="https://same.example/feed",
                job_id="job-1",
                correlation_id="corr-1",
            ),
            queue_backend="filesystem",
            queue_name="default",
        )
        service.create_or_get_job(envelope=envelope, receipt_id="receipt-1")

    _create_job(first_source_db_uri)
    _create_job(second_source_db_uri)

    first_payload = export_persisted_history(db_uri=first_source_db_uri)
    second_payload = export_persisted_history(db_uri=second_source_db_uri)

    assert import_history_raw(target_db_uri, first_payload)["distributed_jobs"] == 1
    assert import_history_raw(target_db_uri, second_payload)["distributed_jobs"] == 1

    jobs = list_distributed_jobs(db_uri=target_db_uri, limit=10)
    assert len(jobs) == 2
    assert [job.job_id for job in jobs] == ["job-1", "job-1"]


def test_import_history_keeps_identical_dead_letter_jobs_from_distinct_payloads_separate(
    tmp_path: Path,
) -> None:
    first_source_db_uri = f"sqlite:///{tmp_path / 'history-dead-first.sqlite'}"
    second_source_db_uri = f"sqlite:///{tmp_path / 'history-dead-second.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-dead-target.sqlite'}"

    def _create_dead_letter(db_uri: str) -> None:
        service = SQLAlchemyDistributedJobService(db_uri)
        envelope = QueueEnvelope(
            request=PipelineJobRequest(
                input_kind="url",
                source_value="https://same.example/feed",
                job_id="job-1",
                correlation_id="corr-1",
            ),
            queue_backend="filesystem",
            queue_name="default",
        )
        service.create_or_get_job(envelope=envelope, receipt_id="receipt-1")
        service.mark_dead_lettered(
            job_id="job-1",
            attempts=2,
            error=PipelineErrorInfo(
                code="INPUT_TIMEOUT",
                category="timeout",
                retryable=True,
                status="failed",
                message="timeout",
            ),
        )

    _create_dead_letter(first_source_db_uri)
    _create_dead_letter(second_source_db_uri)

    first_payload = export_persisted_history(db_uri=first_source_db_uri)
    second_payload = export_persisted_history(db_uri=second_source_db_uri)

    assert import_history_raw(target_db_uri, first_payload)["dead_letter_jobs"] == 1
    assert import_history_raw(target_db_uri, second_payload)["dead_letter_jobs"] == 1

    dead_letters = PersistenceClient(target_db_uri).list_dead_letters(limit=10)
    assert len(dead_letters) == 2
    assert [item.job_id for item in dead_letters] == ["job-1", "job-1"]


def test_import_history_keeps_distinct_dead_letter_jobs_with_same_short_signature(
    tmp_path: Path,
) -> None:
    target_db_uri = f"sqlite:///{tmp_path / 'history-dead-dedupe.sqlite'}"
    payload = {
        "dead_letter_jobs": [
            {
                "id": 1,
                "job_id": "job-1",
                "correlation_id": "corr-a",
                "queue_backend": "filesystem",
                "queue_name": "jobs-a",
                "source_value": "https://same.example/a",
                "attempts": 2,
                "max_attempts": 3,
                "error_code": "INPUT_TIMEOUT",
                "error_category": "timeout",
                "error_message": "timeout",
                "retryable": True,
                "payload_json": json.dumps(
                    {"request": {"job_id": "job-1", "source_value": "https://same.example/a"}}
                ),
                "dead_lettered_at": "2026-01-01T00:00:00+00:00",
            },
            {
                "id": 2,
                "job_id": "job-1",
                "correlation_id": "corr-b",
                "queue_backend": "filesystem",
                "queue_name": "jobs-b",
                "source_value": "https://same.example/b",
                "attempts": 3,
                "max_attempts": 5,
                "error_code": "INPUT_TIMEOUT",
                "error_category": "timeout",
                "error_message": "timeout",
                "retryable": False,
                "payload_json": json.dumps(
                    {"request": {"job_id": "job-1", "source_value": "https://same.example/b"}}
                ),
                "dead_lettered_at": "2026-01-01T00:00:00+00:00",
            },
        ]
    }

    counts = import_history_raw(target_db_uri, payload)

    assert counts["dead_letter_jobs"] == 2
    dead_letters = PersistenceClient(target_db_uri).list_dead_letters(limit=10)
    assert len(dead_letters) == 2
    assert {item.correlation_id for item in dead_letters} == {"corr-a", "corr-b"}


def test_history_export_and_batch_detail_hide_internal_import_marker(tmp_path: Path) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'history-marker-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'history-marker-target.sqlite'}"
    report = {
        "total": 1,
        "successful": 0,
        "failed": 1,
        "status": "failed",
        "duration_ms": 10,
        "items": [
            {
                "url": "https://dup.example",
                "status": "failed",
                "error": "boom",
                "error_type": "Timeout",
                "retry_attempt": 1,
            },
        ],
    }
    persist_batch_job(
        report,
        config=load_config(True, source_db_uri, None),
        source_kind="url",
        run_ids=(),
        effective_config={"url_workers": 2},
    )

    payload = export_persisted_history(db_uri=source_db_uri)
    import_history_raw(target_db_uri, payload)
    exported_target = export_persisted_history(db_uri=target_db_uri)
    batch_config = json.loads(exported_target["batch_jobs"][0]["config_json"])
    assert "__history_import__" not in batch_config

    imported_jobs = list_failed_batch_jobs(db_uri=target_db_uri, limit=10)
    detail = PersistenceClient(target_db_uri).get_batch_job(
        batch_job_id=imported_jobs[0].batch_job_id
    )
    assert detail is not None
    assert "__history_import__" not in detail.effective_config


def test_persist_failed_batch_items_uses_item_key_metadata_for_duplicate_urls(
    tmp_path: Path,
) -> None:
    db_uri = f"sqlite:///{tmp_path / 'duplicate-failed-metadata.sqlite'}"
    config = load_config(True, db_uri, None)
    persist_failed_batch_items(
        {
            "items": [
                {
                    "item_key": "batch-item:1",
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "boom",
                    "duration_ms": 11,
                },
                {
                    "item_key": "batch-item:2",
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "boom",
                    "duration_ms": 22,
                },
            ],
            "run_metadata_map": {
                "batch-item:1": {"duration_ms": 11, "error_message": "boom"},
                "batch-item:2": {"duration_ms": 22, "error_message": "boom"},
            },
        },
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    runs = query_persisted_runs(db_uri=db_uri, limit=10)
    duplicate_runs = [run for run in runs.items if run.source_value == "https://dup.example"]
    assert len(duplicate_runs) == 2
    assert {run.duration_ms for run in duplicate_runs} == {11, 22}


def test_built_batch_report_keeps_failed_duplicate_item_keys_for_persistence(
    tmp_path: Path,
) -> None:
    db_uri = f"sqlite:///{tmp_path / 'built-duplicate-failed-metadata.sqlite'}"
    config = load_config(True, db_uri, None)
    report = build_batch_report(
        {
            "urls": ["https://dup.example", "https://dup.example"],
            "results": {},
            "failures": {"batch-item:1": "first boom", "batch-item:2": "second boom"},
            "item_reports": [
                {
                    "item_key": "batch-item:1",
                    "input_index": 1,
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "first boom",
                    "error_type": "TimeoutError",
                },
                {
                    "item_key": "batch-item:2",
                    "input_index": 2,
                    "url": "https://dup.example",
                    "status": "failed",
                    "error": "second boom",
                    "error_type": "TimeoutError",
                },
            ],
            "source_metadata_map": {},
            "run_metadata_map": {
                "batch-item:1": {"duration_ms": 11, "error_message": "first boom"},
                "batch-item:2": {"duration_ms": 22, "error_message": "second boom"},
            },
            "job_id": "job-1",
            "correlation_id": "corr-1",
            "input_load_ms": 0,
            "batch_started": time.perf_counter(),
            "batch_started_wall": time.time(),
        }
    )

    assert [item.get("item_key") for item in report["items"]] == [
        "batch-item:1",
        "batch-item:2",
    ]
    assert all("item_key" not in item for item in public_batch_report(report)["items"])

    persist_failed_batch_items(
        report,
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    runs = query_persisted_runs(db_uri=db_uri, limit=10)
    duplicate_runs = [run for run in runs.items if run.source_value == "https://dup.example"]
    assert len(duplicate_runs) == 2
    assert {run.duration_ms for run in duplicate_runs} == {11, 22}
    assert {run.error_message for run in duplicate_runs} == {"first boom", "second boom"}
