from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Engine, Inspector, text

from iocparser.errors import TypeValidationError
from iocparser.infrastructure.migration_revisions.rev_0005_fts_metrics import (
    apply as apply_rev_0005,
)
from iocparser.infrastructure.migration_revisions.rev_0006_search_indexes import (
    apply as apply_rev_0006,
)
from iocparser.infrastructure.migration_revisions.rev_0007_distributed_jobs import (
    apply as apply_rev_0007,
)
from iocparser.infrastructure.migration_revisions.rev_0008_history_origin import (
    apply as apply_rev_0008,
)
from iocparser.infrastructure.migration_revisions.rev_0009_dedup_hash import (
    apply as apply_rev_0009,
)
from iocparser.infrastructure.migration_revisions.rev_0010_tags_search_delimiter import (
    apply as apply_rev_0010,
)
from iocparser.infrastructure.migration_revisions.rev_0011_ioc_value_search_refang import (
    apply as apply_rev_0011,
)
from iocparser.infrastructure.persistence_fts import FTS_TABLE
from iocparser.infrastructure.persistence_repository_support import dialect_replace_into

SCHEMA_VERSION_TABLE = "schema_migrations"


def missing_table_problems(table_names: set[str]) -> list[str]:
    required_tables = {
        "sources",
        "runs",
        "iocs",
        "run_iocs",
        "batch_jobs",
        "failed_batch_items",
        "distributed_jobs",
        "dead_letter_jobs",
        "history_metadata",
        SCHEMA_VERSION_TABLE,
    }
    return [f"missing table: {table}" for table in sorted(required_tables - table_names)]


def _column_names(inspector: Inspector, table_name: str) -> set[str]:
    return {str(column["name"]) for column in inspector.get_columns(table_name)}


def _coerce_version_row(row: object | None) -> int:
    if row is None:
        return 0
    if isinstance(row, bool):
        raise TypeValidationError(None, "schema version row to be int-like", row)
    if isinstance(row, int):
        return row
    if isinstance(row, str):
        return int(row)
    return int(str(row))


def missing_column_problems(inspector: Inspector, table_names: set[str]) -> list[str]:
    problems: list[str] = []
    expected_columns = {
        "runs": ("status", "error_message", "batch_job_id"),
        "sources": ("value_search", "dedup_hash"),
        "iocs": ("value_search", "dedup_hash"),
        "run_iocs": ("tags_search",),
        "batch_jobs": ("metrics_json",),
        "distributed_jobs": ("status", "payload_json", "metrics_json"),
        "dead_letter_jobs": ("error_code", "payload_json"),
    }
    for table_name, columns in expected_columns.items():
        if table_name not in table_names:
            continue
        actual = _column_names(inspector, table_name)
        for column_name in columns:
            if column_name not in actual:
                problems.append(f"{table_name} missing column: {column_name}")
    return problems


def create_latest_schema(engine: Engine) -> None:
    from iocparser.infrastructure import persistence_batch, persistence_distributed
    from iocparser.infrastructure.persistence_schema import Base

    _ = (persistence_batch, persistence_distributed)
    Base.metadata.create_all(engine)


def ensure_version_table(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """,
            ),
        )


def current_version(engine: Engine) -> int:
    with engine.begin() as connection:
        row = connection.execute(
            text("SELECT MAX(version) FROM schema_migrations")
        ).scalar_one_or_none()
        return _coerce_version_row(row)


def stamp_version(engine: Engine, version: int) -> None:
    ensure_version_table(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                dialect_replace_into(
                    engine.dialect.name,
                    "schema_migrations(version, applied_at) VALUES (:version, :applied_at)",
                )
            ),
            {"version": version, "applied_at": datetime.now(UTC).isoformat()},
        )


def upgrade_legacy_schema(engine: Engine, inspector: Inspector) -> None:
    table_names = set(inspector.get_table_names())
    if "runs" not in table_names:
        create_latest_schema(engine)
        return
    if has_column(inspector, "runs", "status") and has_column(inspector, "runs", "error_message"):
        stamp_version(engine, 2)
        return
    upgrade_to_v2(engine, inspector)
    stamp_version(engine, 2)


def upgrade_to_version(engine: Engine, inspector: Inspector, version: int) -> None:
    if version == 2:
        upgrade_to_v2(engine, inspector)
    elif version == 3:
        upgrade_to_v3(engine, inspector)
    elif version == 4:
        upgrade_to_v4(engine, inspector)
    elif version == 5:
        apply_rev_0005(engine, inspector)
    elif version == 6:
        apply_rev_0006(engine, inspector)
    elif version == 7:
        apply_rev_0007(engine, inspector)
    elif version == 8:
        apply_rev_0008(engine, inspector)
    elif version == 9:
        apply_rev_0009(engine, inspector)
    elif version == 10:
        apply_rev_0010(engine, inspector)
    elif version == 11:
        apply_rev_0011(engine, inspector)


def upgrade_to_v2(engine: Engine, inspector: Inspector) -> None:
    statements: list[str] = []
    if not has_column(inspector, "runs", "status"):
        statements.append(
            "ALTER TABLE runs ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'success'"
        )
    if not has_column(inspector, "runs", "error_message"):
        statements.append("ALTER TABLE runs ADD COLUMN error_message TEXT NOT NULL DEFAULT ''")
    run_statements(engine, statements)


def upgrade_to_v3(engine: Engine, inspector: Inspector) -> None:
    statements: list[str] = []
    table_names = set(inspector.get_table_names())
    if "sources" in table_names and not has_column(inspector, "sources", "value_search"):
        statements.append("ALTER TABLE sources ADD COLUMN value_search TEXT NOT NULL DEFAULT ''")
    if "iocs" in table_names and not has_column(inspector, "iocs", "value_search"):
        statements.append("ALTER TABLE iocs ADD COLUMN value_search TEXT NOT NULL DEFAULT ''")
    if "run_iocs" in table_names and not has_column(inspector, "run_iocs", "tags_search"):
        statements.append("ALTER TABLE run_iocs ADD COLUMN tags_search TEXT NOT NULL DEFAULT ''")
    if "sources" in table_names:
        statements.extend(
            (
                "UPDATE sources SET value_search = lower(trim(value)) WHERE value_search = ''",
                "CREATE INDEX IF NOT EXISTS ix_sources_kind_value_search ON sources(kind, value_search)",
            ),
        )
    if "iocs" in table_names:
        statements.extend(
            (
                "UPDATE iocs SET value_search = lower(trim(value)) WHERE value_search = ''",
                "CREATE INDEX IF NOT EXISTS ix_iocs_type_value_search ON iocs(ioc_type, value_search)",
            ),
        )
    if "run_iocs" in table_names:
        statements.extend(
            (
                "UPDATE run_iocs SET tags_search = trim(replace(lower("
                "replace(replace(replace(replace(replace(tags_json, '[', ''), ']', ''),"
                " '\"', ''), ',', ' '), '  ', ' ')), '  ', ' ')) WHERE tags_search = ''",
                "CREATE INDEX IF NOT EXISTS ix_run_iocs_run_severity ON run_iocs(run_id, severity)",
                "CREATE INDEX IF NOT EXISTS ix_run_iocs_tags_search ON run_iocs(tags_search)",
            ),
        )
    if "runs" in table_names:
        statements.extend(
            (
                "CREATE INDEX IF NOT EXISTS ix_runs_source_started ON runs(source_id, started_at)",
                "CREATE INDEX IF NOT EXISTS ix_runs_status_started ON runs(status, started_at)",
            ),
        )
    run_statements(engine, statements)


def upgrade_to_v4(engine: Engine, inspector: Inspector) -> None:
    statements: list[str] = []
    if "batch_jobs" not in set(inspector.get_table_names()):
        statements.extend(
            (
                """
                CREATE TABLE IF NOT EXISTS batch_jobs (
                    id INTEGER PRIMARY KEY,
                    source_kind VARCHAR(16) NOT NULL,
                    started_at DATETIME NOT NULL,
                    finished_at DATETIME NOT NULL,
                    total_inputs INTEGER NOT NULL DEFAULT 0,
                    successful_inputs INTEGER NOT NULL DEFAULT 0,
                    failed_inputs INTEGER NOT NULL DEFAULT 0,
                    retry_attempt INTEGER NOT NULL DEFAULT 0,
                    status VARCHAR(16) NOT NULL DEFAULT 'success',
                    config_json TEXT NOT NULL DEFAULT '{}',
                    error_summary_json TEXT NOT NULL DEFAULT '{}'
                )
                """,
                "CREATE INDEX IF NOT EXISTS ix_batch_jobs_status_started ON batch_jobs(status, started_at)",
                "CREATE INDEX IF NOT EXISTS ix_batch_jobs_source_started ON batch_jobs(source_kind, started_at)",
            ),
        )
    if "failed_batch_items" not in set(inspector.get_table_names()):
        statements.extend(
            (
                """
                CREATE TABLE IF NOT EXISTS failed_batch_items (
                    id INTEGER PRIMARY KEY,
                    batch_job_id INTEGER NOT NULL REFERENCES batch_jobs(id),
                    source_value TEXT NOT NULL,
                    error_type VARCHAR(128) NOT NULL DEFAULT '',
                    error_message TEXT NOT NULL DEFAULT '',
                    retry_attempt INTEGER NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS ix_failed_batch_items_job ON failed_batch_items(batch_job_id)",
                "CREATE INDEX IF NOT EXISTS ix_failed_batch_items_type ON failed_batch_items(error_type)",
            ),
        )
    if not has_column(inspector, "runs", "batch_job_id"):
        statements.append(
            "ALTER TABLE runs ADD COLUMN batch_job_id INTEGER REFERENCES batch_jobs(id)"
        )
    statements.append("CREATE INDEX IF NOT EXISTS ix_runs_batch_job ON runs(batch_job_id)")
    run_statements(engine, statements)


def has_column(inspector: Inspector, table_name: str, column_name: str) -> bool:
    if table_name not in set(inspector.get_table_names()):
        return False
    return column_name in _column_names(inspector, table_name)


def run_statements(engine: Engine, statements: list[str]) -> None:
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.exec_driver_sql(statement)


__all__ = [
    "FTS_TABLE",
    "SCHEMA_VERSION_TABLE",
    "create_latest_schema",
    "current_version",
    "ensure_version_table",
    "has_column",
    "missing_column_problems",
    "missing_table_problems",
    "run_statements",
    "stamp_version",
    "upgrade_legacy_schema",
    "upgrade_to_version",
]
