from __future__ import annotations

from sqlalchemy import Engine, Inspector


def apply(engine: Engine, inspector: Inspector) -> None:
    """Add extra search-oriented indexes for large persisted histories."""
    table_names = set(inspector.get_table_names())
    statements: list[str] = []
    if "sources" in table_names:
        statements.append(
            "CREATE INDEX IF NOT EXISTS ix_sources_value_search ON sources(value_search)"
        )
    if "iocs" in table_names:
        statements.extend(
            (
                "CREATE INDEX IF NOT EXISTS ix_iocs_value_search ON iocs(value_search)",
                "CREATE INDEX IF NOT EXISTS ix_iocs_value_search_type ON iocs(value_search, ioc_type)",
            ),
        )
    if "run_iocs" in table_names:
        statements.extend(
            (
                "CREATE INDEX IF NOT EXISTS ix_run_iocs_severity ON run_iocs(severity)",
                "CREATE INDEX IF NOT EXISTS ix_run_iocs_run_id ON run_iocs(run_id)",
            ),
        )
    if "failed_batch_items" in table_names:
        statements.append(
            "CREATE INDEX IF NOT EXISTS ix_failed_batch_items_created_at ON failed_batch_items(created_at)",
        )
    if "batch_jobs" in table_names:
        statements.append(
            "CREATE INDEX IF NOT EXISTS ix_batch_jobs_finished_at ON batch_jobs(finished_at)",
        )
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.exec_driver_sql(statement)
