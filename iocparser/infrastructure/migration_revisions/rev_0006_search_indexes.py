from __future__ import annotations

from sqlalchemy import Engine, Inspector

# (index_name, table, columns) — created only when absent so the statement is
# dialect-agnostic (MySQL rejects CREATE INDEX IF NOT EXISTS). On a fresh database
# create_all has already built these, so every entry is skipped.
_INDEX_SPECS = (
    ("ix_sources_value_search", "sources", "value_search"),
    ("ix_iocs_value_search", "iocs", "value_search"),
    ("ix_iocs_value_search_type", "iocs", "value_search, ioc_type"),
    ("ix_run_iocs_severity", "run_iocs", "severity"),
    ("ix_run_iocs_run_id", "run_iocs", "run_id"),
    ("ix_failed_batch_items_created_at", "failed_batch_items", "created_at"),
    ("ix_batch_jobs_finished_at", "batch_jobs", "finished_at"),
)


def apply(engine: Engine, inspector: Inspector) -> None:
    """Add extra search-oriented indexes for large persisted histories."""
    table_names = set(inspector.get_table_names())
    pending: list[str] = []
    for index_name, table, columns in _INDEX_SPECS:
        if table not in table_names:
            continue
        existing = {idx["name"] for idx in inspector.get_indexes(table)}
        if index_name not in existing:
            pending.append(f"CREATE INDEX {index_name} ON {table}({columns})")
    if not pending:
        return
    with engine.begin() as connection:
        for statement in pending:
            connection.exec_driver_sql(statement)
