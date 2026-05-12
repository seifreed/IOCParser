from __future__ import annotations

from sqlalchemy import Engine, Inspector


def apply(engine: Engine, inspector: Inspector) -> None:
    table_names = set(inspector.get_table_names())
    if "history_metadata" in table_names:
        return
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS history_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
