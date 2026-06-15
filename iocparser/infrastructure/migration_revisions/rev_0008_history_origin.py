from __future__ import annotations

from sqlalchemy import Engine, Inspector

from iocparser.infrastructure.persistence_repository_support import quote_identifier


def apply(engine: Engine, inspector: Inspector) -> None:
    table_names = set(inspector.get_table_names())
    if "history_metadata" in table_names:
        return
    # 'key' is a reserved word and TEXT cannot be a primary key on MySQL/MariaDB,
    # so quote the identifier per dialect and use a bounded VARCHAR primary key.
    key = quote_identifier(engine.dialect.name, "key")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            f"CREATE TABLE IF NOT EXISTS history_metadata ("
            f"{key} VARCHAR(64) PRIMARY KEY, value TEXT NOT NULL)"
        )
