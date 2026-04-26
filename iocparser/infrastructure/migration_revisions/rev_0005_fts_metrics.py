from __future__ import annotations

from sqlalchemy import Engine, Inspector, text


def apply(engine: Engine, inspector: Inspector) -> None:
    """Add batch metrics storage and an optional SQLite FTS index for IOC lookup."""
    statements: list[str] = []
    table_names = set(inspector.get_table_names())
    if "batch_jobs" in set(inspector.get_table_names()):
        batch_columns = {str(column["name"]) for column in inspector.get_columns("batch_jobs")}
        if "metrics_json" not in batch_columns:
            statements.append("ALTER TABLE batch_jobs ADD COLUMN metrics_json TEXT NOT NULL DEFAULT '{}'")
    dialect = engine.dialect.name
    if dialect == "sqlite" and "iocs" in table_names:
        statements.extend(
            (
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS ioc_search_fts
                USING fts5(value, ioc_type, content='iocs', content_rowid='id', tokenize='unicode61')
                """,
                """
                CREATE TRIGGER IF NOT EXISTS iocs_ai AFTER INSERT ON iocs BEGIN
                    INSERT INTO ioc_search_fts(rowid, value, ioc_type) VALUES (new.id, new.value_search, new.ioc_type);
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS iocs_ad AFTER DELETE ON iocs BEGIN
                    INSERT INTO ioc_search_fts(ioc_search_fts, rowid, value, ioc_type)
                    VALUES ('delete', old.id, old.value_search, old.ioc_type);
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS iocs_au AFTER UPDATE ON iocs BEGIN
                    INSERT INTO ioc_search_fts(ioc_search_fts, rowid, value, ioc_type)
                    VALUES ('delete', old.id, old.value_search, old.ioc_type);
                    INSERT INTO ioc_search_fts(rowid, value, ioc_type) VALUES (new.id, new.value_search, new.ioc_type);
                END
                """,
            ),
        )
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        if dialect == "sqlite" and "iocs" in table_names:
            connection.execute(text("INSERT INTO ioc_search_fts(ioc_search_fts) VALUES ('rebuild')"))
