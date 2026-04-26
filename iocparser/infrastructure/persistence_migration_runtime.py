from __future__ import annotations

from sqlalchemy import Engine, inspect

from iocparser.infrastructure.persistence_migration_revisions import (
    CURRENT_SCHEMA_VERSION,
    SCHEMA_REVISIONS,
)
from iocparser.infrastructure.persistence_migration_steps import (
    FTS_TABLE,
    SCHEMA_VERSION_TABLE,
    create_latest_schema,
    current_version,
    ensure_version_table,
    missing_column_problems,
    missing_table_problems,
    stamp_version,
    upgrade_legacy_schema,
    upgrade_to_version,
)


def migrate_engine(engine: Engine) -> None:
    """Create or upgrade the persistence schema to the current version."""
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if not table_names:
        create_latest_schema(engine)
        inspector = inspect(engine)
        for revision in SCHEMA_REVISIONS:
            if revision.version <= 4:
                continue
            upgrade_to_version(engine, inspector, revision.version)
            inspector = inspect(engine)
        stamp_version(engine, CURRENT_SCHEMA_VERSION)
        return
    if SCHEMA_VERSION_TABLE not in table_names:
        ensure_version_table(engine)
        upgrade_legacy_schema(engine, inspector)
    current = current_version(engine)
    while current < CURRENT_SCHEMA_VERSION:
        next_version = current + 1
        upgrade_to_version(engine, inspector, next_version)
        stamp_version(engine, next_version)
        inspector = inspect(engine)
        current = next_version


def schema_version(engine: Engine) -> int:
    """Return the active schema version for an engine."""
    inspector = inspect(engine)
    if SCHEMA_VERSION_TABLE not in set(inspector.get_table_names()):
        return 0
    return current_version(engine)


def validate_schema(engine: Engine) -> list[str]:
    """Return drift problems between expected and actual schema state."""
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    problems = missing_table_problems(table_names)
    problems.extend(missing_column_problems(inspector, table_names))
    if engine.dialect.name == "sqlite" and FTS_TABLE not in table_names:
        problems.append(f"missing table: {FTS_TABLE}")
    version = schema_version(engine)
    if version != CURRENT_SCHEMA_VERSION:
        problems.append(f"schema version drift: current={version} expected={CURRENT_SCHEMA_VERSION}")
    return problems


__all__ = ["migrate_engine", "schema_version", "validate_schema"]
