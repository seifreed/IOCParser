from __future__ import annotations

from sqlalchemy import inspect

from iocparser.infrastructure.persistence_migration_revisions import (
    CURRENT_SCHEMA_VERSION,
    SCHEMA_REVISIONS,
    SchemaRevision,
    revision_history,
)
from iocparser.infrastructure.persistence_migration_runtime import (
    migrate_engine,
    schema_version,
    validate_schema,
)
from iocparser.infrastructure.persistence_migration_steps import (
    FTS_TABLE,
)
from iocparser.infrastructure.persistence_migration_steps import (
    has_column as _has_column,
)
from iocparser.infrastructure.persistence_migration_steps import (
    upgrade_to_v2 as _upgrade_to_v2,
)


def migrate_db_uri(db_uri: str) -> int:
    """Upgrade a database URI and return the resulting schema version."""
    from sqlalchemy import create_engine

    engine = create_engine(db_uri, future=True)
    try:
        migrate_engine(engine)
        return schema_version(engine)
    finally:
        engine.dispose()


__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "FTS_TABLE",
    "SCHEMA_REVISIONS",
    "SchemaRevision",
    "_has_column",
    "_upgrade_to_v2",
    "inspect",
    "migrate_db_uri",
    "migrate_engine",
    "revision_history",
    "schema_version",
    "validate_schema",
]
