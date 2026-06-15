from __future__ import annotations

from sqlalchemy import Engine, Inspector

from iocparser.infrastructure.persistence_repository_support import backfill_dedup_hash_columns


def apply(engine: Engine, inspector: Inspector) -> None:
    """Add hash-based IOC/source uniqueness (MySQL/MariaDB compatible)."""
    backfill_dedup_hash_columns(engine, inspector)
