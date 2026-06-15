from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SchemaRevision:
    """Formal schema revision record."""

    version: int
    name: str
    description: str


SCHEMA_REVISIONS = (
    SchemaRevision(1, "baseline", "Initial persistence schema"),
    SchemaRevision(2, "run-status", "Run status and error message columns"),
    SchemaRevision(3, "search-indexes", "Normalized search columns and indexes"),
    SchemaRevision(4, "batch-jobs", "Batch jobs, failed items, and run batch linkage"),
    SchemaRevision(5, "fts-batch-metrics", "SQLite FTS IOC index and batch metrics"),
    SchemaRevision(6, "search-scale", "Additional search and batch indexes for large histories"),
    SchemaRevision(
        7, "distributed-jobs", "Distributed queue lifecycle and dead-letter persistence"
    ),
    SchemaRevision(
        8, "history-origin", "Stable history origin metadata for export/import identity"
    ),
    SchemaRevision(
        9, "dedup-hash", "Hash-based IOC/source uniqueness for MySQL/MariaDB compatibility"
    ),
)

CURRENT_SCHEMA_VERSION = SCHEMA_REVISIONS[-1].version


def revision_history() -> tuple[SchemaRevision, ...]:
    """Return known schema revisions."""
    return SCHEMA_REVISIONS


__all__ = ["CURRENT_SCHEMA_VERSION", "SCHEMA_REVISIONS", "SchemaRevision", "revision_history"]
