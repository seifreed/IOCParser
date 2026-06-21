from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Iterable
from contextlib import nullcontext
from typing import Any, Protocol, cast, runtime_checkable

from sqlalchemy import Connection, Engine, Inspector, Select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from iocparser.domain.enums import ioc_type_name
from iocparser.domain.models import ExtractionResult
from iocparser.infrastructure.persistence_models import IOCModel, RunIOCModel, RunModel, SourceModel
from iocparser.shared_utils import refang_ioc

SOURCE_MODEL: type[SourceModel] = SourceModel
IOC_MODEL: type[IOCModel] = IOCModel
RUN_MODEL: type[RunModel] = RunModel
RUN_IOC_MODEL: type[RunIOCModel] = RunIOCModel
logger = logging.getLogger(__name__)


def insert_or_refetch[RowT](
    session: Session,
    entity: object,
    refetch_stmt: Select[RowT],
    *,
    on_insert: Callable[[], int],
    on_conflict: Callable[[RowT], int],
) -> int:
    """Insert ``entity`` inside a savepoint, refetching the row on a unique clash.

    On success ``on_insert`` supplies the new row id; on an ``IntegrityError`` the
    savepoint is rolled back, ``refetch_stmt`` is re-run, and ``on_conflict``
    reconciles the existing row and returns its id.
    """
    savepoint = session.begin_nested()
    try:
        session.add(entity)
        session.flush()
    except IntegrityError as exc:
        try:
            savepoint.rollback()
        except Exception as rollback_error:
            session.rollback()
            logger.exception("Savepoint rollback failed while retrying insert")
            raise exc from rollback_error
        with getattr(session, "no_autoflush", nullcontext()):
            rows = session.execute(refetch_stmt).scalars().all()
        if not rows:
            raise
        return on_conflict(rows[0])
    return on_insert()


def normalize_search(value: str | None) -> str:
    return (value or "").strip().lower()


def normalize_ioc_search(value: str | None) -> str:
    return refang_ioc(value or "").strip().lower()


def normalize_source_value(kind: str, value: str) -> str:
    return value.strip() if kind == "url" else value


def _dedup_hash(parts: tuple[str, ...]) -> str:
    """Stable hash of an identity tuple, NUL-joined so parts can't run together."""
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def ioc_dedup_hash(
    ioc_type: str, value: str, is_warning: bool, warning_list: str, warning_description: str
) -> str:
    """Identity hash for an IOC row.

    Replaces the multi-column UNIQUE(ioc_type, value, is_warning, warning_list,
    warning_description), which is invalid on MySQL/MariaDB because TEXT columns
    cannot participate in a key (and the combined length exceeds InnoDB's limit).
    """
    return _dedup_hash(
        (ioc_type, value, "1" if is_warning else "0", warning_list, warning_description)
    )


def source_dedup_hash(kind: str, value: str) -> str:
    """Identity hash for a source row (replaces UNIQUE(kind, value))."""
    return _dedup_hash((kind, normalize_source_value(kind, value)))


def _row_source_hash(row: Any) -> str:
    return source_dedup_hash(str(row.kind), str(row.value))


def _row_ioc_hash(row: Any) -> str:
    return ioc_dedup_hash(
        str(row.ioc_type),
        str(row.value),
        bool(row.is_warning),
        str(row.warning_list),
        str(row.warning_description),
    )


_DEDUP_BACKFILL_PLAN = (
    ("sources", "uq_sources_dedup_hash", _row_source_hash),
    ("iocs", "uq_iocs_dedup_hash", _row_ioc_hash),
)

# Literal backfill SQL per table. Built from constants (never user input) so the
# query carries no string interpolation -- safe by construction, no SQL injection.
_DEDUP_BACKFILL_SQL: dict[str, tuple[str, str]] = {
    "sources": (
        "SELECT id, kind, value FROM sources WHERE dedup_hash = ''",
        "UPDATE sources SET dedup_hash = :h WHERE id = :id",
    ),
    "iocs": (
        "SELECT id, ioc_type, value, is_warning, warning_list, warning_description "
        "FROM iocs WHERE dedup_hash = ''",
        "UPDATE iocs SET dedup_hash = :h WHERE id = :id",
    ),
}


# Literal collision-resolution SQL (constants, never interpolated -> injection-safe).
# Before collapsing rows that newly collide on the normalized dedup_hash, each
# repoint statement points its referencing table at the lowest-id survivor of the
# group; it only runs when that referencing table exists. The delete then keeps one
# row per dedup_hash.
_DEDUP_REPOINT_SQL: dict[str, tuple[tuple[str, str], ...]] = {
    "sources": (
        (
            "runs",
            "UPDATE runs SET source_id = "
            "(SELECT MIN(survivor.id) FROM sources survivor "
            " WHERE survivor.dedup_hash = "
            "  (SELECT ref.dedup_hash FROM sources ref WHERE ref.id = runs.source_id)) "
            "WHERE source_id NOT IN (SELECT MIN(id) FROM sources GROUP BY dedup_hash)",
        ),
    ),
    "iocs": (),
}
_DEDUP_DELETE_SQL: dict[str, str] = {
    "sources": (
        "DELETE FROM sources WHERE id NOT IN (SELECT MIN(id) FROM sources GROUP BY dedup_hash)"
    ),
    "iocs": "DELETE FROM iocs WHERE id NOT IN (SELECT MIN(id) FROM iocs GROUP BY dedup_hash)",
}


def _collapse_dedup_collisions(
    connection: Connection, table: str, existing_tables: set[str]
) -> None:
    """Merge legacy rows that collide on the new normalized dedup_hash.

    The old UNIQUE constraints spanned raw columns, so e.g. two ``url`` sources
    differing only by surrounding whitespace were distinct rows but now hash the
    same. Repoint referencing rows to the lowest-id survivor, then drop the rest,
    so CREATE UNIQUE INDEX does not abort the whole upgrade.
    """
    for dependent_table, statement in _DEDUP_REPOINT_SQL[table]:
        if dependent_table in existing_tables:
            connection.execute(text(statement))
    connection.execute(text(_DEDUP_DELETE_SQL[table]))


def _has_dedup_column(inspector: Inspector, table: str) -> bool:
    return any(col["name"] == "dedup_hash" for col in inspector.get_columns(table))


def _has_unique_key(inspector: Inspector, table: str, name: str) -> bool:
    names = {idx["name"] for idx in inspector.get_indexes(table)}
    names.update(uc["name"] for uc in inspector.get_unique_constraints(table))
    return name in names


def _backfill_dedup_hash(
    connection: Connection,
    table: str,
    hasher: Callable[[Any], str],
) -> None:
    select_sql, update_sql = _DEDUP_BACKFILL_SQL[table]
    rows = cast("list[Any]", connection.execute(text(select_sql)).all())
    for row in rows:
        connection.execute(text(update_sql), {"h": hasher(row), "id": row.id})


def backfill_dedup_hash_columns(engine: Engine, inspector: Inspector) -> None:
    """Add and backfill the dedup_hash uniqueness column for iocs and sources.

    The original UNIQUE constraints spanned TEXT columns, which cannot form a key
    on MySQL/MariaDB; fresh databases get dedup_hash from create_all, this migrates
    legacy SQLite ones. Idempotent and dialect-safe; reflection is resolved before
    the transaction so it cannot disturb the uncommitted ALTER/backfill.
    """
    tables = set(inspector.get_table_names())
    steps = [
        (
            table,
            key,
            hasher,
            _has_dedup_column(inspector, table),
            _has_unique_key(inspector, table, key),
        )
        for table, key, hasher in _DEDUP_BACKFILL_PLAN
        if table in tables
    ]
    with engine.begin() as connection:
        for table, key, hasher, has_column, has_key in steps:
            if not has_column:
                connection.execute(
                    text(
                        f"ALTER TABLE {table} ADD COLUMN dedup_hash VARCHAR(64) NOT NULL DEFAULT ''"
                    )
                )
            _backfill_dedup_hash(connection, table, hasher)
            if not has_key:
                _collapse_dedup_collisions(connection, table, tables)
                connection.execute(text(f"CREATE UNIQUE INDEX {key} ON {table}(dedup_hash)"))


def quote_identifier(dialect_name: str, identifier: str) -> str:
    """Quote a SQL identifier for the given dialect (e.g. the reserved word 'key').

    MySQL/MariaDB use backticks; SQLite and the SQL standard use double quotes.
    """
    if dialect_name in {"mysql", "mariadb"}:
        return f"`{identifier}`"
    return f'"{identifier}"'


def dialect_replace_into(dialect_name: str, table_and_columns: str) -> str:
    """Return a primary-key upsert statement valid for the given SQL dialect.

    SQLite uses ``INSERT OR REPLACE``; MySQL/MariaDB reject ``OR REPLACE`` and use
    ``REPLACE INTO``. Both are delete-then-insert upserts on the primary key, so
    the hard-coded SQLite form broke every migration/history write on MariaDB.
    """
    if dialect_name in {"mysql", "mariadb"}:
        return f"REPLACE INTO {table_and_columns}"
    return f"INSERT OR REPLACE INTO {table_and_columns}"


def int_metadata_value(metadata: dict[str, int | str | None], key: str, default: int) -> int:
    raw_value = metadata.get(key)
    if raw_value is None:
        return default
    if isinstance(raw_value, bool):
        return default
    if isinstance(raw_value, int):
        return raw_value if raw_value >= 0 else default
    stripped = raw_value.strip()
    if not stripped:
        return default
    try:
        parsed = int(stripped)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def optional_int_metadata_value(metadata: dict[str, int | str | None], key: str) -> int | None:
    raw_value = metadata.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        return None
    if isinstance(raw_value, int):
        return raw_value if raw_value >= 0 else None
    stripped = raw_value.strip()
    if not stripped:
        return None
    try:
        parsed = int(stripped)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def string_metadata_value(metadata: dict[str, int | str | None], key: str, default: str) -> str:
    raw_value = metadata.get(key)
    if raw_value is None:
        return default
    if not isinstance(raw_value, str):
        raise TypeError(f"Expected {key} to be string, got {type(raw_value).__name__}")
    stripped = raw_value.strip()
    return stripped or default


class IndicatorValueLike(Protocol):
    raw: str


class IOCTypeLike(Protocol):
    value: str


def normalized_ioc_type_name(value: IOCTypeLike | str) -> str:
    if isinstance(value, str):
        return ioc_type_name(value)
    return ioc_type_name(value.value)


class EvidenceLike(Protocol):
    excerpt: str
    line_number: int | None
    source: str


class IOCMetadataLike(Protocol):
    @property
    def ioc_type(self) -> IOCTypeLike: ...

    @property
    def value(self) -> IndicatorValueLike: ...

    @property
    def severity(self) -> str: ...

    @property
    def tags(self) -> tuple[str, ...]: ...

    @property
    def evidence(self) -> tuple[EvidenceLike, ...]: ...


@runtime_checkable
class WarningMatchLike(Protocol):
    @property
    def ioc(self) -> IOCMetadataLike: ...

    @property
    def warning_list(self) -> str: ...

    @property
    def description(self) -> str: ...


class ExtractionResultLike(Protocol):
    @property
    def iocs(self) -> tuple[IOCMetadataLike, ...]: ...

    @property
    def warnings(self) -> tuple[WarningMatchLike, ...]: ...


class PersistOptionsLike(Protocol):
    def to_dict(self) -> dict[str, bool | str]: ...


type MetadataItem = IOCMetadataLike | WarningMatchLike


def metadata_ioc(item: MetadataItem) -> IOCMetadataLike:
    return item.ioc if isinstance(item, WarningMatchLike) else item


def serialize_tags(tags: tuple[str, ...]) -> str:
    serialized_tags: list[str] = []
    serialized_tags.extend(tags)
    return json.dumps(serialized_tags)


# Tags are joined into a single searchable column. A plain space delimiter is
# ambiguous because a tag may itself contain spaces (custom IOC types inject
# their name/tags verbatim), so a search for "network" would wrongly match the
# compound tag "internal network". Wrap and join with a control character that
# cannot occur in a normalized tag, and match on delimiter-bounded substrings.
TAG_SEARCH_DELIMITER = "\x1f"


def build_tags_search(tags: Iterable[str]) -> str:
    """Build the delimiter-wrapped searchable tags string for a run-IOC row."""
    cleaned = sorted({tag.strip().lower() for tag in tags if tag.strip()})
    if not cleaned:
        return ""
    return TAG_SEARCH_DELIMITER + TAG_SEARCH_DELIMITER.join(cleaned) + TAG_SEARCH_DELIMITER


def tags_from_json(raw: object) -> list[str]:
    """Parse a tags_json column into a list of tag strings, tolerating bad data."""
    try:
        parsed = json.loads(raw) if isinstance(raw, str) and raw else []
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [tag for tag in parsed if isinstance(tag, str)]


def rebuild_tags_search(engine: Engine, inspector: Inspector) -> None:
    """Recompute run_iocs.tags_search using the delimiter-wrapped format."""
    if "run_iocs" not in set(inspector.get_table_names()):
        return
    with engine.begin() as connection:
        rows = cast(
            "list[Any]", connection.execute(text("SELECT id, tags_json FROM run_iocs")).all()
        )
        for row in rows:
            connection.execute(
                text("UPDATE run_iocs SET tags_search = :value WHERE id = :id"),
                {"value": build_tags_search(tags_from_json(row.tags_json)), "id": row.id},
            )


def rebuild_ioc_value_search(engine: Engine, inspector: Inspector) -> None:
    """Recompute iocs.value_search with the refanged normalization the live path uses.

    The v3 SQL backfill set value_search = lower(trim(value)) without refanging, so a
    legacy defanged IOC (e.g. ``hxxp://evil.com``) was indexed as ``hxxp://evil.com``
    while search refangs the query to ``http://evil.com`` -- making the IOC
    unsearchable by its real value. Recompute in Python and resync the FTS index,
    which is populated from value_search.
    """
    from iocparser.infrastructure.persistence_fts import FTS_TABLE, rebuild_fts_statements

    table_names = set(inspector.get_table_names())
    if "iocs" not in table_names:
        return
    with engine.begin() as connection:
        rows = cast("list[Any]", connection.execute(text("SELECT id, value FROM iocs")).all())
        for row in rows:
            connection.execute(
                text("UPDATE iocs SET value_search = :value WHERE id = :id"),
                {"value": normalize_ioc_search(row.value), "id": row.id},
            )
        if FTS_TABLE in table_names:
            for statement in rebuild_fts_statements():
                connection.execute(text(statement))


def serialize_evidence(evidence_items: tuple[EvidenceLike, ...]) -> str:
    evidence_records: list[dict[str, str | int | None]] = []
    for evidence in evidence_items:
        evidence_records.append(
            {
                "excerpt": evidence.excerpt,
                "line_number": evidence.line_number,
                "source": evidence.source,
            }
        )
    return json.dumps(evidence_records)


def result_items(result: ExtractionResultLike | ExtractionResult | None) -> list[MetadataItem]:
    if result is None:
        return []
    normal_items: list[MetadataItem] = [cast("MetadataItem", ioc) for ioc in result.iocs]
    warning_items: list[MetadataItem] = [
        cast("MetadataItem", warning) for warning in result.warnings
    ]
    return normal_items + warning_items


_IOCMetadataLike = IOCMetadataLike
_WarningMatchLike = WarningMatchLike
_int_metadata_value = int_metadata_value
_optional_int_metadata_value = optional_int_metadata_value
_ioc_type_name = normalized_ioc_type_name
