from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast, runtime_checkable

from sqlalchemy import Select
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
    except IntegrityError:
        try:
            savepoint.rollback()
        except Exception:
            session.rollback()
            raise
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
    return str(raw_value)


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


def finished_at_from_duration(duration_ms: int) -> datetime:
    started_at = datetime.now(UTC)
    return started_at + timedelta(milliseconds=duration_ms)


_IOCMetadataLike = IOCMetadataLike
_WarningMatchLike = WarningMatchLike
_int_metadata_value = int_metadata_value
_optional_int_metadata_value = optional_int_metadata_value
_ioc_type_name = normalized_ioc_type_name
