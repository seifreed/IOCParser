from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast, runtime_checkable

from iocparser.domain.enums import ioc_type_name
from iocparser.domain.models import ExtractionResult
from iocparser.infrastructure.persistence_models import IOCModel, RunIOCModel, RunModel, SourceModel

SOURCE_MODEL: type[SourceModel] = SourceModel
IOC_MODEL: type[IOCModel] = IOCModel
RUN_MODEL: type[RunModel] = RunModel
RUN_IOC_MODEL: type[RunIOCModel] = RunIOCModel


def normalize_search(value: str | None) -> str:
    return (value or "").strip().lower()


def int_metadata_value(metadata: dict[str, int | str | None], key: str, default: int) -> int:
    raw_value = metadata.get(key)
    if raw_value is None:
        return default
    if isinstance(raw_value, int):
        return raw_value
    return int(raw_value)


def optional_int_metadata_value(metadata: dict[str, int | str | None], key: str) -> int | None:
    raw_value = metadata.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, int):
        return raw_value
    return int(raw_value)


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
