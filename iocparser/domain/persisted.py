from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from iocparser.domain.enums import ioc_type_name
from iocparser.domain.pipeline import RESULT_SCHEMA_VERSION
from iocparser.domain.results import ExtractionResult
from iocparser.errors import TypeValidationError


def _require_str(value: object, *, field: str, non_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeValidationError(field, "string-like", value)
    if non_empty:
        stripped = value.strip()
        if not stripped:
            raise TypeValidationError(field, "non-empty string-like")
        return stripped
    return value


@dataclass(frozen=True)
class PersistedRunSummary:
    """Summary record for a persisted extraction run."""

    run_id: int
    source_kind: str
    source_value: str
    tool_version: str
    started_at: datetime
    finished_at: datetime
    normal_ioc_count: int = 0
    warning_ioc_count: int = 0
    counts_by_type: dict[str, int] | None = None
    original_url: str | None = None
    normalized_url: str | None = None
    mime_type: str | None = None
    input_size: int | None = None
    content_hash: str | None = None
    fingerprint: str | None = None
    duration_ms: int | None = None
    processed_items: int = 1
    successful_items: int = 1
    failed_items: int = 0
    partial_error_count: int = 0
    status: str = "success"
    error_message: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_kind", _require_str(self.source_kind, field="source_kind", non_empty=True))
        object.__setattr__(self, "source_value", _require_str(self.source_value, field="source_value", non_empty=True))
        object.__setattr__(self, "tool_version", _require_str(self.tool_version, field="tool_version", non_empty=True))
        object.__setattr__(self, "status", _require_str(self.status, field="status", non_empty=True))
        if self.original_url is not None:
            object.__setattr__(self, "original_url", _require_str(self.original_url, field="original_url"))
        if self.normalized_url is not None:
            object.__setattr__(self, "normalized_url", _require_str(self.normalized_url, field="normalized_url"))
        if self.mime_type is not None:
            object.__setattr__(self, "mime_type", _require_str(self.mime_type, field="mime_type"))
        if self.content_hash is not None:
            object.__setattr__(self, "content_hash", _require_str(self.content_hash, field="content_hash"))
        if self.fingerprint is not None:
            object.__setattr__(self, "fingerprint", _require_str(self.fingerprint, field="fingerprint"))

    def to_record(self) -> dict[str, object]:
        """Serialize the summary into a structured record."""
        return {
            "run_id": self.run_id,
            "source_kind": self.source_kind,
            "source_value": self.source_value,
            "tool_version": self.tool_version,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "normal_ioc_count": self.normal_ioc_count,
            "warning_ioc_count": self.warning_ioc_count,
            "counts_by_type": dict(self.counts_by_type or {}),
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,
            "mime_type": self.mime_type,
            "input_size": self.input_size,
            "content_hash": self.content_hash,
            "fingerprint": self.fingerprint,
            "duration_ms": self.duration_ms,
            "processed_items": self.processed_items,
            "successful_items": self.successful_items,
            "failed_items": self.failed_items,
            "partial_error_count": self.partial_error_count,
            "status": self.status,
            "error_message": self.error_message,
        }


@dataclass(frozen=True)
class PersistedRunQueryHit:
    """Query hit for persisted IOCs."""

    run_id: int
    source_kind: str
    source_value: str
    ioc_type: str
    value: str
    is_warning: bool
    severity: str = ""
    tags: tuple[str, ...] = ()
    evidence: tuple[dict[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_kind", _require_str(self.source_kind, field="source_kind", non_empty=True))
        object.__setattr__(self, "source_value", _require_str(self.source_value, field="source_value", non_empty=True))
        object.__setattr__(self, "ioc_type", _require_str(self.ioc_type, field="ioc_type", non_empty=True))
        object.__setattr__(self, "value", _require_str(self.value, field="value", non_empty=True))
        if self.severity is not None:
            object.__setattr__(self, "severity", _require_str(self.severity, field="severity"))

    def to_record(self) -> dict[str, object]:
        """Serialize the query hit into a structured record."""
        return {
            "run_id": self.run_id,
            "source_kind": self.source_kind,
            "source_value": self.source_value,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "is_warning": self.is_warning,
            "severity": self.severity,
            "tags": list(self.tags),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class PersistedRunExport:
    """Exportable persisted run payload."""

    summary: PersistedRunSummary
    result: ExtractionResult

    def to_record(self) -> dict[str, object]:
        """Serialize the export into a structured record."""
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "summary": self.summary.to_record(),
            "result": self.result.to_records(),
        }


@dataclass(frozen=True)
class PersistedRunDiff:
    """Difference between two persisted runs."""

    left_run_id: int
    right_run_id: int
    added: ExtractionResult
    removed: ExtractionResult
    compared_to_previous_source_run_id: int | None = None

    @property
    def added_counts(self) -> dict[str, int]:
        return self.added.counts_by_type(include_warnings=False)

    @property
    def removed_counts(self) -> dict[str, int]:
        return self.removed.counts_by_type(include_warnings=False)

    @property
    def added_warning_counts(self) -> dict[str, int]:
        counter: Counter[str] = Counter(
            ioc_type_name(warning.ioc.ioc_type) for warning in self.added.warnings
        )
        return dict(sorted(counter.items()))

    @property
    def removed_warning_counts(self) -> dict[str, int]:
        counter: Counter[str] = Counter(
            ioc_type_name(warning.ioc.ioc_type) for warning in self.removed.warnings
        )
        return dict(sorted(counter.items()))

    def to_record(self) -> dict[str, object]:
        """Serialize the diff into a structured record."""
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "left_run_id": self.left_run_id,
            "right_run_id": self.right_run_id,
            "compared_to_previous_source_run_id": self.compared_to_previous_source_run_id,
            "added": self.added.to_records(),
            "removed": self.removed.to_records(),
            "added_counts": self.added_counts,
            "removed_counts": self.removed_counts,
            "added_warning_counts": self.added_warning_counts,
            "removed_warning_counts": self.removed_warning_counts,
        }


@dataclass(frozen=True)
class PersistedRun:
    """Return object for persistence operations."""

    run_id: int


@dataclass(frozen=True)
class PersistedRunsPage:
    """Paginated persisted-run listing."""

    items: tuple[PersistedRunSummary, ...]
    total: int
    limit: int
    offset: int

    @property
    def has_next(self) -> bool:
        return self.offset + len(self.items) < self.total

    @property
    def page(self) -> int:
        return (self.offset // self.limit) + 1 if self.limit > 0 else 1

    def to_record(self) -> dict[str, object]:
        """Serialize the paginated listing into a structured record."""
        return {
            "items": [item.to_record() for item in self.items],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
            "has_next": self.has_next,
            "page": self.page,
        }


@dataclass(frozen=True)
class PersistedIOCSearchPage:
    """Paginated persisted IOC search result."""

    items: tuple[PersistedRunQueryHit, ...]
    total: int
    limit: int
    offset: int

    @property
    def has_next(self) -> bool:
        return self.offset + len(self.items) < self.total

    @property
    def page(self) -> int:
        return (self.offset // self.limit) + 1 if self.limit > 0 else 1

    def to_record(self) -> dict[str, object]:
        """Serialize the paginated search into a structured record."""
        return {
            "items": [item.to_record() for item in self.items],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
            "has_next": self.has_next,
            "page": self.page,
        }
