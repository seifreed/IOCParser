from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


def _require_str(value: object, *, field: str, non_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Expected {field} to be string-like, got {type(value).__name__}")
    if non_empty:
        stripped = value.strip()
        if not stripped:
            raise TypeError(f"Expected {field} to be non-empty string-like")
        return stripped
    return value


@dataclass(frozen=True)
class FailedBatchItem:
    """Structured failed item from a persisted batch job."""

    batch_job_id: int
    source_value: str
    error_type: str
    error_message: str
    retry_attempt: int
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_value", _require_str(self.source_value, field="source_value", non_empty=True))
        object.__setattr__(self, "error_type", _require_str(self.error_type, field="error_type", non_empty=True))
        object.__setattr__(self, "error_message", _require_str(self.error_message, field="error_message"))

    def to_record(self) -> dict[str, object]:
        return {
            "batch_job_id": self.batch_job_id,
            "source_value": self.source_value,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "retry_attempt": self.retry_attempt,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class BatchJobSummary:
    """Summary of a persisted batch job."""

    batch_job_id: int
    source_kind: str
    started_at: datetime
    finished_at: datetime
    total_inputs: int
    successful_inputs: int
    failed_inputs: int
    retry_attempt: int
    status: str
    error_summary: dict[str, int]
    failed_item_count: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_kind", _require_str(self.source_kind, field="source_kind", non_empty=True))
        object.__setattr__(self, "status", _require_str(self.status, field="status", non_empty=True))

    def to_record(self) -> dict[str, object]:
        return {
            "batch_job_id": self.batch_job_id,
            "source_kind": self.source_kind,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "total_inputs": self.total_inputs,
            "successful_inputs": self.successful_inputs,
            "failed_inputs": self.failed_inputs,
            "retry_attempt": self.retry_attempt,
            "status": self.status,
            "error_summary": dict(self.error_summary),
            "failed_item_count": self.failed_item_count,
        }


@dataclass(frozen=True)
class BatchJobDetail:
    """Detailed persisted batch job view."""

    batch_job_id: int
    source_kind: str
    status: str
    started_at: datetime
    finished_at: datetime
    total_inputs: int
    successful_inputs: int
    failed_inputs: int
    retry_attempt: int
    error_summary: dict[str, int]
    effective_config: dict[str, object]
    metrics: dict[str, object]
    failed_item_count: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_kind", _require_str(self.source_kind, field="source_kind", non_empty=True))
        object.__setattr__(self, "status", _require_str(self.status, field="status", non_empty=True))

    def to_record(self) -> dict[str, object]:
        return {
            "batch_job_id": self.batch_job_id,
            "source_kind": self.source_kind,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "total_inputs": self.total_inputs,
            "successful_inputs": self.successful_inputs,
            "failed_inputs": self.failed_inputs,
            "retry_attempt": self.retry_attempt,
            "error_summary": dict(self.error_summary),
            "effective_config": dict(self.effective_config),
            "metrics": dict(self.metrics),
            "failed_item_count": self.failed_item_count,
        }


@dataclass(frozen=True)
class BatchDashboardWindow:
    """Aggregated batch metrics for a time bucket."""

    started_at: str
    total_jobs: int
    failed_jobs: int
    partial_jobs: int
    failure_rate: float
    average_duration_ms: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "started_at", _require_str(self.started_at, field="started_at", non_empty=True))

    def to_record(self) -> dict[str, object]:
        return {
            "started_at": self.started_at,
            "total_jobs": self.total_jobs,
            "failed_jobs": self.failed_jobs,
            "partial_jobs": self.partial_jobs,
            "failure_rate": self.failure_rate,
            "average_duration_ms": self.average_duration_ms,
        }


@dataclass(frozen=True)
class BatchDashboard:
    """Historical batch dashboard view for operators."""

    lookback_hours: int
    group_by: str
    total_jobs: int
    failed_jobs: int
    partial_jobs: int
    failure_rate: float
    alerts: tuple[str, ...]
    windows: tuple[BatchDashboardWindow, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "group_by", _require_str(self.group_by, field="group_by", non_empty=True))

    def to_record(self) -> dict[str, object]:
        return {
            "lookback_hours": self.lookback_hours,
            "group_by": self.group_by,
            "total_jobs": self.total_jobs,
            "failed_jobs": self.failed_jobs,
            "partial_jobs": self.partial_jobs,
            "failure_rate": self.failure_rate,
            "alerts": list(self.alerts),
            "windows": [window.to_record() for window in self.windows],
        }
