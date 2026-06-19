from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from iocparser.domain.results import ExtractionResult

RESULT_SCHEMA_VERSION = "1.0"
BATCH_REPORT_SCHEMA_VERSION = "1.0"
PIPELINE_JOB_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class ResourceLimits:
    """Operational limits for pipeline execution."""

    max_input_size_bytes: int | None = None
    max_input_seconds: float | None = None
    memory_limit_bytes: int | None = None
    cpu_seconds: int | None = None
    hard_timeout_seconds: int | None = None
    max_workers: int = 4
    max_queue_size: int = 64
    skip_processed: bool = False

    def __post_init__(self) -> None:
        if self.max_input_size_bytes is not None and self.max_input_size_bytes < 0:
            object.__setattr__(self, "max_input_size_bytes", None)
        if self.max_input_seconds is not None and self.max_input_seconds < 0:
            object.__setattr__(self, "max_input_seconds", None)
        if self.max_workers <= 0:
            object.__setattr__(self, "max_workers", 1)
        if self.max_queue_size <= 0:
            object.__setattr__(self, "max_queue_size", 64)


@dataclass(frozen=True)
class PipelineErrorInfo:
    """Stable machine-readable error description."""

    code: str
    category: str
    retryable: bool
    status: str
    message: str

    def to_record(self) -> dict[str, object]:
        return {
            "code": self.code,
            "category": self.category,
            "retryable": self.retryable,
            "status": self.status,
            "message": self.message,
        }


@dataclass(frozen=True)
class PipelineJobRequest:
    """Structured integration request for worker-driven execution."""

    input_kind: str
    source_value: str
    file_type: str | None = None
    persist: bool = False
    db_uri: str | None = None
    check_warnings: bool = True
    force_update: bool = False
    defang: bool = True
    only: str | None = None
    exclude: str | None = None
    correlation_id: str | None = None
    job_id: str | None = None
    emit_only: bool = False

    def __post_init__(self) -> None:
        def _require_str(value: object, *, field: str) -> str:
            if not isinstance(value, str):
                raise TypeError(f"Expected {field} to be string-like, got {type(value).__name__}")
            stripped = value.strip()
            if not stripped:
                raise TypeError(f"Expected {field} to be non-empty string-like")
            return stripped

        def _require_bool(value: object, *, field: str) -> bool:
            if not isinstance(value, bool):
                raise TypeError(f"Expected {field} to be bool, got {type(value).__name__}")
            return value

        object.__setattr__(self, "input_kind", _require_str(self.input_kind, field="input_kind"))
        object.__setattr__(self, "source_value", _require_str(self.source_value, field="source_value"))
        if self.file_type is not None:
            object.__setattr__(self, "file_type", _require_str(self.file_type, field="file_type"))
        if self.db_uri is not None:
            object.__setattr__(self, "db_uri", _require_str(self.db_uri, field="db_uri"))
        object.__setattr__(self, "persist", _require_bool(self.persist, field="persist"))
        object.__setattr__(
            self, "check_warnings", _require_bool(self.check_warnings, field="check_warnings")
        )
        object.__setattr__(
            self, "force_update", _require_bool(self.force_update, field="force_update")
        )
        object.__setattr__(self, "defang", _require_bool(self.defang, field="defang"))
        if self.only is not None:
            object.__setattr__(self, "only", _require_str(self.only, field="only"))
        if self.exclude is not None:
            object.__setattr__(self, "exclude", _require_str(self.exclude, field="exclude"))
        if self.correlation_id is not None:
            object.__setattr__(
                self, "correlation_id", _require_str(self.correlation_id, field="correlation_id")
            )
        if self.job_id is not None:
            object.__setattr__(self, "job_id", _require_str(self.job_id, field="job_id"))
        object.__setattr__(self, "emit_only", _require_bool(self.emit_only, field="emit_only"))


@dataclass(frozen=True)
class PipelineJobResult:
    """Structured integration result for pipeline execution."""

    input_kind: str
    source_value: str
    status: str
    result: ExtractionResult
    correlation_id: str
    job_id: str
    schema_version: str = PIPELINE_JOB_SCHEMA_VERSION
    run_id: int | None = None
    skipped: bool = False
    fingerprint: str | None = None
    content_hash: str | None = None
    duration_ms: int = 0
    phase_timings_ms: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, object] = field(default_factory=dict)
    error: PipelineErrorInfo | None = None
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "correlation_id": self.correlation_id,
            "input_kind": self.input_kind,
            "source_value": self.source_value,
            "status": self.status,
            "skipped": self.skipped,
            "run_id": self.run_id,
            "fingerprint": self.fingerprint,
            "content_hash": self.content_hash,
            "duration_ms": self.duration_ms,
            "phase_timings_ms": dict(self.phase_timings_ms),
            "metadata": dict(self.metadata),
            "error": self.error.to_record() if self.error is not None else None,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": {
                "schema_version": RESULT_SCHEMA_VERSION,
                "records": self.result.to_records(),
                "counts_by_type": self.result.counts_by_type(),
                "total_count": self.result.total_count(),
            },
        }
