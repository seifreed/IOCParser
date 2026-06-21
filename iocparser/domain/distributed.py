from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

from iocparser.domain.pipeline import (
    PIPELINE_JOB_SCHEMA_VERSION,
    PipelineErrorInfo,
    PipelineJobRequest,
)
from iocparser.errors import NonNegativeValueError, RetryCounterError, TypeValidationError
from iocparser.shared_utils import parse_bool_token

DISTRIBUTED_JOB_SCHEMA_VERSION = "1.0"
JOB_STATUS_QUEUED = "queued"
JOB_STATUS_RUNNING = "running"
JOB_STATUS_COMPLETED = "completed"
JOB_STATUS_FAILED = "failed"
JOB_STATUS_DEAD_LETTERED = "dead-lettered"
TERMINAL_JOB_STATUSES = (JOB_STATUS_COMPLETED, JOB_STATUS_FAILED, JOB_STATUS_DEAD_LETTERED)


def _invalid_int_payload_value(*, key: str, raw_value: object) -> TypeError:
    return TypeError(f"Expected {key} to be int-compatible, got {type(raw_value).__name__}")


def _invalid_bool_payload_value(*, key: str, raw_value: object) -> TypeError:
    return TypeError(f"Expected {key} to be bool-compatible, got {type(raw_value).__name__}")


def _int_from_payload(payload: dict[str, object], key: str, default: int) -> int:
    raw_value = payload.get(key)
    if raw_value is None:
        return default
    if isinstance(raw_value, bool):
        raise _invalid_int_payload_value(key=key, raw_value=raw_value)
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, str):
        try:
            return int(raw_value)
        except ValueError as exc:
            raise _invalid_int_payload_value(key=key, raw_value=raw_value) from exc
    raise _invalid_int_payload_value(key=key, raw_value=raw_value)


def _bool_from_payload(payload: dict[str, object], key: str, default: bool) -> bool:
    raw_value = payload.get(key)
    if raw_value is None:
        return default
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, int) and raw_value in {0, 1}:
        return bool(raw_value)
    if isinstance(raw_value, str):
        parsed = parse_bool_token(raw_value)
        if parsed is not None:
            return parsed
    raise _invalid_bool_payload_value(key=key, raw_value=raw_value)


def _require_str(value: object, *, field: str, non_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeValidationError(field, "string-like", value)
    if non_empty:
        stripped = value.strip()
        if not stripped:
            raise TypeValidationError(field, "non-empty string-like")
        return stripped
    return value


def _require_int(value: object, *, field: str, non_negative: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeValidationError(field, "int-like", value)
    if non_negative and value < 0:
        raise NonNegativeValueError(field)
    return value


@dataclass(frozen=True)
class QueueEnvelope:
    """Machine-readable queue message for distributed processing."""

    request: PipelineJobRequest
    queue_backend: str
    queue_name: str
    attempts: int = 0
    max_attempts: int = 3
    idempotency_key: str | None = None
    schema_version: str = PIPELINE_JOB_SCHEMA_VERSION
    submitted_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        queue_backend = _require_str(self.queue_backend, field="queue_backend", non_empty=True).strip().lower()
        queue_name = _require_str(self.queue_name, field="queue_name", non_empty=True).strip()
        object.__setattr__(
            self, "queue_backend", queue_backend
        )
        object.__setattr__(self, "queue_name", queue_name)
        object.__setattr__(
            self, "schema_version", _require_str(self.schema_version, field="schema_version", non_empty=True)
        )
        object.__setattr__(
            self, "submitted_at", _require_str(self.submitted_at, field="submitted_at", non_empty=True)
        )
        object.__setattr__(self, "attempts", _require_int(self.attempts, field="attempts", non_negative=True))
        object.__setattr__(
            self, "max_attempts", _require_int(self.max_attempts, field="max_attempts", non_negative=True)
        )
        if self.idempotency_key is not None:
            object.__setattr__(self, "idempotency_key", _require_str(self.idempotency_key, field="idempotency_key"))
        if self.max_attempts <= 0:
            raise RetryCounterError

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "queue_backend": self.queue_backend,
            "queue_name": self.queue_name,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "idempotency_key": self.idempotency_key,
            "submitted_at": self.submitted_at,
            "request": {
                "input_kind": self.request.input_kind,
                "source_value": self.request.source_value,
                "file_type": self.request.file_type,
                "persist": self.request.persist,
                "db_uri": self.request.db_uri,
                "check_warnings": self.request.check_warnings,
                "force_update": self.request.force_update,
                "defang": self.request.defang,
                "only": self.request.only,
                "exclude": self.request.exclude,
                "correlation_id": self.request.correlation_id,
                "job_id": self.request.job_id,
                "emit_only": self.request.emit_only,
            },
        }

    @classmethod
    def from_record(cls, payload: dict[str, object]) -> QueueEnvelope:
        request_payload = payload.get("request", {})
        if not isinstance(request_payload, dict):
            request_payload = {}
        return cls(
            request=PipelineJobRequest(
                input_kind=request_payload.get("input_kind", ""),
                source_value=request_payload.get("source_value", ""),
                file_type=request_payload.get("file_type"),
                persist=_bool_from_payload(request_payload, "persist", False),
                db_uri=request_payload.get("db_uri"),
                check_warnings=_bool_from_payload(request_payload, "check_warnings", True),
                force_update=_bool_from_payload(request_payload, "force_update", False),
                defang=_bool_from_payload(request_payload, "defang", True),
                only=request_payload.get("only"),
                exclude=request_payload.get("exclude"),
                correlation_id=request_payload.get("correlation_id"),
                job_id=request_payload.get("job_id"),
                emit_only=_bool_from_payload(request_payload, "emit_only", False),
            ),
            queue_backend=cast("str", payload.get("queue_backend", "filesystem")),
            queue_name=cast("str", payload.get("queue_name", "default")),
            attempts=_int_from_payload(payload, "attempts", 0),
            max_attempts=_int_from_payload(payload, "max_attempts", 3),
            idempotency_key=cast("str | None", payload.get("idempotency_key")),
            schema_version=cast("str", payload.get("schema_version", PIPELINE_JOB_SCHEMA_VERSION)),
            submitted_at=cast("str", payload.get("submitted_at", datetime.now(UTC).isoformat())),
        )
@dataclass(frozen=True)
class QueueReceipt:
    """Opaque handle returned by queue adapters for ack/nack operations."""

    queue_backend: str
    queue_name: str
    receipt_id: str
    message_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "queue_backend", _require_str(self.queue_backend, field="queue_backend").strip().lower())
        object.__setattr__(self, "queue_name", _require_str(self.queue_name, field="queue_name").strip())
        object.__setattr__(self, "receipt_id", _require_str(self.receipt_id, field="receipt_id").strip())
        object.__setattr__(self, "message_id", _require_str(self.message_id, field="message_id").strip())
@dataclass(frozen=True)
class DistributedJobRecord:
    """Persisted distributed job lifecycle record."""

    job_id: str
    correlation_id: str
    queue_backend: str
    queue_name: str
    input_kind: str
    source_value: str
    status: str
    attempts: int
    max_attempts: int
    idempotency_key: str | None = None
    retryable: bool | None = None
    run_id: int | None = None
    last_error: PipelineErrorInfo | None = None
    submitted_at: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    dead_lettered_at: str | None = None
    receipt_id: str | None = None
    result_json: dict[str, object] | None = None
    phase_timings_ms: dict[str, int] = field(default_factory=dict)
    queue_metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _require_str(self.job_id, field="job_id").strip())
        object.__setattr__(self, "correlation_id", _require_str(self.correlation_id, field="correlation_id").strip())
        object.__setattr__(self, "queue_backend", _require_str(self.queue_backend, field="queue_backend").strip().lower())
        object.__setattr__(self, "queue_name", _require_str(self.queue_name, field="queue_name").strip())
        object.__setattr__(self, "input_kind", _require_str(self.input_kind, field="input_kind").strip())
        object.__setattr__(self, "source_value", _require_str(self.source_value, field="source_value").strip())
        object.__setattr__(self, "status", _require_str(self.status, field="status").strip())
        object.__setattr__(self, "attempts", _require_int(self.attempts, field="attempts", non_negative=True))
        object.__setattr__(
            self, "max_attempts", _require_int(self.max_attempts, field="max_attempts", non_negative=True)
        )
        if self.idempotency_key is not None:
            object.__setattr__(
                self, "idempotency_key", _require_str(self.idempotency_key, field="idempotency_key").strip()
            )
        if self.run_id is not None:
            object.__setattr__(self, "run_id", _require_int(self.run_id, field="run_id"))
        if self.submitted_at:
            object.__setattr__(self, "submitted_at", _require_str(self.submitted_at, field="submitted_at").strip())
        if self.started_at is not None:
            object.__setattr__(self, "started_at", _require_str(self.started_at, field="started_at").strip())
        if self.completed_at is not None:
            object.__setattr__(self, "completed_at", _require_str(self.completed_at, field="completed_at").strip())
        if self.dead_lettered_at is not None:
            object.__setattr__(
                self, "dead_lettered_at", _require_str(self.dead_lettered_at, field="dead_lettered_at").strip()
            )
        if self.receipt_id is not None:
            object.__setattr__(self, "receipt_id", _require_str(self.receipt_id, field="receipt_id").strip())

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": DISTRIBUTED_JOB_SCHEMA_VERSION,
            "job_id": self.job_id,
            "correlation_id": self.correlation_id,
            "queue_backend": self.queue_backend,
            "queue_name": self.queue_name,
            "input_kind": self.input_kind,
            "source_value": self.source_value,
            "status": self.status,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "idempotency_key": self.idempotency_key,
            "retryable": self.retryable,
            "run_id": self.run_id,
            "last_error": self.last_error.to_record() if self.last_error else None,
            "submitted_at": self.submitted_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "dead_lettered_at": self.dead_lettered_at,
            "receipt_id": self.receipt_id,
            "phase_timings_ms": dict(self.phase_timings_ms),
            "queue_metadata": dict(self.queue_metadata),
            "result": dict(self.result_json or {}),
        }


@dataclass(frozen=True)
class DeadLetterRecord:
    """Persisted dead-letter event."""

    job_id: str
    correlation_id: str
    queue_backend: str
    queue_name: str
    source_value: str
    attempts: int
    max_attempts: int
    error: PipelineErrorInfo
    dead_lettered_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _require_str(self.job_id, field="job_id").strip())
        object.__setattr__(self, "correlation_id", _require_str(self.correlation_id, field="correlation_id").strip())
        object.__setattr__(self, "queue_backend", _require_str(self.queue_backend, field="queue_backend").strip().lower())
        object.__setattr__(self, "queue_name", _require_str(self.queue_name, field="queue_name").strip())
        object.__setattr__(self, "source_value", _require_str(self.source_value, field="source_value").strip())
        object.__setattr__(self, "attempts", _require_int(self.attempts, field="attempts", non_negative=True))
        object.__setattr__(
            self, "max_attempts", _require_int(self.max_attempts, field="max_attempts", non_negative=True)
        )
        object.__setattr__(self, "dead_lettered_at", _require_str(self.dead_lettered_at, field="dead_lettered_at").strip())

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": DISTRIBUTED_JOB_SCHEMA_VERSION,
            "job_id": self.job_id,
            "correlation_id": self.correlation_id,
            "queue_backend": self.queue_backend,
            "queue_name": self.queue_name,
            "source_value": self.source_value,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "error": self.error.to_record(),
            "dead_lettered_at": self.dead_lettered_at,
        }


@dataclass(frozen=True)
class TelemetryEvent:
    """Structured telemetry event for pipeline orchestration."""

    name: str
    job_id: str
    correlation_id: str
    queue_backend: str
    queue_name: str
    attributes: dict[str, object] = field(default_factory=dict)
    emitted_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_str(self.name, field="name").strip())
        object.__setattr__(self, "job_id", _require_str(self.job_id, field="job_id").strip())
        object.__setattr__(self, "correlation_id", _require_str(self.correlation_id, field="correlation_id").strip())
        object.__setattr__(self, "queue_backend", _require_str(self.queue_backend, field="queue_backend").strip().lower())
        object.__setattr__(self, "queue_name", _require_str(self.queue_name, field="queue_name").strip())
        object.__setattr__(self, "emitted_at", _require_str(self.emitted_at, field="emitted_at").strip())

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": DISTRIBUTED_JOB_SCHEMA_VERSION,
            "name": self.name,
            "job_id": self.job_id,
            "correlation_id": self.correlation_id,
            "queue_backend": self.queue_backend,
            "queue_name": self.queue_name,
            "attributes": dict(self.attributes),
            "emitted_at": self.emitted_at,
        }
