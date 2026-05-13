from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from iocparser.domain.pipeline import (
    PIPELINE_JOB_SCHEMA_VERSION,
    PipelineErrorInfo,
    PipelineJobRequest,
)

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


def _invalid_retry_counter_value(*, key: str) -> ValueError:
    return ValueError(f"{key} must be a valid retry counter")


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
        normalized = raw_value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    raise _invalid_bool_payload_value(key=key, raw_value=raw_value)


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
        if self.attempts < 0:
            raise _invalid_retry_counter_value(key="attempts")
        if self.max_attempts <= 0:
            raise _invalid_retry_counter_value(key="max_attempts")

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
                input_kind=str(request_payload.get("input_kind", "")),
                source_value=str(request_payload.get("source_value", "")),
                file_type=str(request_payload["file_type"])
                if request_payload.get("file_type") is not None
                else None,
                persist=_bool_from_payload(request_payload, "persist", False),
                db_uri=str(request_payload["db_uri"])
                if request_payload.get("db_uri") is not None
                else None,
                check_warnings=_bool_from_payload(request_payload, "check_warnings", True),
                force_update=_bool_from_payload(request_payload, "force_update", False),
                defang=_bool_from_payload(request_payload, "defang", True),
                only=str(request_payload["only"])
                if request_payload.get("only") is not None
                else None,
                exclude=str(request_payload["exclude"])
                if request_payload.get("exclude") is not None
                else None,
                correlation_id=str(request_payload["correlation_id"])
                if request_payload.get("correlation_id") is not None
                else None,
                job_id=str(request_payload["job_id"])
                if request_payload.get("job_id") is not None
                else None,
                emit_only=_bool_from_payload(request_payload, "emit_only", False),
            ),
            queue_backend=str(payload.get("queue_backend", "filesystem")),
            queue_name=str(payload.get("queue_name", "default")),
            attempts=_int_from_payload(payload, "attempts", 0),
            max_attempts=_int_from_payload(payload, "max_attempts", 3),
            idempotency_key=str(payload["idempotency_key"])
            if payload.get("idempotency_key") is not None
            else None,
            schema_version=str(payload.get("schema_version", PIPELINE_JOB_SCHEMA_VERSION)),
            submitted_at=str(payload.get("submitted_at", datetime.now(UTC).isoformat())),
        )


@dataclass(frozen=True)
class QueueReceipt:
    """Opaque handle returned by queue adapters for ack/nack operations."""

    queue_backend: str
    queue_name: str
    receipt_id: str
    message_id: str


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
