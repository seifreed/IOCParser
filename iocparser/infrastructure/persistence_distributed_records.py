from __future__ import annotations

import json
from datetime import datetime
from typing import cast

from iocparser.domain.models import (
    JOB_STATUS_DEAD_LETTERED,
    DeadLetterRecord,
    DistributedJobRecord,
    PipelineErrorInfo,
)
from iocparser.infrastructure.persistence_schema import DeadLetterJobModel, DistributedJobModel

HISTORY_IMPORT_MARKER_KEY = "__history_import__"


def to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_object(raw_value: str) -> dict[str, object]:
    try:
        decoded = cast("object", json.loads(raw_value or "{}"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(decoded, dict):
        return {}
    return {str(name): value for name, value in decoded.items()}


def _json_int_map(raw_value: str) -> dict[str, int]:
    decoded = _json_object(raw_value)
    metrics: dict[str, int] = {}
    for name, value in decoded.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            metrics[name] = value
            continue
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.lstrip("-").isdigit():
                metrics[name] = int(stripped)
    return metrics


def _public_queue_metadata(raw_value: str) -> dict[str, object]:
    payload = _json_object(raw_value)
    payload.pop(HISTORY_IMPORT_MARKER_KEY, None)
    return payload


def _public_job_id(model: DistributedJobModel | DeadLetterJobModel) -> str:
    payload = _public_queue_metadata(model.payload_json or "{}")
    request_payload = payload.get("request")
    raw_job_id = request_payload.get("job_id") if isinstance(request_payload, dict) else None
    if isinstance(raw_job_id, str) and raw_job_id.strip():
        return raw_job_id
    return model.job_id


def job_record(model: DistributedJobModel) -> DistributedJobRecord:
    error = None
    # The three error columns are written together; an error with an empty
    # message (e.g. str(RuntimeError()) == "") must not drop the code/category.
    if model.last_error_code is not None:
        error = PipelineErrorInfo(
            code=model.last_error_code,
            category=model.last_error_category or "",
            retryable=bool(model.retryable),
            status=model.status,
            message=model.last_error_message or "",
        )
    return DistributedJobRecord(
        job_id=_public_job_id(model) or "",
        correlation_id=model.correlation_id or "",
        queue_backend=model.queue_backend or "",
        queue_name=model.queue_name or "",
        input_kind=model.input_kind or "",
        source_value=model.source_value or "",
        status=model.status or "",
        attempts=model.attempts,
        max_attempts=model.max_attempts,
        idempotency_key=model.idempotency_key,
        retryable=model.retryable,
        run_id=model.run_id,
        last_error=error,
        submitted_at=to_iso(model.submitted_at) or "",
        started_at=to_iso(model.started_at),
        completed_at=to_iso(model.completed_at),
        dead_lettered_at=to_iso(model.dead_lettered_at),
        receipt_id=model.receipt_id,
        result_json=_json_object(model.result_json or "{}"),
        phase_timings_ms=_json_int_map(model.metrics_json or "{}"),
        queue_metadata=_public_queue_metadata(model.payload_json or "{}"),
    )


def dead_letter_record(model: DeadLetterJobModel) -> DeadLetterRecord:
    return DeadLetterRecord(
        job_id=_public_job_id(model) or "",
        correlation_id=model.correlation_id or "",
        queue_backend=model.queue_backend or "",
        queue_name=model.queue_name or "",
        source_value=model.source_value or "",
        attempts=model.attempts,
        max_attempts=model.max_attempts,
        error=PipelineErrorInfo(
            code=model.error_code,
            category=model.error_category,
            retryable=model.retryable,
            status=JOB_STATUS_DEAD_LETTERED,
            message=model.error_message,
        ),
        dead_lettered_at=to_iso(model.dead_lettered_at) or "",
    )


__all__ = ["dead_letter_record", "job_record", "to_iso"]
