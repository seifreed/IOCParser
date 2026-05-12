from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TypedDict

from sqlalchemy import Select, select
from sqlalchemy.exc import IntegrityError

from iocparser.domain.models import (
    JOB_STATUS_COMPLETED,
    JOB_STATUS_DEAD_LETTERED,
    JOB_STATUS_FAILED,
    JOB_STATUS_QUEUED,
    JOB_STATUS_RUNNING,
    DistributedJobRecord,
    PipelineErrorInfo,
    QueueEnvelope,
)
from iocparser.infrastructure.persistence_distributed_records import job_record
from iocparser.infrastructure.persistence_schema import (
    DeadLetterJobModel,
    DistributedJobModel,
    SQLAlchemyUnitOfWork,
)

ACTIVE_JOB_STATUSES = (JOB_STATUS_QUEUED, JOB_STATUS_RUNNING, JOB_STATUS_COMPLETED)
HISTORY_IMPORT_MARKER_KEY = "__history_import__"


class RunningTransition(TypedDict):
    job_id: str
    status: str
    attempts: int
    receipt_id: str
    started_at: datetime


class CompletedTransition(TypedDict):
    job_id: str
    status: str
    attempts: int
    run_id: int | None
    result_json: dict[str, object]
    metrics: dict[str, object]
    completed_at: datetime
    retryable: bool


class FailedTransition(TypedDict):
    job_id: str
    status: str
    attempts: int
    error: PipelineErrorInfo
    metrics: dict[str, object]
    retryable: bool
    completed_at: datetime | None


@dataclass(frozen=True)
class TransitionUpdate:
    status: str
    attempts: int
    receipt_id: str | None = None
    run_id: int | None = None
    result_json: dict[str, object] | None = None
    metrics: dict[str, object] | None = None
    error: PipelineErrorInfo | None = None
    retryable: bool | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


def active_idempotency_stmt(idempotency_key: str) -> Select[DistributedJobModel]:
    return (
        select(DistributedJobModel)
        .where(
            DistributedJobModel.idempotency_key == idempotency_key,
            DistributedJobModel.status.in_(ACTIVE_JOB_STATUSES),
            DistributedJobModel.payload_json.not_like(f'%"{HISTORY_IMPORT_MARKER_KEY}"%'),
        )
        .order_by(DistributedJobModel.submitted_at.desc())
        .limit(1)
        .with_for_update()
    )


def job_by_id_stmt(job_id: str) -> Select[DistributedJobModel]:
    return select(DistributedJobModel).where(DistributedJobModel.job_id == job_id).with_for_update()


def list_jobs_stmt(
    *, limit: int, statuses: tuple[str, ...], queue_backend: str | None
) -> Select[DistributedJobModel]:
    stmt = (
        select(DistributedJobModel)
        .order_by(DistributedJobModel.submitted_at.desc())
        .limit(max(0, limit))
    )
    if statuses:
        stmt = stmt.where(DistributedJobModel.status.in_(statuses))
    if queue_backend:
        stmt = stmt.where(DistributedJobModel.queue_backend == queue_backend)
    return stmt


def list_dead_letters_stmt(*, limit: int, queue_backend: str | None) -> Select[DeadLetterJobModel]:
    stmt = (
        select(DeadLetterJobModel)
        .order_by(DeadLetterJobModel.dead_lettered_at.desc())
        .limit(max(0, limit))
    )
    if queue_backend:
        stmt = stmt.where(DeadLetterJobModel.queue_backend == queue_backend)
    return stmt


def build_new_job(*, envelope: QueueEnvelope, receipt_id: str) -> DistributedJobModel:
    now = datetime.now(UTC)
    return DistributedJobModel(
        job_id=str(envelope.request.job_id),
        correlation_id=str(envelope.request.correlation_id or envelope.request.job_id),
        queue_backend=envelope.queue_backend,
        queue_name=envelope.queue_name,
        input_kind=envelope.request.input_kind,
        source_value=envelope.request.source_value,
        idempotency_key=envelope.idempotency_key,
        status=JOB_STATUS_QUEUED,
        attempts=envelope.attempts,
        max_attempts=envelope.max_attempts,
        receipt_id=receipt_id,
        payload_json=json.dumps(envelope.to_record(), sort_keys=True),
        submitted_at=now,
    )


def update_envelope(
    model: DistributedJobModel, *, envelope: QueueEnvelope, receipt_id: str
) -> None:
    model.receipt_id = receipt_id
    model.payload_json = json.dumps(envelope.to_record(), sort_keys=True)


def apply_transition(model: DistributedJobModel, update: TransitionUpdate) -> None:
    model.status = update.status
    model.attempts = update.attempts
    model.receipt_id = update.receipt_id or model.receipt_id
    model.run_id = update.run_id if update.run_id is not None else model.run_id
    model.retryable = update.retryable if update.retryable is not None else model.retryable
    if update.error is not None:
        model.last_error_code = update.error.code
        model.last_error_category = update.error.category
        model.last_error_message = update.error.message
        model.retryable = update.error.retryable
    if update.result_json is not None:
        model.result_json = json.dumps(update.result_json, sort_keys=True)
    if update.metrics is not None:
        model.metrics_json = json.dumps(update.metrics, sort_keys=True)
    if update.started_at is not None:
        model.started_at = update.started_at
    if update.completed_at is not None:
        model.completed_at = update.completed_at


def commit_new_job_or_fetch(
    unit: SQLAlchemyUnitOfWork,
    model: DistributedJobModel,
    job_id: str,
) -> DistributedJobModel:
    """Commit a new job, or return existing row on IntegrityError race."""
    unit.session.add(model)
    try:
        unit.commit()
        return model
    except IntegrityError:
        unit.rollback()
        existing = unit.session.execute(job_by_id_stmt(job_id)).scalar_one_or_none()
        if existing is not None:
            return existing
        raise


def dead_letter_model(
    model: DistributedJobModel, *, attempts: int, error: PipelineErrorInfo
) -> DeadLetterJobModel:
    timestamp = datetime.now(UTC)
    model.status = JOB_STATUS_DEAD_LETTERED
    model.attempts = attempts
    model.retryable = error.retryable
    model.last_error_code = error.code
    model.last_error_category = error.category
    model.last_error_message = error.message
    model.dead_lettered_at = timestamp
    return DeadLetterJobModel(
        job_id=model.job_id,
        correlation_id=model.correlation_id,
        queue_backend=model.queue_backend,
        queue_name=model.queue_name,
        source_value=model.source_value,
        attempts=attempts,
        max_attempts=model.max_attempts,
        error_code=error.code,
        error_category=error.category,
        error_message=error.message,
        retryable=error.retryable,
        payload_json=model.payload_json,
        dead_lettered_at=timestamp,
    )


def running_transition(*, job_id: str, attempts: int, receipt_id: str) -> RunningTransition:
    return {
        "job_id": job_id,
        "status": JOB_STATUS_RUNNING,
        "attempts": attempts,
        "receipt_id": receipt_id,
        "started_at": datetime.now(UTC),
    }


def completed_transition(
    *,
    job_id: str,
    attempts: int,
    run_id: int | None,
    result_json: dict[str, object],
    metrics: dict[str, object],
) -> CompletedTransition:
    return {
        "job_id": job_id,
        "status": JOB_STATUS_COMPLETED,
        "attempts": attempts,
        "run_id": run_id,
        "result_json": result_json,
        "metrics": metrics,
        "completed_at": datetime.now(UTC),
        "retryable": False,
    }


def failed_transition(
    *,
    job_id: str,
    attempts: int,
    error: PipelineErrorInfo,
    will_retry: bool,
    metrics: dict[str, object],
) -> FailedTransition:
    return {
        "job_id": job_id,
        "status": JOB_STATUS_QUEUED if will_retry else JOB_STATUS_FAILED,
        "attempts": attempts,
        "error": error,
        "metrics": metrics,
        "retryable": error.retryable,
        "completed_at": None if will_retry else datetime.now(UTC),
    }


def model_record(model: DistributedJobModel) -> DistributedJobRecord:
    return job_record(model)
