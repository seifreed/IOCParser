from __future__ import annotations

import logging
from datetime import datetime
from typing import cast

from sqlalchemy import select

from iocparser.domain.models import (
    TERMINAL_JOB_STATUSES,
    DeadLetterRecord,
    DistributedJobRecord,
    PipelineErrorInfo,
    QueueEnvelope,
)
from iocparser.infrastructure.persistence_distributed_records import (
    dead_letter_record as _dead_letter_record,
)
from iocparser.infrastructure.persistence_distributed_support import (
    TransitionUpdate,
    active_idempotency_stmt,
    apply_transition,
    build_new_job,
    commit_new_job_or_fetch,
    completed_transition,
    dead_letter_model,
    failed_transition,
    job_by_id_stmt,
    list_dead_letters_stmt,
    list_jobs_stmt,
    materialize_envelope,
    model_record,
    running_transition,
    update_envelope,
)
from iocparser.infrastructure.persistence_schema import (
    DistributedJobModel,
    SQLAlchemyUnitOfWork,
)
from iocparser.shared_utils import close_and_log, rollback_and_log

AMBIGUOUS_DISTRIBUTED_JOB_ID = "ambiguous distributed job id"
logger = logging.getLogger(__name__)


def _history_job_like_prefix(job_id: str) -> str:
    escaped = job_id.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}#history:%"


class SQLAlchemyDistributedJobService:
    """Persistence helper for distributed queue lifecycle records."""

    def __init__(self, db_uri: str) -> None:
        self.db_uri = db_uri

    def create_or_get_job(
        self, *, envelope: QueueEnvelope, receipt_id: str
    ) -> DistributedJobRecord:
        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            return self._create_or_get_job_inner(
                envelope=envelope, receipt_id=receipt_id, unit=unit
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            rollback_and_log(
                unit,
                logger=logger,
                message="Rollback failed while creating distributed job",
            )
            raise
        finally:
            close_and_log(
                unit,
                logger=logger,
                message="Close failed while creating distributed job",
            )

    def _create_or_get_job_inner(
        self, *, envelope: QueueEnvelope, receipt_id: str, unit: SQLAlchemyUnitOfWork
    ) -> DistributedJobRecord:
        envelope = materialize_envelope(envelope)
        job_id = cast("str", envelope.request.job_id)
        stmt = job_by_id_stmt(job_id)
        model = unit.session.execute(stmt).scalar_one_or_none()
        if model is None:
            if envelope.idempotency_key:
                idem_stmt = active_idempotency_stmt(envelope.idempotency_key)
                existing = unit.session.execute(idem_stmt).scalar_one_or_none()
                if existing is not None:
                    return model_record(existing)
            model = build_new_job(envelope=envelope, receipt_id=receipt_id)
            committed = commit_new_job_or_fetch(unit, model, job_id)
            return model_record(committed)
        update_envelope(model, envelope=envelope, receipt_id=receipt_id)
        unit.commit()
        return model_record(model)

    def get_job(self, *, job_id: str) -> DistributedJobRecord | None:
        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            exact = (
                unit.session.execute(
                    select(DistributedJobModel)
                    .where(DistributedJobModel.job_id == job_id)
                    .order_by(
                        DistributedJobModel.submitted_at.desc(),
                        DistributedJobModel.id.desc(),
                    )
                )
                .scalars()
                .first()
            )
            if exact is not None:
                return model_record(exact)
            imported = list(
                unit.session.execute(
                    select(DistributedJobModel)
                    .where(
                        DistributedJobModel.job_id.like(
                            _history_job_like_prefix(job_id),
                            escape="\\",
                        ),
                    )
                    .order_by(
                        DistributedJobModel.submitted_at.desc(),
                        DistributedJobModel.id.desc(),
                    )
                )
                .scalars()
                .all()
            )
            if not imported:
                return None
            if len(imported) > 1:
                raise ValueError(AMBIGUOUS_DISTRIBUTED_JOB_ID)
            return model_record(imported[0])
        finally:
            close_and_log(unit, logger=logger, message="Close failed while reading distributed job")

    def find_by_idempotency_key(self, *, idempotency_key: str) -> DistributedJobRecord | None:
        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            stmt = active_idempotency_stmt(idempotency_key)
            model = unit.session.execute(stmt).scalar_one_or_none()
            return model_record(model) if model is not None else None
        finally:
            close_and_log(
                unit, logger=logger, message="Close failed while reading idempotency key"
            )

    def list_jobs(
        self, *, limit: int = 50, statuses: tuple[str, ...] = (), queue_backend: str | None = None
    ) -> list[DistributedJobRecord]:
        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            stmt = list_jobs_stmt(limit=limit, statuses=statuses, queue_backend=queue_backend)
            models = list(unit.session.execute(stmt).scalars().all())
            return [model_record(model) for model in models]
        finally:
            close_and_log(unit, logger=logger, message="Close failed while listing distributed jobs")

    def mark_running(
        self, *, job_id: str, attempts: int, receipt_id: str
    ) -> DistributedJobRecord | None:
        transition = running_transition(job_id=job_id, attempts=attempts, receipt_id=receipt_id)
        return self._transition(
            job_id=transition["job_id"],
            status=transition["status"],
            attempts=transition["attempts"],
            receipt_id=transition["receipt_id"],
            started_at=transition["started_at"],
            # A terminal job must not be resurrected to running by a redelivered message
            # (e.g. one whose post-completion ack failed); returning None makes the
            # coordinator ack-and-skip it instead of reprocessing a finished job.
            forbidden_from=TERMINAL_JOB_STATUSES,
        )

    def mark_completed(
        self,
        *,
        job_id: str,
        attempts: int,
        run_id: int | None,
        result_json: dict[str, object],
        metrics: dict[str, object],
    ) -> DistributedJobRecord | None:
        transition = completed_transition(
            job_id=job_id,
            attempts=attempts,
            run_id=run_id,
            result_json=result_json,
            metrics=metrics,
        )
        return self._transition(
            job_id=transition["job_id"],
            status=transition["status"],
            attempts=transition["attempts"],
            run_id=transition["run_id"],
            result_json=transition["result_json"],
            metrics=transition["metrics"],
            completed_at=transition["completed_at"],
            retryable=transition["retryable"],
        )

    def mark_failed(
        self,
        *,
        job_id: str,
        attempts: int,
        error: PipelineErrorInfo,
        will_retry: bool,
        metrics: dict[str, object],
    ) -> DistributedJobRecord | None:
        transition = failed_transition(
            job_id=job_id,
            attempts=attempts,
            error=error,
            will_retry=will_retry,
            metrics=metrics,
        )
        return self._transition(
            job_id=transition["job_id"],
            status=transition["status"],
            attempts=transition["attempts"],
            error=transition["error"],
            metrics=transition["metrics"],
            completed_at=transition["completed_at"],
            retryable=transition["retryable"],
        )

    def mark_dead_lettered(
        self,
        *,
        job_id: str,
        attempts: int,
        error: PipelineErrorInfo,
        metrics: dict[str, object] | None = None,
    ) -> DistributedJobRecord | None:
        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            stmt = job_by_id_stmt(job_id)
            model = unit.session.execute(stmt).scalar_one_or_none()
            if model is None:
                return None
            unit.session.add(
                dead_letter_model(model, attempts=attempts, error=error, metrics=metrics)
            )
            unit.commit()
            return model_record(model)
        finally:
            close_and_log(
                unit, logger=logger, message="Close failed while marking job dead lettered"
            )

    def list_dead_letters(
        self, *, limit: int = 50, queue_backend: str | None = None
    ) -> list[DeadLetterRecord]:
        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            stmt = list_dead_letters_stmt(limit=limit, queue_backend=queue_backend)
            models = list(unit.session.execute(stmt).scalars().all())
            return [_dead_letter_record(model) for model in models]
        finally:
            close_and_log(
                unit,
                logger=logger,
                message="Close failed while listing distributed dead letters",
            )

    def _transition(
        self,
        *,
        job_id: str,
        status: str,
        attempts: int,
        receipt_id: str | None = None,
        run_id: int | None = None,
        result_json: dict[str, object] | None = None,
        metrics: dict[str, object] | None = None,
        error: PipelineErrorInfo | None = None,
        retryable: bool | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        forbidden_from: tuple[str, ...] = (),
    ) -> DistributedJobRecord | None:
        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            stmt = job_by_id_stmt(job_id)
            model = unit.session.execute(stmt).scalar_one_or_none()
            if model is None or model.status in forbidden_from:
                return None
            apply_transition(
                model,
                TransitionUpdate(
                    status=status,
                    attempts=attempts,
                    receipt_id=receipt_id,
                    run_id=run_id,
                    result_json=result_json,
                    metrics=metrics,
                    error=error,
                    retryable=retryable,
                    started_at=started_at,
                    completed_at=completed_at,
                ),
            )
            unit.commit()
            return model_record(model)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            rollback_and_log(
                unit,
                logger=logger,
                message="Rollback failed while transitioning distributed job",
            )
            raise
        finally:
            close_and_log(unit, logger=logger, message="Close failed while transitioning distributed job")
