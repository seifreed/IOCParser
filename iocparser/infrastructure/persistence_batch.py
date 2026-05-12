from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from iocparser.infrastructure.persistence_schema import Base, RunModel


def _invalid_report_int_error(*, key: str, raw_value: object) -> TypeError:
    return TypeError(f"Expected {key} to be int-compatible, got {type(raw_value).__name__}")


def _int_report_value(payload: dict[str, object], key: str, default: int = 0) -> int:
    raw_value = payload.get(key)
    if raw_value is None:
        return default
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, str):
        return int(raw_value)
    raise _invalid_report_int_error(key=key, raw_value=raw_value)


def _dict_report_value(payload: dict[str, object], key: str) -> dict[str, object]:
    raw_value = payload.get(key)
    if isinstance(raw_value, dict):
        return {str(name): value for name, value in raw_value.items()}
    return {}


def _failed_items(items: object) -> list[dict[str, object]]:
    if not isinstance(items, list):
        return []
    failed: list[dict[str, object]] = []
    for item in items:
        if isinstance(item, dict) and str(item.get("status", "")).lower() == "failed":
            failed.append({str(name): value for name, value in item.items()})
    return failed


class BatchJobModel(Base):
    """Persisted aggregate for a multi-input batch execution."""

    __tablename__ = "batch_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    total_inputs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful_inputs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_inputs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retry_attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    error_summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    metrics_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    __table_args__ = (
        Index("ix_batch_jobs_status_started", "status", "started_at"),
        Index("ix_batch_jobs_source_started", "source_kind", "started_at"),
    )


class FailedBatchItemModel(Base):
    """Persisted failed item from a batch execution."""

    __tablename__ = "failed_batch_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_job_id: Mapped[int] = mapped_column(ForeignKey("batch_jobs.id"), nullable=False)
    source_value: Mapped[str] = mapped_column(Text, nullable=False)
    error_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    error_message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    retry_attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    __table_args__ = (
        Index("ix_failed_batch_items_job", "batch_job_id"),
        Index("ix_failed_batch_items_type", "error_type"),
    )


def create_batch_job(
    session: Session,
    *,
    source_kind: str,
    run_ids: tuple[int, ...],
    report: dict[str, object],
    config: dict[str, object] | None = None,
) -> int:
    """Persist a batch job aggregate and attach its runs and failures."""
    items = report.get("items", [])
    failures = _failed_items(items)
    retry_attempt = _batch_retry_attempt(items)
    duration_ms = _int_report_value(report, "duration_ms", 0)
    started_at, finished_at = _batch_timestamps(report, duration_ms=duration_ms)
    error_summary: Counter[str] = Counter(
        str(item.get("error_type", "unknown")) for item in failures
    )
    metrics = _dict_report_value(report, "metrics")
    serialized_config = dict(config) if config is not None else {}
    serialized_error_summary: dict[str, int] = dict(sorted(error_summary.items()))
    job = BatchJobModel(
        source_kind=source_kind,
        started_at=started_at,
        finished_at=finished_at,
        total_inputs=_int_report_value(report, "total", 0),
        successful_inputs=_int_report_value(report, "successful", 0),
        failed_inputs=_int_report_value(report, "failed", 0),
        retry_attempt=retry_attempt,
        status=_batch_status(report),
        config_json=json.dumps(serialized_config, sort_keys=True),
        error_summary_json=json.dumps(serialized_error_summary, sort_keys=True),
        metrics_json=json.dumps(metrics, sort_keys=True),
    )
    session.add(job)
    session.flush()
    for run_id in run_ids:
        run = session.get(RunModel, run_id)
        if run is not None:
            run.batch_job_id = job.id
    for item in failures:
        session.add(
            FailedBatchItemModel(
                batch_job_id=job.id,
                source_value=str(item.get("url", "")),
                error_type=str(item.get("error_type", "unknown")),
                error_message=str(item.get("error", "")),
                retry_attempt=_int_report_value(item, "retry_attempt", 0),
                created_at=finished_at,
            ),
        )
    return job.id


def _batch_timestamps(report: dict[str, object], *, duration_ms: int) -> tuple[datetime, datetime]:
    current_started = datetime.now(UTC)
    phase_timestamps = report.get("phase_timestamps")
    if not isinstance(phase_timestamps, dict):
        return current_started, current_started + timedelta(milliseconds=max(0, duration_ms))
    started_at = _report_datetime(phase_timestamps.get("started_at"))
    finished_at = _report_datetime(phase_timestamps.get("finished_at"))
    if started_at is None:
        started_at = current_started
    if finished_at is None:
        finished_at = started_at + timedelta(milliseconds=max(0, duration_ms))
    if finished_at < started_at:
        finished_at = started_at + timedelta(milliseconds=max(0, duration_ms))
    return started_at, finished_at


def _report_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _batch_retry_attempt(items: object) -> int:
    if not isinstance(items, list):
        return 0
    attempts = [
        _int_report_value(
            {key: value for key, value in item.items() if isinstance(key, str)}, "retry_attempt", 0
        )
        for item in items
        if isinstance(item, dict)
    ]
    return max(attempts, default=0)


def _batch_status(report: dict[str, object]) -> str:
    raw_status = report.get("status")
    if isinstance(raw_status, str):
        normalized = raw_status.strip().lower()
        if normalized in {"failed", "partial", "success"}:
            return normalized
    failed_inputs = _int_report_value(report, "failed", 0)
    successful_inputs = _int_report_value(report, "successful", 0)
    if failed_inputs and not successful_inputs:
        return "failed"
    if failed_inputs:
        return "partial"
    return "success"


def list_failed_batch_jobs(session: Session, *, limit: int = 20) -> list[tuple[BatchJobModel, int]]:
    """Return recent batch jobs with failure counts."""
    stmt = (
        select(BatchJobModel)
        .where(BatchJobModel.failed_inputs > 0)
        .order_by(BatchJobModel.started_at.desc())
        .limit(limit)
    )
    jobs: list[BatchJobModel] = list(session.execute(stmt).scalars().all())
    return [
        (
            job,
            session.query(FailedBatchItemModel)
            .filter(FailedBatchItemModel.batch_job_id == job.id)
            .count(),
        )
        for job in jobs
    ]


def load_failed_batch_items(session: Session, *, batch_job_id: int) -> list[FailedBatchItemModel]:
    """Load failed items for a batch job."""
    stmt = select(FailedBatchItemModel).where(FailedBatchItemModel.batch_job_id == batch_job_id)
    return list(
        session.execute(
            stmt.order_by(FailedBatchItemModel.created_at.asc(), FailedBatchItemModel.id.asc())
        )
        .scalars()
        .all()
    )
