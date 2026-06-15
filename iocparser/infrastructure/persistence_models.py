from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class SourceModel(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    value_search: Mapped[str] = mapped_column(Text, nullable=False, default="")
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    original_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    __table_args__ = (
        # Uniqueness on a hash of (kind, value): a TEXT column cannot be a key on
        # MySQL/MariaDB, so the natural (kind, value) constraint is invalid there.
        UniqueConstraint("dedup_hash", name="uq_sources_dedup_hash"),
        Index("ix_sources_kind_value_search", "kind", "value_search", mysql_length={"value_search": 255}),
        Index("ix_sources_value_search", "value_search", mysql_length=255),
    )


class RunModel(Base):
    __tablename__ = "runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    batch_job_id: Mapped[int | None] = mapped_column(ForeignKey("batch_jobs.id"), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    options_json: Mapped[str] = mapped_column(Text, nullable=False)
    normal_ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warning_ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processed_items: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    successful_items: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    failed_items: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    partial_error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    error_message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[SourceModel] = relationship()
    __table_args__ = (
        Index("ix_runs_source_started", "source_id", "started_at"),
        Index("ix_runs_status_started", "status", "started_at"),
        Index("ix_runs_batch_job", "batch_job_id"),
    )


class IOCModel(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    value_search: Mapped[str] = mapped_column(Text, nullable=False, default="")
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    is_warning: Mapped[bool] = mapped_column(Boolean, nullable=False)
    warning_list: Mapped[str] = mapped_column(Text, nullable=False, default="")
    warning_description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    __table_args__ = (
        # Uniqueness on a hash of (ioc_type, value, is_warning, warning_list,
        # warning_description): those TEXT columns cannot form a key on
        # MySQL/MariaDB and their combined length exceeds InnoDB's index limit.
        UniqueConstraint("dedup_hash", name="uq_iocs_dedup_hash"),
        Index("ix_iocs_type_value_search", "ioc_type", "value_search", mysql_length={"value_search": 255}),
        Index("ix_iocs_value_search", "value_search", mysql_length=255),
        Index("ix_iocs_value_search_type", "value_search", "ioc_type", mysql_length={"value_search": 255}),
    )


class RunIOCModel(Base):
    __tablename__ = "run_iocs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    tags_search: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    __table_args__ = (
        UniqueConstraint("run_id", "ioc_id", name="uq_run_ioc"),
        Index("ix_run_iocs_run_severity", "run_id", "severity"),
        Index("ix_run_iocs_tags_search", "tags_search", mysql_length=255),
        Index("ix_run_iocs_severity", "severity"),
        Index("ix_run_iocs_run_id", "run_id"),
    )


class DistributedJobModel(Base):
    __tablename__ = "distributed_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    queue_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    queue_name: Mapped[str] = mapped_column(String(128), nullable=False)
    input_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    source_value: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    retryable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    receipt_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    result_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    metrics_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dead_lettered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    __table_args__ = (
        Index("ix_distributed_jobs_status_submitted", "status", "submitted_at"),
        Index("ix_distributed_jobs_backend_status", "queue_backend", "status"),
        Index("ix_distributed_jobs_correlation", "correlation_id"),
        Index("ix_distributed_jobs_idempotency", "idempotency_key"),
    )


class DeadLetterJobModel(Base):
    __tablename__ = "dead_letter_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    queue_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    queue_name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_value: Mapped[str] = mapped_column(Text, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    error_code: Mapped[str] = mapped_column(String(64), nullable=False)
    error_category: Mapped[str] = mapped_column(String(64), nullable=False)
    error_message: Mapped[str] = mapped_column(Text, nullable=False)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    dead_lettered_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    __table_args__ = (
        Index("ix_dead_letter_jobs_backend_created", "queue_backend", "dead_lettered_at"),
        Index("ix_dead_letter_jobs_job_id", "job_id"),
    )


__all__ = [
    "Base",
    "DeadLetterJobModel",
    "DistributedJobModel",
    "IOCModel",
    "RunIOCModel",
    "RunModel",
    "SourceModel",
]
