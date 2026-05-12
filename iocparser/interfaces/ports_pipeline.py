from __future__ import annotations

from typing import Protocol

from iocparser.domain.distributed import (
    DeadLetterRecord,
    DistributedJobRecord,
    QueueEnvelope,
    QueueReceipt,
    TelemetryEvent,
)
from iocparser.domain.pipeline import PipelineErrorInfo, PipelineJobRequest, PipelineJobResult


class QueueAdapter(Protocol):
    """Port for pluggable distributed queue backends."""

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        """Publish a job envelope to a queue."""

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        """Receive a job envelope from a queue."""

    def ack(self, receipt: QueueReceipt) -> None:
        """Acknowledge a successfully processed message."""

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        """Return a message back to the active queue with updated metadata."""

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        """Move a message to a dead-letter queue."""


class TelemetrySink(Protocol):
    """Port for pipeline telemetry emission."""

    def emit(self, event: TelemetryEvent) -> None:
        """Emit a structured telemetry event."""


class PipelineProcessor(Protocol):
    """Port for processing a single pipeline job request."""

    def process(self, request: PipelineJobRequest) -> PipelineJobResult:
        """Process a single pipeline request."""


class DistributedJobService(Protocol):
    """Port for persisting and querying distributed job lifecycle."""

    def create_or_get_job(
        self, *, envelope: QueueEnvelope, receipt_id: str
    ) -> DistributedJobRecord:
        """Create or update a queued job record."""

    def find_by_idempotency_key(self, *, idempotency_key: str) -> DistributedJobRecord | None:
        """Find a prior queued/running/completed job by idempotency key."""

    def mark_running(
        self, *, job_id: str, attempts: int, receipt_id: str
    ) -> DistributedJobRecord | None:
        """Transition a job to running."""

    def mark_completed(
        self,
        *,
        job_id: str,
        attempts: int,
        run_id: int | None,
        result_json: dict[str, object],
        metrics: dict[str, object],
    ) -> DistributedJobRecord | None:
        """Transition a job to completed."""

    def mark_failed(
        self,
        *,
        job_id: str,
        attempts: int,
        error: PipelineErrorInfo,
        will_retry: bool,
        metrics: dict[str, object],
    ) -> DistributedJobRecord | None:
        """Transition a job to failed or queued-for-retry."""

    def mark_dead_lettered(
        self,
        *,
        job_id: str,
        attempts: int,
        error: PipelineErrorInfo,
    ) -> DistributedJobRecord | None:
        """Transition a job to dead-lettered."""

    def get_job(self, *, job_id: str) -> DistributedJobRecord | None:
        """Load a job lifecycle record."""

    def list_jobs(
        self,
        *,
        limit: int = 50,
        statuses: tuple[str, ...] = (),
        queue_backend: str | None = None,
    ) -> list[DistributedJobRecord]:
        """List distributed job lifecycle records."""

    def list_dead_letters(
        self,
        *,
        limit: int = 50,
        queue_backend: str | None = None,
    ) -> list[DeadLetterRecord]:
        """List dead-lettered jobs."""


class ContentDigester(Protocol):
    """Port for generating stable content digests without filesystem leakage in application."""

    def digest_text(self, value: str) -> str:
        """Return a stable digest for raw text or URL identifiers."""

    def digest_file(self, file_path: str) -> str:
        """Return a stable digest for a file input."""
