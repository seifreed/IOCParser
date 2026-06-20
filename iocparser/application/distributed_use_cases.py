from __future__ import annotations

from dataclasses import replace

from iocparser.application.distributed_coordinator_support import (
    advance_envelope,
    normalize_submit_request,
    phase_metrics,
)
from iocparser.application.distributed_idempotency import idempotency_key_for
from iocparser.domain.distributed import (
    DeadLetterRecord,
    DistributedJobRecord,
    QueueEnvelope,
    QueueReceipt,
    TelemetryEvent,
)
from iocparser.domain.pipeline import PipelineJobRequest, PipelineJobResult
from iocparser.interfaces.ports import (
    ContentDigester,
    DistributedJobService,
    PipelineProcessor,
    QueueAdapter,
    TelemetrySink,
)
from iocparser.pipeline_errors import classify_pipeline_exception, error_for_failed_result

__all__ = ["DistributedPipelineCoordinator", "idempotency_key_for"]


class DistributedPipelineCoordinator:
    """Application-level coordinator for queue-backed distributed pipeline execution."""

    def __init__(
        self,
        *,
        queue_adapter: QueueAdapter,
        processor: PipelineProcessor,
        telemetry_sink: TelemetrySink,
        job_service: DistributedJobService | None = None,
        content_digester: ContentDigester | None = None,
    ) -> None:
        self.queue_adapter = queue_adapter
        self.processor = processor
        self.telemetry_sink = telemetry_sink
        self.job_service = job_service
        self.content_digester = content_digester

    def submit(
        self,
        request: PipelineJobRequest,
        *,
        queue_name: str = "default",
        queue_backend: str = "filesystem",
        max_attempts: int = 3,
        idempotency_key: str | None = None,
    ) -> DistributedJobRecord | dict[str, str]:
        normalized_request = normalize_submit_request(request)
        envelope = QueueEnvelope(
            request=normalized_request,
            queue_backend=queue_backend,
            queue_name=queue_name,
            attempts=0,
            max_attempts=max_attempts,
            idempotency_key=idempotency_key
            or idempotency_key_for(normalized_request, digester=self.content_digester),
        )
        if self.job_service is not None and envelope.idempotency_key:
            existing = self.job_service.find_by_idempotency_key(
                idempotency_key=envelope.idempotency_key
            )
            if existing is not None:
                self._emit("job_deduplicated", envelope, {"existing_job_id": existing.job_id})
                return existing
        receipt = self.queue_adapter.enqueue(queue_name=queue_name, envelope=envelope)
        if receipt.queue_backend != envelope.queue_backend:
            # The configured adapter is the single source of truth for where the job
            # physically lives; record that, not the requested backend (which the adapter
            # cannot honor). Otherwise list_jobs(queue_backend=...) surfaces a phantom and
            # a worker bound to the requested backend never drains the job.
            envelope = replace(envelope, queue_backend=receipt.queue_backend)
        stored = (
            self.job_service.create_or_get_job(envelope=envelope, receipt_id=receipt.receipt_id)
            if self.job_service
            else None
        )
        self._emit("job_submitted", envelope, {"receipt_id": receipt.receipt_id})
        return stored or {
            "job_id": str(normalized_request.job_id),
            "correlation_id": str(normalized_request.correlation_id),
            "queue_backend": envelope.queue_backend,
            "queue_name": queue_name,
        }

    def _begin_processing(self, *, envelope: QueueEnvelope, receipt: QueueReceipt) -> bool:
        """Mark the job running; ack-and-skip (returning False) when no row tracks it."""
        if self.job_service is not None:
            running = self.job_service.mark_running(
                job_id=str(envelope.request.job_id),
                attempts=envelope.attempts + 1,
                receipt_id=receipt.receipt_id,
            )
            if running is None:
                # A duplicate (an equivalent job already owns the work) or an untracked
                # message; re-running it would break idempotency, so ack-and-skip.
                self.queue_adapter.ack(receipt)
                self._emit("job_skipped", envelope, {"reason": "no_tracked_job"})
                return False
        self._emit("job_started", envelope, {"attempt": envelope.attempts + 1})
        return True

    def process_next(
        self, *, queue_name: str = "default"
    ) -> DistributedJobRecord | PipelineJobResult | None:
        item = self.queue_adapter.dequeue(queue_name=queue_name)
        if item is None:
            return None
        receipt, envelope = item
        # Set once persisted completed, so the outer handler treats a later ack/emit
        # failure (e.g. expired SQS receipt) as benign redelivery, not a dead-letter.
        completed: DistributedJobRecord | PipelineJobResult | None = None
        try:
            if not self._begin_processing(envelope=envelope, receipt=receipt):
                return None
            result = self.processor.process(envelope.request)
            if result.status in {"success", "skipped"}:
                # Handled before bookkeeping: a transition failure redelivers, not dead-letters.
                completed = result
                stored = (
                    self.job_service.mark_completed(
                        job_id=str(envelope.request.job_id),
                        attempts=envelope.attempts + 1,
                        run_id=result.run_id,
                        result_json=result.to_record(),
                        metrics=phase_metrics(result),
                    )
                    if self.job_service
                    else None
                )
                completed = stored or result
                self.queue_adapter.ack(receipt)
                self._emit(
                    "job_completed", envelope, {"status": result.status, "run_id": result.run_id}
                )
                return completed

            failure_error = error_for_failed_result(result)
            should_retry = bool(
                failure_error.retryable and (envelope.attempts + 1) < envelope.max_attempts
            )
            if should_retry:
                completed = result  # see above: a requeue/mark_failed failure must redeliver
                stored = (
                    self.job_service.mark_failed(
                        job_id=str(envelope.request.job_id),
                        attempts=envelope.attempts + 1,
                        error=failure_error,
                        will_retry=True,
                        metrics=phase_metrics(result),
                    )
                    if self.job_service
                    else None
                )
                next_envelope = advance_envelope(envelope)
                next_receipt = self.queue_adapter.requeue(receipt, envelope=next_envelope)
                self._emit("job_requeued", envelope, {"receipt_id": next_receipt.receipt_id})
                return stored or result

            stored = (
                self.job_service.mark_dead_lettered(
                    job_id=str(envelope.request.job_id),
                    attempts=envelope.attempts + 1,
                    error=failure_error,
                    metrics=phase_metrics(result),
                )
                if self.job_service
                else None
            )
            dead_receipt_id = self._archive_dead_letter(receipt=receipt, envelope=envelope)
            self._emit(
                "job_dead_lettered",
                envelope,
                {"receipt_id": dead_receipt_id, "error_code": failure_error.code},
            )
            return stored or result
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if completed is not None:
                self._emit("job_ack_failed", envelope, {"error": str(exc)})
                return completed
            if self.job_service is not None:
                self.job_service.mark_dead_lettered(
                    job_id=str(envelope.request.job_id),
                    attempts=envelope.attempts + 1,
                    error=classify_pipeline_exception(exc),
                )
            self._archive_dead_letter(receipt=receipt, envelope=envelope)
            self._emit(
                "job_dead_lettered",
                envelope,
                {"receipt_id": receipt.receipt_id, "error_code": "unhandled"},
            )
            raise

    def _archive_dead_letter(self, *, receipt: QueueReceipt, envelope: QueueEnvelope) -> str:
        """Archive the message to the dead-letter sink."""
        try:
            return self.queue_adapter.dead_letter(
                receipt, envelope=advance_envelope(envelope)
            ).receipt_id
        except RuntimeError as exc:
            if str(exc) != (
                "SQS dead-letter queue URL not configured; refusing to re-enqueue to the main "
                "queue which would cause an infinite processing loop. Set dead_letter_queue_url."
            ):
                raise
            self.queue_adapter.ack(receipt)
            return receipt.receipt_id

    def drain(
        self,
        *,
        queue_name: str = "default",
        limit: int = 100,
    ) -> list[DistributedJobRecord | PipelineJobResult]:
        results: list[DistributedJobRecord | PipelineJobResult] = []
        for _ in range(limit):
            current = self.process_next(queue_name=queue_name)
            if current is None:
                break
            results.append(current)
        return results

    def get_job(self, *, job_id: str) -> DistributedJobRecord | None:
        return self.job_service.get_job(job_id=job_id) if self.job_service else None

    def list_jobs(
        self,
        *,
        limit: int = 50,
        statuses: tuple[str, ...] = (),
        queue_backend: str | None = None,
    ) -> list[DistributedJobRecord]:
        return (
            self.job_service.list_jobs(limit=limit, statuses=statuses, queue_backend=queue_backend)
            if self.job_service
            else []
        )

    def list_dead_letters(
        self, *, limit: int = 50, queue_backend: str | None = None
    ) -> list[DeadLetterRecord]:
        return (
            self.job_service.list_dead_letters(limit=limit, queue_backend=queue_backend)
            if self.job_service
            else []
        )

    def _emit(self, name: str, envelope: QueueEnvelope, attributes: dict[str, object]) -> None:
        self.telemetry_sink.emit(
            TelemetryEvent(
                name=name,
                job_id=str(envelope.request.job_id or ""),
                correlation_id=str(
                    envelope.request.correlation_id or envelope.request.job_id or ""
                ),
                queue_backend=envelope.queue_backend,
                queue_name=envelope.queue_name,
                attributes=attributes,
            ),
        )
