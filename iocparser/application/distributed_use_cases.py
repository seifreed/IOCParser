from __future__ import annotations

from contextlib import suppress
from uuid import uuid4

from iocparser.application.distributed_idempotency import idempotency_key_for
from iocparser.domain.distributed import (
    DeadLetterRecord,
    DistributedJobRecord,
    QueueEnvelope,
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


def _phase_metrics(result: PipelineJobResult) -> dict[str, object]:
    return dict(result.phase_timings_ms)


def _advance_envelope(envelope: QueueEnvelope) -> QueueEnvelope:
    return QueueEnvelope(
        request=envelope.request,
        queue_backend=envelope.queue_backend,
        queue_name=envelope.queue_name,
        attempts=envelope.attempts + 1,
        max_attempts=envelope.max_attempts,
        idempotency_key=envelope.idempotency_key,
        schema_version=envelope.schema_version,
        submitted_at=envelope.submitted_at,
    )


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
        job_id = request.job_id or str(uuid4())
        correlation_id = request.correlation_id or job_id
        normalized_request = PipelineJobRequest(
            input_kind=request.input_kind,
            source_value=request.source_value,
            file_type=request.file_type,
            persist=request.persist,
            db_uri=request.db_uri,
            check_warnings=request.check_warnings,
            force_update=request.force_update,
            defang=request.defang,
            only=request.only,
            exclude=request.exclude,
            correlation_id=correlation_id,
            job_id=job_id,
            emit_only=request.emit_only,
        )
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
        stored = (
            self.job_service.create_or_get_job(envelope=envelope, receipt_id=receipt.receipt_id)
            if self.job_service
            else None
        )
        self._emit("job_submitted", envelope, {"receipt_id": receipt.receipt_id})
        return stored or {
            "job_id": job_id,
            "correlation_id": correlation_id,
            "queue_backend": queue_backend,
            "queue_name": queue_name,
        }

    def process_next(
        self, *, queue_name: str = "default"
    ) -> DistributedJobRecord | PipelineJobResult | None:
        item = self.queue_adapter.dequeue(queue_name=queue_name)
        if item is None:
            return None
        receipt, envelope = item
        try:
            if self.job_service is not None:
                self.job_service.mark_running(
                    job_id=str(envelope.request.job_id),
                    attempts=envelope.attempts + 1,
                    receipt_id=receipt.receipt_id,
                )
            self._emit("job_started", envelope, {"attempt": envelope.attempts + 1})
            result = self.processor.process(envelope.request)
            if result.status in {"success", "skipped"}:
                stored = (
                    self.job_service.mark_completed(
                        job_id=str(envelope.request.job_id),
                        attempts=envelope.attempts + 1,
                        run_id=result.run_id,
                        result_json=result.to_record(),
                        metrics=_phase_metrics(result),
                    )
                    if self.job_service
                    else None
                )
                self.queue_adapter.ack(receipt)
                self._emit(
                    "job_completed", envelope, {"status": result.status, "run_id": result.run_id}
                )
                return stored or result

            failure_error = error_for_failed_result(result)
            should_retry = bool(
                failure_error.retryable and (envelope.attempts + 1) < envelope.max_attempts
            )
            if should_retry:
                stored = (
                    self.job_service.mark_failed(
                        job_id=str(envelope.request.job_id),
                        attempts=envelope.attempts + 1,
                        error=failure_error,
                        will_retry=True,
                        metrics=_phase_metrics(result),
                    )
                    if self.job_service
                    else None
                )
                next_envelope = _advance_envelope(envelope)
                next_receipt = self.queue_adapter.requeue(receipt, envelope=next_envelope)
                self._emit("job_requeued", envelope, {"receipt_id": next_receipt.receipt_id})
                return stored or result

            dead_envelope = _advance_envelope(envelope)
            stored = (
                self.job_service.mark_dead_lettered(
                    job_id=str(envelope.request.job_id),
                    attempts=envelope.attempts + 1,
                    error=failure_error,
                )
                if self.job_service
                else None
            )
            dead_receipt = self.queue_adapter.dead_letter(receipt, envelope=dead_envelope)
            self._emit(
                "job_dead_lettered",
                envelope,
                {
                    "receipt_id": dead_receipt.receipt_id,
                    "error_code": failure_error.code,
                },
            )
            return stored or result
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            failed_envelope = _advance_envelope(envelope)
            if self.job_service is not None:
                self.job_service.mark_dead_lettered(
                    job_id=str(envelope.request.job_id),
                    attempts=envelope.attempts + 1,
                    error=classify_pipeline_exception(exc),
                )
            with suppress(Exception):
                self.queue_adapter.dead_letter(receipt, envelope=failed_envelope)
            self._emit(
                "job_dead_lettered",
                envelope,
                {"receipt_id": receipt.receipt_id, "error_code": "unhandled"},
            )
            raise

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
