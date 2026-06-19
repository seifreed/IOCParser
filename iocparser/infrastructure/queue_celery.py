from __future__ import annotations

from typing import Protocol, cast
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.infrastructure.queue_records import (
    import_optional_backend_module,
    materialize_queue_envelope,
    serialize_queue_record,
)


class _CeleryAsyncResult(Protocol):
    id: str | None


class _CeleryApp(Protocol):
    def send_task(
        self,
        name: str,
        args: list[dict[str, object]],
        *,
        queue: str,
        task_id: str,
    ) -> _CeleryAsyncResult: ...


class _CeleryFactory(Protocol):
    def __call__(self, main: str, *, broker: str) -> _CeleryApp: ...


class _CeleryModule(Protocol):
    Celery: _CeleryFactory


def _celery_module() -> _CeleryModule:
    return cast("_CeleryModule", import_optional_backend_module("celery", backend="celery"))


class CeleryQueueAdapter:
    """Celery adapter that submits queue envelopes as tasks through a Celery app."""

    def __init__(self, broker_url: str, *, task_name: str = "iocparser.process_envelope") -> None:
        celery_module = _celery_module()
        self.app: _CeleryApp = celery_module.Celery("iocparser-pipeline", broker=broker_url)
        self.task_name = task_name

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        envelope = materialize_queue_envelope(envelope)
        task_id = str(envelope.request.job_id or uuid4())
        result = self.app.send_task(
            self.task_name,
            args=[envelope.to_record()],
            queue=queue_name,
            task_id=task_id,
        )
        message_id = str(result.id or task_id)
        return QueueReceipt("celery", queue_name, message_id, message_id)

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        del queue_name
        return None

    def ack(self, receipt: QueueReceipt) -> None:
        del receipt

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        envelope = materialize_queue_envelope(envelope)
        target_queue = receipt.queue_name or envelope.queue_name
        return self.enqueue(queue_name=target_queue, envelope=envelope)

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        envelope = materialize_queue_envelope(envelope)
        source_queue = receipt.queue_name or envelope.queue_name
        dead_queue = f"{source_queue}.dead"
        return self.enqueue(
            queue_name=dead_queue,
            envelope=QueueEnvelope(
                request=envelope.request,
                queue_backend=envelope.queue_backend,
                queue_name=dead_queue,
                attempts=envelope.attempts,
                max_attempts=envelope.max_attempts,
                idempotency_key=envelope.idempotency_key,
                schema_version=envelope.schema_version,
                submitted_at=envelope.submitted_at,
            ),
        )


def build_celery_task_payload(envelope: QueueEnvelope) -> str:
    """Serialize a queue envelope for external Celery workers."""
    return serialize_queue_record(materialize_queue_envelope(envelope))
