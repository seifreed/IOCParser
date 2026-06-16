from __future__ import annotations

from iocparser.domain.distributed import QueueEnvelope
from iocparser.domain.pipeline import PipelineJobResult


def phase_metrics(result: PipelineJobResult) -> dict[str, object]:
    return dict(result.phase_timings_ms)


def advance_envelope(envelope: QueueEnvelope) -> QueueEnvelope:
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
