from __future__ import annotations

from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope
from iocparser.domain.pipeline import PipelineJobRequest, PipelineJobResult


def phase_metrics(result: PipelineJobResult) -> dict[str, object]:
    return dict(result.phase_timings_ms)


def normalize_submit_request(request: PipelineJobRequest) -> PipelineJobRequest:
    """Return the request with job_id and correlation_id materialized for submission."""
    job_id = request.job_id or str(uuid4())
    return PipelineJobRequest(
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
        correlation_id=request.correlation_id or job_id,
        job_id=job_id,
        emit_only=request.emit_only,
    )


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
