from __future__ import annotations

from iocparser.domain.pipeline import PipelineJobRequest


def bind_request_db_uri(request: PipelineJobRequest, *, db_uri: str | None) -> PipelineJobRequest:
    """Inject the runtime DB URI into a request when the request omitted it."""
    if request.db_uri is not None or db_uri is None:
        return request
    return PipelineJobRequest(
        input_kind=request.input_kind,
        source_value=request.source_value,
        file_type=request.file_type,
        persist=request.persist,
        db_uri=db_uri,
        check_warnings=request.check_warnings,
        force_update=request.force_update,
        defang=request.defang,
        only=request.only,
        exclude=request.exclude,
        correlation_id=request.correlation_id,
        job_id=request.job_id,
        emit_only=request.emit_only,
    )


__all__ = ["bind_request_db_uri"]
