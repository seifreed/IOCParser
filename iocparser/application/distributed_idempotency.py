from __future__ import annotations

from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.interfaces.ports import ContentDigester


def idempotency_key_for(request: PipelineJobRequest, *, digester: ContentDigester | None) -> str:
    """Build a stable idempotency key for a pipeline request."""
    if digester is None:
        return (
            f"{request.input_kind}:{request.source_value}"
            f":cw={request.check_warnings}"
            f":fu={request.force_update}"
            f":df={request.defang}"
            f":o={request.only or ''}"
            f":e={request.exclude or ''}"
            f":eo={request.emit_only}"
        )
    if request.input_kind == "text":
        return digester.digest_text(request.source_value)
    if request.input_kind == "file":
        return digester.digest_file(request.source_value)
    return digester.digest_text(request.source_value)
