from __future__ import annotations

import hashlib

from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.interfaces.ports import ContentDigester


def _processing_options_key(request: PipelineJobRequest) -> str:
    return (
        f"cw={request.check_warnings}"
        f":fu={request.force_update}"
        f":df={request.defang}"
        f":o={request.only or ''}"
        f":e={request.exclude or ''}"
        f":eo={request.emit_only}"
        f":ft={request.file_type or ''}"
    )


def _source_digest(request: PipelineJobRequest, *, digester: ContentDigester) -> str:
    if request.input_kind == "file":
        return digester.digest_file(request.source_value)
    return digester.digest_text(request.source_value)


def idempotency_key_for(request: PipelineJobRequest, *, digester: ContentDigester | None) -> str:
    """Build a stable idempotency key for a pipeline request."""
    options_key = _processing_options_key(request)
    if digester is None:
        return f"{request.input_kind}:{request.source_value}:{options_key}"
    material = f"{request.input_kind}:{_source_digest(request, digester=digester)}:{options_key}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
