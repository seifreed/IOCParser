from __future__ import annotations

import json
from dataclasses import replace
from importlib import import_module
from types import ModuleType
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from iocparser.errors import IOCParserError

if TYPE_CHECKING:
    from iocparser.domain.distributed import QueueEnvelope

MISSING_BACKEND_DEPENDENCY_ERROR = (
    "{backend} backend requires the optional '{module_name}' package; "
    "install it with: pip install iocparser-tool[pipeline]"
)


def import_optional_backend_module(module_name: str, *, backend: str) -> ModuleType:
    """Import an optional queue-backend dependency, or raise a clean install hint.

    The pipeline backends (boto3/pika/celery) ship in the optional ``pipeline`` extra;
    a bare ModuleNotFoundError would surface as a stack trace instead of telling the
    operator which package to install.
    """
    try:
        return import_module(module_name)
    except ModuleNotFoundError as exc:
        raise IOCParserError(
            MISSING_BACKEND_DEPENDENCY_ERROR.format(backend=backend, module_name=module_name)
        ) from exc


def queue_payload_type_error() -> TypeError:
    return TypeError("Queue payload must be a JSON object")


def serialize_queue_record(envelope: QueueEnvelope) -> str:
    """Encode a queue envelope to its canonical JSON string (decode: load_queue_record)."""
    return json.dumps(envelope.to_record(), sort_keys=True)


def materialize_queue_envelope(envelope: QueueEnvelope) -> QueueEnvelope:
    from iocparser.domain.pipeline import PipelineJobRequest

    request = envelope.request
    job_id = getattr(request, "job_id", None) or str(uuid4())
    correlation_id = getattr(request, "correlation_id", None) or job_id
    if (
        getattr(request, "job_id", None) == job_id
        and getattr(request, "correlation_id", None) == correlation_id
    ):
        return envelope
    materialized_request = PipelineJobRequest(
        input_kind=request.input_kind,
        source_value=request.source_value,
        file_type=getattr(request, "file_type", None),
        persist=getattr(request, "persist", False),
        db_uri=getattr(request, "db_uri", None),
        check_warnings=getattr(request, "check_warnings", True),
        force_update=getattr(request, "force_update", False),
        defang=getattr(request, "defang", True),
        only=getattr(request, "only", None),
        exclude=getattr(request, "exclude", None),
        correlation_id=correlation_id,
        job_id=job_id,
        emit_only=getattr(request, "emit_only", False),
    )
    return replace(envelope, request=materialized_request)


def build_invalid_payload_record(
    *, payload: str, queue_name: str, message_id: str, error: Exception
) -> str:
    """Serialize a quarantined invalid-payload record to canonical JSON."""
    return json.dumps(
        {
            "invalid_payload": payload,
            "queue_name": queue_name,
            "message_id": message_id,
            "error": str(error),
        },
        sort_keys=True,
    )


def load_queue_record(payload: str) -> dict[str, object]:
    decoded = cast("object", json.loads(payload))
    if not isinstance(decoded, dict):
        raise queue_payload_type_error()
    return cast("dict[str, object]", decoded)
