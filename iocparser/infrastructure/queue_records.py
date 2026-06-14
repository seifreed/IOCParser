from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from iocparser.domain.distributed import QueueEnvelope


def queue_payload_type_error() -> TypeError:
    return TypeError("Queue payload must be a JSON object")


def serialize_queue_record(envelope: QueueEnvelope) -> str:
    """Encode a queue envelope to its canonical JSON string (decode: load_queue_record)."""
    return json.dumps(envelope.to_record(), sort_keys=True)


def load_queue_record(payload: str) -> dict[str, object]:
    decoded = cast("object", json.loads(payload))
    if not isinstance(decoded, dict):
        raise queue_payload_type_error()
    return cast("dict[str, object]", decoded)
