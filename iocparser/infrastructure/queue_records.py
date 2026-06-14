from __future__ import annotations

import json
from typing import cast


def queue_payload_type_error() -> TypeError:
    return TypeError("Queue payload must be a JSON object")


def load_queue_record(payload: str) -> dict[str, object]:
    decoded = cast("object", json.loads(payload))
    if not isinstance(decoded, dict):
        raise queue_payload_type_error()
    return cast("dict[str, object]", decoded)
