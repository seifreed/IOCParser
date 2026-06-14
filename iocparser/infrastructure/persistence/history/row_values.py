from __future__ import annotations

from contextlib import suppress
from datetime import datetime

from iocparser.shared_utils import TRUE_BOOL_VALUES

INT_FIELD_DEFAULTS: dict[str, int | None] = {
    "id": None,
    "source_id": None,
    "batch_job_id": None,
    "run_id": None,
    "ioc_id": None,
    "input_size": None,
    "normal_ioc_count": 0,
    "warning_ioc_count": 0,
    "processed_items": 0,
    "successful_items": 0,
    "failed_items": 0,
    "partial_error_count": 0,
    "duration_ms": 0,
    "total_inputs": 0,
    "successful_inputs": 0,
    "failed_inputs": 0,
    "retry_attempt": 0,
    "attempts": 0,
    "max_attempts": 0,
}
BOOL_FIELDS = {"is_warning", "retryable"}


def bool_from_row(value: object, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in TRUE_BOOL_VALUES
    return bool(value)


def int_from_row(value: object, *, default: int | None = None) -> int | None:
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lstrip("-").isdigit():
            return int(stripped)
    return default


def typed_row(row: dict[str, object]) -> dict[str, object]:
    row_dict = dict(row)
    for key, value in list(row_dict.items()):
        if isinstance(value, str) and key.endswith(("_at", "_seen")) and value:
            with suppress(ValueError, TypeError):
                row_dict[key] = datetime.fromisoformat(value)
        if key in INT_FIELD_DEFAULTS:
            parsed = int_from_row(value, default=INT_FIELD_DEFAULTS[key])
            if parsed is None:
                row_dict.pop(key, None)
            else:
                row_dict[key] = parsed
        if key in BOOL_FIELDS:
            row_dict[key] = bool_from_row(value)
    return row_dict
