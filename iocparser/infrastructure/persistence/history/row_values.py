from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime

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
BOOL_FIELDS = {"is_warning"}
# retryable is nullable (None == "not yet determined"); coercing None to False
# on a history export/import round-trip would lose that tri-state distinction.
NULLABLE_BOOL_FIELDS = {"retryable"}


def bool_from_row(value: object, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in TRUE_BOOL_VALUES
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise TypeError(f"Expected boolean-compatible value, got {type(value).__name__}")


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
            stripped = value.strip()
            if not stripped:
                continue
            with suppress(ValueError, TypeError):
                parsed = datetime.fromisoformat(stripped)
                # The DB stores naive UTC and every live writer uses datetime.now(UTC)
                # then drops tzinfo. Archives may carry a tz offset (hand-edited or
                # produced by another tool); normalize so imported timestamps compare
                # against existing naive rows instead of raising a TypeError.
                if parsed.tzinfo is not None:
                    parsed = parsed.astimezone(UTC).replace(tzinfo=None)
                row_dict[key] = parsed
        if key in INT_FIELD_DEFAULTS:
            parsed = int_from_row(value, default=INT_FIELD_DEFAULTS[key])
            if parsed is None:
                row_dict.pop(key, None)
            else:
                row_dict[key] = parsed
        if key in BOOL_FIELDS:
            row_dict[key] = bool_from_row(value)
        if key in NULLABLE_BOOL_FIELDS:
            row_dict[key] = None if value is None else bool_from_row(value)
    return row_dict
