from __future__ import annotations

import os
from pathlib import Path

from iocparser.runtime_config import find_default_config_paths, load_ini_sections

WORKER_DEFAULTS: dict[str, object] = {
    "queue_backend": "filesystem",
    "queue_name": "default",
    "queue_url": None,
    "queue_path": ".iocparser-queue",
    "dead_letter_queue_url": None,
    "db_uri": None,
    "poll_interval_seconds": 1.0,
    "max_messages_per_cycle": 1,
    "max_cycles": None,
    "concurrency": 1,
    "telemetry_mode": "logging",
    "max_input_size_bytes": None,
    "max_input_seconds": None,
    "memory_limit_bytes": None,
    "cpu_seconds": None,
    "hard_timeout_seconds": None,
    "max_queue_size": 64,
    "skip_processed": False,
}


def _int_type_error(value: object) -> TypeError:
    return TypeError(f"Expected int-compatible value, got {type(value).__name__}")


def _float_type_error(value: object) -> TypeError:
    return TypeError(f"Expected float-compatible value, got {type(value).__name__}")


def int_env(name: str, default: int | None = None) -> int | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def float_env(name: str, default: float | None = None) -> float | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return float(raw)


def bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def resolve_config_path(config_path: str | None) -> Path | None:
    chosen = config_path or os.environ.get("IOCPARSER_CONFIG")
    if chosen:
        candidate = Path(chosen)
        return candidate if candidate.exists() else None
    for candidate in find_default_config_paths():
        if candidate.exists():
            return candidate
    return None


def load_worker_file_values(config_path: Path | None) -> dict[str, object]:
    if config_path is None:
        return dict(WORKER_DEFAULTS)
    parser = load_ini_sections(config_path)
    values = dict(WORKER_DEFAULTS)
    if parser.has_section("database"):
        values["db_uri"] = parser.get("database", "uri", fallback=None)
    if parser.has_section("network"):
        values["max_input_seconds"] = parser.getfloat("network", "max_input_seconds", fallback=None)
        values["max_queue_size"] = parser.getint("network", "max_queue_size", fallback=64)
        values["skip_processed"] = parser.getboolean("network", "skip_processed", fallback=False)
    if parser.has_section("worker"):
        values["queue_backend"] = parser.get("worker", "queue_backend", fallback="filesystem")
        values["queue_name"] = parser.get("worker", "queue_name", fallback="default")
        values["queue_url"] = parser.get("worker", "queue_url", fallback=None)
        values["queue_path"] = parser.get("worker", "queue_path", fallback=".iocparser-queue")
        values["dead_letter_queue_url"] = parser.get("worker", "dead_letter_queue_url", fallback=None)
        values["poll_interval_seconds"] = parser.getfloat("worker", "poll_interval_seconds", fallback=1.0)
        values["max_messages_per_cycle"] = parser.getint("worker", "max_messages_per_cycle", fallback=1)
        values["max_cycles"] = parser.getint("worker", "max_cycles", fallback=None)
        values["concurrency"] = parser.getint("worker", "concurrency", fallback=1)
        values["telemetry_mode"] = parser.get("worker", "telemetry_mode", fallback="logging")
    if parser.has_section("runtime"):
        values["max_input_size_bytes"] = parser.getint("runtime", "max_input_size_bytes", fallback=None)
        values["memory_limit_bytes"] = parser.getint("runtime", "memory_limit_bytes", fallback=None)
        values["cpu_seconds"] = parser.getint("runtime", "cpu_seconds", fallback=None)
        values["hard_timeout_seconds"] = parser.getint("runtime", "hard_timeout_seconds", fallback=None)
        values["max_queue_size"] = parser.getint("runtime", "max_queue_size", fallback=64)
        values["skip_processed"] = parser.getboolean("runtime", "skip_processed", fallback=False)
    return values


def str_or_none(value: object) -> str | None:
    return str(value) if value is not None else None


def int_or(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise _int_type_error(value)


def int_or_none(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise _int_type_error(value)


def float_or(value: object, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise _float_type_error(value)


def float_or_none(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise _float_type_error(value)
