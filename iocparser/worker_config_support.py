from __future__ import annotations

import os
from configparser import ConfigParser
from pathlib import Path

from iocparser.runtime_config import find_default_config_paths, load_ini_sections
from iocparser.shared_utils import FALSE_BOOL_VALUES, TRUE_BOOL_VALUES


def _ini_has_value(parser: ConfigParser, section: str, option: str) -> bool:
    # ConfigParser.get*(fallback=...) only applies the fallback when the option is
    # absent, so a present-but-empty value (``key =``) reaches the converter and
    # raises ValueError. Treat empty/whitespace-only values as absent.
    return bool(parser.get(section, option, fallback="").strip())


def _ini_int[T](parser: ConfigParser, section: str, option: str, *, fallback: T) -> int | T:
    return parser.getint(section, option) if _ini_has_value(parser, section, option) else fallback


def _ini_float[T](parser: ConfigParser, section: str, option: str, *, fallback: T) -> float | T:
    return parser.getfloat(section, option) if _ini_has_value(parser, section, option) else fallback


def _ini_bool[T](parser: ConfigParser, section: str, option: str, *, fallback: T) -> bool | T:
    return (
        parser.getboolean(section, option) if _ini_has_value(parser, section, option) else fallback
    )


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
INVALID_BOOL_ENV_ERROR = "Invalid boolean environment value for {name}: {value!r}"


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
    normalized = raw.strip().lower()
    if normalized in TRUE_BOOL_VALUES:
        return True
    if normalized in FALSE_BOOL_VALUES:
        return False
    raise ValueError(INVALID_BOOL_ENV_ERROR.format(name=name, value=raw))


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
        values["max_input_seconds"] = _ini_float(
            parser, "network", "max_input_seconds", fallback=None
        )
        values["max_queue_size"] = _ini_int(parser, "network", "max_queue_size", fallback=64)
        values["skip_processed"] = _ini_bool(parser, "network", "skip_processed", fallback=False)
    if parser.has_section("worker"):
        values["queue_backend"] = parser.get("worker", "queue_backend", fallback="filesystem")
        values["queue_name"] = parser.get("worker", "queue_name", fallback="default")
        values["queue_url"] = parser.get("worker", "queue_url", fallback=None)
        values["queue_path"] = parser.get("worker", "queue_path", fallback=".iocparser-queue")
        values["dead_letter_queue_url"] = parser.get(
            "worker", "dead_letter_queue_url", fallback=None
        )
        values["poll_interval_seconds"] = _ini_float(
            parser, "worker", "poll_interval_seconds", fallback=1.0
        )
        values["max_messages_per_cycle"] = _ini_int(
            parser, "worker", "max_messages_per_cycle", fallback=1
        )
        values["max_cycles"] = _ini_int(parser, "worker", "max_cycles", fallback=None)
        values["concurrency"] = _ini_int(parser, "worker", "concurrency", fallback=1)
        values["telemetry_mode"] = parser.get("worker", "telemetry_mode", fallback="logging")
    if parser.has_section("runtime"):
        values["max_input_size_bytes"] = _ini_int(
            parser, "runtime", "max_input_size_bytes", fallback=None
        )
        values["memory_limit_bytes"] = _ini_int(
            parser, "runtime", "memory_limit_bytes", fallback=None
        )
        values["cpu_seconds"] = _ini_int(parser, "runtime", "cpu_seconds", fallback=None)
        values["hard_timeout_seconds"] = _ini_int(
            parser, "runtime", "hard_timeout_seconds", fallback=None
        )
        if _ini_has_value(parser, "runtime", "max_queue_size"):
            values["max_queue_size"] = parser.getint("runtime", "max_queue_size")
        if _ini_has_value(parser, "runtime", "skip_processed"):
            values["skip_processed"] = parser.getboolean("runtime", "skip_processed")
    return values


def str_or_none(value: object) -> str | None:
    return str(value) if value is not None else None


def int_or(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise _int_type_error(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise _int_type_error(value)


def int_or_none(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise _int_type_error(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise _int_type_error(value)


def float_or(value: object, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool):
        raise _float_type_error(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise _float_type_error(value)


def float_or_none(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise _float_type_error(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise _float_type_error(value)
