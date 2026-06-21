from __future__ import annotations

import os
from configparser import ConfigParser
from pathlib import Path

from iocparser.errors import SourceNotFoundError, TypeValidationError
from iocparser.runtime_config import find_default_config_paths, load_ini_sections
from iocparser.shared_utils import FALSE_BOOL_VALUES, TRUE_BOOL_VALUES


def _ini_has_value(parser: ConfigParser, section: str, option: str) -> bool:
    # ConfigParser.get*(fallback=...) only applies the fallback when the option is
    # absent, so a present-but-empty value (``key =``) reaches the converter and
    # raises ValueError. Treat empty/whitespace-only values as absent.
    return bool(parser.get(section, option, fallback="").strip())


def _ini_optional_str(parser: ConfigParser, section: str, option: str) -> str | None:
    raw_value = parser.get(section, option, fallback=None)
    if raw_value is None:
        return None
    stripped = raw_value.strip()
    return stripped or None


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
INVALID_INT_ENV_ERROR = "Invalid integer environment value for {name}: {value!r}"
INVALID_FLOAT_ENV_ERROR = "Invalid float environment value for {name}: {value!r}"


def _int_type_error(value: object) -> TypeError:
    return TypeError(f"Expected int-compatible value, got {type(value).__name__}")


def _float_type_error(value: object) -> TypeError:
    return TypeError(f"Expected float-compatible value, got {type(value).__name__}")


def int_env(name: str, default: int | None = None) -> int | None:
    raw = os.environ.get(name)
    if raw is None:
        return default
    stripped = raw.strip()
    if not stripped:
        return default
    try:
        return int(stripped)
    except ValueError as exc:
        raise ValueError(INVALID_INT_ENV_ERROR.format(name=name, value=raw)) from exc


def float_env(name: str, default: float | None = None) -> float | None:
    raw = os.environ.get(name)
    if raw is None:
        return default
    stripped = raw.strip()
    if not stripped:
        return default
    try:
        return float(stripped)
    except ValueError as exc:
        raise ValueError(INVALID_FLOAT_ENV_ERROR.format(name=name, value=raw)) from exc


def bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if not normalized:
        return default
    if normalized in TRUE_BOOL_VALUES:
        return True
    if normalized in FALSE_BOOL_VALUES:
        return False
    raise ValueError(INVALID_BOOL_ENV_ERROR.format(name=name, value=raw))


def resolve_config_path(config_path: str | None) -> Path | None:
    if config_path is not None:
        chosen = config_path.strip()
        if not chosen:
            return None
        candidate = Path(chosen).expanduser()
        if not candidate.exists():
            raise SourceNotFoundError(str(candidate))
        return candidate
    env_value = os.environ.get("IOCPARSER_CONFIG")
    env_chosen = env_value.strip() if env_value is not None else None
    if env_chosen:
        candidate = Path(env_chosen).expanduser()
        if not candidate.exists():
            raise SourceNotFoundError(str(candidate))
        return candidate
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
        values["db_uri"] = _ini_optional_str(parser, "database", "uri")
    if parser.has_section("network"):
        values["max_input_seconds"] = _ini_float(
            parser, "network", "max_input_seconds", fallback=None
        )
        values["max_queue_size"] = _ini_int(parser, "network", "max_queue_size", fallback=64)
        values["skip_processed"] = _ini_bool(parser, "network", "skip_processed", fallback=False)
    if parser.has_section("worker"):
        values["queue_backend"] = (
            _ini_optional_str(parser, "worker", "queue_backend") or "filesystem"
        )
        values["queue_name"] = _ini_optional_str(parser, "worker", "queue_name") or "default"
        values["queue_url"] = _ini_optional_str(parser, "worker", "queue_url")
        values["queue_path"] = _ini_optional_str(parser, "worker", "queue_path") or ".iocparser-queue"
        values["dead_letter_queue_url"] = _ini_optional_str(
            parser, "worker", "dead_letter_queue_url"
        )
        values["poll_interval_seconds"] = _ini_float(
            parser, "worker", "poll_interval_seconds", fallback=1.0
        )
        values["max_messages_per_cycle"] = _ini_int(
            parser, "worker", "max_messages_per_cycle", fallback=1
        )
        values["max_cycles"] = _ini_int(parser, "worker", "max_cycles", fallback=None)
        values["concurrency"] = _ini_int(parser, "worker", "concurrency", fallback=1)
        values["telemetry_mode"] = _ini_optional_str(parser, "worker", "telemetry_mode") or "logging"
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
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeValidationError(None, "string value", value)
    stripped = value.strip()
    return stripped or None


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
