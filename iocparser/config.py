#!/usr/bin/env python3

"""
Configuration loader for IOCParser.
"""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast

from dotenv import load_dotenv

from iocparser.errors import SourceNotFoundError, ValidationError
from iocparser.runtime_config import find_default_config_paths, load_ini_sections
from iocparser.shared_utils import FALSE_BOOL_VALUES, TRUE_BOOL_VALUES

INVALID_BOOLEAN_ERROR = "Invalid boolean for {option_name}: {value!r}"
INVALID_INTEGER_ERROR = "Invalid integer for {option_name}: {value!r}"
INVALID_FLOAT_ERROR = "Invalid number for {option_name}: {value!r}"
INVALID_CONFIG_FILE_ERROR = "Invalid config file {path}: {detail}"

# Options resolvable from IOCPARSER_<OPTION> environment variables, grouped by the
# coercion their value needs. persist/db_uri are handled separately because they
# also carry a CLI override; everything else only layers env over the INI file.
_ENV_STR_OPTIONS: tuple[str, ...] = (
    "only",
    "exclude",
    "stix_types",
    "output_format",
    "severity",
    "tag",
    "user_agent",
    "headers_json",
    "cookies_json",
    "proxy",
    "tls_cert",
    "ca_bundle",
)
_ENV_BOOL_OPTIONS: tuple[str, ...] = (
    "with_context",
    "streaming",
    "summary",
    "allow_redirects",
    "tls_verify",
    "skip_processed",
)
_ENV_INT_OPTIONS: tuple[str, ...] = (
    "url_workers",
    "url_retries",
    "parallel",
    "chunk_size",
    "overlap",
    "max_queue_size",
)
_ENV_FLOAT_OPTIONS: tuple[str, ...] = (
    "url_backoff",
    "rate_limit",
    "connect_timeout",
    "read_timeout",
    "max_input_size_mb",
    "max_input_seconds",
)


@dataclass(frozen=True)
class AppConfig:
    """Resolved application configuration."""

    persist: bool
    db_uri: str | None
    config_path: Path | None
    only: str | None = None
    exclude: str | None = None
    stix_types: str | None = None
    output_format: str | None = None
    with_context: bool = False
    streaming: bool = False
    summary: bool = False
    severity: str | None = None
    tag: str | None = None
    url_workers: int = 4
    url_retries: int = 0
    url_backoff: float = 0.0
    rate_limit: float = 0.0
    parallel: int = 1
    chunk_size: int = 1024 * 1024
    overlap: int = 1024
    diff_only: str = "all"
    user_agent: str | None = None
    headers_json: str | None = None
    cookies_json: str | None = None
    proxy: str | None = None
    allow_redirects: bool = True
    tls_verify: bool = True
    tls_cert: str | None = None
    ca_bundle: str | None = None
    connect_timeout: float | None = None
    read_timeout: float | None = None
    max_input_size_mb: float | None = None
    max_input_seconds: float | None = None
    max_queue_size: int = 64
    skip_processed: bool = False


class ConfigValues(TypedDict):
    persist: bool | None
    db_uri: str | None
    only: str | None
    exclude: str | None
    stix_types: str | None
    output_format: str | None
    with_context: bool
    streaming: bool
    summary: bool
    severity: str | None
    tag: str | None
    url_workers: int
    url_retries: int
    url_backoff: float
    rate_limit: float
    parallel: int
    chunk_size: int
    overlap: int
    diff_only: str
    user_agent: str | None
    headers_json: str | None
    cookies_json: str | None
    proxy: str | None
    allow_redirects: bool
    tls_verify: bool
    tls_cert: str | None
    ca_bundle: str | None
    connect_timeout: float | None
    read_timeout: float | None
    max_input_size_mb: float | None
    max_input_seconds: float | None
    max_queue_size: int
    skip_processed: bool


def default_config_values() -> ConfigValues:
    """Return the baseline config dictionary used by loaders."""
    return {
        "persist": None,
        "db_uri": None,
        "only": None,
        "exclude": None,
        "stix_types": None,
        "output_format": None,
        "with_context": False,
        "streaming": False,
        "summary": False,
        "severity": None,
        "tag": None,
        "url_workers": 4,
        "url_retries": 0,
        "url_backoff": 0.0,
        "rate_limit": 0.0,
        "parallel": 1,
        "chunk_size": 1024 * 1024,
        "overlap": 1024,
        "diff_only": "all",
        "user_agent": None,
        "headers_json": None,
        "cookies_json": None,
        "proxy": None,
        "allow_redirects": True,
        "tls_verify": True,
        "tls_cert": None,
        "ca_bundle": None,
        "connect_timeout": None,
        "read_timeout": None,
        "max_input_size_mb": None,
        "max_input_seconds": None,
        "max_queue_size": 64,
        "skip_processed": False,
    }


def _parse_bool_value(value: str, *, option_name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in TRUE_BOOL_VALUES:
        return True
    if normalized in FALSE_BOOL_VALUES:
        return False
    raise ValueError(INVALID_BOOLEAN_ERROR.format(option_name=option_name, value=value))


def _parse_int_value(value: str, *, option_name: str) -> int:
    try:
        return int(value.strip())
    except ValueError as exc:
        raise ValueError(
            INVALID_INTEGER_ERROR.format(option_name=option_name, value=value)
        ) from exc


def _parse_float_value(value: str, *, option_name: str) -> float:
    try:
        return float(value.strip())
    except ValueError as exc:
        raise ValueError(INVALID_FLOAT_ERROR.format(option_name=option_name, value=value)) from exc


def _ini_has_value(parser: configparser.ConfigParser, section: str, option: str) -> bool:
    return bool(parser.get(section, option, fallback="").strip())


def _ini_bool(
    parser: configparser.ConfigParser, section: str, option: str, *, fallback: bool
) -> bool:
    if not _ini_has_value(parser, section, option):
        return fallback
    return _parse_bool_value(parser.get(section, option), option_name=f"{section}.{option}")


def _ini_int(parser: configparser.ConfigParser, section: str, option: str, *, fallback: int) -> int:
    if not _ini_has_value(parser, section, option):
        return fallback
    return _parse_int_value(parser.get(section, option), option_name=f"{section}.{option}")


def _ini_float(
    parser: configparser.ConfigParser, section: str, option: str, *, fallback: float
) -> float:
    if not _ini_has_value(parser, section, option):
        return fallback
    return _parse_float_value(parser.get(section, option), option_name=f"{section}.{option}")


def _ini_optional_float(
    parser: configparser.ConfigParser, section: str, option: str
) -> float | None:
    if not _ini_has_value(parser, section, option):
        return None
    return _parse_float_value(parser.get(section, option), option_name=f"{section}.{option}")


def _apply_env_overrides(values: ConfigValues) -> None:
    """Layer IOCPARSER_<OPTION> environment variables over INI values in place.

    This realises the documented CLI > env > INI precedence: the CLI layer is
    applied downstream, so overriding the INI values here leaves env below CLI and
    above the file for every option (persist/db_uri are resolved separately).
    """
    mutable = cast("dict[str, object]", values)  # dynamic keys; ConfigValues is a dict at runtime
    for option in _ENV_STR_OPTIONS:
        raw = os.environ.get(f"IOCPARSER_{option.upper()}")
        if raw is not None:
            mutable[option] = raw.strip() or None
    # diff_only is a non-optional str ("all" default); an empty env value must fall back
    # to "all" rather than None (which would break its type contract), mirroring the INI loader.
    diff_only_raw = os.environ.get("IOCPARSER_DIFF_ONLY")
    if diff_only_raw is not None:
        mutable["diff_only"] = diff_only_raw.strip() or "all"
    for option in _ENV_BOOL_OPTIONS:
        raw = os.environ.get(f"IOCPARSER_{option.upper()}")
        if raw is not None:
            mutable[option] = _parse_bool_value(raw, option_name=f"IOCPARSER_{option.upper()}")
    for option in _ENV_INT_OPTIONS:
        raw = os.environ.get(f"IOCPARSER_{option.upper()}")
        if raw is not None:
            mutable[option] = _parse_int_value(raw, option_name=f"IOCPARSER_{option.upper()}")
    for option in _ENV_FLOAT_OPTIONS:
        raw = os.environ.get(f"IOCPARSER_{option.upper()}")
        if raw is not None:
            mutable[option] = _parse_float_value(raw, option_name=f"IOCPARSER_{option.upper()}")


def _load_ini_config(config_path: Path) -> ConfigValues:
    """Load config values from an INI file, reporting malformed files cleanly.

    A structurally broken INI (no section headers) raises configparser.Error and a
    bad numeric/boolean value raises ValueError; both are expected user-facing errors,
    so translate them to a ValidationError instead of an uncaught stack trace.
    """
    try:
        return _read_ini_config(config_path)
    except (configparser.Error, ValueError) as exc:
        raise ValidationError(
            INVALID_CONFIG_FILE_ERROR.format(path=config_path, detail=exc)
        ) from exc


def _optional_str(parser: configparser.ConfigParser, section: str, option: str) -> str | None:
    raw_value = parser.get(section, option, fallback=None)
    if raw_value is None:
        return None
    stripped = raw_value.strip()
    return stripped or None


def _read_ini_config(config_path: Path) -> ConfigValues:
    """Parse an INI file into config values (see _load_ini_config for error handling)."""
    parser = load_ini_sections(config_path)

    values = default_config_values()

    if parser.has_section("database"):
        if parser.has_option("database", "persist"):
            raw_persist = parser.get("database", "persist")
            values["persist"] = _parse_bool_value(raw_persist, option_name="database.persist")
        values["db_uri"] = _optional_str(parser, "database", "uri")

    if parser.has_section("defaults"):
        values["only"] = _optional_str(parser, "defaults", "only")
        values["exclude"] = _optional_str(parser, "defaults", "exclude")
        values["stix_types"] = _optional_str(parser, "defaults", "stix_types")
        values["output_format"] = _optional_str(parser, "defaults", "output_format")
        values["severity"] = _optional_str(parser, "defaults", "severity")
        values["tag"] = _optional_str(parser, "defaults", "tag")
        values["with_context"] = _ini_bool(parser, "defaults", "with_context", fallback=False)
        values["streaming"] = _ini_bool(parser, "defaults", "streaming", fallback=False)
        values["summary"] = _ini_bool(parser, "defaults", "summary", fallback=False)
        values["parallel"] = _ini_int(parser, "defaults", "parallel", fallback=1)
        values["chunk_size"] = _ini_int(parser, "defaults", "chunk_size", fallback=1024 * 1024)
        values["overlap"] = _ini_int(parser, "defaults", "overlap", fallback=1024)
        raw_diff_only = parser.get("defaults", "diff_only", fallback="all")
        values["diff_only"] = raw_diff_only if raw_diff_only.strip() else "all"

    if parser.has_section("network"):
        values["url_workers"] = _ini_int(parser, "network", "url_workers", fallback=4)
        values["url_retries"] = _ini_int(parser, "network", "url_retries", fallback=0)
        values["url_backoff"] = _ini_float(parser, "network", "url_backoff", fallback=0.0)
        values["rate_limit"] = _ini_float(parser, "network", "rate_limit", fallback=0.0)
        values["user_agent"] = _optional_str(parser, "network", "user_agent")
        values["headers_json"] = _optional_str(parser, "network", "headers_json")
        values["cookies_json"] = _optional_str(parser, "network", "cookies_json")
        values["proxy"] = _optional_str(parser, "network", "proxy")
        values["allow_redirects"] = _ini_bool(parser, "network", "allow_redirects", fallback=True)
        values["tls_verify"] = _ini_bool(parser, "network", "tls_verify", fallback=True)
        values["tls_cert"] = _optional_str(parser, "network", "tls_cert")
        values["ca_bundle"] = _optional_str(parser, "network", "ca_bundle")
        values["connect_timeout"] = _ini_optional_float(parser, "network", "connect_timeout")
        values["read_timeout"] = _ini_optional_float(parser, "network", "read_timeout")
        values["max_input_size_mb"] = _ini_optional_float(parser, "network", "max_input_size_mb")
        values["max_input_seconds"] = _ini_optional_float(parser, "network", "max_input_seconds")
        values["max_queue_size"] = _ini_int(parser, "network", "max_queue_size", fallback=64)
        values["skip_processed"] = _ini_bool(parser, "network", "skip_processed", fallback=False)

    return values


def load_config(
    cli_persist: bool | None,
    cli_db_uri: str | None,
    cli_config_path: str | None,
) -> AppConfig:
    """Load configuration with precedence: CLI > env > config file."""
    load_dotenv(override=False)

    config_path: Path | None = None
    file_values = default_config_values()

    if cli_config_path:
        config_path = Path(cli_config_path).expanduser()
        if not config_path.is_file():
            # SourceNotFoundError subclasses both FileNotFoundError (the contract
            # callers/tests expect) and IOCParserError, so the CLI reports a missing
            # --config path as a clean message instead of an "unexpected" traceback.
            raise SourceNotFoundError(str(config_path))
        file_values = _load_ini_config(config_path)
    else:
        for path in find_default_config_paths():
            if path.exists():
                config_path = path
                file_values = _load_ini_config(path)
                break

    _apply_env_overrides(file_values)

    env_persist: bool | None = None
    raw_env_persist = os.environ.get("IOCPARSER_PERSIST")
    if raw_env_persist is not None and raw_env_persist.strip():
        env_persist = _parse_bool_value(raw_env_persist, option_name="IOCPARSER_PERSIST")

    env_db_uri = os.environ.get("IOCPARSER_DB_URI")

    resolved_persist = (
        cli_persist
        if cli_persist is not None
        else env_persist
        if env_persist is not None
        else file_values["persist"] or False
    )
    resolved_db_uri = cli_db_uri or env_db_uri or file_values["db_uri"]

    return AppConfig(
        persist=resolved_persist,
        db_uri=resolved_db_uri,
        config_path=config_path,
        only=file_values["only"],
        exclude=file_values["exclude"],
        stix_types=file_values["stix_types"],
        output_format=file_values["output_format"],
        with_context=file_values["with_context"],
        streaming=file_values["streaming"],
        summary=file_values["summary"],
        severity=file_values["severity"],
        tag=file_values["tag"],
        url_workers=file_values["url_workers"],
        url_retries=file_values["url_retries"],
        url_backoff=file_values["url_backoff"],
        rate_limit=file_values["rate_limit"],
        parallel=file_values["parallel"],
        chunk_size=file_values["chunk_size"],
        overlap=file_values["overlap"],
        diff_only=file_values["diff_only"],
        user_agent=file_values["user_agent"],
        headers_json=file_values["headers_json"],
        cookies_json=file_values["cookies_json"],
        proxy=file_values["proxy"],
        allow_redirects=file_values["allow_redirects"],
        tls_verify=file_values["tls_verify"],
        tls_cert=file_values["tls_cert"],
        ca_bundle=file_values["ca_bundle"],
        connect_timeout=file_values["connect_timeout"],
        read_timeout=file_values["read_timeout"],
        max_input_size_mb=file_values["max_input_size_mb"],
        max_input_seconds=file_values["max_input_seconds"],
        max_queue_size=file_values["max_queue_size"],
        skip_processed=file_values["skip_processed"],
    )
