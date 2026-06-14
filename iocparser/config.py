#!/usr/bin/env python3

"""
Configuration loader for IOCParser.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from dotenv import load_dotenv

from iocparser.runtime_config import find_default_config_paths, load_ini_sections

TRUE_BOOL_VALUES = {"1", "true", "yes", "on"}
FALSE_BOOL_VALUES = {"0", "false", "no", "off"}
INVALID_BOOLEAN_ERROR = "Invalid boolean for {option_name}: {value!r}"


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


def _load_ini_config(config_path: Path) -> ConfigValues:
    """Load config values from an INI file."""
    parser = load_ini_sections(config_path)

    values = default_config_values()

    if parser.has_section("database"):
        if parser.has_option("database", "persist"):
            raw_persist = parser.get("database", "persist")
            values["persist"] = _parse_bool_value(raw_persist, option_name="database.persist")
        values["db_uri"] = parser.get("database", "uri", fallback=None)

    if parser.has_section("defaults"):
        values["only"] = parser.get("defaults", "only", fallback=None)
        values["exclude"] = parser.get("defaults", "exclude", fallback=None)
        values["stix_types"] = parser.get("defaults", "stix_types", fallback=None)
        values["output_format"] = parser.get("defaults", "output_format", fallback=None)
        values["severity"] = parser.get("defaults", "severity", fallback=None)
        values["tag"] = parser.get("defaults", "tag", fallback=None)
        values["with_context"] = parser.getboolean("defaults", "with_context", fallback=False)
        values["streaming"] = parser.getboolean("defaults", "streaming", fallback=False)
        values["summary"] = parser.getboolean("defaults", "summary", fallback=False)
        values["parallel"] = parser.getint("defaults", "parallel", fallback=1)
        values["chunk_size"] = parser.getint("defaults", "chunk_size", fallback=1024 * 1024)
        values["overlap"] = parser.getint("defaults", "overlap", fallback=1024)
        values["diff_only"] = parser.get("defaults", "diff_only", fallback="all")

    if parser.has_section("network"):
        values["url_workers"] = parser.getint("network", "url_workers", fallback=4)
        values["url_retries"] = parser.getint("network", "url_retries", fallback=0)
        values["url_backoff"] = parser.getfloat("network", "url_backoff", fallback=0.0)
        values["rate_limit"] = parser.getfloat("network", "rate_limit", fallback=0.0)
        values["user_agent"] = parser.get("network", "user_agent", fallback=None)
        values["headers_json"] = parser.get("network", "headers_json", fallback=None)
        values["cookies_json"] = parser.get("network", "cookies_json", fallback=None)
        values["proxy"] = parser.get("network", "proxy", fallback=None)
        values["allow_redirects"] = parser.getboolean("network", "allow_redirects", fallback=True)
        values["tls_verify"] = parser.getboolean("network", "tls_verify", fallback=True)
        values["tls_cert"] = parser.get("network", "tls_cert", fallback=None)
        values["ca_bundle"] = parser.get("network", "ca_bundle", fallback=None)
        values["connect_timeout"] = parser.getfloat("network", "connect_timeout", fallback=None)
        values["read_timeout"] = parser.getfloat("network", "read_timeout", fallback=None)
        values["max_input_size_mb"] = parser.getfloat("network", "max_input_size_mb", fallback=None)
        values["max_input_seconds"] = parser.getfloat("network", "max_input_seconds", fallback=None)
        values["max_queue_size"] = parser.getint("network", "max_queue_size", fallback=64)
        values["skip_processed"] = parser.getboolean("network", "skip_processed", fallback=False)

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
        config_path = Path(cli_config_path)
        if not config_path.is_file():
            raise FileNotFoundError(config_path)
        file_values = _load_ini_config(config_path)
    else:
        for path in find_default_config_paths():
            if path.exists():
                config_path = path
                file_values = _load_ini_config(path)
                break

    env_persist: bool | None = None
    if "IOCPARSER_PERSIST" in os.environ:
        env_persist = _parse_bool_value(
            os.environ["IOCPARSER_PERSIST"], option_name="IOCPARSER_PERSIST"
        )

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
