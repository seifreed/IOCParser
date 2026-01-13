#!/usr/bin/env python3

"""
Configuration loader for IOCParser.

Supports .env, environment variables, and INI config files.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class AppConfig:
    """Resolved application configuration."""

    persist: bool
    db_uri: str | None
    config_path: Path | None


def _find_default_config_paths() -> Iterable[Path]:
    """Return default config locations in priority order."""
    cwd = Path.cwd()
    yield cwd / "iocparser.ini"

    home_config = Path.home() / ".config" / "iocparser" / "config.ini"
    yield home_config


def _load_ini_config(config_path: Path) -> tuple[bool | None, str | None]:
    """Load config values from an INI file."""
    parser = ConfigParser()
    parser.read(config_path)

    if not parser.has_section("database"):
        return None, None

    persist_value: bool | None = None
    if parser.has_option("database", "persist"):
        raw_persist = parser.get("database", "persist")
        persist_value = raw_persist.strip().lower() in {"1", "true", "yes", "on"}

    db_uri = parser.get("database", "uri", fallback=None)
    return persist_value, db_uri


def load_config(
    cli_persist: bool | None,
    cli_db_uri: str | None,
    cli_config_path: str | None,
) -> AppConfig:
    """Load configuration with precedence: CLI > env > config file."""
    load_dotenv(override=False)

    config_path: Path | None = None
    file_persist: bool | None = None
    file_db_uri: str | None = None

    if cli_config_path:
        config_path = Path(cli_config_path)
        if config_path.exists():
            file_persist, file_db_uri = _load_ini_config(config_path)
    else:
        for path in _find_default_config_paths():
            if path.exists():
                config_path = path
                file_persist, file_db_uri = _load_ini_config(path)
                break

    env_persist: bool | None = None
    if "IOCPARSER_PERSIST" in os.environ:
        env_persist = os.environ["IOCPARSER_PERSIST"].strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    env_db_uri = os.environ.get("IOCPARSER_DB_URI")

    resolved_persist = (
        cli_persist
        if cli_persist is not None
        else env_persist
        if env_persist is not None
        else file_persist or False
    )
    resolved_db_uri = cli_db_uri or env_db_uri or file_db_uri

    return AppConfig(
        persist=bool(resolved_persist),
        db_uri=resolved_db_uri,
        config_path=config_path,
    )
