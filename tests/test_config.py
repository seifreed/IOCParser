#!/usr/bin/env python3

"""
Tests for configuration loading.
"""

from __future__ import annotations

import os
from contextlib import contextmanager

from iocparser.config import load_config


@contextmanager
def _env(**values: str):
    previous = {key: os.environ.get(key) for key in values}
    try:
        for key, value in values.items():
            os.environ[key] = value
        yield
    finally:
        for key, old_value in previous.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value


def test_config_precedence(tmp_path) -> None:
    """CLI should override env, which overrides config."""
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[database]\npersist=true\nuri=sqlite:///from_config.db\n",
        encoding="utf-8",
    )

    with _env(IOCPARSER_PERSIST="0", IOCPARSER_DB_URI="sqlite:///from_env.db"):
        config = load_config(
            cli_persist=True,
            cli_db_uri="sqlite:///from_cli.db",
            cli_config_path=str(config_path),
        )

    assert config.persist is True
    assert config.db_uri == "sqlite:///from_cli.db"


def test_config_env_fallback(tmp_path) -> None:
    """Env should override config when CLI is unset."""
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[database]\npersist=false\nuri=sqlite:///from_config.db\n",
        encoding="utf-8",
    )

    with _env(IOCPARSER_PERSIST="1", IOCPARSER_DB_URI="sqlite:///from_env.db"):
        config = load_config(
            cli_persist=None,
            cli_db_uri=None,
            cli_config_path=str(config_path),
        )

    assert config.persist is True
    assert config.db_uri == "sqlite:///from_env.db"
