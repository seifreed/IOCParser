#!/usr/bin/env python3

"""
Tests for configuration loading.
"""

from __future__ import annotations

import os
from pathlib import Path

from iocparser.modules.config import load_config


def test_config_precedence(tmp_path, monkeypatch) -> None:
    """CLI should override env, which overrides config."""
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[database]\n"
        "persist=true\n"
        "uri=sqlite:///from_config.db\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("IOCPARSER_PERSIST", "0")
    monkeypatch.setenv("IOCPARSER_DB_URI", "sqlite:///from_env.db")

    config = load_config(
        cli_persist=True,
        cli_db_uri="sqlite:///from_cli.db",
        cli_config_path=str(config_path),
    )

    assert config.persist is True
    assert config.db_uri == "sqlite:///from_cli.db"


def test_config_env_fallback(tmp_path, monkeypatch) -> None:
    """Env should override config when CLI is unset."""
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[database]\n"
        "persist=false\n"
        "uri=sqlite:///from_config.db\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("IOCPARSER_PERSIST", "1")
    monkeypatch.setenv("IOCPARSER_DB_URI", "sqlite:///from_env.db")

    config = load_config(
        cli_persist=None,
        cli_db_uri=None,
        cli_config_path=str(config_path),
    )

    assert config.persist is True
    assert config.db_uri == "sqlite:///from_env.db"
