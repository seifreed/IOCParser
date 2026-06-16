#!/usr/bin/env python3

"""
Tests for configuration loading.
"""

from __future__ import annotations

import os
from contextlib import contextmanager

import pytest

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


def test_config_env_overrides_all_option_types(tmp_path) -> None:
    """Documented CLI > env > INI must hold for every option, not just persist/db_uri.

    Regression: only IOCPARSER_PERSIST/IOCPARSER_DB_URI were read; every other
    option ignored its IOCPARSER_<OPTION> env var, contradicting the documented
    precedence.
    """
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        "[defaults]\noutput_format=text\nstreaming=false\nparallel=1\n"
        "[network]\nurl_backoff=0.0\nproxy=http://ini-proxy\n",
        encoding="utf-8",
    )

    with _env(
        IOCPARSER_OUTPUT_FORMAT="json",  # str
        IOCPARSER_STREAMING="true",  # bool
        IOCPARSER_PARALLEL="8",  # int
        IOCPARSER_URL_BACKOFF="1.5",  # float
        IOCPARSER_PROXY="http://env-proxy",  # str overriding INI
    ):
        config = load_config(None, None, str(config_path))

    assert config.output_format == "json"
    assert config.streaming is True
    assert config.parallel == 8
    assert config.url_backoff == 1.5
    assert config.proxy == "http://env-proxy"


def test_config_rejects_invalid_int_env_value() -> None:
    with _env(IOCPARSER_PARALLEL="not-an-int"), pytest.raises(
        ValueError, match=r"IOCPARSER_PARALLEL"
    ):
        load_config(None, None, None)


def test_config_rejects_invalid_float_env_value() -> None:
    with _env(IOCPARSER_URL_BACKOFF="fast"), pytest.raises(
        ValueError, match=r"IOCPARSER_URL_BACKOFF"
    ):
        load_config(None, None, None)


def test_config_rejects_invalid_bool_env_value() -> None:
    with _env(IOCPARSER_STREAMING="maybe"), pytest.raises(
        ValueError, match=r"IOCPARSER_STREAMING"
    ):
        load_config(None, None, None)


def test_config_rejects_invalid_boolean_values(tmp_path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[database]\npersist=definitely\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"database\.persist"):
        load_config(None, None, str(config_path))

    with _env(IOCPARSER_PERSIST="definitely"):
        with pytest.raises(ValueError, match="IOCPARSER_PERSIST"):
            load_config(None, None, None)


def test_explicit_missing_config_path_is_rejected(tmp_path) -> None:
    missing_config = tmp_path / "missing.ini"

    with pytest.raises(FileNotFoundError, match=r"missing\.ini"):
        load_config(None, None, str(missing_config))
