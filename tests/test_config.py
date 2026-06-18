#!/usr/bin/env python3

"""
Tests for configuration loading.
"""

from __future__ import annotations

import os
from contextlib import contextmanager

import pytest

from iocparser.config import load_config
from iocparser.errors import ValidationError


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


def test_config_ignores_blank_persist_env() -> None:
    with _env(IOCPARSER_PERSIST="   "):
        config = load_config(None, None, None)

    assert config.persist is False


def test_config_rejects_invalid_boolean_values(tmp_path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[database]\npersist=definitely\n", encoding="utf-8")

    # An invalid value inside the INI file is reported as a clean ValidationError
    # (wrapped with the file path) rather than an "unexpected error" stack trace.
    with pytest.raises(ValidationError, match=r"database\.persist"):
        load_config(None, None, str(config_path))

    with _env(IOCPARSER_PERSIST="definitely"):
        with pytest.raises(ValueError, match="IOCPARSER_PERSIST"):
            load_config(None, None, None)


def test_config_reports_structurally_broken_ini_cleanly(tmp_path) -> None:
    # Regression: a config file with no section headers raised configparser's
    # MissingSectionHeaderError, which escaped both CLI error handlers as a raw
    # stack trace. It must surface as a clean ValidationError naming the file.
    config_path = tmp_path / "broken.ini"
    config_path.write_text("this is not valid ini [[[\n", encoding="utf-8")

    with pytest.raises(ValidationError, match=r"broken\.ini"):
        load_config(None, None, str(config_path))


def test_config_reports_invalid_numeric_ini_value_cleanly(tmp_path) -> None:
    # Regression: a non-numeric value for a numeric INI option raised a bare
    # ValueError reported as an "unexpected error" stack trace.
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[network]\nmax_input_size_mb = notanumber\n", encoding="utf-8")

    with pytest.raises(ValidationError, match=r"iocparser\.ini"):
        load_config(None, None, str(config_path))


def test_config_empty_numeric_and_boolean_ini_values_use_defaults(tmp_path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        (
            "[defaults]\n"
            "streaming =\n"
            "parallel =\n"
            "chunk_size =\n"
            "[network]\n"
            "url_workers =\n"
            "url_backoff =\n"
            "allow_redirects =\n"
            "connect_timeout =\n"
        ),
        encoding="utf-8",
    )

    config = load_config(None, None, str(config_path))

    assert config.streaming is False
    assert config.parallel == 1
    assert config.chunk_size == 1024 * 1024
    assert config.url_workers == 4
    assert config.url_backoff == 0.0
    assert config.allow_redirects is True
    assert config.connect_timeout is None


def test_config_blank_diff_only_uses_default(tmp_path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        (
            "[defaults]\n"
            "diff_only =   \n"
            "stix_types =   \n"
            "[network]\n"
            "user_agent =   \n"
            "proxy =   \n"
        ),
        encoding="utf-8",
    )

    config = load_config(None, None, str(config_path))

    assert config.diff_only == "all"
    assert config.stix_types is None
    assert config.user_agent is None
    assert config.proxy is None


def test_explicit_missing_config_path_is_rejected(tmp_path) -> None:
    missing_config = tmp_path / "missing.ini"

    with pytest.raises(FileNotFoundError, match=r"missing\.ini"):
        load_config(None, None, str(missing_config))


def test_missing_config_path_error_is_an_iocparser_error(tmp_path) -> None:
    # The missing-config error must be an IOCParserError (while staying a
    # FileNotFoundError) so the CLI top-level handler reports it as a clean message
    # instead of an "unexpected error" stack trace.
    from iocparser.errors import IOCParserError

    missing_config = tmp_path / "missing.ini"

    with pytest.raises(IOCParserError, match=r"missing\.ini"):
        load_config(None, None, str(missing_config))
