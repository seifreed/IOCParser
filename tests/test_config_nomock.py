from __future__ import annotations

import os
from pathlib import Path

from iocparser.config import _load_ini_config, load_config


def test_load_ini_config_without_database_section(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[other]\nvalue=yes\n", encoding="utf-8")

    loaded = _load_ini_config(config_path)
    assert loaded["persist"] is None
    assert loaded["db_uri"] is None
    assert loaded["output_format"] is None


def test_load_config_uses_default_config_path_from_cwd(tmp_path: Path) -> None:
    original_cwd = Path.cwd()
    original_persist = os.environ.pop("IOCPARSER_PERSIST", None)
    original_db_uri = os.environ.pop("IOCPARSER_DB_URI", None)
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[database]\npersist=true\nuri=sqlite:///from_default.db\n", encoding="utf-8")

    try:
        os.chdir(tmp_path)
        config = load_config(cli_persist=None, cli_db_uri=None, cli_config_path=None)
    finally:
        os.chdir(original_cwd)
        if original_persist is not None:
            os.environ["IOCPARSER_PERSIST"] = original_persist
        if original_db_uri is not None:
            os.environ["IOCPARSER_DB_URI"] = original_db_uri

    assert config.persist is True
    assert config.db_uri == "sqlite:///from_default.db"
    assert config.config_path == config_path
