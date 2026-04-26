from __future__ import annotations

from collections.abc import Iterable
from configparser import ConfigParser
from pathlib import Path


def find_default_config_paths() -> Iterable[Path]:
    """Return default config locations in priority order."""
    cwd = Path.cwd()
    yield cwd / "iocparser.ini"
    yield Path.home() / ".config" / "iocparser" / "config.ini"


def load_ini_sections(config_path: Path) -> ConfigParser:
    """Load an INI file and return a parsed ConfigParser."""
    parser = ConfigParser()
    parser.read(config_path)
    return parser
