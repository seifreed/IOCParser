"""Single source of truth for the package version.

The authoritative version lives in pyproject.toml (`[project].version`); deriving the
runtime version from the installed distribution metadata keeps `iocparser --version`,
`iocparser.__version__`, and the persisted `tool_version` from drifting apart.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

DISTRIBUTION_NAME = "iocparser-tool"
_FALLBACK_VERSION = "0.0.0+unknown"


def resolve_version() -> str:
    """Return the installed distribution version, or a sentinel if not installed."""
    try:
        return version(DISTRIBUTION_NAME)
    except PackageNotFoundError:
        return _FALLBACK_VERSION
