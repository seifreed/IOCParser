from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DATA_FILES = {
    "infrastructure/data/legitimate_domains.json",
    "infrastructure/data/misp_warninglists_metadata.json",
}


def test_runtime_reference_data_is_packaged_from_current_location() -> None:
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = set(config["tool"]["setuptools"]["package-data"]["iocparser"])

    assert RUNTIME_DATA_FILES.issubset(package_data)
    assert all(not path.startswith("modules/data/") for path in package_data)
