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


def test_removed_modules_package_is_excluded_from_distribution_config() -> None:
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_find = config["tool"]["setuptools"]["packages"]["find"]

    assert "iocparser.modules" in package_find["exclude"]
    assert "iocparser.modules.*" in package_find["exclude"]
    assert "build_py" in (REPO_ROOT / "setup.py").read_text(encoding="utf-8")
