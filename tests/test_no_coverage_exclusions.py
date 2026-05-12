from __future__ import annotations

import runpy
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_coverage_config_does_not_exclude_lines() -> None:
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    report_config = config["tool"]["coverage"]["report"]
    assert "exclude_lines" not in report_config


def test_python_sources_do_not_use_inline_coverage_exclusions() -> None:
    forbidden = ("# " + "pragma: " + "no cover").encode("ascii")
    ignored_dirs = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__"}
    offenders = []
    for root in (REPO_ROOT / "iocparser", REPO_ROOT / "tests"):
        for path in root.rglob("*.py"):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if forbidden in path.read_bytes():
                offenders.append(path.relative_to(REPO_ROOT).as_posix())

    assert offenders == []


def test_package_main_module_executes_entrypoint_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    import iocparser.cli

    calls: list[str] = []
    monkeypatch.setattr(iocparser.cli, "execute", lambda: calls.append("execute"))

    runpy.run_path(str(REPO_ROOT / "iocparser" / "__main__.py"), run_name="__main__")

    assert calls == ["execute"]


def test_worker_main_module_executes_entrypoint_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    from iocparser.worker_config import WorkerServiceConfig
    from iocparser.worker_service import DistributedWorkerService

    calls: list[tuple[str, object]] = []

    def from_sources(cls: type[WorkerServiceConfig], config_path: str | None = None) -> object:
        del cls
        calls.append(("config", config_path))
        return SimpleNamespace(max_cycles=3)

    class Service:
        def run_forever(self, *, max_cycles: int | None = None) -> int:
            calls.append(("run", max_cycles))
            return 0

    def from_config(
        cls: type[DistributedWorkerService],
        config: object,
        *,
        worker: object | None = None,
    ) -> Service:
        del cls, worker
        calls.append(("service", config))
        return Service()

    monkeypatch.setattr(WorkerServiceConfig, "from_sources", classmethod(from_sources))
    monkeypatch.setattr(DistributedWorkerService, "from_config", classmethod(from_config))
    monkeypatch.setattr(sys, "argv", ["iocparser-worker", "--config", "worker.ini"])

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(REPO_ROOT / "iocparser" / "worker_main.py"), run_name="__main__")

    assert raised.value.code == 0
    assert calls[0] == ("config", "worker.ini")
    assert calls[1][0] == "service"
    assert calls[2] == ("run", 3)


def test_warning_list_matching_base_cleaner_fails_explicitly() -> None:
    from iocparser.infrastructure.warninglists_matching import WarningListMatchingMixin

    class Matcher(WarningListMatchingMixin):
        def _clean_defanged_value(self, value: str) -> str:
            return WarningListMatchingMixin._clean_defanged_value(self, value)

    with pytest.raises(NotImplementedError):
        Matcher()._clean_defanged_value("example.com")
