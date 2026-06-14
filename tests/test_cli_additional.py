from __future__ import annotations

import argparse
import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

import iocparser.cli as cli_module
import iocparser.cli_output_rendering as cli_output_rendering_module
from iocparser.cli import handle_misp_init, process_single_input, save_output
from iocparser.cli_output import PersistResultsRequest, persist_results
from iocparser.config import AppConfig
from iocparser.domain.models import PersistOptions
from tests.http_server_helpers import LocalHTTPTextServer


@pytest.mark.slow
def test_process_single_input_with_real_url_server() -> None:
    args = argparse.Namespace(
        file=None,
        url=None,
        url_direct=None,
        type="text",
        no_defang=True,
        no_check_warnings=True,
        force_update=False,
    )

    with LocalHTTPTextServer(b"IOC URL: https://from-server.example/path\n") as url:
        args.url = url
        normal_iocs, warning_iocs, input_display = process_single_input(args)

    assert normal_iocs == {"urls": ["https://from-server.example/path"]}
    assert warning_iocs == {}
    assert input_display == args.url


def test_save_output_stix_format_to_file(tmp_path: Path) -> None:
    output_path = tmp_path / "output.stix.json"
    args = argparse.Namespace(
        json=False,
        stix=True,
        output=str(output_path),
    )

    save_output(args, {"domains": ["example.com"]}, {}, "input.txt")

    content = output_path.read_text(encoding="utf-8")
    assert '"type": "bundle"' in content
    assert "[domain-name:value = 'example.com']" in content


def test_persist_results_returns_when_db_uri_missing(tmp_path: Path) -> None:
    db_path = tmp_path / "should-not-exist.db"
    config = AppConfig(persist=True, db_uri=None, config_path=None)

    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="sample.txt",
            normal_iocs={"domains": ["example.com"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False,
                check_warnings=False,
                force_update=False,
                output_format="text",
            ),
            tool_version="1.0.0",
        )
    )

    assert not db_path.exists()


def test_persist_results_writes_to_sqlite(tmp_path: Path) -> None:
    db_path = tmp_path / "iocparser.db"
    config = AppConfig(persist=True, db_uri=f"sqlite:///{db_path}", config_path=None)

    persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value="sample.txt",
            normal_iocs={"domains": ["example.com"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False,
                check_warnings=False,
                force_update=False,
                output_format="json",
            ),
            tool_version="1.0.0",
        )
    )

    assert db_path.exists()


def test_persist_results_continues_when_file_metadata_detection_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "iocparser.db"
    sample = tmp_path / "sample.txt"
    sample.write_text("IOC domain: example.com", encoding="utf-8")
    config = AppConfig(persist=True, db_uri=f"sqlite:///{db_path}", config_path=None)

    def raise_value_error(_path: Path) -> str:
        raise ValueError("unreadable magic metadata")

    monkeypatch.setattr(cli_output_rendering_module, "detect_file_type", raise_value_error)

    run_id = persist_results(
        PersistResultsRequest(
            config=config,
            source_kind="file",
            source_value=str(sample),
            normal_iocs={"domains": ["example.com"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False,
                check_warnings=False,
                force_update=False,
                output_format="json",
            ),
            tool_version="1.0.0",
        )
    )

    assert isinstance(run_id, int)
    assert db_path.exists()


def test_persist_results_closes_owned_unit_of_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    created_units = []

    class FakeUnitOfWork:
        def __init__(self, db_uri: str) -> None:
            self.db_uri = db_uri
            self.closed = False
            created_units.append(self)

        def close(self) -> None:
            self.closed = True

    def fake_persist_run(_request, *, unit_of_work):
        assert unit_of_work is created_units[0]
        return SimpleNamespace(run_id=42)

    monkeypatch.setattr(cli_output_rendering_module, "SQLAlchemyUnitOfWork", FakeUnitOfWork)
    monkeypatch.setattr(cli_output_rendering_module, "persist_run_use_case", fake_persist_run)

    run_id = persist_results(
        PersistResultsRequest(
            config=AppConfig(
                persist=True,
                db_uri=f"sqlite:///{tmp_path / 'owned.db'}",
                config_path=None,
            ),
            source_kind="file",
            source_value="sample.txt",
            normal_iocs={"domains": ["example.com"]},
            warning_iocs={},
            options=PersistOptions(
                defang=False,
                check_warnings=False,
                force_update=False,
                output_format="json",
            ),
            tool_version="1.0.0",
        )
    )

    assert run_id == 42
    assert created_units[0].closed is True


def test_persist_results_closes_owned_unit_of_work_on_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    created_units = []

    class FakeUnitOfWork:
        def __init__(self, db_uri: str) -> None:
            self.db_uri = db_uri
            self.closed = False
            created_units.append(self)

        def close(self) -> None:
            self.closed = True

    def raise_persist_error(_request, *, unit_of_work) -> None:
        assert unit_of_work is created_units[0]
        raise RuntimeError("persist failed")

    monkeypatch.setattr(cli_output_rendering_module, "SQLAlchemyUnitOfWork", FakeUnitOfWork)
    monkeypatch.setattr(cli_output_rendering_module, "persist_run_use_case", raise_persist_error)

    with pytest.raises(RuntimeError, match="persist failed"):
        persist_results(
            PersistResultsRequest(
                config=AppConfig(
                    persist=True,
                    db_uri=f"sqlite:///{tmp_path / 'owned-error.db'}",
                    config_path=None,
                ),
                source_kind="file",
                source_value="sample.txt",
                normal_iocs={"domains": ["example.com"]},
                warning_iocs={},
                options=PersistOptions(
                    defang=False,
                    check_warnings=False,
                    force_update=False,
                    output_format="json",
                ),
                tool_version="1.0.0",
            )
        )

    assert created_units[0].closed is True


def test_save_output_stix_to_stdout() -> None:
    args = argparse.Namespace(
        json=False,
        stix=True,
        output="-",
    )
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        save_output(args, {"urls": ["https://stdout.example/path"]}, {}, "stdout.txt")

    rendered = buffer.getvalue()
    assert '"type": "bundle"' in rendered
    assert "stdout.example" in rendered


def test_handle_misp_init_with_concrete_replacement() -> None:
    class LocalWarningLists:
        def __init__(self, cache_duration: int = 0, force_update: bool = True) -> None:
            del cache_duration, force_update
            self.warning_lists = {
                "dns-google": {"name": "DNS Google"},
                "dns-cloudflare": {"name": "DNS Cloudflare"},
                "other-list": {},
            }

    original_warning_lists = cli_module.MISPWarningLists
    cli_module.MISPWarningLists = LocalWarningLists
    try:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            handle_misp_init()
    finally:
        cli_module.MISPWarningLists = original_warning_lists

    output = buffer.getvalue()
    assert "Dns: 2 lists" in output
    assert "Other: 1 lists" in output
