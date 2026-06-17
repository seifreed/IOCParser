from __future__ import annotations

import argparse
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from iocparser import cli_dispatch, cli_output, cli_persistence, cli_processing, cli_queries
from iocparser.application.contracts import (
    DiffPersistedRunsInput,
    ExportPersistedRunInput,
    QueryRunsInput,
    SearchPersistedIOCsInput,
)
from iocparser.application.query_use_cases import (
    diff_persisted_runs,
    export_persisted_run,
    query_runs,
    search_persisted_iocs,
)
from iocparser.application.use_cases import extract_from_text
from iocparser.cli_args import create_argument_parser
from iocparser.domain.models import (
    IOC,
    ExtractionOptions,
    ExtractionResult,
    IOCEvidence,
    IOCType,
    PersistedRunDiff,
    PersistedRunExport,
    PersistedRunQueryHit,
    PersistedRunSummary,
    PersistOptions,
    WarningMatch,
)
from iocparser.errors import FileExistenceError, SourceProcessingError, ValidationError
from iocparser.infrastructure.extraction import DefaultIOCExtractionEngine
from iocparser.infrastructure.file_readers import MagicTextSourceReader
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
from iocparser.infrastructure.runtime import LocalFileWriter
from iocparser.infrastructure.warninglists_service import MISPWarningListService


class StaticQueryService:
    def __init__(self) -> None:
        self.summary = PersistedRunSummary(
            run_id=1,
            source_kind="file",
            source_value="sample.txt",
            tool_version="1.0.0",
            started_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            finished_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        self.result = ExtractionResult(iocs=(IOC.from_raw("domains", "alpha.example"),))

    def list_runs(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        date_from: str | None = None,
        date_to: str | None = None,
        source_kind: str | None = None,
        source_value: str | None = None,
        sort_by: str = "newest",
    ) -> list[PersistedRunSummary]:
        del offset, date_from, date_to, source_kind, source_value, sort_by
        assert limit >= 1
        return [self.summary]

    def search_iocs(
        self,
        *,
        value: str,
        limit: int = 50,
        offset: int = 0,
        date_from: str | None = None,
        date_to: str | None = None,
        source_kind: str | None = None,
        source_value: str | None = None,
        ioc_type: str | None = None,
        severity: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
        exclude_tags: tuple[str, ...] = (),
        min_severity: str | None = None,
        tag_mode: str = "all",
        sort_by: str = "newest",
        search_backend: str = "auto",
    ) -> list[PersistedRunQueryHit]:
        del (
            limit,
            offset,
            date_from,
            date_to,
            source_kind,
            source_value,
            ioc_type,
            severity,
            tags,
            exclude_tags,
            min_severity,
            tag_mode,
            sort_by,
            search_backend,
        )
        return [
            PersistedRunQueryHit(
                run_id=1,
                source_kind="file",
                source_value="sample.txt",
                ioc_type="domains",
                value=value,
                is_warning=False,
            ),
        ]

    def export_run(self, *, run_id: int) -> PersistedRunExport:
        return PersistedRunExport(summary=self.summary, result=self.result)

    def diff_runs(self, *, left_run_id: int, right_run_id: int) -> PersistedRunDiff:
        return PersistedRunDiff(
            left_run_id=left_run_id,
            right_run_id=right_run_id,
            added=ExtractionResult(iocs=(IOC.from_raw("domains", "beta.example"),)),
            removed=ExtractionResult(iocs=(IOC.from_raw("domains", "alpha.example"),)),
        )


class MemoryWriter:
    def __init__(self) -> None:
        self.writes: list[tuple[str, str]] = []

    def write(self, path: str, content: str) -> None:
        self.writes.append((path, content))


class WarningService:
    def separate(self, iocs, *, force_update: bool = False):
        return ExtractionResult(
            warnings=(
                WarningMatch(
                    ioc=next(iter(iocs)),
                    warning_list="Demo",
                    description="Flagged",
                ),
            ),
        )


def _query_args(**overrides: object) -> argparse.Namespace:
    base = {
        "list_runs": False,
        "run_limit": 10,
        "search_ioc": None,
        "diff_runs": None,
        "export_run": None,
        "output": None,
        "json": False,
        "jsonl": False,
        "csv": False,
        "stix": False,
        "stix_types": None,
        "with_context": False,
        "date_from": None,
        "date_to": None,
        "source_kind": None,
        "source_value": None,
        "ioc_type": None,
        "severity": None,
        "tag": None,
        "exclude_tag": None,
        "offset": 0,
        "query_limit": 50,
        "query_sort": "newest",
        "tag_mode": "all",
        "min_severity": None,
        "only_warnings": False,
        "only_normal": False,
        "max_evidence": None,
        "sort_by": "type",
        "diff_latest": None,
        "diff_only": "all",
        "diff_warnings_only": False,
        "delete_run": None,
        "prune_before": None,
        "keep_latest": 0,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_query_use_cases_delegate_to_query_service() -> None:
    service = StaticQueryService()
    assert query_runs(QueryRunsInput(limit=1), persistence_query_service=service)[0].run_id == 1
    assert (
        search_persisted_iocs(
            SearchPersistedIOCsInput(value="alpha"),
            persistence_query_service=service,
        )[0].value
        == "alpha"
    )
    assert (
        export_persisted_run(
            ExportPersistedRunInput(run_id=1),
            persistence_query_service=service,
        ).summary.source_value
        == "sample.txt"
    )
    assert diff_persisted_runs(
        DiffPersistedRunsInput(left_run_id=1, right_run_id=2),
        persistence_query_service=service,
    ).added.grouped_iocs() == {"domains": ["beta.example"]}


def test_cli_search_repeated_exclude_tags_are_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class CaptureSearchService:
        def search_iocs(self, **kwargs: object) -> list[PersistedRunQueryHit]:
            captured.update(kwargs)
            return []

    monkeypatch.setattr(cli_queries, "_query_service_for", lambda _config: CaptureSearchService())

    assert (
        cli_queries.handle_query_commands(
            _query_args(search_ioc="alpha", exclude_tag=["benign,noise", "internal"]),
            SimpleNamespace(db_uri="sqlite:///unused"),
            file_writer=MemoryWriter(),
        )
        is True
    )

    assert captured["exclude_tags"] == ("benign", "noise", "internal")


def test_cli_negative_run_limit_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the CLI must reject a negative limit like the programmatic API,
    not silently clamp it to 0 and return an empty result with exit 0."""
    monkeypatch.setattr(cli_queries, "_query_service_for", lambda _config: StaticQueryService())
    with pytest.raises(ValidationError, match="limit"):
        cli_queries.handle_query_commands(
            _query_args(list_runs=True, run_limit=-1),
            SimpleNamespace(db_uri="sqlite:///unused"),
            file_writer=MemoryWriter(),
        )


def test_cli_invalid_severity_on_export_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: --severity must be validated on export/diff like on search, not
    silently passed through to match nothing (hiding a user's typo)."""
    monkeypatch.setattr(cli_queries, "_query_service_for", lambda _config: StaticQueryService())
    with pytest.raises(ValidationError, match="severity"):
        cli_queries.handle_query_commands(
            _query_args(export_run=1, severity="critical"),
            SimpleNamespace(db_uri="sqlite:///unused"),
            file_writer=MemoryWriter(),
        )


def test_cli_negative_keep_latest_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: a negative --keep-latest folds to "keep none" downstream and would
    delete every matching run -- it must be rejected, not silently destroy data."""
    monkeypatch.setattr(cli_queries, "_query_service_for", lambda _config: StaticQueryService())
    with pytest.raises(ValidationError, match="keep-latest"):
        cli_queries.handle_query_commands(
            _query_args(prune_before="2030-01-01", keep_latest=-1),
            SimpleNamespace(db_uri="sqlite:///unused"),
            file_writer=MemoryWriter(),
        )


def test_cli_repeated_prune_statuses_are_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, tuple[str, ...]] = {}

    class CaptureMaintenanceService:
        def list_batch_jobs(self, *, limit: int, statuses: tuple[str, ...]):
            del limit
            captured["list"] = statuses
            return []

        def prune_runs(
            self,
            *,
            before: str | None,
            keep_latest: int,
            source_kind: str | None,
            source_value: str | None,
            statuses: tuple[str, ...],
        ) -> int:
            del before, keep_latest, source_kind, source_value
            captured["prune"] = statuses
            return 0

    service = CaptureMaintenanceService()
    monkeypatch.setattr(cli_queries, "_query_service_for", lambda _config: service)

    status_args = ["failed,partial", "success"]
    assert (
        cli_queries.handle_query_commands(
            _query_args(list_batches=True, prune_status=status_args),
            SimpleNamespace(db_uri="sqlite:///unused"),
            file_writer=MemoryWriter(),
        )
        is True
    )
    assert (
        cli_queries.handle_query_commands(
            _query_args(prune_before="2999-01-01T00:00:00", prune_status=status_args),
            SimpleNamespace(db_uri="sqlite:///unused"),
            file_writer=MemoryWriter(),
        )
        is True
    )

    assert captured["list"] == ("failed", "partial", "success")
    assert captured["prune"] == ("failed", "partial", "success")


def test_cli_prune_before_rejects_invalid_iso_datetime() -> None:
    """Regression: an invalid --prune-before must raise a clean ValidationError,
    not let a raw ValueError from datetime.fromisoformat bubble up as a traceback."""
    with pytest.raises(ValidationError):
        cli_queries.handle_query_commands(
            _query_args(prune_before="not-a-date"),
            SimpleNamespace(db_uri="sqlite:///unused"),
            file_writer=MemoryWriter(),
        )


def test_cli_persistence_builds_all_output_formats_and_persists(tmp_path: Path) -> None:
    for flag, output_format in (
        ("stix", "stix"),
        ("jsonl", "jsonl"),
        ("csv", "csv"),
        ("json", "json"),
    ):
        args = _query_args(
            **{flag: True, "no_defang": False, "no_check_warnings": False, "force_update": False}
        )
        assert cli_persistence.build_persist_options(args).output_format == output_format

    text_args = _query_args(no_defang=True, no_check_warnings=True, force_update=True)
    text_options = cli_persistence.build_persist_options(text_args)
    assert text_options.output_format == "text"
    assert text_options.defang is False
    assert text_options.check_warnings is False
    assert text_options.force_update is True

    config = SimpleNamespace(persist=True, db_uri=f"sqlite:///{tmp_path / 'persist.sqlite'}")
    cli_persistence.persist_many_results(
        {"sample.txt": ({"domains": ["alpha.example"]}, {})},
        config=config,
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    service = SQLAlchemyPersistenceService(config.db_uri)
    assert service.list_runs(limit=5)[0].source_value == "sample.txt"


def test_cli_output_helpers_cover_text_and_export_paths(tmp_path: Path) -> None:
    result = ExtractionResult(
        iocs=(
            IOC.from_raw(
                "domains",
                "alpha.example",
                evidence=(IOCEvidence(excerpt="alpha.example seen", line_number=4),),
            ),
        ),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw("ips", "198.51.100.10"),
                warning_list="Known Benign",
                description="Resolver",
            ),
        ),
    )
    text = cli_output.render_result(_query_args(with_context=True), result)
    assert text[1] == "text"
    assert "Context:" in text[0]

    jsonl = cli_output.render_result(_query_args(jsonl=True), result)
    csv = cli_output.render_result(_query_args(csv=True), result)
    assert jsonl[2] == "jsonl"
    assert csv[2] == "csv"

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        cli_output.print_run_summaries([StaticQueryService().summary])
        cli_output.print_query_hits([StaticQueryService().search_iocs(value="alpha")[0]])
    assert "sample.txt" in stdout.getvalue()

    writer = MemoryWriter()
    export = PersistedRunExport(summary=StaticQueryService().summary, result=result)
    cli_output.save_exported_run(
        _query_args(output=str(tmp_path / "export.json"), json=True), export, file_writer=writer
    )
    assert writer.writes
    assert writer.writes[0][0].endswith("export.json")

    diff = PersistedRunDiff(
        left_run_id=1,
        right_run_id=2,
        added=ExtractionResult(iocs=(IOC.from_raw("domains", "beta.example"),)),
        removed=ExtractionResult(iocs=(IOC.from_raw("domains", "alpha.example"),)),
    )
    cli_output.save_diff_output(
        _query_args(output=str(tmp_path / "diff.txt")), diff, file_writer=writer
    )
    cli_output.save_diff_output(
        _query_args(output=str(tmp_path / "diff.jsonl"), jsonl=True), diff, file_writer=writer
    )
    warning_diff = PersistedRunDiff(
        left_run_id=1,
        right_run_id=2,
        added=ExtractionResult(
            warnings=(
                WarningMatch(
                    ioc=IOC.from_raw("domains", "warning.example"),
                    warning_list="Demo",
                ),
            )
        ),
        removed=ExtractionResult(iocs=(IOC.from_raw("domains", "normal.example"),)),
    )
    cli_output.save_diff_output(
        _query_args(output=str(tmp_path / "diff.csv"), csv=True),
        warning_diff,
        file_writer=writer,
    )
    cli_output.save_rendered_output(
        rendered_output="payload",
        output_label="text",
        input_display="stdin",
        chosen_format="text",
        output_path="-",
        file_writer=writer,
    )
    assert any(path.endswith("diff.txt") for path, _ in writer.writes)
    assert any(path.endswith("diff.jsonl") for path, _ in writer.writes)
    assert "warning.example,True" in next(
        content for path, content in writer.writes if path.endswith("diff.csv")
    )


def test_cli_diff_invalid_ioc_type_raises_validation_error(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'diff-bad-type.sqlite'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            ("file", "alpha.txt", ExtractionResult.from_grouped_payload({"domains": ["a.x"]}, {})),
            ("file", "beta.txt", ExtractionResult.from_grouped_payload({"domains": ["b.x"]}, {})),
        ],
        tool_version="1.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    config = SimpleNamespace(db_uri=db_uri)

    # A bad --ioc-type must surface a clean ValidationError, not a raw ValueError
    # that the top-level handler reports as an "Unexpected error" with a traceback.
    with pytest.raises(ValidationError, match="Invalid ioc_type"):
        cli_queries.handle_query_commands(
            _query_args(
                diff_runs=[str(run_ids[0]), str(run_ids[1])],
                ioc_type="bogus",
            ),
            config,
            file_writer=LocalFileWriter(),
        )


def test_cli_queries_and_dispatch_paths(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'queries.sqlite'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "alpha.txt",
                ExtractionResult.from_grouped_payload({"domains": ["alpha.example"]}, {}),
            ),
            (
                "file",
                "beta.txt",
                ExtractionResult.from_grouped_payload({"domains": ["beta.example"]}, {}),
            ),
        ],
        tool_version="1.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )
    writer = LocalFileWriter()
    config = SimpleNamespace(db_uri=db_uri)

    assert (
        cli_queries.handle_query_commands(_query_args(list_runs=True), config, file_writer=writer)
        is True
    )
    assert (
        cli_queries.handle_query_commands(
            _query_args(search_ioc="beta"), config, file_writer=writer
        )
        is True
    )
    assert (
        cli_queries.handle_query_commands(
            _query_args(
                diff_runs=[str(run_ids[0]), str(run_ids[1])],
                output=str(tmp_path / "diff.json"),
                json=True,
            ),
            config,
            file_writer=writer,
        )
        is True
    )
    assert (
        cli_queries.handle_query_commands(
            _query_args(export_run=run_ids[0], output=str(tmp_path / "run.json"), json=True),
            config,
            file_writer=writer,
        )
        is True
    )
    assert (
        cli_queries.handle_query_commands(
            _query_args(delete_run=run_ids[0]),
            config,
            file_writer=writer,
        )
        is True
    )
    assert (
        cli_queries.handle_query_commands(
            _query_args(
                prune_before="2999-01-01T00:00:00",
                keep_latest=0,
                source_kind="file",
                source_value="beta",
            ),
            config,
            file_writer=writer,
        )
        is True
    )
    assert cli_queries.handle_query_commands(_query_args(), config, file_writer=writer) is False
    with pytest.raises(ValidationError):
        cli_queries.handle_query_commands(
            _query_args(list_runs=True), SimpleNamespace(db_uri=None), file_writer=writer
        )

    def _save_output(*args) -> None:
        del args

    args = argparse.Namespace(
        init=True, force_update=False, multiple=None, directory=None, url_file=None
    )
    called = {"init": 0}
    cli_dispatch.run_cli(
        args,
        handle_misp_init=lambda: called.__setitem__("init", called["init"] + 1),
        process_multiple_files_input=lambda _args: None,
        process_single_input=lambda _args: None,
        save_output=_save_output,
    )
    assert called["init"] == 1


def test_cli_dispatch_force_update_with_input_still_processes_file(tmp_path: Path) -> None:
    input_file = tmp_path / "report.txt"
    input_file.write_text("IOC domain: force-update.example\n", encoding="utf-8")
    args = create_argument_parser().parse_args(
        ["-f", str(input_file), "--force-update", "--no-check-warnings"]
    )
    called = {"init": 0, "single": 0, "saved": 0}

    cli_dispatch.run_cli(
        args,
        handle_misp_init=lambda: called.__setitem__("init", called["init"] + 1),
        process_multiple_files_input=lambda _args: (_ for _ in ()).throw(
            AssertionError("unexpected")
        ),
        process_single_input=lambda _args: (
            called.__setitem__("single", called["single"] + 1)
            or ({"domains": ["force-update.example"]}, {}, str(input_file), None)
        ),
        save_output=lambda *_args: called.__setitem__("saved", called["saved"] + 1),
    )

    assert called == {"init": 0, "single": 1, "saved": 1}


def test_cli_dispatch_directory_url_file_and_stdin_paths(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "a.txt").write_text("IOC domain: alpha.example\n", encoding="utf-8")
    url_file = tmp_path / "urls.txt"
    url_file.write_text("# comment only\n", encoding="utf-8")

    base_args = {
        "init": False,
        "force_update": False,
        "multiple": None,
        "directory": str(reports),
        "url_file": None,
        "persist": False,
        "db_uri": None,
        "config": None,
        "debug": False,
        "verbose": False,
        "output": None,
        "json": False,
        "jsonl": False,
        "csv": False,
        "stix": False,
        "stix_types": None,
        "with_context": False,
        "url": None,
        "url_direct": None,
        "stdin": False,
        "glob": "*.txt",
        "recursive": False,
        "parallel": 1,
        "type": "text",
        "no_defang": True,
        "no_check_warnings": True,
        "only": None,
        "exclude": None,
        "streaming": False,
        "chunk_size": 1024,
        "overlap": 64,
        "list_runs": False,
        "search_ioc": None,
        "diff_runs": None,
        "export_run": None,
        "run_limit": 20,
    }

    cli_dispatch.run_cli(
        argparse.Namespace(**base_args),
        handle_misp_init=lambda: None,
        process_multiple_files_input=lambda _args: (_ for _ in ()).throw(
            AssertionError("unexpected")
        ),
        process_single_input=lambda _args: (_ for _ in ()).throw(AssertionError("unexpected")),
        save_output=lambda *args: None,
    )

    args_url = argparse.Namespace(**(base_args | {"directory": None, "url_file": str(url_file)}))
    cli_dispatch.run_cli(
        args_url,
        handle_misp_init=lambda: None,
        process_multiple_files_input=lambda _args: (_ for _ in ()).throw(
            AssertionError("unexpected")
        ),
        process_single_input=lambda _args: (_ for _ in ()).throw(AssertionError("unexpected")),
        save_output=lambda *args: None,
    )

    stdin_args = argparse.Namespace(**(base_args | {"directory": None, "stdin": True}))
    original_stdin = sys.stdin
    sys.stdin = io.StringIO("IOC URL: https://stdin.example/path\n")
    try:
        cli_dispatch.run_cli(
            stdin_args,
            handle_misp_init=lambda: None,
            process_multiple_files_input=lambda _args: (_ for _ in ()).throw(
                AssertionError("unexpected")
            ),
            process_single_input=lambda _args: ({}, {}, "stdin", None),
            save_output=lambda *args: None,
        )
    finally:
        sys.stdin = original_stdin


def test_cli_processing_edge_cases_and_streaming_paths(tmp_path: Path) -> None:
    reader = MagicTextSourceReader()
    warning_service = MISPWarningListService()
    downloader = RequestsURLDownloader()

    with pytest.raises(FileExistenceError):
        cli_processing.process_directory_input(
            argparse.Namespace(directory=str(tmp_path / "missing"), glob="*", recursive=False),
            reader=reader,
            warning_service=None,
        )

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    with pytest.raises(ValidationError):
        cli_processing.process_directory_input(
            argparse.Namespace(directory=str(empty_dir), glob="*.txt", recursive=False),
            reader=reader,
            warning_service=None,
        )

    with pytest.raises(FileExistenceError):
        cli_processing.process_url_file_input(
            argparse.Namespace(
                url_file=str(tmp_path / "missing.txt"),
                no_defang=True,
                no_check_warnings=True,
                force_update=False,
                type="text",
                only=None,
                exclude=None,
            ),
            reader=reader,
            warning_service=None,
            downloader=downloader,
        )

    url_file = tmp_path / "urls.txt"
    url_file.write_text("# comment\n\n", encoding="utf-8")
    normal_iocs, warning_iocs, display, results = cli_processing.process_url_file_input(
        argparse.Namespace(
            url_file=str(url_file),
            no_defang=True,
            no_check_warnings=True,
            force_update=False,
            type="text",
            only=None,
            exclude=None,
        ),
        reader=reader,
        warning_service=None,
        downloader=downloader,
    )
    assert normal_iocs == {}
    assert warning_iocs == {}
    assert display == "0 URLs"
    assert results == {}

    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("IOC URL: https://alpha.example/path\n", encoding="utf-8")
    b.write_text("IOC URL: https://beta.example/path\n", encoding="utf-8")
    results = cli_processing.process_multiple_files(
        [a, b],
        reader=reader,
        warning_service=warning_service,
        request=cli_processing.MultiFileProcessingRequest(
            file_type=None,
            defang=False,
            check_warnings=True,
            force_update=False,
            include_types=(IOCType.URL,),
            exclude_types=(),
            streaming=True,
            chunk_size=1024 * 1024,
            overlap=1024,
            max_workers=1,
        ),
    )
    assert str(a) in results
    assert str(b) in results

    streaming_result = cli_processing._streaming_result(
        a,
        options=cli_processing.ProcessingOptions(
            defang=False,
            check_warnings=True,
            force_update=False,
            include_types=(IOCType.URL,),
            exclude_types=(),
        ),
        warning_service=WarningService(),
        chunk_size=64,
        overlap=16,
    )
    assert streaming_result.warnings


def test_process_multiple_streaming_error_item_becomes_empty_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from iocparser.infrastructure.streaming import StreamingIOCExtractor

    good_file = tmp_path / "good.txt"
    bad_file = tmp_path / "bad.txt"
    good_file.write_text("IOC URL: https://good.example.com/path\n", encoding="utf-8")
    bad_file.write_text("this file will fail during streaming\n", encoding="utf-8")
    reader = MagicTextSourceReader()
    original_extract = StreamingIOCExtractor.extract_from_file

    def fail_one_file(self, file_path, *args, **kwargs):
        if Path(file_path) == bad_file:
            raise PermissionError(str(bad_file))
        return original_extract(self, file_path, *args, **kwargs)

    monkeypatch.setattr(StreamingIOCExtractor, "extract_from_file", fail_one_file)

    results = cli_processing.process_multiple_files(
        [good_file, bad_file],
        reader=reader,
        warning_service=None,
        request=cli_processing.MultiFileProcessingRequest(
            file_type=None,
            defang=False,
            check_warnings=False,
            force_update=False,
            include_types=(),
            exclude_types=(),
            streaming=True,
            chunk_size=1024 * 1024,
            overlap=1024,
            max_workers=1,
        ),
    )

    good_iocs, good_warnings = results[str(good_file)]
    bad_iocs, bad_warnings = results[str(bad_file)]
    assert good_iocs
    assert good_warnings == {}
    assert bad_iocs == {}
    assert bad_warnings == {}


def test_process_multiple_duplicate_streaming_files_isolates_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from iocparser.infrastructure.streaming import StreamingIOCExtractor

    good_file = tmp_path / "good.txt"
    bad_file = tmp_path / "bad.txt"
    good_file.write_text("IOC URL: https://good.example.com/path\n", encoding="utf-8")
    bad_file.write_text("this file will fail during streaming\n", encoding="utf-8")
    reader = MagicTextSourceReader()
    original_extract = StreamingIOCExtractor.extract_from_file

    def fail_bad_file(self, file_path, *args, **kwargs):
        if Path(file_path) == bad_file:
            raise PermissionError(str(bad_file))
        return original_extract(self, file_path, *args, **kwargs)

    monkeypatch.setattr(StreamingIOCExtractor, "extract_from_file", fail_bad_file)

    results = cli_processing.process_multiple_files(
        [good_file, bad_file, bad_file],
        reader=reader,
        warning_service=None,
        request=cli_processing.MultiFileProcessingRequest(
            file_type=None,
            defang=False,
            check_warnings=False,
            force_update=False,
            include_types=(),
            exclude_types=(),
            streaming=True,
            chunk_size=1024 * 1024,
            overlap=1024,
            max_workers=1,
        ),
    )

    good_iocs, good_warnings = results[str(good_file)]
    bad_entries = [entry for entry in results.entries if entry.source_value == str(bad_file)]
    assert good_iocs
    assert good_warnings == {}
    assert len(bad_entries) == 2
    assert all(entry.normal_iocs == {} for entry in bad_entries)
    assert all(entry.warning_iocs == {} for entry in bad_entries)


def test_process_multiple_duplicate_files_isolates_extraction_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from iocparser import cli_processing_files

    good_file = tmp_path / "good.txt"
    bad_file = tmp_path / "bad.txt"
    good_file.write_text("IOC URL: https://good.example.com/path\n", encoding="utf-8")
    bad_file.write_text("this file will fail during extraction\n", encoding="utf-8")
    reader = MagicTextSourceReader()

    def fake_extract_from_file(input_data, *, reader, extractor_engine, warning_service):
        del reader, extractor_engine, warning_service
        if input_data.file_path == str(bad_file):
            raise SourceProcessingError(str(bad_file), "boom")
        return ExtractionResult(iocs=(IOC.from_raw("urls", "https://good.example.com/path"),))

    monkeypatch.setattr(cli_processing_files, "_extract_from_file", lambda: fake_extract_from_file)

    results = cli_processing.process_multiple_files(
        [good_file, bad_file, bad_file],
        reader=reader,
        warning_service=None,
        request=cli_processing.MultiFileProcessingRequest(
            file_type=None,
            defang=False,
            check_warnings=False,
            force_update=False,
            include_types=(),
            exclude_types=(),
            streaming=False,
            chunk_size=1024 * 1024,
            overlap=1024,
            max_workers=1,
        ),
    )

    good_iocs, good_warnings = results[str(good_file)]
    bad_entries = [entry for entry in results.entries if entry.source_value == str(bad_file)]
    assert good_iocs == {"urls": ["https://good.example.com/path"]}
    assert good_warnings == {}
    assert len(bad_entries) == 2
    assert all(entry.normal_iocs == {} for entry in bad_entries)
    assert all(entry.warning_iocs == {} for entry in bad_entries)


def test_dispatch_execute_and_use_case_edge_branches() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--value")
    parser.parse_args = lambda argv=None: argparse.Namespace(
        init=False,
        force_update=False,
        file=None,
        url=None,
        url_direct=None,
        multiple=None,
        directory=None,
        url_file=None,
        stdin=False,
        list_runs=False,
        search_ioc=None,
        diff_runs=None,
        export_run=None,
    )
    with pytest.raises(ValidationError):
        cli_dispatch.execute(create_argument_parser=lambda: parser, run_cli=lambda _args: None)

    result = extract_from_text(
        cli_processing.ExtractTextInput(
            text_content="https://evil.example/path\nhttps://evil.example/path\nhttps://evil.example/path\n",
            options=ExtractionOptions(defang=False, check_warnings=False),
        ),
        extractor_engine=DefaultIOCExtractionEngine(),
    )
    assert result.iocs[0].evidence

    empty_result = extract_from_text(
        cli_processing.ExtractTextInput(
            text_content="https://evil.example/path\n",
            options=ExtractionOptions(defang=False, check_warnings=False),
        ),
        extractor_engine=DefaultIOCExtractionEngine(),
    )
    assert empty_result.iocs[0].evidence


def test_missing_run_value_error_becomes_validation_error() -> None:
    """A missing-run ValueError from the query layer must surface as a clean
    ValidationError at the CLI boundary (so the user sees a message, not a stack
    trace), while a successful block passes through unchanged."""
    with pytest.raises(ValidationError, match="Run not found: 7"):
        with cli_queries._missing_run_as_validation():
            raise ValueError("Run not found: 7")

    with cli_queries._missing_run_as_validation():
        result = 42
    assert result == 42


def test_local_file_writer_reports_write_failures_cleanly(tmp_path: Path) -> None:
    """A bad output path must raise an IOCParserError (clean CLI message), not let
    the raw OSError reach the top-level handler as an unexpected-error traceback."""
    from iocparser.errors import IOCParserError
    from iocparser.infrastructure.runtime import LocalFileWriter

    writer = LocalFileWriter()
    # A path whose parent is an existing *file* cannot be turned into a directory.
    blocking_file = tmp_path / "blocker"
    blocking_file.write_text("x", encoding="utf-8")
    with pytest.raises(IOCParserError, match="Could not write output"):
        writer.write(str(blocking_file / "child" / "out.json"), "{}")

    ok_path = tmp_path / "nested" / "ok.json"
    writer.write(str(ok_path), "{}")
    assert ok_path.read_text(encoding="utf-8") == "{}"
