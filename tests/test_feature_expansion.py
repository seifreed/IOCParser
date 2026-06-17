from __future__ import annotations

import argparse
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import iocparser.cli as cli_module
from iocparser import cli_output, cli_runtime
from iocparser.adapters.renderers import (
    CSVOutputRenderer,
    JSONLinesOutputRenderer,
    JSONOutputRenderer,
    STIXOutputRenderer,
)
from iocparser.api_extraction import extract_iocs_from_url
from iocparser.application.contracts import (
    DiffPersistedRunsInput,
    ExportPersistedRunInput,
    ExtractTextInput,
    QueryRunsInput,
    SearchPersistedIOCsInput,
)
from iocparser.application.query_use_cases import (
    diff_persisted_runs,
    export_persisted_run,
    query_runs,
    search_persisted_iocs,
)
from iocparser.application.use_cases import (
    extract_from_text,
)
from iocparser.cli import process_file as cli_process_file
from iocparser.cli import process_single_input as cli_process_single_input
from iocparser.cli_processing import process_directory_input, process_url_file_input
from iocparser.cli_runtime import downloader as cli_downloader
from iocparser.cli_runtime import reader as cli_reader
from iocparser.cli_runtime import warning_service as cli_warning_service
from iocparser.domain.models import (
    IOC,
    ExtractionOptions,
    ExtractionResult,
    IOCType,
    PersistOptions,
    WarningMatch,
)
from iocparser.errors import ValidationError
from iocparser.infrastructure.extraction import DefaultIOCExtractionEngine
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
from tests.http_server_helpers import LocalHTTPTextServer


def test_public_api_extract_iocs_from_url_supports_filters() -> None:
    with LocalHTTPTextServer(b"IOC URL: https://evil.example/path Domain: sample.org") as url:
        normal_iocs, warning_iocs = extract_iocs_from_url(
            url, check_warnings=False, only="urls", defang=False
        )

    assert normal_iocs == {"urls": ["https://evil.example/path"]}
    assert warning_iocs == {}


def test_extract_from_text_adds_context_and_classification() -> None:
    result = extract_from_text(
        ExtractTextInput(
            text_content="Line one\nIOC URL: https://evil.example/path\n",
            options=ExtractionOptions(defang=False, check_warnings=False),
        ),
        extractor_engine=DefaultIOCExtractionEngine(),
    )

    assert result.iocs
    url_ioc = next(ioc for ioc in result.iocs if ioc.ioc_type is IOCType.URL)
    assert url_ioc.severity == "medium"
    assert "network" in url_ioc.tags
    assert url_ioc.evidence[0].line_number == 2
    assert "evil.example" in url_ioc.evidence[0].excerpt


def test_extract_from_text_preserves_evidence_for_refanged_outputs() -> None:
    result = extract_from_text(
        ExtractTextInput(
            text_content="Line one\nIOC domain: evil[.]com\n",
            options=ExtractionOptions(defang=False, check_warnings=False),
        ),
        extractor_engine=DefaultIOCExtractionEngine(),
    )

    domain_ioc = next(ioc for ioc in result.iocs if ioc.ioc_type is IOCType.DOMAIN)

    assert domain_ioc.value.raw == "evil.com"
    assert domain_ioc.evidence[0].line_number == 2
    assert "evil[.]com" in domain_ioc.evidence[0].excerpt


def test_new_renderers_support_context_and_type_filters() -> None:
    result = ExtractionResult(
        iocs=(
            IOC.from_raw("domains", "example.com"),
            IOC.from_raw("urls", "https://evil.example/path"),
        ),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw("ips", "198.51.100.7"),
                warning_list="Known Benign",
                description="Resolver",
            ),
        ),
    )

    json_payload = JSONOutputRenderer(include_context=True).render(result)
    assert '"records"' in json_payload

    jsonl_payload = JSONLinesOutputRenderer().render(result)
    assert len(jsonl_payload.splitlines()) == 3

    csv_payload = CSVOutputRenderer().render(result)
    assert "severity" in csv_payload
    assert "warning_list" in csv_payload

    bundle = STIXOutputRenderer(allowed_types={IOCType.DOMAIN}).render(result)
    assert "[domain-name:value = 'example.com']" in bundle
    assert "[url:value = 'https://evil.example/path']" not in bundle


def test_cli_supports_stdin_directory_streaming_and_url_file(tmp_path: Path) -> None:
    original_stdin = sys.stdin
    sys.stdin = io.StringIO("IOC URL: https://stdin.example/path\n")
    try:
        stdin_args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            stdin=True,
            type="text",
            no_defang=True,
            no_check_warnings=True,
            force_update=False,
            only=None,
            exclude=None,
        )
        normal_iocs, _warning_iocs, input_display = cli_process_single_input(stdin_args)
        assert input_display == "stdin"
        assert normal_iocs == {"urls": ["https://stdin.example/path"]}
    finally:
        sys.stdin = original_stdin

    nested = tmp_path / "reports" / "nested"
    nested.mkdir(parents=True)
    (tmp_path / "reports" / "a.txt").write_text("IOC domain: alpha.example.com\n", encoding="utf-8")
    (nested / "b.txt").write_text("IOC domain: beta.example.com\n", encoding="utf-8")
    directory_args = argparse.Namespace(
        directory=str(tmp_path / "reports"),
        recursive=True,
        glob="*.txt",
        multiple=None,
        parallel=1,
        type="text",
        no_defang=True,
        no_check_warnings=True,
        force_update=False,
        only=None,
        exclude=None,
        streaming=False,
        chunk_size=1024,
        overlap=64,
    )
    normal_iocs, _warnings, display, _results = process_directory_input(
        directory_args,
        reader=cli_reader,
        warning_service=cli_warning_service,
    )
    assert display == "2 files"
    assert sorted(normal_iocs["domains"]) == ["alpha.example.com", "beta.example.com"]

    large_file = tmp_path / "large.txt"
    large_file.write_text("IOC domain: stream.example.com\n" * 200, encoding="utf-8")
    normal_iocs, _warnings = cli_process_file(
        large_file,
        defang=False,
        check_warnings=False,
        include_types=(IOCType.DOMAIN,),
        streaming=True,
        chunk_size=128,
        overlap=16,
    )
    assert normal_iocs == {"domains": ["stream.example.com"]}

    url_file = tmp_path / "urls.txt"
    with LocalHTTPTextServer(b"IOC URL: https://batch.example/path\n") as url:
        url_file.write_text(f"{url}\n", encoding="utf-8")
        url_args = argparse.Namespace(
            url_file=str(url_file),
            type="text",
            no_defang=True,
            no_check_warnings=True,
            force_update=False,
            only=None,
            exclude=None,
        )
        normal_iocs, _warnings, display, _results = process_url_file_input(
            url_args,
            reader=cli_reader,
            warning_service=cli_warning_service,
            downloader=cli_downloader,
        )
    assert display == "1 URLs"
    assert normal_iocs == {"urls": ["https://batch.example/path"]}


@pytest.mark.parametrize("forced_type", ["pdf", "html"])
def test_stdin_rejects_document_type_instead_of_silently_parsing_as_text(
    forced_type: str,
) -> None:
    # Regression: --stdin always reads text, so forcing a document type used to be
    # silently ignored — e.g. `--stdin -t html` extracted IOCs from inside <script>
    # tags that the file/URL HTML parser would have stripped. Reject it cleanly.
    original_stdin = sys.stdin
    sys.stdin = io.StringIO("<html><script>var ip='8.8.8.8';</script></html>")
    try:
        stdin_args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            stdin=True,
            type=forced_type,
            no_defang=True,
            no_check_warnings=True,
            force_update=False,
            only=None,
            exclude=None,
        )
        with pytest.raises(ValidationError, match=f"--type {forced_type}"):
            cli_process_single_input(stdin_args)
    finally:
        sys.stdin = original_stdin


def test_persistence_queries_and_cli_query_paths(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'iocparser.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    result_a = ExtractionResult.from_grouped_payload({"domains": ["alpha.example"]}, {})
    result_b = ExtractionResult.from_grouped_payload({"domains": ["beta.example"]}, {})
    run_ids = service.persist_multiple_runs(
        [
            ("file", "alpha.txt", result_a),
            ("file", "beta.txt", result_b),
        ],
        tool_version="9.9.9",
        options=PersistOptions(
            defang=False,
            check_warnings=False,
            force_update=False,
            output_format="json",
        ),
    )

    runs = query_runs(QueryRunsInput(limit=10), persistence_query_service=service)
    assert len(runs) == 2

    hits = search_persisted_iocs(
        SearchPersistedIOCsInput(value="beta"), persistence_query_service=service
    )
    assert len(hits) == 1
    assert hits[0].value == "beta.example"

    export = export_persisted_run(
        ExportPersistedRunInput(run_id=run_ids[0]), persistence_query_service=service
    )
    assert export.summary.source_value == "alpha.txt"
    assert export.result.grouped_iocs() == {"domains": ["alpha.example"]}

    diff = diff_persisted_runs(
        DiffPersistedRunsInput(left_run_id=run_ids[0], right_run_id=run_ids[1]),
        persistence_query_service=service,
    )
    assert diff.added.grouped_iocs() == {"domains": ["beta.example"]}
    assert diff.removed.grouped_iocs() == {"domains": ["alpha.example"]}

    query_args = argparse.Namespace(
        list_runs=True,
        run_limit=10,
        search_ioc=None,
        diff_runs=None,
        export_run=None,
        persist=None,
        db_uri=db_uri,
        config=None,
        debug=False,
        verbose=False,
        log_file=None,
        init=False,
        force_update=False,
    )
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        cli_module.run_cli(query_args)
    assert "alpha.txt" in buffer.getvalue() or "beta.txt" in buffer.getvalue()


def test_cli_export_and_diff_outputs_use_new_renderers(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'iocparser2.db'}"
    service = SQLAlchemyPersistenceService(db_uri)
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "first.txt",
                ExtractionResult.from_grouped_payload({"domains": ["one.example"]}, {}),
            ),
            (
                "file",
                "second.txt",
                ExtractionResult.from_grouped_payload({"domains": ["two.example"]}, {}),
            ),
        ],
        tool_version="9.9.9",
        options=PersistOptions(
            defang=False,
            check_warnings=False,
            force_update=False,
            output_format="json",
        ),
    )

    export_args = argparse.Namespace(
        output="-",
        jsonl=True,
        csv=False,
        json=False,
        stix=False,
        stix_types=None,
        with_context=False,
    )
    export = service.export_run(run_id=run_ids[0])
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        cli_output.save_exported_run(export_args, export, file_writer=cli_runtime.file_writer)
    assert "one.example" in buffer.getvalue()

    diff_args = argparse.Namespace(
        output="-",
        json=True,
        jsonl=False,
        csv=False,
        stix=False,
        stix_types=None,
        with_context=False,
    )
    diff = service.diff_runs(left_run_id=run_ids[0], right_run_id=run_ids[1])
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        cli_output.save_diff_output(diff_args, diff, file_writer=cli_runtime.file_writer)
    assert '"added"' in buffer.getvalue()
