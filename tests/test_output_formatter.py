from __future__ import annotations

import json
from pathlib import Path

from iocparser.domain.models import IOC, ExtractionResult, WarningMatch
from iocparser.renderers import (
    CSVOutputRenderer,
    JSONLinesOutputRenderer,
    JSONOutputRenderer,
    STIXOutputRenderer,
    TextOutputRenderer,
)


def _result() -> ExtractionResult:
    return ExtractionResult(
        iocs=(
            IOC.from_raw("domains", "example.com"),
            IOC.from_raw("urls", "https://evil.example/path"),
        ),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw("ips", "198.51.100.10"),
                warning_list="Known Benign",
                description="Resolver",
            ),
        ),
    )


def test_json_renderer_produces_expected_payload() -> None:
    payload = json.loads(JSONOutputRenderer(include_context=True).render(_result()))

    assert payload["format"] == "json"
    assert payload["schema_version"] == "1.0"
    assert payload["domains"] == ["example.com"]
    assert payload["urls"] == ["https://evil.example/path"]
    assert payload["warning_list_matches"]["ips"][0]["value"] == "198.51.100.10"
    assert payload["records"]


def test_text_renderer_renders_iocs_and_warnings() -> None:
    rendered = TextOutputRenderer(include_context=True).render(_result())

    assert "example.com" in rendered
    assert "https://evil.example/path" in rendered
    assert "Known Benign" in rendered


def test_line_and_tabular_renderers_cover_non_text_formats() -> None:
    result = _result()

    jsonl_lines = JSONLinesOutputRenderer().render(result).splitlines()
    csv_lines = CSVOutputRenderer().render(result).splitlines()

    assert len(jsonl_lines) == 3
    assert '"format": "jsonl"' in jsonl_lines[0]
    assert csv_lines[0].startswith("schema_version,")
    assert any("198.51.100.10" in line for line in csv_lines[1:])


def test_csv_renderer_neutralizes_formula_injection() -> None:
    """A leading =/+/-/@ in an IOC value must be neutralized for spreadsheets.

    IOC values come from attacker-controlled documents, so an unguarded cell like
    =cmd|'/c calc'!A1 would execute as a formula when opened in Excel/Sheets.
    """
    result = ExtractionResult(iocs=(IOC.from_raw("mutex", "=cmd|'/c calc'!A1"),))
    rows = CSVOutputRenderer().render(result).splitlines()
    value_cell = rows[1].split(",", 3)[2]
    assert value_cell.startswith("'=")

    # A normal value is untouched.
    benign = ExtractionResult(iocs=(IOC.from_raw("domains", "evil.com"),))
    assert "'evil.com" not in CSVOutputRenderer().render(benign)


def test_csv_line_numbers_stay_aligned_with_evidence_excerpts() -> None:
    """The line_numbers and evidence columns must stay positionally aligned.

    Regression: line_numbers iterated every evidence entry while evidence filtered
    out empty excerpts, so an entry with an empty excerpt added a phantom
    line-number slot, desyncing the two columns.
    """
    import csv
    import io

    from iocparser.domain.models import IOCEvidence

    evidence = (
        IOCEvidence(excerpt="first", line_number=10),
        IOCEvidence(excerpt="", line_number=20),
        IOCEvidence(excerpt="third", line_number=30),
    )
    result = ExtractionResult(iocs=(IOC.from_raw("domains", "evil.example", evidence=evidence),))
    row = next(csv.DictReader(io.StringIO(CSVOutputRenderer().render(result))))

    assert row["evidence"] == "first | third"
    assert row["line_numbers"] == "10,30"


def test_csv_field_rejects_missing_required_field() -> None:
    """_csv_field must raise on a record missing a required column, not emit blank."""
    import pytest

    from iocparser.adapters.renderers_json import _csv_field
    from iocparser.errors import TypeValidationError

    assert _csv_field({"type": "domains"}, "type") == "domains"
    with pytest.raises(TypeValidationError):
        _csv_field({}, "type")


def test_csv_line_number_blank_when_absent() -> None:
    """Evidence without a line number renders an empty line_numbers cell, not 'None'."""
    import csv
    import io

    from iocparser.domain.models import IOCEvidence

    evidence = (IOCEvidence(excerpt="only-excerpt"),)  # line_number defaults to None
    result = ExtractionResult(iocs=(IOC.from_raw("domains", "evil.example", evidence=evidence),))
    row = next(csv.DictReader(io.StringIO(CSVOutputRenderer().render(result))))

    assert row["evidence"] == "only-excerpt"
    assert row["line_numbers"] == ""


def test_stix_renderer_can_be_written_to_disk(tmp_path: Path) -> None:
    output_file = tmp_path / "rendered" / "bundle.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    output_file.write_text(STIXOutputRenderer().render(_result()), encoding="utf-8")

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["type"] == "bundle"
    assert payload["x_iocparser_format"] == "stix"
    assert output_file.exists()
