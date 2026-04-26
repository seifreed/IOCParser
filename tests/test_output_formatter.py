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


def test_stix_renderer_can_be_written_to_disk(tmp_path: Path) -> None:
    output_file = tmp_path / "rendered" / "bundle.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    output_file.write_text(STIXOutputRenderer().render(_result()), encoding="utf-8")

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["type"] == "bundle"
    assert payload["x_iocparser_format"] == "stix"
    assert output_file.exists()
