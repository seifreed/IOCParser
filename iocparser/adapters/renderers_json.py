from __future__ import annotations

import json
from csv import DictWriter
from io import StringIO
from typing import ClassVar

from iocparser.domain.models import ExtractionResult
from iocparser.domain.pipeline import RESULT_SCHEMA_VERSION
from iocparser.interfaces.ports import OutputRenderer
from iocparser.rendering_support import (
    evidence_excerpts,
    group_canonical_by_type,
    serialize_pretty_json,
)


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Expected {field} to be string, got {type(value).__name__}")
    return value


class JSONOutputRenderer(OutputRenderer):
    """Render extraction results as JSON."""

    def __init__(self, *, include_context: bool = False) -> None:
        # Accepted for renderer-interface parity; JSON records always carry
        # evidence via to_records(), so the flag does not change the payload.
        self.include_context = include_context

    def render(self, result: ExtractionResult) -> str:
        grouped = group_canonical_by_type(result)
        warnings = result.grouped_warnings()
        payload: dict[str, object] = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "format": "json",
            "records": result.to_records(),
            "counts_by_type": result.counts_by_type(),
            "total_count": result.total_count(),
        }
        for key, values in grouped.items():
            payload[key] = sorted(_require_str(v, field="value") for v in values)
        if warnings:
            payload["warning_list_matches"] = warnings
        return serialize_pretty_json(payload)


class JSONLinesOutputRenderer(OutputRenderer):
    """Render extraction results as JSON lines."""

    def render(self, result: ExtractionResult) -> str:
        return "\n".join(
            json.dumps(jsonl_record(record), sort_keys=True) for record in result.to_records()
        )


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection in a CSV cell.

    IOC values come straight from attacker-controlled documents, so a value like
    ``=cmd|'/c calc'!A1`` would execute as a formula when the CSV is opened in
    Excel/Sheets. Prefixing a leading =/+/-/@ (after any leading whitespace) with
    a single quote makes the spreadsheet treat the cell as text.
    """
    if value.lstrip("\t\r\n ")[:1] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


class CSVOutputRenderer(OutputRenderer):
    """Render extraction results as CSV."""

    FIELDNAMES: ClassVar[list[str]] = [
        "schema_version",
        "type",
        "value",
        "raw_value",
        "severity",
        "tags",
        "warning_list",
        "description",
        "line_numbers",
        "evidence",
    ]

    def render(self, result: ExtractionResult) -> str:
        buffer = StringIO()
        writer = DictWriter(buffer, fieldnames=self.FIELDNAMES)
        writer.writeheader()
        for record in result.to_records():
            evidence_list = record_dict_list(record, "evidence")
            line_numbers = ",".join(
                str(entry["line_number"])
                for entry in evidence_list
                if isinstance(entry, dict) and entry.get("line_number") is not None
            )
            evidence_text = " | ".join(evidence_excerpts(evidence_list))
            writer.writerow(
                {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "type": str(record.get("type", "")),
                    "value": _csv_safe(str(record.get("value", ""))),
                    "raw_value": _csv_safe(str(record.get("raw_value", ""))),
                    "severity": str(record.get("severity", "")),
                    "tags": _csv_safe(",".join(record_string_list(record, "tags"))),
                    "warning_list": _csv_safe(str(record.get("warning_list", ""))),
                    "description": _csv_safe(str(record.get("description", ""))),
                    "line_numbers": line_numbers,
                    "evidence": _csv_safe(evidence_text),
                }
            )
        return buffer.getvalue()


def jsonl_record(record: dict[str, object]) -> dict[str, object]:
    payload = dict(record)
    payload["schema_version"] = RESULT_SCHEMA_VERSION
    payload["format"] = "jsonl"
    return payload


def record_string_list(record: dict[str, object], key: str) -> tuple[str, ...]:
    raw_value = record.get(key, [])
    if not isinstance(raw_value, list):
        return ()
    values: list[str] = []
    for value in raw_value:
        if not isinstance(value, str):
            raise TypeError(f"Expected {key} entries to be string, got {type(value).__name__}")
        values.append(value)
    return tuple(values)


def record_dict_list(record: dict[str, object], key: str) -> list[dict[str, object]]:
    raw_value = record.get(key, [])
    if not isinstance(raw_value, list):
        return []
    return [entry for entry in raw_value if isinstance(entry, dict)]


def json_object(raw_value: str) -> dict[str, object]:
    decoded: object = json.loads(raw_value)
    if not isinstance(decoded, dict):
        return {}
    return {str(key): value for key, value in decoded.items()}
