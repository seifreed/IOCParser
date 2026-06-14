from __future__ import annotations

import json
from csv import DictWriter
from io import StringIO
from typing import ClassVar

from iocparser.domain.models import ExtractionResult
from iocparser.domain.pipeline import RESULT_SCHEMA_VERSION
from iocparser.interfaces.ports import OutputRenderer
from iocparser.rendering_support import group_canonical_by_type, serialize_pretty_json


class JSONOutputRenderer(OutputRenderer):
    """Render extraction results as JSON."""

    def __init__(self, *, include_context: bool = False) -> None:
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
            payload[key] = (
                sorted(str(v) for v in values)
                if values and all(isinstance(v, str) for v in values)
                else list(values)
            )
        if warnings:
            payload["warning_list_matches"] = warnings
        if self.include_context:
            payload["records"] = result.to_records()
        return serialize_pretty_json(payload)


class JSONLinesOutputRenderer(OutputRenderer):
    """Render extraction results as JSON lines."""

    def render(self, result: ExtractionResult) -> str:
        return "\n".join(
            json.dumps(jsonl_record(record), sort_keys=True) for record in result.to_records()
        )


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
            evidence_text = " | ".join(
                str(entry["excerpt"])
                for entry in evidence_list
                if isinstance(entry, dict) and entry.get("excerpt")
            )
            writer.writerow(
                {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "type": str(record.get("type", "")),
                    "value": str(record.get("value", "")),
                    "raw_value": str(record.get("raw_value", "")),
                    "severity": str(record.get("severity", "")),
                    "tags": ",".join(record_string_list(record, "tags")),
                    "warning_list": str(record.get("warning_list", "")),
                    "description": str(record.get("description", "")),
                    "line_numbers": line_numbers,
                    "evidence": evidence_text,
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
    return tuple(str(value) for value in raw_value)


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
