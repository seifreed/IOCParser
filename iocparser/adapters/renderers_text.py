from __future__ import annotations

from typing import ClassVar

from iocparser.domain.models import ExtractionResult
from iocparser.errors import TypeValidationError
from iocparser.interfaces.ports import OutputRenderer
from iocparser.rendering_support import (
    SECTION_ORDER,
    evidence_excerpts,
    group_canonical_by_type,
    render_text_output,
)
from iocparser.shared_utils import refang_ioc


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeValidationError(field, "string", value)
    return value


class TextOutputRenderer(OutputRenderer):
    """Render extraction results as plain text."""

    SECTION_ORDER: ClassVar[list[tuple[str, str]]] = SECTION_ORDER

    def __init__(self, *, include_context: bool = False) -> None:
        self.include_context = include_context

    def render(self, result: ExtractionResult) -> str:
        grouped = group_canonical_by_type(result)
        warning_grouped = result.grouped_warnings()
        context_map: dict[tuple[str, str], list[str]] = {}
        if self.include_context:
            for record in result.to_records():
                raw_val = _require_str(record["raw_value"], field="raw_value")
                canonical_val = _require_str(record.get("value", raw_val), field="value")
                section = _require_str(record["type"], field="type")
                evidence_items = record.get("evidence", ())
                if not isinstance(evidence_items, list):
                    continue
                excerpts = evidence_excerpts(evidence_items)
                for variant in {
                    raw_val,
                    raw_val.lower(),
                    canonical_val,
                    canonical_val.lower(),
                    refang_ioc(raw_val),
                    refang_ioc(raw_val).lower(),
                }:
                    context_map.setdefault((section, variant), excerpts)

        def _lookup(section_key: str, item: str) -> list[str]:
            for candidate in (item, item.lower(), refang_ioc(item), refang_ioc(item).lower()):
                result_list = context_map.get((section_key, candidate))
                if result_list is not None:
                    return result_list
            return []

        return render_text_output(
            grouped,
            warning_grouped,
            format_section=lambda _section_key, data: sorted(
                _require_str(value, field="value") for value in data
            ),
            format_warning=format_warning_item,
            context_map=context_map if self.include_context else None,
            context_lookup=_lookup,
        )


def format_warning_item(warning: dict[str, str] | str) -> list[str]:
    if isinstance(warning, dict):
        value = _require_str(warning["value"], field="value")
        warning_list = _require_str(warning["warning_list"], field="warning_list")
        lines = [f"{value} - *{warning_list}*"]
        description = warning.get("description")
        if description:
            lines.append(f"  Description: {_require_str(description, field='description')}")
        return lines
    return [_require_str(warning, field="warning")]
