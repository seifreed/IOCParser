from __future__ import annotations

from typing import ClassVar

from iocparser.domain.models import ExtractionResult
from iocparser.interfaces.ports import OutputRenderer
from iocparser.rendering_support import SECTION_ORDER, group_canonical_by_type, render_text_output
from iocparser.shared_utils import refang_ioc


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
                raw_val = str(record["raw_value"])
                canonical_val = str(record.get("value", raw_val))
                section = str(record["type"])
                evidence_items = record.get("evidence", ())
                if not isinstance(evidence_items, list):
                    continue
                excerpts = [
                    str(evidence["excerpt"])
                    for evidence in evidence_items
                    if isinstance(evidence, dict) and evidence.get("excerpt")
                ]
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
            format_section=lambda _section_key, data: sorted(str(value) for value in data),
            format_warning=format_warning_item,
            context_map=context_map if self.include_context else None,
            context_lookup=_lookup,
        )


def format_warning_item(warning: dict[str, str] | str) -> list[str]:
    if isinstance(warning, dict):
        lines = [f"{warning['value']} - *{warning['warning_list']}*"]
        if warning.get("description"):
            lines.append(f"  Description: {warning['description']}")
        return lines
    return [str(warning)]
