from __future__ import annotations

import argparse
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from colorama import Fore, Style

from iocparser.application.contracts import PersistRunInput
from iocparser.application.use_cases import persist_run as persist_run_use_case
from iocparser.cli_args import (
    get_bool_arg,
    get_optional_str_arg,
    get_output_filename,
    parse_string_filters,
)
from iocparser.config import AppConfig
from iocparser.domain.models import ExtractionResult, PersistOptions, Source
from iocparser.infrastructure.file_readers import detect_file_type
from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.persistence import SQLAlchemyUnitOfWork
from iocparser.interfaces.ports import FileWriter
from iocparser.plugins import get_renderer

color_cyan: str = str(Fore.CYAN)
color_red: str = str(Fore.RED)
color_yellow: str = str(Fore.YELLOW)
style_reset: str = str(Style.RESET_ALL)
logger = get_logger(__name__)

__all__ = [
    "PersistResultsRequest",
    "_filter_result_for_output",
    "_int_run_metadata_value",
    "_optional_int_run_metadata_value",
    "_optional_str_run_metadata_value",
    "_render_summary",
    "_source_metadata_values",
    "display_results",
    "persist_results",
    "print_warning_lists",
    "render_result",
    "save_output",
    "save_rendered_output",
]


@dataclass(frozen=True)
class PersistResultsRequest:
    config: AppConfig
    source_kind: str
    source_value: str
    normal_iocs: dict[str, list[str | dict[str, str]]]
    warning_iocs: dict[str, list[dict[str, str]]]
    options: PersistOptions
    tool_version: str
    source_metadata: dict[str, object] | None = None
    run_metadata: dict[str, int | str | None] | None = None


def source_metadata_values(
    source_metadata: dict[str, object],
) -> tuple[str | None, str | None, str | None, int | None]:
    original_url = source_metadata.get("original_url")
    normalized_url = source_metadata.get("normalized_url")
    mime_type = source_metadata.get("mime_type")
    input_size = source_metadata.get("input_size")
    return (
        str(original_url) if isinstance(original_url, str) and original_url else None,
        str(normalized_url) if isinstance(normalized_url, str) and normalized_url else None,
        str(mime_type) if isinstance(mime_type, str) and mime_type else None,
        input_size if isinstance(input_size, int) else None,
    )


def int_run_metadata_value(
    run_metadata: dict[str, int | str | None], key: str, default: int
) -> int:
    raw_value = run_metadata.get(key)
    if raw_value is None:
        return default
    if isinstance(raw_value, int):
        return raw_value
    return int(raw_value)


def optional_int_run_metadata_value(
    run_metadata: dict[str, int | str | None], key: str
) -> int | None:
    raw_value = run_metadata.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, int):
        return raw_value
    return int(raw_value)


def optional_str_run_metadata_value(
    run_metadata: dict[str, int | str | None], key: str
) -> str | None:
    raw_value = run_metadata.get(key)
    if raw_value is None:
        return None
    return str(raw_value)


def persist_results_request(request: PersistResultsRequest) -> int | None:
    if not request.config.persist:
        return None
    if not request.config.db_uri:
        logger.error("Persistence enabled but no database URI provided")
        return None
    metadata = dict(request.source_metadata or {})
    path = Path(request.source_value)
    if request.source_kind == "file" and path.is_file():
        try:
            content = path.read_bytes()
            metadata.setdefault("input_size", path.stat().st_size)
            metadata.setdefault("content_hash", hashlib.sha256(content).hexdigest())
            metadata.setdefault("fingerprint", str(metadata["content_hash"])[:16])
            metadata.setdefault("mime_type", detect_file_type(path))
        except (OSError, ValueError):
            logger.debug("Failed to collect file metadata for %s", request.source_value)
    if request.source_kind == "url":
        metadata.setdefault("original_url", request.source_value)
    original_url, normalized_url, mime_type, input_size = source_metadata_values(metadata)
    effective_run_metadata = dict(request.run_metadata or {})
    persisted = persist_run_use_case(
        PersistRunInput(
            source=Source.from_raw(
                request.source_kind,
                request.source_value,
                original_url=original_url,
                normalized_url=normalized_url,
                mime_type=mime_type,
                input_size=input_size,
                content_hash=str(metadata["content_hash"])
                if metadata.get("content_hash")
                else None,
                fingerprint=str(metadata["fingerprint"]) if metadata.get("fingerprint") else None,
            ),
            result=ExtractionResult.from_grouped_payload(request.normal_iocs, request.warning_iocs),
            tool_version=request.tool_version,
            options=request.options,
            duration_ms=optional_int_run_metadata_value(effective_run_metadata, "duration_ms"),
            processed_items=int_run_metadata_value(effective_run_metadata, "processed_items", 1),
            successful_items=int_run_metadata_value(effective_run_metadata, "successful_items", 1),
            failed_items=int_run_metadata_value(effective_run_metadata, "failed_items", 0),
            partial_error_count=int_run_metadata_value(
                effective_run_metadata, "partial_error_count", 0
            ),
            status=optional_str_run_metadata_value(effective_run_metadata, "status"),
            error_message=optional_str_run_metadata_value(effective_run_metadata, "error_message")
            or "",
        ),
        unit_of_work=SQLAlchemyUnitOfWork(request.config.db_uri),
    )
    return persisted.run_id


def filter_result_for_output(
    args: argparse.Namespace, result: ExtractionResult
) -> ExtractionResult:
    namespace: Mapping[str, object] = vars(args)
    raw_max_evidence = namespace.get("max_evidence")
    severities = parse_string_filters(get_optional_str_arg(args, "severity"))
    tags = parse_string_filters(get_optional_str_arg(args, "tag"))
    include_normal = not get_bool_arg(args, "only_warnings")
    include_warnings = not get_bool_arg(args, "only_normal")
    return result.filter_analyst_view(
        severities=severities,
        tags=tags,
        include_normal=include_normal,
        include_warnings=include_warnings,
        max_evidence=raw_max_evidence if isinstance(raw_max_evidence, int) else None,
        sort_by=get_optional_str_arg(args, "sort_by") or "type",
    )


def render_summary(result: ExtractionResult) -> str:
    counts = result.counts_by_type()
    name_width = max([len("IOC Type"), *(len(name) for name in counts)], default=8)
    count_width = max([len("Count"), *(len(str(value)) for value in counts.values())], default=5)
    lines = [
        "# IOC Summary",
        "",
        f"Total records: {result.total_count()}",
        f"Normal IOCs: {len(result.iocs)}",
        f"Warning-list matches: {len(result.warnings)}",
        "",
        f"{'IOC Type':<{name_width}} | {'Count':>{count_width}}",
        f"{'-' * name_width}-+-{'-' * count_width}",
    ]
    lines.extend(
        f"{ioc_type:<{name_width}} | {count:>{count_width}}" for ioc_type, count in counts.items()
    )
    if result.warnings:
        lines.extend(["", "## Warning Matches", ""])
        lines.extend(
            f"- {warning.ioc.canonical_value()} [{warning.warning_list}]"
            for warning in result.warnings
        )
    return "\n".join(lines)


def render_result(args: argparse.Namespace, result: ExtractionResult) -> tuple[str, str, str]:
    include_context = get_bool_arg(args, "with_context")
    result = filter_result_for_output(args, result)
    plugin_renderer = get_optional_str_arg(args, "renderer")
    if plugin_renderer:
        renderer = get_renderer(
            plugin_renderer,
            with_context=include_context,
            stix_types=get_optional_str_arg(args, "stix_types"),
        )
        return renderer.render(result), plugin_renderer, plugin_renderer
    if get_bool_arg(args, "summary") and not any(
        get_bool_arg(args, name) for name in ("json", "jsonl", "csv", "stix")
    ):
        return render_summary(result), "summary", "text"
    if get_bool_arg(args, "stix"):
        renderer = get_renderer("stix", stix_types=get_optional_str_arg(args, "stix_types"))
        return renderer.render(result), "STIX 2.1", "stix"
    if get_bool_arg(args, "jsonl"):
        renderer = get_renderer("jsonl")
        return renderer.render(result), "JSON Lines", "jsonl"
    if get_bool_arg(args, "csv"):
        renderer = get_renderer("csv")
        return renderer.render(result), "CSV", "csv"
    if get_bool_arg(args, "json"):
        renderer = get_renderer("json", with_context=include_context)
        return renderer.render(result), "JSON", "json"
    renderer = get_renderer("text", with_context=include_context)
    return renderer.render(result), "text", "text"


def save_rendered_output(
    *,
    rendered_output: str,
    output_label: str | None = None,
    input_display: str,
    chosen_format: str,
    output_path: str | None,
    file_writer: FileWriter,
) -> str | None:
    del output_label
    if output_path == "-":
        print(rendered_output)
        return None
    if output_path:
        file_writer.write(output_path, rendered_output)
        return output_path
    output_filename = get_output_filename(
        input_display, is_json=chosen_format == "json", output_format=chosen_format
    )
    file_writer.write(output_filename, rendered_output)
    return output_filename


_filter_result_for_output = filter_result_for_output
_render_summary = render_summary
_source_metadata_values = source_metadata_values
_int_run_metadata_value = int_run_metadata_value
_optional_int_run_metadata_value = optional_int_run_metadata_value
_optional_str_run_metadata_value = optional_str_run_metadata_value


def _write(text: str) -> None:
    import sys

    sys.stdout.write(text + "\n")


def print_warning_lists(warnings: dict[str, list[dict[str, str]]]) -> None:
    if not warnings:
        return
    logger.warning("IOCs found that might be false positives according to MISP warning lists:")
    for ioc_type, type_warnings in warnings.items():
        _write(f"\n{color_yellow}IOCs of type {ioc_type} with warnings:{style_reset}")
        for warning in type_warnings:
            _write(
                f"  {color_red}- {warning['value']} - List: {warning['warning_list']}{style_reset}"
            )
            _write(f"    {color_yellow}Description: {warning['description']}{style_reset}")


def display_results(
    normal_iocs: dict[str, list[str | dict[str, str]]],
    warning_iocs: dict[str, list[dict[str, str]]],
) -> None:
    total_iocs = sum(len(iocs) for iocs in normal_iocs.values())
    logger.info("Found %s indicators of compromise", total_iocs)
    for ioc_type, ioc_list in normal_iocs.items():
        if ioc_list:
            _write(f"    {color_cyan}- {ioc_type}: {len(ioc_list)}{style_reset}")
    if warning_iocs:
        print_warning_lists(warning_iocs)
        logger.warning(
            "Found %s potential false positives",
            sum(len(values) for values in warning_iocs.values()),
        )


def persist_results(request: PersistResultsRequest) -> int | None:
    return persist_results_request(request)


def save_output(
    args: argparse.Namespace,
    normal_iocs: dict[str, list[str | dict[str, str]]],
    warning_iocs: dict[str, list[dict[str, str]]],
    input_display: str,
    *,
    file_writer: FileWriter,
) -> None:
    result = ExtractionResult.from_grouped_payload(normal_iocs, warning_iocs)
    rendered_output, output_label, chosen_format = render_result(args, result)
    saved_path = save_rendered_output(
        rendered_output=rendered_output,
        input_display=input_display,
        chosen_format=chosen_format,
        output_path=get_optional_str_arg(args, "output"),
        file_writer=file_writer,
    )
    if saved_path is None:
        logger.info("Results displayed in %s format", output_label)
        return
    logger.info("Results saved to %s", saved_path)
