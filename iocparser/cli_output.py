from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from typing import TextIO

from iocparser.cli_args import get_bool_arg, get_optional_str_arg
from iocparser.cli_output_rendering import (
    PersistResultsRequest,
    _filter_result_for_output,
    _render_summary,
    display_results,
    persist_results,
    print_warning_lists,
    render_result,
    save_output,
    save_rendered_output,
)
from iocparser.cli_processing_urls import int_value as _int_value
from iocparser.domain.models import (
    BatchJobDetail,
    BatchJobSummary,
    ExtractionResult,
    PersistedRunDiff,
    PersistedRunExport,
    PersistedRunQueryHit,
    PersistedRunSummary,
)
from iocparser.interfaces.ports import FileWriter


def print_run_summaries(runs: list[PersistedRunSummary]) -> None:
    sys.stdout.write(
        "run_id\tstatus\tsource_kind\tsource_value\tnormal_iocs\twarnings\tprocessed\tfailed\ttool_version\tstarted_at"
        + "\n"
    )
    for run in runs:
        sys.stdout.write(
            f"{run.run_id}\t{run.status}\t{run.source_kind}\t{run.source_value}\t"
            f"{run.normal_ioc_count}\t{run.warning_ioc_count}\t"
            f"{run.processed_items}\t{run.failed_items}\t"
            f"{run.tool_version}\t{run.started_at.isoformat()}\n"
        )


def print_query_hits(hits: list[PersistedRunQueryHit]) -> None:
    for hit in hits:
        warning_label = "warning" if hit.is_warning else "normal"
        sys.stdout.write(
            f"{hit.run_id}\t{hit.source_kind}\t{hit.source_value}\t"
            f"{hit.ioc_type}\t{hit.value}\t{warning_label}\t{hit.severity}\t{','.join(hit.tags)}\n"
        )


def print_maintenance_result(action: str, affected: int) -> None:
    sys.stdout.write(f"{action}\taffected_runs={affected}" + "\n")


def print_status_line(label: str, value: object) -> None:
    sys.stdout.write(f"{label}\t{value}" + "\n")


def print_text_lines(lines: list[str]) -> None:
    for line in lines:
        sys.stdout.write(line + "\n")


def print_json_payload(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def print_failed_batch_jobs(jobs: list[BatchJobSummary]) -> None:
    sys.stdout.write("batch_job_id\tstatus\tsource_kind\ttotal\tfailed\tretry_attempt" + "\n")
    for job in jobs:
        sys.stdout.write(
            f"{job.batch_job_id}\t{job.status}\t{job.source_kind}\t{job.total_inputs}\t"
            f"{job.failed_inputs}\t{job.retry_attempt}\n"
        )


def print_batch_job_detail(detail: BatchJobDetail) -> None:
    sys.stdout.write(f"batch_job_id\t{detail.batch_job_id}" + "\n")
    sys.stdout.write(f"status\t{detail.status}" + "\n")
    sys.stdout.write(f"source_kind\t{detail.source_kind}" + "\n")
    sys.stdout.write(f"total_inputs\t{detail.total_inputs}" + "\n")
    sys.stdout.write(f"successful_inputs\t{detail.successful_inputs}" + "\n")
    sys.stdout.write(f"failed_inputs\t{detail.failed_inputs}" + "\n")
    sys.stdout.write(f"retry_attempt\t{detail.retry_attempt}" + "\n")
    sys.stdout.write(f"failed_item_count\t{detail.failed_item_count}" + "\n")
    sys.stdout.write(f"started_at\t{detail.started_at.isoformat()}" + "\n")
    sys.stdout.write(f"finished_at\t{detail.finished_at.isoformat()}" + "\n")
    sys.stdout.write("config\t" + json.dumps(detail.effective_config, sort_keys=True) + "\n")
    sys.stdout.write("metrics\t" + json.dumps(detail.metrics, sort_keys=True) + "\n")


def print_batch_report(report: Mapping[str, object], *, stream: TextIO | None = None) -> None:
    # The batch report is a human summary; under -o - the caller passes stderr so it does
    # not corrupt the machine output (JSONL/JSON/CSV/STIX) piped to stdout.
    out = stream if stream is not None else sys.stdout
    if not all(isinstance(key, str) for key in report):
        raise TypeError("Expected batch report keys to be strings")
    schema_version = str(report.get("schema_version", "")).strip()
    if schema_version:
        out.write(f"Batch report schema\t{schema_version}" + "\n")
    total = _int_value(report.get("total", 0))
    successful = _int_value(report.get("successful", 0))
    failed = _int_value(report.get("failed", 0))
    out.write(f"Batch summary\t{successful}/{total} successful\t{failed} failed" + "\n")
    failures = report.get("failures", {})
    if isinstance(failures, dict) and failures:
        if not all(isinstance(key, str) for key in failures):
            raise TypeError("Expected batch report failure keys to be strings")
        for item, error in sorted((key, str(value)) for key, value in failures.items()):
            out.write(f"  FAIL\t{item}\t{error}" + "\n")
    error_groups = report.get("error_groups", {})
    if isinstance(error_groups, dict) and error_groups:
        out.write("Failure groups" + "\n")
        if not all(isinstance(key, str) for key in error_groups):
            raise TypeError("Expected batch report error group keys to be strings")
        for error_type, count in sorted(
            (key, _int_value(value)) for key, value in error_groups.items()
        ):
            out.write(f"  {error_type}\t{count}" + "\n")
    phase_timings = report.get("phase_timings_ms", {})
    if isinstance(phase_timings, dict) and phase_timings:
        out.write("Phase timings (ms)" + "\n")
        if not all(isinstance(key, str) for key in phase_timings):
            raise TypeError("Expected batch report phase timing keys to be strings")
        for phase, value in sorted(
            (key, _int_value(val)) for key, val in phase_timings.items()
        ):
            out.write(f"  {phase}\t{value}" + "\n")
    metrics = report.get("metrics", {})
    if isinstance(metrics, dict) and metrics:
        out.write("Batch metrics" + "\n")
        if not all(isinstance(key, str) for key in metrics):
            raise TypeError("Expected batch report metric keys to be strings")
        for name, value in sorted(metrics.items()):
            out.write(f"  {name}\t{value}" + "\n")


def save_batch_report(
    report: Mapping[str, object], output_path: str | None, *, file_writer: FileWriter
) -> None:
    if not all(isinstance(key, str) for key in report):
        raise TypeError("Expected batch report keys to be strings")
    payload = dict(report)
    content = json.dumps(payload, indent=2, sort_keys=True)
    if output_path == "-":
        sys.stdout.write(content + "\n")
        return
    if output_path:
        file_writer.write(output_path, content)
        return
    file_writer.write("iocparser_batch_report.json", content)


def save_exported_run(
    args: argparse.Namespace, export: PersistedRunExport, *, file_writer: FileWriter
) -> None:
    rendered_output, output_label, chosen_format = render_result(args, export.result)
    save_rendered_output(
        rendered_output=rendered_output,
        output_label=output_label,
        input_display=f"run_{export.summary.run_id}",
        chosen_format=chosen_format,
        output_path=get_optional_str_arg(args, "output"),
        file_writer=file_writer,
    )


def _render_diff_csv(
    added_records: list[dict[str, object]],
    removed_records: list[dict[str, object]],
    diff_only: str,
) -> str:
    import csv
    import io

    from iocparser.adapters.renderers_json import _csv_safe

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["change", "type", "value", "is_warning"])

    def _row(change: str, record: dict[str, object]) -> list[str]:
        # Neutralize spreadsheet formula injection in the attacker-controlled value
        # (and type) cells, matching CSVOutputRenderer; the diff exporter previously
        # wrote raw_value straight through, reintroducing the injection it guards.
        return [
            change,
            _csv_safe(str(record.get("type", ""))),
            _csv_safe(str(record.get("raw_value", ""))),
            str(record.get("is_warning", "")),
        ]

    if diff_only != "removed":
        for record in added_records:
            writer.writerow(_row("added", record))
    if diff_only != "added":
        for record in removed_records:
            writer.writerow(_row("removed", record))
    return output.getvalue()


def _diff_records(result: ExtractionResult) -> list[dict[str, object]]:
    records = [dict(ioc.to_record(), is_warning=False) for ioc in result.iocs]
    records.extend(dict(warning.to_record(), is_warning=True) for warning in result.warnings)
    return records


def _build_diff_payload(
    diff: PersistedRunDiff, diff_only: str
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    added_records = _diff_records(diff.added)
    removed_records = _diff_records(diff.removed)
    payload: dict[str, object] = {
        "left_run_id": diff.left_run_id,
        "right_run_id": diff.right_run_id,
        "compared_to_previous_source_run_id": diff.compared_to_previous_source_run_id,
        "added_counts": diff.added_counts,
        "removed_counts": diff.removed_counts,
        "added": added_records,
        "removed": removed_records,
    }
    if diff_only == "added":
        payload.pop("removed")
        payload.pop("removed_counts")
    elif diff_only == "removed":
        payload.pop("added")
        payload.pop("added_counts")
    return payload, added_records, removed_records


def _render_structured_diff(
    args: argparse.Namespace,
    payload: dict[str, object],
    added_records: list[dict[str, object]],
    removed_records: list[dict[str, object]],
    diff_only: str,
) -> tuple[str, str]:
    if get_bool_arg(args, "jsonl"):
        rows: list[dict[str, object]] = []
        if diff_only != "removed":
            rows.extend({**record, "change": "added"} for record in added_records)
        if diff_only != "added":
            rows.extend({**record, "change": "removed"} for record in removed_records)
        return "\n".join(json.dumps(row, sort_keys=True) for row in rows), "jsonl"
    if get_bool_arg(args, "csv"):
        return _render_diff_csv(added_records, removed_records, diff_only), "csv"
    return json.dumps(payload, indent=4, sort_keys=True), "json"


def save_diff_output(
    args: argparse.Namespace, diff: PersistedRunDiff, *, file_writer: FileWriter
) -> None:
    diff_only = get_optional_str_arg(args, "diff_only") or "all"
    payload, added_records, removed_records = _build_diff_payload(diff, diff_only)
    if get_bool_arg(args, "json") or get_bool_arg(args, "jsonl") or get_bool_arg(args, "csv"):
        rendered_output, chosen_format = _render_structured_diff(
            args, payload, added_records, removed_records, diff_only
        )
        save_rendered_output(
            rendered_output=rendered_output,
            output_label="diff",
            input_display=f"diff_{diff.left_run_id}_{diff.right_run_id}",
            chosen_format=chosen_format,
            output_path=get_optional_str_arg(args, "output"),
            file_writer=file_writer,
        )
        return
    lines = [f"# Diff {diff.left_run_id} -> {diff.right_run_id}", ""]
    if diff.compared_to_previous_source_run_id is not None:
        lines.append(
            f"Compared against previous run from same source: {diff.compared_to_previous_source_run_id}"
        )
        lines.append("")
    if diff_only != "removed":
        lines.extend(["## Added Counts", ""])
        lines.extend(f"- {ioc_type}: {count}" for ioc_type, count in diff.added_counts.items())
        lines.append("")
    if diff_only in {"all", "added"}:
        lines.extend(["## Added", ""])
        lines.extend(ioc.canonical_value() for ioc in diff.added.iocs)
        lines.extend(
            f"warning: {warning.ioc.canonical_value()} [{warning.warning_list}]"
            for warning in diff.added.warnings
        )
        lines.append("")
    if diff_only != "added":
        lines.extend(["## Removed Counts", ""])
        lines.extend(f"- {ioc_type}: {count}" for ioc_type, count in diff.removed_counts.items())
        lines.append("")
    if diff_only in {"all", "removed"}:
        lines.extend(["## Removed", ""])
        lines.extend(ioc.canonical_value() for ioc in diff.removed.iocs)
        lines.extend(
            f"warning: {warning.ioc.canonical_value()} [{warning.warning_list}]"
            for warning in diff.removed.warnings
        )
    save_rendered_output(
        rendered_output="\n".join(lines),
        output_label="diff",
        input_display=f"diff_{diff.left_run_id}_{diff.right_run_id}",
        chosen_format="text",
        output_path=get_optional_str_arg(args, "output"),
        file_writer=file_writer,
    )


__all__ = [
    "PersistResultsRequest",
    "_filter_result_for_output",
    "_render_summary",
    "display_results",
    "persist_results",
    "print_batch_job_detail",
    "print_batch_report",
    "print_failed_batch_jobs",
    "print_json_payload",
    "print_maintenance_result",
    "print_query_hits",
    "print_run_summaries",
    "print_status_line",
    "print_text_lines",
    "print_warning_lists",
    "render_result",
    "save_batch_report",
    "save_diff_output",
    "save_exported_run",
    "save_output",
    "save_rendered_output",
]
