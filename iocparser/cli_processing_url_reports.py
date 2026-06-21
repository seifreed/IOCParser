from __future__ import annotations

import math
import time
from json import loads
from pathlib import Path
from typing import TypedDict, cast

from iocparser.cli_args_values import int_value
from iocparser.domain.pipeline import BATCH_REPORT_SCHEMA_VERSION
from iocparser.errors import JSONShapeError
from iocparser.shared_utils import parse_bool_token


class BatchItemReport(TypedDict, total=False):
    item_key: str
    input_index: int
    url: str
    status: str
    duration_ms: int
    normal_ioc_count: int
    warning_ioc_count: int
    metadata: dict[str, object]
    retry_attempt: int
    error: str
    error_type: str
    error_code: str
    error_category: str
    retryable: bool


class BatchReport(TypedDict):
    schema_version: str
    report_type: str
    job_id: str
    correlation_id: str
    status: str
    failure_cause: str | None
    total: int
    successful: int
    failed: int
    failures: dict[str, str]
    error_groups: dict[str, int]
    items: list[BatchItemReport]
    source_metadata_map: dict[str, dict[str, object]]
    run_metadata_map: dict[str, dict[str, int | str]]
    duration_ms: int
    phase_timings_ms: dict[str, int]
    phase_timestamps: dict[str, str]
    metrics: dict[str, float | int]


class BatchReportContext(TypedDict):
    urls: list[str]
    results: object
    failures: dict[str, str]
    item_reports: list[BatchItemReport]
    source_metadata_map: dict[str, dict[str, object]]
    run_metadata_map: dict[str, dict[str, int | str]]
    job_id: str
    correlation_id: str
    input_load_ms: int
    batch_started: float
    batch_started_wall: float


def bool_value(value: object, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        parsed = parse_bool_token(value)
        if parsed is not None:
            return parsed
        raise TypeError(f"Expected boolean-compatible value, got {type(value).__name__}")
    raise TypeError(f"Expected boolean-compatible value, got {type(value).__name__}")


def _json_dict(path: Path) -> dict[str, object]:
    payload: object = loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise JSONShapeError("object")
    normalized: dict[str, object] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            continue
        if key == "metadata" and isinstance(value, dict):
            normalized[key] = {name: data for name, data in value.items() if isinstance(name, str)}
            continue
        normalized[key] = value
    return normalized


def _report_items(payload: dict[str, object]) -> list[BatchItemReport]:
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return []
    return [_report_item(entry) for entry in raw_items if isinstance(entry, dict)]


def _report_item(entry: dict[object, object]) -> BatchItemReport:
    item: BatchItemReport = {}
    for key, value in entry.items():
        if not isinstance(key, str):
            continue
        key_str = key
        if _set_batch_item_string(item, key_str, value):
            continue
        if _set_batch_item_int(item, key_str, value):
            continue
        if key_str == "retryable":
            item["retryable"] = bool_value(value)
            continue
        if key_str == "metadata" and isinstance(value, dict):
            item["metadata"] = {name: data for name, data in value.items() if isinstance(name, str)}
    return item


def _group_failures(item_reports: list[BatchItemReport]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in item_reports:
        if str(item.get("status", "")).lower() != "failed":
            continue
        error_type = str(item.get("error_type", "unknown"))
        counts[error_type] = counts.get(error_type, 0) + 1
    return dict(sorted(counts.items()))


def _item_url(item: BatchItemReport) -> str:
    value = item.get("url", "")
    return value.strip() if isinstance(value, str) else ""


def _public_batch_item(item: BatchItemReport) -> BatchItemReport:
    public_item = dict(item)
    public_item.pop("item_key", None)
    public_item.pop("input_index", None)
    return cast("BatchItemReport", public_item)


def public_batch_report(report: BatchReport) -> BatchReport:
    public_items = [
        _public_batch_item(item) for item in report.get("items", []) if isinstance(item, dict)
    ]
    public_failures: dict[str, str] = {}
    url_totals: dict[str, int] = {}
    for item in public_items:
        if str(item.get("status", "")).lower() != "failed":
            continue
        url = _item_url(item)
        if url:
            url_totals[url] = url_totals.get(url, 0) + 1
    url_counts: dict[str, int] = {}
    for item in public_items:
        if str(item.get("status", "")).lower() != "failed":
            continue
        url = _item_url(item)
        error = str(item.get("error", "")).strip()
        if url:
            # Gate on url only, not error: a message-less exception (str(exc) == "") is
            # still counted in report["failed"], so requiring a non-empty error here
            # dropped the failed URL from the summary, making the count disagree with the
            # listed failures and skewing the [N] occurrence suffix.
            url_counts[url] = url_counts.get(url, 0) + 1
            occurrence = url_counts[url]
            key = url if url_totals.get(url, 0) <= 1 else f"{url} [{occurrence}]"
            public_failures[key] = error or "unknown error"
    public_report = dict(report)
    public_report["items"] = public_items
    public_report["failures"] = public_failures
    public_report.pop("source_metadata_map", None)
    public_report.pop("run_metadata_map", None)
    return cast("BatchReport", public_report)


def build_batch_report(context: BatchReportContext) -> BatchReport:
    urls = context["urls"]
    failures = context["failures"]
    item_reports = context["item_reports"]
    successful_items = sum(1 for item in item_reports if item.get("status") == "ok")
    failed_items = sum(1 for item in item_reports if item.get("status") == "failed")
    item_durations = sorted(
        int_value(item.get("duration_ms", 0)) for item in item_reports if item.get("status") == "ok"
    )
    downloader_bytes = sum(
        int_value(
            item.get("metadata", {}).get("input_size", 0)
            if isinstance(item.get("metadata"), dict)
            else 0
        )
        for item in item_reports
    )
    downloader_attempts = sum(
        int_value(
            item.get("metadata", {}).get("attempt_count", 1)
            if isinstance(item.get("metadata"), dict)
            else 1,
            default=1,
        )
        for item in item_reports
    )
    return {
        "schema_version": BATCH_REPORT_SCHEMA_VERSION,
        "report_type": "url_batch",
        "job_id": context["job_id"],
        "correlation_id": context["correlation_id"],
        "status": "failed"
        if failed_items and not successful_items
        else "partial"
        if failed_items
        else "success",
        "failure_cause": next(iter(sorted(_group_failures(item_reports))), None)
        if failures
        else None,
        "total": len(urls),
        "successful": successful_items,
        "failed": failed_items,
        "failures": failures,
        "error_groups": _group_failures(item_reports),
        "items": [
            cast("BatchItemReport", dict(item))
            for item in sorted(item_reports, key=lambda item: int_value(item.get("input_index", 0)))
        ],
        "source_metadata_map": context["source_metadata_map"],
        "run_metadata_map": context["run_metadata_map"],
        "duration_ms": int((time.perf_counter() - context["batch_started"]) * 1000),
        "phase_timings_ms": {
            "input_load": context["input_load_ms"],
            "execution": int((time.perf_counter() - context["batch_started"]) * 1000)
            - context["input_load_ms"],
        },
        "phase_timestamps": {
            "started_at": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(context["batch_started_wall"])
            ),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        },
        "metrics": {
            "average_item_duration_ms": int(sum(item_durations) / len(item_durations))
            if item_durations
            else 0,
            # Nearest-rank p95: ceil(0.95*n)-1. Using int()/floor returned the
            # absolute maximum (p100) whenever n was a multiple of 20.
            "p95_item_duration_ms": item_durations[
                min(len(item_durations) - 1, math.ceil(len(item_durations) * 0.95) - 1)
            ]
            if item_durations
            else 0,
            "downloaded_bytes": downloader_bytes,
            "request_attempts": downloader_attempts,
            "throughput_items_per_second": round(
                len(urls) / max((time.perf_counter() - context["batch_started"]), 0.001), 2
            ),
        },
    }


def _set_batch_item_string(item: BatchItemReport, key: str, value: object) -> bool:
    def require_string(field: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"Expected {field} to be string, got {type(value).__name__}")
        return value

    if key == "url":
        if isinstance(value, str):
            item["url"] = value
        return True
    if key == "status":
        item["status"] = require_string("status")
        return True
    if key == "error":
        item["error"] = require_string("error")
        return True
    if key == "error_type":
        item["error_type"] = require_string("error_type")
        return True
    if key == "error_code":
        item["error_code"] = require_string("error_code")
        return True
    if key == "error_category":
        item["error_category"] = require_string("error_category")
        return True
    return False


def _set_batch_item_int(item: BatchItemReport, key: str, value: object) -> bool:
    if key == "input_index":
        item["input_index"] = int_value(value)
        return True
    if key == "duration_ms":
        item["duration_ms"] = int_value(value)
        return True
    if key == "normal_ioc_count":
        item["normal_ioc_count"] = int_value(value)
        return True
    if key == "warning_ioc_count":
        item["warning_ioc_count"] = int_value(value)
        return True
    if key == "retry_attempt":
        item["retry_attempt"] = int_value(value)
        return True
    return False
