from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Protocol, cast

from iocparser import cli_processing_urls_execution as _execution
from iocparser.cli_args import get_optional_str_arg
from iocparser.cli_processing_support import (
    BatchResultsCollection,
    GroupedIocs,
    GroupedWarnings,
    URLBatchInputPayload,
)
from iocparser.cli_processing_url_reports import (
    BatchItemReport,
    BatchReport,
    _group_failures,
    _item_url,
    _json_dict,
    _report_item,
    _report_items,
    _set_batch_item_int,
    build_batch_report,
    int_value,
    public_batch_report,
)
from iocparser.domain.models import FailedBatchItem
from iocparser.errors import FileExistenceError, ValidationError
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
from iocparser.interfaces.ports import TextSourceReader, URLDownloader, WarningListService
from iocparser.pipeline_errors import classify_pipeline_exception

BatchResults = BatchResultsCollection

__all__ = [
    "BatchItemReport",
    "BatchReport",
    "BatchResults",
    "_failed_urls_from_report",
    "_group_failures",
    "_int_value",
    "_item_url",
    "_json_dict",
    "_report_item",
    "_report_items",
    "_retry_attempt_for_url",
    "_retry_attempt_from_batch",
    "_set_batch_item_int",
    "build_batch_report",
    "int_value",
    "load_batch_urls",
    "process_url_file_input",
    "process_url_file_input_with_report",
    "process_url_file_payload",
    "public_batch_report",
    "record_failed_url",
    "retry_attempt_for_url",
]


class FailedBatchLookupService(Protocol):
    def list_failed_batch_items(self, *, batch_job_id: int) -> list[FailedBatchItem]: ...


def failed_batch_lookup_service(db_uri: str) -> FailedBatchLookupService:
    return SQLAlchemyPersistenceService(db_uri)


def _failed_urls_from_report(
    report_path: Path,
    *,
    error_type_filter: str | None = None,
    error_substring: str | None = None,
) -> list[str]:
    if not report_path.is_file():
        raise FileExistenceError(str(report_path))
    payload = _json_dict(report_path)
    if not payload:
        raise _invalid_batch_report(report_path)
    raw_items = payload.get("items")
    if raw_items is not None and not isinstance(raw_items, list):
        raise _invalid_batch_report_items(report_path)
    urls = [
        str(item.get("url", "")).strip()
        for item in _report_items(payload)
        if str(item.get("status", "")).lower() == "failed"
        and str(item.get("url", "")).strip()
        and (
            error_type_filter is None
            or str(item.get("error_type", "")).lower() == error_type_filter.lower()
        )
        and (
            error_substring is None or error_substring.lower() in str(item.get("error", "")).lower()
        )
    ]
    if not urls:
        raise _no_failed_urls_in_report(report_path)
    return urls


def _failed_urls_from_batch(
    db_uri: str,
    *,
    batch_job_id: int,
    error_type_filter: str | None = None,
    error_substring: str | None = None,
) -> list[str]:
    service = failed_batch_lookup_service(db_uri)
    urls = [
        item.source_value
        for item in service.list_failed_batch_items(batch_job_id=batch_job_id)
        if (error_type_filter is None or item.error_type.lower() == error_type_filter.lower())
        and (error_substring is None or error_substring.lower() in item.error_message.lower())
    ]
    if not urls:
        raise _no_failed_urls_for_batch_job(batch_job_id)
    return urls


def _retry_attempt_from_report(
    url: str, retry_report: str | None, *, occurrence: int
) -> int | None:
    if not retry_report:
        return None
    matches = [
        item
        for item in _report_items(_json_dict(Path(retry_report)))
        if str(item.get("url", "")).strip() == url
    ]
    if 0 < occurrence <= len(matches):
        return int_value(matches[occurrence - 1].get("retry_attempt", 0)) + 1
    if matches:
        return 1
    return None


def _retry_attempt_from_batch(
    db_uri: str | None,
    *,
    batch_job_id: int | None,
    url: str,
    occurrence: int,
) -> int | None:
    if not db_uri or batch_job_id is None:
        return None
    service = failed_batch_lookup_service(db_uri)
    matches = [
        item
        for item in service.list_failed_batch_items(batch_job_id=batch_job_id)
        if item.source_value == url
    ]
    if 0 < occurrence <= len(matches):
        return matches[occurrence - 1].retry_attempt + 1
    if matches:
        return 1
    return None


def retry_attempt_for_url(
    url: str,
    retry_report: str | None,
    *,
    retry_batch_job: int | None = None,
    db_uri: str | None = None,
    occurrence: int = 1,
) -> int:
    retry_attempt = _retry_attempt_from_report(url, retry_report, occurrence=occurrence)
    if retry_attempt is not None:
        return retry_attempt
    retry_attempt = _retry_attempt_from_batch(
        db_uri,
        batch_job_id=retry_batch_job,
        url=url,
        occurrence=occurrence,
    )
    if retry_attempt is not None:
        return retry_attempt
    return 0


def _load_batch_urls(
    args: argparse.Namespace,
    *,
    retry_report: str | None,
    retry_batch_job: int | None,
    db_uri: str | None,
) -> tuple[list[str], str, int]:
    input_load_started = time.perf_counter()
    if retry_report:
        urls = _failed_urls_from_report(
            Path(retry_report),
            error_type_filter=get_optional_str_arg(args, "retry_error_type"),
            error_substring=get_optional_str_arg(args, "retry_error_contains"),
        )
        input_label = "retried URLs"
    elif retry_batch_job is not None:
        if not db_uri:
            raise _retry_batch_requires_persistence()
        urls = _failed_urls_from_batch(
            db_uri,
            batch_job_id=int(retry_batch_job),
            error_type_filter=get_optional_str_arg(args, "retry_error_type"),
            error_substring=get_optional_str_arg(args, "retry_error_contains"),
        )
        input_label = f"retried batch {retry_batch_job}"
    else:
        url_file = Path(get_optional_str_arg(args, "url_file") or "")
        if not url_file.is_file():
            raise FileExistenceError(str(url_file))
        urls = [
            raw_url.strip()
            for raw_url in url_file.read_text(encoding="utf-8").splitlines()
            if raw_url.strip() and not raw_url.strip().startswith("#")
        ]
        input_label = "URLs"
    input_load_ms = int((time.perf_counter() - input_load_started) * 1000)
    return urls, input_label, input_load_ms


def _record_failed_url(
    item_key: str,
    input_index: int,
    url: str,
    exc: Exception,
    *,
    occurrence: int,
    retry_report: str | None,
    retry_batch_job: int | None,
    db_uri: str | None,
    failures: dict[str, str],
    run_metadata_map: dict[str, dict[str, int | str]],
    item_reports: list[BatchItemReport],
) -> None:
    classified = classify_pipeline_exception(exc)
    failures[item_key] = str(exc)
    run_metadata_map[item_key] = {
        "duration_ms": 0,
        "processed_items": 1,
        "successful_items": 0,
        "failed_items": 1,
        "partial_error_count": 1,
        "status": "failed",
        "error_message": str(exc),
    }
    item_reports.append(
        {
            "item_key": item_key,
            "input_index": input_index,
            "url": url,
            "status": "failed",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "error_code": classified.code,
            "error_category": classified.category,
            "retryable": classified.retryable,
            "retry_attempt": retry_attempt_for_url(
                url,
                retry_report,
                retry_batch_job=retry_batch_job,
                db_uri=db_uri,
                occurrence=occurrence,
            ),
        },
    )


def _invalid_batch_report(report_path: Path) -> ValidationError:
    return ValidationError(f"Invalid batch report: {report_path}")


def _invalid_batch_report_items(report_path: Path) -> ValidationError:
    return ValidationError(f"Invalid batch report items: {report_path}")


def _no_failed_urls_for_batch_job(batch_job_id: int) -> ValidationError:
    return ValidationError(f"No failed URLs found for batch job: {batch_job_id}")


def _no_failed_urls_in_report(report_path: Path) -> ValidationError:
    return ValidationError(f"No failed URLs found in batch report: {report_path}")


def _retry_batch_requires_persistence() -> ValidationError:
    return ValidationError("retry-batch-job requires configured persistence")


_int_value = int_value
load_batch_urls = _load_batch_urls
_build_batch_report = build_batch_report
record_failed_url = _record_failed_url
_retry_attempt_for_url = retry_attempt_for_url
PluginClient = _execution.PluginClient
_extractor_engine = _execution.extractor_engine
_temporary_resource_cleaner = _execution.temporary_resource_cleaner
_joined_type_filters = _execution.joined_type_filters
_plugin_client = _execution.plugin_client
_process_url = _execution.process_url


def process_url_file_input(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    downloader: URLDownloader,
    db_uri: str | None = None,
) -> tuple[GroupedIocs, GroupedWarnings, str, BatchResults]:
    payload = process_url_file_payload(
        args,
        reader=reader,
        warning_service=warning_service,
        downloader=downloader,
        db_uri=db_uri,
    )
    return payload.normal_iocs, payload.warning_iocs, payload.input_display, payload.results


def process_url_file_input_with_report(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    downloader: URLDownloader,
    db_uri: str | None = None,
) -> tuple[GroupedIocs, GroupedWarnings, str, BatchResults, BatchReport]:
    payload = process_url_file_payload(
        args,
        reader=reader,
        warning_service=warning_service,
        downloader=downloader,
        db_uri=db_uri,
    )
    return (
        payload.normal_iocs,
        payload.warning_iocs,
        payload.input_display,
        payload.results,
        cast("BatchReport", payload.batch_report),
    )


def process_url_file_payload(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    downloader: URLDownloader,
    db_uri: str | None = None,
) -> URLBatchInputPayload:
    from iocparser import cli_url_batch_workflow as _workflow

    normal_iocs, warning_iocs, input_display, results, report = _workflow.run_url_batch_workflow(
        _workflow.URLBatchWorkflowRequest(
            args=args,
            reader=reader,
            warning_service=warning_service,
            downloader=downloader,
            db_uri=db_uri,
        ),
    )
    return URLBatchInputPayload(
        normal_iocs=normal_iocs,
        warning_iocs=warning_iocs,
        input_display=input_display,
        results=results,
        batch_report=report,
    )
