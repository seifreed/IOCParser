from __future__ import annotations

import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import TYPE_CHECKING

from iocparser import cli_processing_urls_execution as _execution
from iocparser.cli_args import ProcessingOptions, get_int_arg, get_optional_str_arg
from iocparser.cli_processing_files import merge_batch_results
from iocparser.cli_processing_support import (
    BatchResultsCollection,
    GroupedIocs,
    GroupedWarnings,
    batch_item_keys,
)
from iocparser.domain.options import ExtractionOptions
from iocparser.interfaces.ports import TextSourceReader, URLDownloader, WarningListService

if TYPE_CHECKING:
    from iocparser.cli_processing_urls import BatchItemReport, BatchReport
else:
    BatchItemReport = dict[str, object]
    BatchReport = dict[str, object]

BatchResults = BatchResultsCollection


@dataclass(frozen=True)
class URLBatchWorkflowRequest:
    args: argparse.Namespace
    reader: TextSourceReader
    warning_service: WarningListService | None
    downloader: URLDownloader
    db_uri: str | None = None


@dataclass
class URLBatchWorkflowState:
    results: BatchResults
    source_metadata_map: dict[str, dict[str, object]]
    run_metadata_map: dict[str, dict[str, int | str]]
    failures: dict[str, str]
    item_reports: list[BatchItemReport]


def run_url_batch_workflow(
    request: URLBatchWorkflowRequest,
) -> tuple[GroupedIocs, GroupedWarnings, str, BatchResults, BatchReport]:
    from iocparser import cli_processing_urls as _support

    batch_started = time.perf_counter()
    batch_started_wall = time.time()
    retry_report = get_optional_str_arg(request.args, "retry_failed_from")
    retry_batch_job_value: object = getattr(request.args, "retry_batch_job", None)
    retry_batch_job = (
        _support.int_value(retry_batch_job_value) if retry_batch_job_value is not None else None
    )
    job_id = (
        get_optional_str_arg(request.args, "job_id")
        or f"url-batch-{int(batch_started_wall * 1000)}"
    )
    correlation_id = get_optional_str_arg(request.args, "correlation_id") or job_id
    urls, input_label, input_load_ms = _support.load_batch_urls(
        request.args,
        retry_report=retry_report,
        retry_batch_job=retry_batch_job,
        db_uri=request.db_uri,
    )
    options = ProcessingOptions.from_args(request.args).to_domain()
    configured_plugin_client = _execution.plugin_client(
        args=request.args,
        reader=request.reader,
        downloader=request.downloader,
        warning_service=request.warning_service,
    )
    state = URLBatchWorkflowState(
        results=BatchResultsCollection(),
        source_metadata_map={},
        run_metadata_map={},
        failures={},
        item_reports=[],
    )
    _collect_url_results(
        request,
        url_items=batch_item_keys(urls),
        options=options,
        retry_report=retry_report,
        retry_batch_job=retry_batch_job,
        configured_plugin_client=configured_plugin_client,
        state=state,
    )
    merged = merge_batch_results(state.results)
    report = _support.build_batch_report(
        {
            "urls": urls,
            "results": state.results,
            "failures": state.failures,
            "item_reports": state.item_reports,
            "source_metadata_map": state.source_metadata_map,
            "run_metadata_map": state.run_metadata_map,
            "job_id": job_id,
            "correlation_id": correlation_id,
            "input_load_ms": input_load_ms,
            "batch_started": batch_started,
            "batch_started_wall": batch_started_wall,
        },
    )
    display_label = f"{len(urls)} {input_label}"
    return merged.grouped_iocs(), merged.grouped_warnings(), display_label, state.results, report


def _collect_url_results(
    request: URLBatchWorkflowRequest,
    *,
    url_items: list[tuple[str, str]],
    options: ExtractionOptions,
    retry_report: str | None,
    retry_batch_job: int | None,
    configured_plugin_client: _execution.PluginClient | None,
    state: URLBatchWorkflowState,
) -> None:
    from iocparser import cli_processing_urls as _support

    max_workers = max(1, get_int_arg(request.args, "url_workers", 4))
    retry_error_type = get_optional_str_arg(request.args, "retry_error_type")
    retry_error_contains = get_optional_str_arg(request.args, "retry_error_contains")
    url_occurrences: dict[str, int] = {}
    item_occurrences: dict[str, int] = {}
    item_indexes: dict[str, int] = {}
    for input_index, (item_key, url) in enumerate(url_items, start=1):
        url_occurrences[url] = url_occurrences.get(url, 0) + 1
        item_occurrences[item_key] = url_occurrences[url]
        item_indexes[item_key] = input_index
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                _execution.process_url,
                url,
                options=options,
                reader=request.reader,
                warning_service=request.warning_service,
                downloader=request.downloader,
                configured_plugin_client=configured_plugin_client,
            ): (item_key, url)
            for item_key, url in url_items
        }
        for future in as_completed(future_map):
            item_key, url = future_map[future]
            occurrence = item_occurrences[item_key]
            try:
                _, result, metadata, duration_ms = future.result()
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                _support.record_failed_url(
                    item_key,
                    item_indexes[item_key],
                    url,
                    exc,
                    occurrence=occurrence,
                    retry_report=retry_report,
                    retry_batch_job=retry_batch_job,
                    db_uri=request.db_uri,
                    retry_error_type=retry_error_type,
                    retry_error_contains=retry_error_contains,
                    failures=state.failures,
                    run_metadata_map=state.run_metadata_map,
                    item_reports=state.item_reports,
                )
                continue
            state.results.add(
                item_key=item_key,
                source_value=url,
                normal_iocs=result.grouped_iocs(),
                warning_iocs=result.grouped_warnings(),
                result=result,
            )
            state.item_reports.append(
                {
                    "item_key": item_key,
                    "input_index": item_indexes[item_key],
                    "url": url,
                    "status": "ok",
                    "duration_ms": duration_ms,
                    "normal_ioc_count": len(result.iocs),
                    "warning_ioc_count": len(result.warnings),
                    "metadata": metadata,
                    "retry_attempt": _support.retry_attempt_for_url(
                        url,
                        retry_report,
                        retry_batch_job=retry_batch_job,
                        db_uri=request.db_uri,
                        occurrence=occurrence,
                        error_type_filter=retry_error_type,
                        error_substring=retry_error_contains,
                    ),
                },
            )
            state.run_metadata_map[item_key] = {
                "duration_ms": duration_ms,
                "processed_items": 1,
                "successful_items": 1,
                "failed_items": 0,
                "partial_error_count": 0,
                "status": "success",
                "error_message": "",
            }
            state.source_metadata_map[item_key] = (
                {**metadata, "input_value": url} if metadata else {"input_value": url}
            )
