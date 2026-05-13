from __future__ import annotations

import argparse
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import cast

from iocparser import cli_args as _cli_args
from iocparser import cli_output as _cli_output
from iocparser import cli_persistence as _cli_persistence
from iocparser import cli_processing as _cli_processing
from iocparser import cli_queries as _cli_queries
from iocparser import cli_runtime as _cli_runtime
from iocparser import cli_schema as _cli_schema
from iocparser.cli_processing_support import BatchResultsCollection, GroupedIocs, GroupedWarnings
from iocparser.cli_processing_urls import BatchReport as URLBatchReport
from iocparser.cli_processing_urls import public_batch_report as _public_batch_report
from iocparser.config import AppConfig
from iocparser.domain.models import PersistOptions
from iocparser.plugins import (
    custom_ioc_types,
    enricher_names,
    extractor_names,
    ioc_type_plugin_names,
    postprocessor_names,
    renderer_names,
)

BatchResults = BatchResultsCollection


@dataclass(frozen=True)
class ResolvedInputPayload:
    normal_iocs: GroupedIocs
    warning_iocs: GroupedWarnings
    input_display: str
    results: BatchResults | None = None
    batch_report: URLBatchReport | None = None


def plugin_listing_payload() -> Mapping[str, object]:
    return {
        "renderers": list(renderer_names()),
        "enrichers": list(enricher_names()),
        "extractors": list(extractor_names()),
        "postprocessors": list(postprocessor_names()),
        "ioc_type_plugins": list(ioc_type_plugin_names()),
        "custom_ioc_types": list(custom_ioc_types()),
    }


def resolve_input_payload(
    args: argparse.Namespace,
    *,
    config: AppConfig | None = None,
    process_multiple_files_input: Callable[
        [argparse.Namespace], tuple[GroupedIocs, GroupedWarnings, str, BatchResults]
    ],
    process_single_input: Callable[[argparse.Namespace], tuple[GroupedIocs, GroupedWarnings, str]],
) -> ResolvedInputPayload:
    values = cast("Mapping[str, object]", vars(args))
    if _cli_args.get_list_arg(args, "multiple"):
        multi = process_multiple_files_input(args)
        return ResolvedInputPayload(multi[0], multi[1], multi[2], results=multi[3])
    if _cli_args.get_optional_str_arg(args, "directory"):
        dir_result = _cli_processing.process_directory_input(
            args,
            reader=_cli_runtime.reader,
            warning_service=_cli_runtime.warning_service_for_args(args),
        )
        return ResolvedInputPayload(
            dir_result[0], dir_result[1], dir_result[2], results=dir_result[3]
        )
    if (
        _cli_args.get_optional_str_arg(args, "url_file")
        or _cli_args.get_optional_str_arg(args, "retry_failed_from")
        or values.get("retry_batch_job") is not None
    ):
        url_result = _cli_processing.process_url_file_input_with_report(
            args,
            reader=_cli_runtime.reader,
            warning_service=_cli_runtime.warning_service_for_args(args),
            downloader=_cli_runtime.downloader_for_args(args),
            db_uri=config.db_uri if config is not None else None,
        )
        return ResolvedInputPayload(
            url_result[0],
            url_result[1],
            url_result[2],
            results=url_result[3],
            batch_report=url_result[4],
        )
    single = process_single_input(args)
    return ResolvedInputPayload(single[0], single[1], single[2])


def persist_batch_results(
    args: argparse.Namespace,
    config: AppConfig,
    persist_options: PersistOptions,
    results: BatchResults,
    batch_report: URLBatchReport | None,
) -> None:
    source_kind = _batch_source_kind_for_args(args)
    persist_started = time.perf_counter()
    if batch_report is None:
        _cli_persistence.persist_many_results(
            results,
            config=config,
            options=persist_options,
            source_kind=source_kind,
        )
        return
    persisted_run_ids = (
        _cli_persistence.persist_many_results(
            results,
            config=config,
            options=persist_options,
            source_kind=source_kind,
            source_metadata_map=batch_report.get("source_metadata_map"),
            run_metadata_map=batch_report.get("run_metadata_map"),
        )
        or ()
    )
    failed_run_ids = (
        _cli_persistence.persist_failed_batch_items(
            batch_report,
            config=config,
            options=persist_options,
            source_kind="url",
        )
        or ()
    )
    phase_timings = batch_report.get("phase_timings_ms", {})
    phase_timings["persistence"] = int((time.perf_counter() - persist_started) * 1000)
    _cli_persistence.persist_batch_job(
        batch_report,
        config=config,
        source_kind=source_kind,
        run_ids=persisted_run_ids + failed_run_ids,
        effective_config=effective_batch_config(args),
    )


def effective_batch_config(args: argparse.Namespace) -> dict[str, object]:
    values = cast("Mapping[str, object]", vars(args))
    return {
        "url_workers": values.get("url_workers"),
        "url_retries": values.get("url_retries"),
        "url_backoff": values.get("url_backoff"),
        "rate_limit": values.get("rate_limit"),
        "retry_failed_from": values.get("retry_failed_from"),
    }


def handle_preprocessing_commands(
    args: argparse.Namespace,
    *,
    config: AppConfig,
    handle_misp_init: Callable[[], None],
) -> bool:
    if _cli_args.get_bool_arg(args, "list_plugins"):
        _cli_output.print_json_payload(dict(plugin_listing_payload()))
        return True
    if _cli_args.get_bool_arg(args, "init") or (
        _cli_args.get_bool_arg(args, "force_update") and not _cli_args.has_input_args(args)
    ):
        handle_misp_init()
        return True
    if _cli_schema.handle_schema_commands(args, config, file_writer=_cli_runtime.file_writer):
        return True
    if _cli_queries.handle_query_commands(args, config, file_writer=_cli_runtime.file_writer):
        return True
    return False


def finalize_cli_run(
    args: argparse.Namespace,
    *,
    config: AppConfig,
    workflow_started: float,
    normal_iocs: GroupedIocs,
    warning_iocs: GroupedWarnings,
    input_display: str,
    results: BatchResults | None,
    batch_report: URLBatchReport | None,
    save_output: Callable[[argparse.Namespace, GroupedIocs, GroupedWarnings, str], None],
) -> None:
    _cli_output.display_results(normal_iocs, warning_iocs)
    save_output(args, normal_iocs, warning_iocs, input_display)

    persist_options = _cli_persistence.build_persist_options(args)
    if batch_report is not None:
        persist_batch_results(
            args, config, persist_options, results or BatchResultsCollection(), batch_report
        )
        public_report = _public_batch_report(batch_report)
        _cli_output.print_batch_report(public_report)
        _cli_output.save_batch_report(
            public_report,
            _cli_args.get_optional_str_arg(args, "batch_report_json"),
            file_writer=_cli_runtime.file_writer,
        )
        return
    if results:
        persist_batch_results(args, config, persist_options, results, batch_report)
        return

    _cli_output.persist_results(
        _cli_output.PersistResultsRequest(
            config=config,
            source_kind=_source_kind_for_args(args),
            source_value=input_display,
            normal_iocs=normal_iocs,
            warning_iocs=warning_iocs,
            options=persist_options,
            tool_version=_cli_args.VERSION,
            run_metadata={"duration_ms": int((time.perf_counter() - workflow_started) * 1000)},
        ),
    )


def _source_kind_for_args(args: argparse.Namespace) -> str:
    if _cli_args.get_bool_arg(args, "stdin"):
        return "text"
    if (
        _cli_args.get_optional_str_arg(args, "url")
        or _cli_args.get_optional_str_arg(args, "url_direct")
        or _batch_source_kind_for_args(args) == "url"
    ):
        return "url"
    return "file"


def _batch_source_kind_for_args(args: argparse.Namespace) -> str:
    if (
        _cli_args.get_optional_str_arg(args, "url_file")
        or _cli_args.get_optional_str_arg(args, "retry_failed_from")
        or getattr(args, "retry_batch_job", None) is not None
    ):
        return "url"
    return "file"
