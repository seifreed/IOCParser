from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass

from iocparser import cli_args as _cli_args
from iocparser import cli_output as _cli_output
from iocparser.cli_processing_support import BatchResultsCollection, GroupedIocs, GroupedWarnings
from iocparser.config import AppConfig
from iocparser.domain.models import PersistOptions
from iocparser.errors import ValidationError
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
from iocparser.interfaces.ports import PersistenceQueryService
from iocparser.shared_utils import normalize_metadata_values

VERSION = _cli_args.VERSION
get_bool_arg = _cli_args.get_bool_arg
BatchResults = BatchResultsCollection


def query_service_for(config: AppConfig, *, missing_message: str) -> PersistenceQueryService:
    db_uri = config.db_uri
    if not db_uri:
        raise ValidationError(missing_message)
    return SQLAlchemyPersistenceService(db_uri)


@dataclass(frozen=True)
class PersistResultsRequestData:
    config: AppConfig
    source_kind: str
    source_value: str
    normal_iocs: GroupedIocs
    warning_iocs: GroupedWarnings
    options: PersistOptions
    source_metadata: dict[str, object] | None = None
    run_metadata: dict[str, int | str | None] | None = None


def build_persist_options(args: argparse.Namespace) -> PersistOptions:
    if get_bool_arg(args, "stix"):
        output_format = "stix"
    elif get_bool_arg(args, "jsonl"):
        output_format = "jsonl"
    elif get_bool_arg(args, "csv"):
        output_format = "csv"
    elif get_bool_arg(args, "json"):
        output_format = "json"
    else:
        output_format = "text"
    return PersistOptions(
        defang=not get_bool_arg(args, "no_defang"),
        check_warnings=not get_bool_arg(args, "no_check_warnings"),
        force_update=get_bool_arg(args, "force_update"),
        output_format=output_format,
    )


def _normalized_run_metadata_map(
    run_metadata_map: dict[str, dict[str, int | str]]
    | dict[str, dict[str, int | str | None]]
    | None,
) -> dict[str, dict[str, int | str | None]] | None:
    if run_metadata_map is None:
        return None
    return {
        source_path: normalize_metadata_values(metadata)
        for source_path, metadata in run_metadata_map.items()
    }


def _persist_results_request(
    request: PersistResultsRequestData,
) -> _cli_output.PersistResultsRequest:
    return _cli_output.PersistResultsRequest(
        config=request.config,
        source_kind=request.source_kind,
        source_value=request.source_value,
        normal_iocs=request.normal_iocs,
        warning_iocs=request.warning_iocs,
        options=request.options,
        tool_version=VERSION,
        source_metadata=request.source_metadata,
        run_metadata=request.run_metadata,
    )


def persist_many_results(
    results: BatchResults,
    *,
    config: AppConfig,
    options: PersistOptions,
    source_kind: str = "file",
    source_metadata_map: dict[str, dict[str, object]] | None = None,
    run_metadata_map: dict[str, dict[str, int | str]]
    | dict[str, dict[str, int | str | None]]
    | None = None,
) -> tuple[int, ...]:
    normalized = _normalized_run_metadata_map(run_metadata_map)
    run_ids: list[int] = []
    for item_key, source_path, file_iocs, file_warnings, error_message in _batch_result_entries(
        results
    ):
        run_metadata = _batch_run_metadata(normalized, item_key, source_path)
        if error_message:
            run_metadata = dict(run_metadata or {})
            run_metadata["error_message"] = error_message
        run_id = _cli_output.persist_results(
            _persist_results_request(
                PersistResultsRequestData(
                    config=config,
                    source_kind=source_kind,
                    source_value=source_path,
                    normal_iocs=file_iocs,
                    warning_iocs=file_warnings,
                    options=options,
                    source_metadata=_batch_metadata(source_metadata_map, item_key),
                    run_metadata=run_metadata,
                )
            ),
        )
        if run_id is not None:
            run_ids.append(run_id)
    return tuple(run_ids)


def persist_failed_batch_items(
    report: Mapping[str, object],
    *,
    config: AppConfig,
    options: PersistOptions,
    source_kind: str = "url",
) -> tuple[int, ...]:
    items = report.get("items", [])
    if not isinstance(items, list):
        return ()
    run_metadata_map = report.get("run_metadata_map", {})
    if not isinstance(run_metadata_map, dict):
        run_metadata_map = {}
    run_ids: list[int] = []
    for item in items:
        if not isinstance(item, dict) or str(item.get("status", "")).lower() != "failed":
            continue
        raw_url = item.get("url")
        source_value = raw_url.strip() if isinstance(raw_url, str) else ""
        if not source_value:
            continue
        run_id = _cli_output.persist_results(
            _persist_results_request(
                PersistResultsRequestData(
                    config=config,
                    source_kind=source_kind,
                    source_value=source_value,
                    normal_iocs={},
                    warning_iocs={},
                    options=options,
                    run_metadata=_failed_item_run_metadata(item, run_metadata_map, source_value),
                )
            ),
        )
        if run_id is not None:
            run_ids.append(run_id)
    return tuple(run_ids)


def _batch_result_entries(
    results: BatchResults | dict[str, tuple[GroupedIocs, GroupedWarnings]],
) -> list[tuple[str, str, GroupedIocs, GroupedWarnings, str | None]]:
    if isinstance(results, dict):
        return [
            (item_key, item_key, normal_iocs, warning_iocs, None)
            for item_key, (normal_iocs, warning_iocs) in results.items()
        ]
    return [
        (
            entry.item_key,
            entry.source_value,
            entry.normal_iocs,
            entry.warning_iocs,
            entry.error_message,
        )
        for entry in results.entries
    ]


def _batch_metadata(
    source_metadata_map: dict[str, dict[str, object]] | None,
    item_key: str,
) -> dict[str, object] | None:
    if source_metadata_map is None:
        return None
    return source_metadata_map.get(item_key)


def _batch_run_metadata(
    run_metadata_map: dict[str, dict[str, int | str | None]] | None,
    item_key: str,
    source_value: str,
) -> dict[str, int | str | None] | None:
    if run_metadata_map is None:
        return None
    return run_metadata_map.get(item_key) or run_metadata_map.get(source_value)


def _failed_item_run_metadata(
    item: Mapping[str, object],
    run_metadata_map: Mapping[str, dict[str, int | str | None]] | None,
    source_value: str,
) -> dict[str, int | str | None]:
    item_key = str(item.get("item_key", "")).strip()
    fallback = None
    if run_metadata_map is not None:
        fallback = run_metadata_map.get(item_key) if item_key else None
        if fallback is None:
            fallback = run_metadata_map.get(source_value)
    return {
        "duration_ms": _cli_args.int_value(
            item.get("duration_ms"), default=fallback_int(fallback, "duration_ms", 0)
        ),
        "processed_items": 1,
        "successful_items": 0,
        "failed_items": 1,
        "partial_error_count": 1,
        "status": "failed",
        "error_message": fallback_str(item, "error", fallback_str(fallback, "error_message", "")),
    }


def fallback_int(metadata: Mapping[str, int | str | None] | None, key: str, default: int) -> int:
    if metadata is None:
        return default
    value = metadata.get(key)
    return _cli_args.int_value(value, default=default)


def fallback_str(metadata: Mapping[str, int | str | None] | None, key: str, default: str) -> str:
    if metadata is None:
        return default
    value = metadata.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise TypeError(f"Expected {key} to be string, got {type(value).__name__}")
    return value


def persist_batch_job(
    report: Mapping[str, object],
    *,
    config: AppConfig,
    source_kind: str,
    run_ids: tuple[int, ...],
    effective_config: Mapping[str, object],
) -> int | None:
    db_uri = config.db_uri
    if not config.persist or not db_uri:
        return None
    service = SQLAlchemyPersistenceService(db_uri)
    return service.persist_batch_job(
        source_kind=source_kind,
        run_ids=run_ids,
        report=dict(report),
        config=dict(effective_config),
    )


__all__ = [
    "VERSION",
    "BatchResults",
    "GroupedIocs",
    "GroupedWarnings",
    "build_persist_options",
    "get_bool_arg",
    "persist_batch_job",
    "persist_failed_batch_items",
    "persist_many_results",
    "query_service_for",
]
