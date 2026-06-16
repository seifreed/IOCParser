from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import NoReturn

from iocparser import cli_args as _cli_args
from iocparser import cli_output as _cli_output
from iocparser.api_persistence_query import (
    validated_ioc_type_filter,
    validated_ioc_type_filters,
    validated_iso_datetime,
    validated_non_negative_int,
)
from iocparser.application.contracts import (
    BatchJobInput,
    DeletePersistedRunInput,
    DiffLatestSourceRunInput,
    DiffPersistedRunsInput,
    ExportPersistedRunInput,
    ListBatchJobsInput,
    PrunePersistedRunsInput,
    QueryRunsInput,
    SearchPersistedIOCsInput,
)
from iocparser.application.query_use_cases import (
    delete_persisted_run as uc_delete_persisted_run,
)
from iocparser.application.query_use_cases import (
    diff_latest_source_run as uc_diff_latest_source_run,
)
from iocparser.application.query_use_cases import (
    diff_persisted_runs as uc_diff_persisted_runs,
)
from iocparser.application.query_use_cases import (
    export_persisted_run as uc_export_persisted_run,
)
from iocparser.application.query_use_cases import (
    get_batch_job as uc_get_batch_job,
)
from iocparser.application.query_use_cases import (
    list_batch_jobs as uc_list_batch_jobs,
)
from iocparser.application.query_use_cases import (
    list_batch_runs as uc_list_batch_runs,
)
from iocparser.application.query_use_cases import (
    prune_persisted_runs as uc_prune_persisted_runs,
)
from iocparser.application.query_use_cases import (
    query_runs as uc_query_runs,
)
from iocparser.application.query_use_cases import (
    search_persisted_iocs as uc_search_persisted_iocs,
)
from iocparser.cli_persistence import query_service_for
from iocparser.config import AppConfig
from iocparser.errors import ValidationError
from iocparser.interfaces.ports import FileWriter, PersistenceQueryService
from iocparser.shared_utils import validated_severity_filters

PERSISTENCE_QUERY_MESSAGE = "Persistence query commands require --db-uri or configured persistence"
BATCH_JOB_NOT_FOUND = "Batch job not found"
INVALID_KEEP_LATEST_ERROR = "Invalid --keep-latest: {value} (must be >= 0)"


def _query_service_for(config: AppConfig) -> PersistenceQueryService:
    return query_service_for(config, missing_message=PERSISTENCE_QUERY_MESSAGE)


def _optional_int_attr(args: argparse.Namespace, field_name: str) -> int | None:
    raw_value = _cli_args.namespace_value(args, field_name)
    if raw_value is None:
        return None
    return _cli_args.int_arg_value(raw_value, field_name)


def _string_filters_attr(args: argparse.Namespace, field_name: str) -> tuple[str, ...]:
    return _cli_args.parse_string_filters(_cli_args.namespace_value(args, field_name))


def _validated_limit(args: argparse.Namespace, name: str, default: int, *, field: str) -> int:
    # Reject negatives, matching the programmatic API (the CLI used to clamp to 0).
    return validated_non_negative_int(_cli_args.get_int_arg(args, name, default), field=field)


def _diff_run_ids(args: argparse.Namespace) -> tuple[int, int] | None:
    raw_value = _cli_args.namespace_value(args, "diff_runs")
    if not isinstance(raw_value, (list, tuple)) or len(raw_value) != 2:
        return None
    return (
        _cli_args.int_arg_value(raw_value[0], "diff-runs"),
        _cli_args.int_arg_value(raw_value[1], "diff-runs"),
    )


def _raise_batch_job_not_found() -> NoReturn:
    raise ValidationError(BATCH_JOB_NOT_FOUND)


def _emit_query_result(
    args: argparse.Namespace,
    *,
    json_payload: dict[str, object],
    render_text: Callable[[], None],
) -> None:
    if _cli_args.get_bool_arg(args, "json"):
        _cli_output.print_json_payload(json_payload)
    else:
        render_text()


def _handle_list_runs(args: argparse.Namespace, config: AppConfig) -> bool:
    if not _cli_args.get_bool_arg(args, "list_runs"):
        return False
    runs = uc_query_runs(
        QueryRunsInput(
            limit=_validated_limit(args, "run_limit", 20, field="limit"),
            offset=_validated_limit(args, "offset", 0, field="offset"),
            date_from=_cli_args.get_optional_str_arg(args, "date_from"),
            date_to=_cli_args.get_optional_str_arg(args, "date_to"),
            source_kind=_cli_args.get_optional_str_arg(args, "source_kind"),
            source_value=_cli_args.get_optional_str_arg(args, "source_value"),
            sort_by=_cli_args.get_optional_str_arg(args, "query_sort") or "newest",
        ),
        persistence_query_service=_query_service_for(config),
    )
    _emit_query_result(
        args,
        json_payload={"items": [run.to_record() for run in runs]},
        render_text=lambda: _cli_output.print_run_summaries(runs),
    )
    return True


def _handle_search_ioc(args: argparse.Namespace, config: AppConfig) -> bool:
    search_value = _cli_args.get_optional_str_arg(args, "search_ioc")
    if not search_value:
        return False
    hits = uc_search_persisted_iocs(
        SearchPersistedIOCsInput(
            value=search_value,
            limit=_validated_limit(args, "query_limit", 50, field="limit"),
            offset=_validated_limit(args, "offset", 0, field="offset"),
            date_from=_cli_args.get_optional_str_arg(args, "date_from"),
            date_to=_cli_args.get_optional_str_arg(args, "date_to"),
            source_kind=_cli_args.get_optional_str_arg(args, "source_kind"),
            source_value=_cli_args.get_optional_str_arg(args, "source_value"),
            ioc_type=validated_ioc_type_filter(_cli_args.get_optional_str_arg(args, "ioc_type")),
            severity=validated_severity_filters(_cli_args.get_optional_str_arg(args, "severity")),
            tags=_string_filters_attr(args, "tag"),
            exclude_tags=_string_filters_attr(args, "exclude_tag"),
            min_severity=_cli_args.get_optional_str_arg(args, "min_severity"),
            tag_mode=_cli_args.get_optional_str_arg(args, "tag_mode") or "all",
            sort_by=_cli_args.get_optional_str_arg(args, "query_sort") or "newest",
            search_backend=_cli_args.get_optional_str_arg(args, "search_backend") or "auto",
        ),
        persistence_query_service=_query_service_for(config),
    )
    _emit_query_result(
        args,
        json_payload={"items": [hit.to_record() for hit in hits]},
        render_text=lambda: _cli_output.print_query_hits(hits),
    )
    return True


def _handle_diff_runs(
    args: argparse.Namespace, config: AppConfig, *, file_writer: FileWriter
) -> bool:
    current_diff_run_ids = _diff_run_ids(args)
    if current_diff_run_ids is None:
        return False
    diff = uc_diff_persisted_runs(
        DiffPersistedRunsInput(
            left_run_id=current_diff_run_ids[0],
            right_run_id=current_diff_run_ids[1],
            only_added=_cli_args.get_optional_str_arg(args, "diff_only") == "added",
            only_removed=_cli_args.get_optional_str_arg(args, "diff_only") == "removed",
            only_warnings=_cli_args.get_bool_arg(args, "diff_warnings_only"),
            only_normal=_cli_args.get_bool_arg(args, "only_normal"),
            ioc_types=validated_ioc_type_filters(_cli_args.get_optional_str_arg(args, "ioc_type")),
            severity=validated_severity_filters(_cli_args.namespace_value(args, "severity")),
            tags=_string_filters_attr(args, "tag"),
        ),
        persistence_query_service=_query_service_for(config),
    )
    _cli_output.save_diff_output(args, diff, file_writer=file_writer)
    return True


def _handle_diff_latest(
    args: argparse.Namespace, config: AppConfig, *, file_writer: FileWriter
) -> bool:
    diff_latest_run_id = _optional_int_attr(args, "diff_latest")
    if diff_latest_run_id is None:
        return False
    diff = uc_diff_latest_source_run(
        DiffLatestSourceRunInput(
            run_id=diff_latest_run_id,
            only_added=_cli_args.get_optional_str_arg(args, "diff_only") == "added",
            only_removed=_cli_args.get_optional_str_arg(args, "diff_only") == "removed",
            only_warnings=_cli_args.get_bool_arg(args, "diff_warnings_only"),
            only_normal=_cli_args.get_bool_arg(args, "only_normal"),
            ioc_types=validated_ioc_type_filters(_cli_args.get_optional_str_arg(args, "ioc_type")),
            severity=validated_severity_filters(_cli_args.namespace_value(args, "severity")),
            tags=_string_filters_attr(args, "tag"),
        ),
        persistence_query_service=_query_service_for(config),
    )
    _cli_output.save_diff_output(args, diff, file_writer=file_writer)
    return True


def _handle_export_run(
    args: argparse.Namespace, config: AppConfig, *, file_writer: FileWriter
) -> bool:
    export_run_id = _optional_int_attr(args, "export_run")
    if export_run_id is None:
        return False
    export = uc_export_persisted_run(
        ExportPersistedRunInput(
            run_id=export_run_id,
            severity=validated_severity_filters(_cli_args.namespace_value(args, "severity")),
            tags=_string_filters_attr(args, "tag"),
            include_normal=not _cli_args.get_bool_arg(args, "only_warnings"),
            include_warnings=not _cli_args.get_bool_arg(args, "only_normal"),
            max_evidence=_optional_int_attr(args, "max_evidence"),
            sort_by=_cli_args.get_optional_str_arg(args, "sort_by") or "type",
        ),
        persistence_query_service=_query_service_for(config),
    )
    _cli_output.save_exported_run(args, export, file_writer=file_writer)
    return True


def _handle_list_batches(args: argparse.Namespace, config: AppConfig) -> bool:
    if not _cli_args.get_bool_arg(args, "list_batches"):
        return False
    jobs = uc_list_batch_jobs(
        ListBatchJobsInput(
            limit=_cli_args.get_int_arg(args, "batch_limit", 20),
            statuses=_string_filters_attr(args, "prune_status"),
        ),
        persistence_query_service=_query_service_for(config),
    )
    _emit_query_result(
        args,
        json_payload={"items": [job.to_record() for job in jobs]},
        render_text=lambda: _cli_output.print_failed_batch_jobs(jobs),
    )
    return True


def _handle_batch_job_detail(args: argparse.Namespace, config: AppConfig) -> bool:
    batch_job_id = _optional_int_attr(args, "batch_job")
    if batch_job_id is None:
        return False
    detail = uc_get_batch_job(
        BatchJobInput(batch_job_id=batch_job_id),
        persistence_query_service=_query_service_for(config),
    )
    if detail is None:
        _raise_batch_job_not_found()
    _emit_query_result(
        args,
        json_payload=detail.to_record(),
        render_text=lambda: _cli_output.print_batch_job_detail(detail),
    )
    return True


def _handle_batch_runs(args: argparse.Namespace, config: AppConfig) -> bool:
    batch_runs_id = _optional_int_attr(args, "batch_runs")
    if batch_runs_id is None:
        return False
    runs = uc_list_batch_runs(
        BatchJobInput(batch_job_id=batch_runs_id),
        persistence_query_service=_query_service_for(config),
    )
    _emit_query_result(
        args,
        json_payload={"items": [run.to_record() for run in runs]},
        render_text=lambda: _cli_output.print_run_summaries(runs),
    )
    return True


def _handle_delete_run(args: argparse.Namespace, config: AppConfig) -> bool:
    delete_run_id = _optional_int_attr(args, "delete_run")
    if delete_run_id is None:
        return False
    deleted = uc_delete_persisted_run(
        DeletePersistedRunInput(run_id=delete_run_id),
        persistence_query_service=_query_service_for(config),
    )
    _cli_output.print_maintenance_result("delete-run", 1 if deleted else 0)
    return True


def _handle_prune_runs(args: argparse.Namespace, config: AppConfig) -> bool:
    prune_before = validated_iso_datetime(
        _cli_args.get_optional_str_arg(args, "prune_before")
    )
    if prune_before is None:
        return False
    # A negative keep_latest folds to "keep none" downstream (delete every match).
    keep_latest = _cli_args.get_int_arg(args, "keep_latest", 0)
    if keep_latest < 0:
        raise ValidationError(INVALID_KEEP_LATEST_ERROR.format(value=keep_latest))
    deleted_count = uc_prune_persisted_runs(
        PrunePersistedRunsInput(
            before=prune_before,
            keep_latest=keep_latest,
            source_kind=_cli_args.get_optional_str_arg(args, "source_kind"),
            source_value=_cli_args.get_optional_str_arg(args, "source_value"),
            statuses=_string_filters_attr(args, "prune_status"),
        ),
        persistence_query_service=_query_service_for(config),
    )
    _cli_output.print_maintenance_result("prune-runs", deleted_count)
    return True


def handle_query_commands(
    args: argparse.Namespace,
    config: AppConfig,
    *,
    file_writer: FileWriter,
) -> bool:
    """Handle CLI persistence-query commands."""
    return (
        _handle_list_runs(args, config)
        or _handle_list_batches(args, config)
        or _handle_batch_job_detail(args, config)
        or _handle_batch_runs(args, config)
        or _handle_search_ioc(args, config)
        or _handle_diff_runs(args, config, file_writer=file_writer)
        or _handle_diff_latest(args, config, file_writer=file_writer)
        or _handle_export_run(args, config, file_writer=file_writer)
        or _handle_delete_run(args, config)
        or _handle_prune_runs(args, config)
    )
