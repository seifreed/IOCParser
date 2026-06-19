from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from iocparser import cli_args as _cli_args
from iocparser import cli_output as _cli_output
from iocparser.api_persistence_query import validated_non_negative_int
from iocparser.application.contracts import ListFailedBatchesInput, RetainHistoryInput
from iocparser.application.maintenance_use_cases import (
    compact_persisted_history as uc_compact_persisted_history,
)
from iocparser.application.maintenance_use_cases import (
    export_persisted_history as uc_export_persisted_history,
)
from iocparser.application.maintenance_use_cases import (
    import_persisted_history as uc_import_persisted_history,
)
from iocparser.application.maintenance_use_cases import (
    list_failed_batch_jobs as uc_list_failed_batch_jobs,
)
from iocparser.application.maintenance_use_cases import (
    retain_persisted_history as uc_retain_persisted_history,
)
from iocparser.cli_persistence import query_service_for
from iocparser.config import AppConfig
from iocparser.errors import ValidationError
from iocparser.infrastructure.persistence import (
    migrate_db_uri,
    revision_history,
    schema_version,
    validate_schema,
)
from iocparser.interfaces.ports import FileWriter, PersistenceQueryService

__all__ = ["handle_schema_commands", "print_schema_revisions"]

PERSISTENCE_REQUIRED = "Persistence maintenance commands require --db-uri or configured persistence"
SCHEMA_VERSION_REQUIRED = "schema-version requires persistence configuration"
MIGRATE_REQUIRED = "migrate requires persistence configuration"
VALIDATE_REQUIRED = "validate-schema requires persistence configuration"
HISTORY_IMPORT_OBJECT_REQUIRED = "history import file must contain a JSON object"
HISTORY_FILE_NOT_FOUND = "History file not found: {path}"
HISTORY_FILE_UNREADABLE = "Could not read history file {path}: {error}"


def _query_service_for(config: AppConfig) -> PersistenceQueryService:
    return query_service_for(config, missing_message=PERSISTENCE_REQUIRED)


def _history_payload(path: str) -> dict[str, object]:
    # A missing/unreadable archive is user error (typo'd path, bad JSON); report it
    # cleanly rather than letting the raw OSError/JSONDecodeError reach the top-level
    # handler as an "unexpected error" stack trace.
    archive = Path(path)
    if not archive.is_file():
        raise ValidationError(HISTORY_FILE_NOT_FOUND.format(path=path))
    try:
        loaded: object = json.loads(archive.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(HISTORY_FILE_UNREADABLE.format(path=path, error=exc)) from exc
    if not isinstance(loaded, dict):
        raise ValidationError(HISTORY_IMPORT_OBJECT_REQUIRED)
    if not all(isinstance(key, str) for key in loaded):
        raise ValidationError(HISTORY_IMPORT_OBJECT_REQUIRED)
    return dict(loaded)


def _run_with_engine[T](db_uri: str, operation: Callable[[Engine], T]) -> T:
    engine = create_engine(db_uri, future=True)
    try:
        return operation(engine)
    finally:
        engine.dispose()


def _handle_schema_inspection(args: argparse.Namespace, db_uri: str | None) -> bool:
    if _cli_args.get_bool_arg(args, "schema_version"):
        if not db_uri:
            raise ValidationError(SCHEMA_VERSION_REQUIRED)
        value = _run_with_engine(db_uri, schema_version)
        _cli_output.print_status_line("schema_version", value)
        return True
    if _cli_args.get_bool_arg(args, "migrate"):
        if not db_uri:
            raise ValidationError(MIGRATE_REQUIRED)
        value = migrate_db_uri(db_uri)
        _cli_output.print_status_line("migrated_to", value)
        return True
    if not _cli_args.get_bool_arg(args, "validate_schema"):
        return False
    if not db_uri:
        raise ValidationError(VALIDATE_REQUIRED)
    problems = _run_with_engine(db_uri, validate_schema)
    _cli_output.print_status_line("schema_valid", "true" if not problems else "false")
    if problems:
        _cli_output.print_text_lines([f"  {problem}" for problem in problems])
    return True


def _handle_history_io(
    args: argparse.Namespace, config: AppConfig, *, file_writer: FileWriter
) -> bool:
    export_path = _cli_args.get_optional_str_arg(
        args, "export_history"
    ) or _cli_args.get_optional_str_arg(args, "archive_history")
    if export_path:
        payload = uc_export_persisted_history(persistence_query_service=_query_service_for(config))
        content = json.dumps(payload, indent=2, sort_keys=True)
        if export_path == "-":
            _cli_output.print_text_lines([content])
        else:
            file_writer.write(export_path, content)
            _cli_output.print_status_line("history_exported", export_path)
        return True
    import_path = _cli_args.get_optional_str_arg(
        args, "import_history"
    ) or _cli_args.get_optional_str_arg(args, "restore_history")
    if not import_path:
        return False
    imported = uc_import_persisted_history(
        _history_payload(import_path), persistence_query_service=_query_service_for(config)
    )
    # import_history returns newly-inserted row counts keyed per table (runs, iocs,
    # sources, ...); report them verbatim. The previous code read "imported"/"skipped"
    # keys the use case never emits, so it always printed {"imported": 0, "skipped": 0}
    # even when rows were actually inserted.
    _cli_output.print_json_payload(dict(imported))
    return True


def _handle_history_maintenance(args: argparse.Namespace, config: AppConfig) -> bool:
    if _cli_args.get_bool_arg(args, "compact_history"):
        uc_compact_persisted_history(persistence_query_service=_query_service_for(config))
        _cli_output.print_status_line("history_compacted", "true")
        return True
    retain_days = _cli_args.namespace_value(args, "retain_days")
    if retain_days is not None:
        deleted = uc_retain_persisted_history(
            RetainHistoryInput(
                days=_cli_args.int_arg_value(retain_days, "retain-days"),
                statuses=_cli_args.parse_string_filters(
                    _cli_args.namespace_value(args, "prune_status")
                ),
            ),
            persistence_query_service=_query_service_for(config),
        )
        _cli_output.print_maintenance_result("retain_history", deleted)
        return True
    if not _cli_args.get_bool_arg(args, "list_failed_batches"):
        return False
    jobs = uc_list_failed_batch_jobs(
        ListFailedBatchesInput(
            limit=validated_non_negative_int(
                _cli_args.validated_int_arg(args, "batch_limit", 20), field="limit"
            )
        ),
        persistence_query_service=_query_service_for(config),
    )
    if _cli_args.get_bool_arg(args, "json"):
        _cli_output.print_json_payload({"items": [job.to_record() for job in jobs]})
    else:
        _cli_output.print_failed_batch_jobs(jobs)
    return True


def print_schema_revisions() -> None:
    _cli_output.print_text_lines(
        [
            f"{revision.version}\t{revision.name}\t{revision.description}"
            for revision in revision_history()
        ],
    )


def handle_schema_commands(
    args: argparse.Namespace, config: AppConfig, *, file_writer: FileWriter
) -> bool:
    """Handle schema and history maintenance CLI commands."""
    db_uri = config.db_uri
    return (
        _handle_schema_inspection(args, db_uri)
        or _handle_history_io(args, config, file_writer=file_writer)
        or _handle_history_maintenance(args, config)
    )
