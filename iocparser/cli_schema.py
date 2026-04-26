from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from sqlalchemy import create_engine

from iocparser import cli_args as _cli_args
from iocparser import cli_output as _cli_output
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
from iocparser.config import AppConfig
from iocparser.errors import ValidationError
from iocparser.infrastructure.persistence import (
    SQLAlchemyPersistenceService,
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
INTEGER_VALUE_REQUIRED = "{field_name} requires an integer value"
HISTORY_IMPORT_OBJECT_REQUIRED = "history import file must contain a JSON object"


def _query_service_for(config: AppConfig) -> PersistenceQueryService:
    db_uri = config.db_uri
    if not db_uri:
        raise ValidationError(PERSISTENCE_REQUIRED)
    return SQLAlchemyPersistenceService(db_uri)


def _int_arg_value(raw_value: object, field_name: str) -> int:
    if isinstance(raw_value, bool) or not isinstance(raw_value, int | str):
        raise ValidationError(INTEGER_VALUE_REQUIRED.format(field_name=field_name))
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValidationError(INTEGER_VALUE_REQUIRED.format(field_name=field_name)) from exc


def _history_payload(path: str) -> dict[str, object]:
    loaded: object = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValidationError(HISTORY_IMPORT_OBJECT_REQUIRED)
    return {str(key): value for key, value in loaded.items()}


def _namespace_value(args: argparse.Namespace, field_name: str) -> object | None:
    namespace = cast("Mapping[str, object]", vars(args))
    return namespace.get(field_name)


def _handle_schema_inspection(args: argparse.Namespace, db_uri: str | None) -> bool:
    if _cli_args.get_bool_arg(args, "schema_version"):
        if not db_uri:
            raise ValidationError(SCHEMA_VERSION_REQUIRED)
        value = schema_version(create_engine(db_uri, future=True))
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
    problems = validate_schema(create_engine(db_uri, future=True))
    _cli_output.print_status_line("schema_valid", "true" if not problems else "false")
    if problems:
        _cli_output.print_text_lines([f"  {problem}" for problem in problems])
    return True


def _handle_history_io(args: argparse.Namespace, config: AppConfig, *, file_writer: FileWriter) -> bool:
    export_path = _cli_args.get_optional_str_arg(args, "export_history") or _cli_args.get_optional_str_arg(args, "archive_history")
    if export_path:
        payload = uc_export_persisted_history(persistence_query_service=_query_service_for(config))
        content = json.dumps(payload, indent=2, sort_keys=True)
        if export_path == "-":
            _cli_output.print_text_lines([content])
        else:
            file_writer.write(export_path, content)
            _cli_output.print_status_line("history_exported", export_path)
        return True
    import_path = _cli_args.get_optional_str_arg(args, "import_history") or _cli_args.get_optional_str_arg(args, "restore_history")
    if not import_path:
        return False
    imported = uc_import_persisted_history(_history_payload(import_path), persistence_query_service=_query_service_for(config))
    imported_count = int(imported.get("imported", imported.get("runs_imported", 0)))
    skipped_count = int(imported.get("skipped", imported.get("runs_skipped", 0)))
    _cli_output.print_json_payload({"imported": imported_count, "skipped": skipped_count})
    return True


def _handle_history_maintenance(args: argparse.Namespace, config: AppConfig) -> bool:
    if _cli_args.get_bool_arg(args, "compact_history"):
        uc_compact_persisted_history(persistence_query_service=_query_service_for(config))
        _cli_output.print_status_line("history_compacted", "true")
        return True
    retain_days = _namespace_value(args, "retain_days")
    if retain_days is not None:
        deleted = uc_retain_persisted_history(
            RetainHistoryInput(
                days=_int_arg_value(retain_days, "retain-days"),
                statuses=_cli_args.parse_string_filters(_namespace_value(args, "prune_status")),
            ),
            persistence_query_service=_query_service_for(config),
        )
        _cli_output.print_maintenance_result("retain_history", deleted)
        return True
    if not _cli_args.get_bool_arg(args, "list_failed_batches"):
        return False
    jobs = uc_list_failed_batch_jobs(
        ListFailedBatchesInput(limit=_cli_args.get_int_arg(args, "batch_limit", 20)),
        persistence_query_service=_query_service_for(config),
    )
    if _cli_args.get_bool_arg(args, "json"):
        _cli_output.print_json_payload({"items": [job.to_record() for job in jobs]})
    else:
        _cli_output.print_failed_batch_jobs(jobs)
    return True


def print_schema_revisions() -> None:
    _cli_output.print_text_lines(
        [f"{revision.version}\t{revision.name}\t{revision.description}" for revision in revision_history()],
    )


def handle_schema_commands(args: argparse.Namespace, config: AppConfig, *, file_writer: FileWriter) -> bool:
    """Handle schema and history maintenance CLI commands."""
    db_uri = config.db_uri
    return (
        _handle_schema_inspection(args, db_uri)
        or _handle_history_io(args, config, file_writer=file_writer)
        or _handle_history_maintenance(args, config)
    )
