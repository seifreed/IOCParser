from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from sqlalchemy import inspect, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from iocparser.domain.enums import IOCType, ioc_type_name
from iocparser.domain.jobs import BatchJobDetail, BatchJobSummary, FailedBatchItem
from iocparser.domain.models import PersistedRunSummary
from iocparser.errors import InvalidJSONError, JSONShapeError, TypeValidationError
from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.persistence.history.row_values import (
    typed_row,
)
from iocparser.infrastructure.persistence_batch import (
    BatchJobModel,
    FailedBatchItemModel,
    load_failed_batch_items,
)
from iocparser.infrastructure.persistence_distributed_records import HISTORY_IMPORT_MARKER_KEY
from iocparser.infrastructure.persistence_migrations import migrate_engine
from iocparser.infrastructure.persistence_repository_support import (
    dialect_replace_into,
    quote_identifier,
)
from iocparser.infrastructure.persistence_schema import (
    DeadLetterJobModel,
    DistributedJobModel,
    IOCModel,
    RunIOCModel,
    RunModel,
    SourceModel,
)
from iocparser.infrastructure.persistence_support import (
    build_summary,
    prune_runs,
)
from iocparser.infrastructure.persistence_uow import create_engine_for_uri

_typed_row = typed_row

logger = get_logger(__name__)


@contextmanager
def _managed_session(db_uri: str) -> Iterator[Session]:
    """Create, migrate, and safely dispose a SQLAlchemy engine, yielding a Session."""
    engine = create_engine_for_uri(db_uri)
    try:
        migrate_engine(engine)
        with Session(engine) as session:
            yield session
    finally:
        engine.dispose()


@contextmanager
def _managed_connection(db_uri: str) -> Iterator[Connection]:
    """Create, migrate, and safely dispose a SQLAlchemy engine, yielding a Connection."""
    engine = create_engine_for_uri(db_uri)
    try:
        migrate_engine(engine)
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            yield connection
    finally:
        engine.dispose()


INVALID_HISTORY_ARCHIVE = "invalid history archive"
AMBIGUOUS_LEGACY_HISTORY_ARCHIVE = "ambiguous legacy history archive"
HISTORY_ARCHIVE_ID_KEY = "__history_archive_id__"
HISTORY_ORIGIN_ID_KEY = "__history_origin_id__"
HistoryModel = (
    SourceModel
    | RunModel
    | IOCModel
    | RunIOCModel
    | BatchJobModel
    | FailedBatchItemModel
    | DistributedJobModel
    | DeadLetterJobModel
)
HistoryModelType = (
    type[SourceModel]
    | type[RunModel]
    | type[IOCModel]
    | type[RunIOCModel]
    | type[BatchJobModel]
    | type[FailedBatchItemModel]
    | type[DistributedJobModel]
    | type[DeadLetterJobModel]
)


def _string_key_mapping(mapping: Mapping[object, object]) -> dict[str, object]:
    return {key: value for key, value in mapping.items() if isinstance(key, str)}


def _normalized_ioc_type(value: str) -> str:
    try:
        return ioc_type_name(IOCType.from_name(value))
    except ValueError:
        return value.strip().lower()


def _json_object(raw_value: str) -> dict[str, object]:
    try:
        decoded: object = json.loads(raw_value or "{}")
    except json.JSONDecodeError as exc:
        raise InvalidJSONError("object") from exc
    if not isinstance(decoded, dict):
        raise JSONShapeError("object")
    return _string_key_mapping(decoded)


def _is_int_like(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, str):
        stripped = value.lstrip("-")
        return stripped.isdigit() and len(stripped) > 0
    return False


def _json_int_map(raw_value: str) -> dict[str, int]:
    decoded = _json_object(raw_value)
    return {key: int(value) for key, value in decoded.items() if _is_int_like(value)}  # type: ignore[call-overload]


def _payload_fingerprint(payload: Mapping[str, object]) -> str:
    filtered_payload = {
        key: value
        for key, value in payload.items()
        if key not in {HISTORY_ARCHIVE_ID_KEY, HISTORY_ORIGIN_ID_KEY}
    }
    encoded = json.dumps(filtered_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _select_rows(session: Session, model: HistoryModelType) -> list[dict[str, object]]:
    return [_row_dict(row) for row in session.execute(select(model)).scalars().all()]


def _archive_id(payload: dict[str, object]) -> str:
    raw_value = payload.get(HISTORY_ARCHIVE_ID_KEY)
    if isinstance(raw_value, str) and raw_value.strip():
        return raw_value.strip()
    origin_id = payload.get(HISTORY_ORIGIN_ID_KEY)
    if isinstance(origin_id, str) and origin_id.strip():
        return hashlib.sha256(
            f"{origin_id.strip()}:{_payload_fingerprint(payload)}".encode()
        ).hexdigest()
    return f"legacy:{_payload_fingerprint(payload)}"


def _is_legacy_archive(payload: dict[str, object]) -> bool:
    raw_archive_id = payload.get(HISTORY_ARCHIVE_ID_KEY)
    raw_origin_id = payload.get(HISTORY_ORIGIN_ID_KEY)
    has_archive_id = isinstance(raw_archive_id, str) and raw_archive_id.strip()
    has_origin_id = isinstance(raw_origin_id, str) and raw_origin_id.strip()
    return not has_archive_id and not has_origin_id


def _has_legacy_archive_collision(session: Session, *, archive_id: str) -> bool:
    for raw_json in session.execute(select(BatchJobModel.config_json)).scalars().all():
        marker = _json_import_marker(raw_json)
        if marker is not None and marker.get("archive_id") == archive_id:
            return True
    for raw_json in session.execute(select(RunModel.options_json)).scalars().all():
        marker = _json_import_marker(raw_json)
        if marker is not None and marker.get("archive_id") == archive_id:
            return True
    for raw_json in session.execute(select(DistributedJobModel.payload_json)).scalars().all():
        marker = _json_import_marker(raw_json)
        if marker is not None and marker.get("archive_id") == archive_id:
            return True
    for raw_json in session.execute(select(DeadLetterJobModel.payload_json)).scalars().all():
        marker = _json_import_marker(raw_json)
        if marker is not None and marker.get("archive_id") == archive_id:
            return True
    return False


def _history_origin_id(session: Session) -> str:
    dialect_name = session.get_bind().dialect.name
    key = quote_identifier(dialect_name, "key")
    origin_select = (
        "SELECT value FROM history_metadata WHERE `key` = 'origin_id'"
        if key == "`key`"
        else "SELECT value FROM history_metadata WHERE \"key\" = 'origin_id'"
    )
    row = session.execute(text(origin_select)).scalar_one_or_none()
    if isinstance(row, str) and row.strip():
        return row.strip()
    origin_id = str(uuid4())
    session.execute(
        text(
            dialect_replace_into(
                dialect_name,
                f"history_metadata({key}, value) VALUES ('origin_id', :value)",
            )
        ),
        {"value": origin_id},
    )
    return origin_id


def _payload_rows(payload: dict[str, object], key: str) -> list[dict[str, object]]:
    raw_rows = payload.get(key, [])
    if not isinstance(raw_rows, list):
        return []
    rows: list[dict[str, object]] = []
    for row in raw_rows:
        if isinstance(row, Mapping):
            rows.append(_string_key_mapping(row))
    return rows


def _same_origin_archive(session: Session, payload: dict[str, object]) -> bool:
    raw_origin_id = payload.get(HISTORY_ORIGIN_ID_KEY)
    if not isinstance(raw_origin_id, str) or not raw_origin_id.strip():
        return False
    return _history_origin_id(session) == raw_origin_id.strip()


def _normalized_text(value: object, *, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise TypeValidationError(None, "string", value)
    stripped = value.strip()
    return stripped or default


def _public_batch_job_config(raw_config_json: object) -> dict[str, object]:
    config = _json_object(str(raw_config_json or "{}"))
    config.pop(HISTORY_IMPORT_MARKER_KEY, None)
    return config


def _json_with_import_marker(
    raw_json: object,
    *,
    archive_id: str,
    original_id: int | None,
) -> str:
    payload = _json_object(str(raw_json or "{}"))
    if original_id is not None:
        payload[HISTORY_IMPORT_MARKER_KEY] = {
            "archive_id": archive_id,
            "original_id": original_id,
        }
    return json.dumps(payload, sort_keys=True)


def _json_without_import_marker(raw_json: object) -> str:
    payload = _json_object(str(raw_json or "{}"))
    payload.pop(HISTORY_IMPORT_MARKER_KEY, None)
    return json.dumps(payload, sort_keys=True)


def _json_import_marker(raw_json: object) -> dict[str, object] | None:
    marker = _json_object(str(raw_json or "{}")).get(HISTORY_IMPORT_MARKER_KEY)
    return marker if isinstance(marker, dict) else None


def _distributed_internal_job_id(*, job_id: str, archive_id: str) -> str:
    return f"{job_id}#history:{archive_id}"


def _public_job_id(model: DistributedJobModel | DeadLetterJobModel) -> str:
    payload = _json_object(model.payload_json or "{}")
    marker = _json_import_marker(model.payload_json or "{}")
    request_payload = payload.get("request")
    original_job_id = request_payload.get("job_id") if isinstance(request_payload, dict) else None
    if isinstance(original_job_id, str) and original_job_id.strip() and marker is not None:
        return original_job_id
    return model.job_id


def _row_dict(model: HistoryModel) -> dict[str, object]:
    if isinstance(model, SourceModel):
        return {
            "id": model.id,
            "kind": model.kind,
            "value": model.value,
            "value_search": model.value_search,
            "original_url": model.original_url,
            "normalized_url": model.normalized_url,
            "mime_type": model.mime_type,
            "input_size": model.input_size,
            "content_hash": model.content_hash,
            "fingerprint": model.fingerprint,
            "first_seen": model.first_seen.isoformat(),
            "last_seen": model.last_seen.isoformat(),
        }
    if isinstance(model, RunModel):
        return {
            "id": model.id,
            "source_id": model.source_id,
            "batch_job_id": model.batch_job_id,
            "started_at": model.started_at.isoformat(),
            "finished_at": model.finished_at.isoformat(),
            "tool_version": model.tool_version,
            "options_json": _json_without_import_marker(model.options_json),
            "normal_ioc_count": model.normal_ioc_count,
            "warning_ioc_count": model.warning_ioc_count,
            "processed_items": model.processed_items,
            "successful_items": model.successful_items,
            "failed_items": model.failed_items,
            "partial_error_count": model.partial_error_count,
            "duration_ms": model.duration_ms,
            "status": model.status,
            "error_message": model.error_message,
        }
    if isinstance(model, IOCModel):
        return {
            "id": model.id,
            "ioc_type": model.ioc_type,
            "value": model.value,
            "value_search": model.value_search,
            "is_warning": model.is_warning,
            "warning_list": model.warning_list,
            "warning_description": model.warning_description,
        }
    if isinstance(model, RunIOCModel):
        return {
            "id": model.id,
            "run_id": model.run_id,
            "ioc_id": model.ioc_id,
            "severity": model.severity,
            "tags_json": model.tags_json,
            "tags_search": model.tags_search,
            "evidence_json": model.evidence_json,
        }
    if isinstance(model, BatchJobModel):
        return {
            "id": model.id,
            "source_kind": model.source_kind,
            "started_at": model.started_at.isoformat(),
            "finished_at": model.finished_at.isoformat(),
            "total_inputs": model.total_inputs,
            "successful_inputs": model.successful_inputs,
            "failed_inputs": model.failed_inputs,
            "retry_attempt": model.retry_attempt,
            "status": model.status,
            "error_summary_json": model.error_summary_json,
            "config_json": json.dumps(_public_batch_job_config(model.config_json), sort_keys=True),
            "metrics_json": model.metrics_json,
        }
    if isinstance(model, FailedBatchItemModel):
        return {
            "id": model.id,
            "batch_job_id": model.batch_job_id,
            "source_value": model.source_value,
            "error_type": model.error_type,
            "error_message": model.error_message,
            "retry_attempt": model.retry_attempt,
            "created_at": model.created_at.isoformat(),
        }
    if isinstance(model, DistributedJobModel):
        return {
            "id": model.id,
            "job_id": _public_job_id(model),
            "correlation_id": model.correlation_id,
            "queue_backend": model.queue_backend,
            "queue_name": model.queue_name,
            "input_kind": model.input_kind,
            "source_value": model.source_value,
            "idempotency_key": model.idempotency_key,
            "status": model.status,
            "attempts": model.attempts,
            "max_attempts": model.max_attempts,
            "retryable": model.retryable,
            "receipt_id": model.receipt_id,
            "payload_json": _json_without_import_marker(model.payload_json),
            "result_json": model.result_json,
            "metrics_json": model.metrics_json,
            "last_error_code": model.last_error_code,
            "last_error_category": model.last_error_category,
            "last_error_message": model.last_error_message,
            "run_id": model.run_id,
            "submitted_at": model.submitted_at.isoformat(),
            "started_at": model.started_at.isoformat() if model.started_at is not None else None,
            "completed_at": model.completed_at.isoformat()
            if model.completed_at is not None
            else None,
            "dead_lettered_at": model.dead_lettered_at.isoformat()
            if model.dead_lettered_at is not None
            else None,
        }
    return {
        "id": model.id,
        "job_id": _public_job_id(model),
        "correlation_id": model.correlation_id,
        "queue_backend": model.queue_backend,
        "queue_name": model.queue_name,
        "source_value": model.source_value,
        "attempts": model.attempts,
        "max_attempts": model.max_attempts,
        "error_code": model.error_code,
        "error_category": model.error_category,
        "error_message": model.error_message,
        "retryable": model.retryable,
        "payload_json": _json_without_import_marker(model.payload_json),
        "dead_lettered_at": model.dead_lettered_at.isoformat(),
    }


def export_history(db_uri: str) -> dict[str, object]:
    with _managed_session(db_uri) as session:
        origin_id = _history_origin_id(session)
        session.commit()
        payload = {
            "sources": _select_rows(session, SourceModel),
            "runs": _select_rows(session, RunModel),
            "iocs": _select_rows(session, IOCModel),
            "run_iocs": _select_rows(session, RunIOCModel),
            "batch_jobs": _select_rows(session, BatchJobModel),
            "failed_batch_items": _select_rows(session, FailedBatchItemModel),
            "distributed_jobs": _select_rows(session, DistributedJobModel),
            "dead_letter_jobs": _select_rows(session, DeadLetterJobModel),
        }
        archive_id = hashlib.sha256(
            f"{origin_id}:{_payload_fingerprint(payload)}".encode()
        ).hexdigest()
        return {
            HISTORY_ORIGIN_ID_KEY: origin_id,
            HISTORY_ARCHIVE_ID_KEY: archive_id,
            **payload,
        }


def archive_history(db_uri: str, output_path: str) -> str:
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(export_history(db_uri), indent=2, sort_keys=True), encoding="utf-8")
    logger.info("Archived history to %s", path)
    return str(path)


def _history_compaction_sql(dialect_name: str, table_names: tuple[str, ...]) -> list[str]:
    """Per-dialect space reclamation: SQLite VACUUM, MySQL/MariaDB OPTIMIZE TABLE, else no-op."""
    if dialect_name == "sqlite":
        return ["VACUUM"]
    if dialect_name in ("mysql", "mariadb") and table_names:
        return ["OPTIMIZE TABLE " + ", ".join(f"`{name}`" for name in table_names)]
    return []


def compact_history(db_uri: str) -> None:
    with _managed_connection(db_uri) as connection:
        table_names = tuple(inspect(connection).get_table_names())
        dialect_name = connection.engine.dialect.name
        statements = _history_compaction_sql(dialect_name, table_names)
        for statement in statements:
            connection.exec_driver_sql(statement)
        logger.info(
            "Compacted history store (%s): ran %s reclamation statement(s)",
            dialect_name,
            len(statements),
        )


def retain_history(db_uri: str, *, days: int, statuses: tuple[str, ...] = ()) -> int:
    cutoff = (datetime.now(UTC) - timedelta(days=max(0, days))).isoformat()
    with _managed_session(db_uri) as session:
        deleted = prune_runs(session, before=cutoff, statuses=statuses)
        session.commit()
        logger.info(
            "Retention pruned %s run(s) older than %s (statuses=%s)",
            deleted,
            cutoff,
            statuses or "all",
        )
        return deleted


def list_failed_batches(db_uri: str, *, limit: int = 20) -> list[BatchJobSummary]:
    safe_limit = max(0, limit)
    with _managed_session(db_uri) as session:
        jobs = (
            session.execute(
                select(BatchJobModel)
                .where(BatchJobModel.failed_inputs > 0)
                .order_by(BatchJobModel.started_at.desc(), BatchJobModel.id.desc())
                .limit(safe_limit)
            )
            .scalars()
            .all()
        )
        return [_batch_job_summary(session, job) for job in jobs]


def list_failed_batch_items(db_uri: str, *, batch_job_id: int) -> list[FailedBatchItem]:
    with _managed_session(db_uri) as session:
        return [
            FailedBatchItem(
                batch_job_id=item.batch_job_id,
                source_value=item.source_value,
                error_type=item.error_type,
                error_message=item.error_message,
                retry_attempt=item.retry_attempt,
                created_at=item.created_at,
            )
            for item in load_failed_batch_items(session, batch_job_id=batch_job_id)
        ]


def list_batch_jobs(
    db_uri: str, *, limit: int = 20, statuses: tuple[str, ...] = ()
) -> list[BatchJobSummary]:
    safe_limit = max(0, limit)
    with _managed_session(db_uri) as session:
        stmt = (
            select(BatchJobModel)
            .order_by(BatchJobModel.started_at.desc(), BatchJobModel.id.desc())
            .limit(safe_limit)
        )
        if statuses:
            stmt = stmt.where(BatchJobModel.status.in_(statuses))
        jobs = session.execute(stmt).scalars().all()
        return [_batch_job_summary(session, job) for job in jobs]


def get_batch_job(db_uri: str, *, batch_job_id: int) -> BatchJobDetail | None:
    with _managed_session(db_uri) as session:
        job = session.get(BatchJobModel, batch_job_id)
        if job is None:
            return None
        return BatchJobDetail(
            batch_job_id=job.id,
            source_kind=job.source_kind,
            status=job.status,
            started_at=job.started_at,
            finished_at=job.finished_at,
            total_inputs=job.total_inputs,
            successful_inputs=job.successful_inputs,
            failed_inputs=job.failed_inputs,
            retry_attempt=job.retry_attempt,
            error_summary=_json_int_map(job.error_summary_json or "{}"),
            effective_config=_public_batch_job_config(job.config_json or "{}"),
            metrics=_json_object(job.metrics_json or "{}"),
            failed_item_count=len(load_failed_batch_items(session, batch_job_id=job.id)),
        )


def list_batch_runs(db_uri: str, *, batch_job_id: int) -> list[PersistedRunSummary]:
    with _managed_session(db_uri) as session:
        stmt = (
            select(RunModel)
            .where(RunModel.batch_job_id == batch_job_id)
            .order_by(RunModel.started_at.asc(), RunModel.id.asc())
        )
        return [build_summary(session, run) for run in session.execute(stmt).scalars().all()]


def _batch_job_summary(session: Session, job: BatchJobModel) -> BatchJobSummary:
    return BatchJobSummary(
        batch_job_id=job.id,
        source_kind=job.source_kind,
        started_at=job.started_at,
        finished_at=job.finished_at,
        total_inputs=job.total_inputs,
        successful_inputs=job.successful_inputs,
        failed_inputs=job.failed_inputs,
        retry_attempt=job.retry_attempt,
        status=job.status,
        error_summary=_json_int_map(job.error_summary_json or "{}"),
        failed_item_count=len(load_failed_batch_items(session, batch_job_id=job.id)),
    )
