from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, or_, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from iocparser.domain.jobs import BatchJobDetail, BatchJobSummary, FailedBatchItem
from iocparser.domain.models import PersistedRunSummary
from iocparser.domain.sources import normalize_url_value
from iocparser.infrastructure.persistence.history.row_values import (
    bool_from_row,
    int_from_row,
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
    build_tags_search,
    dialect_replace_into,
    ioc_dedup_hash,
    normalize_ioc_search,
    quote_identifier,
    source_dedup_hash,
    tags_from_json,
)
from iocparser.infrastructure.persistence_schema import (
    DeadLetterJobModel,
    DistributedJobModel,
    IOCModel,
    RunIOCModel,
    RunModel,
    SourceModel,
)
from iocparser.infrastructure.persistence_support import build_summary, prune_runs

_typed_row = typed_row


@contextmanager
def _managed_session(db_uri: str) -> Iterator[Session]:
    """Create, migrate, and safely dispose a SQLAlchemy engine, yielding a Session."""
    engine = create_engine(db_uri, future=True)
    try:
        migrate_engine(engine)
        with Session(engine) as session:
            yield session
    finally:
        engine.dispose()


@contextmanager
def _managed_connection(db_uri: str) -> Iterator[Connection]:
    """Create, migrate, and safely dispose a SQLAlchemy engine, yielding a Connection."""
    engine = create_engine(db_uri, future=True)
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


def _json_object(raw_value: str) -> dict[str, object]:
    decoded: object = json.loads(raw_value or "{}")
    if not isinstance(decoded, dict):
        return {}
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
    encoded = json.dumps(filtered_payload, sort_keys=True, separators=(",", ":"), default=str)
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
    row = session.execute(
        text(f"SELECT value FROM history_metadata WHERE {key} = 'origin_id'")  # noqa: S608
    ).scalar_one_or_none()
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


def _source_identity(row: dict[str, object]) -> tuple[object, ...]:
    kind = str(row.get("kind", ""))
    value = str(row.get("value", ""))
    normalized_url = row.get("normalized_url")
    if kind == "url":
        normalized = normalize_url_value(str(normalized_url)) or normalize_url_value(value) or value
        return ("url", normalized)
    return (kind, value)


def _existing_source(session: Session, row: dict[str, object]) -> SourceModel | None:
    identity = _source_identity(row)
    if identity[0] == "url":
        value = str(row.get("value", ""))
        normalized_url = str(identity[1])
        stmt = select(SourceModel).where(SourceModel.kind == "url")
        clauses = []
        if value:
            clauses.append(SourceModel.value == value)
        if normalized_url:
            clauses.append(SourceModel.normalized_url == normalized_url)
        stmt = stmt.where(or_(*clauses)) if clauses else stmt.where(SourceModel.value == value)
        candidates = session.execute(stmt).scalars().all()
        for candidate in candidates:
            candidate_identity = _source_identity(
                {
                    "kind": candidate.kind,
                    "value": candidate.value,
                    "normalized_url": candidate.normalized_url,
                }
            )
            if candidate_identity == identity:
                return candidate
        return None
    return session.execute(
        select(SourceModel).where(
            SourceModel.kind == str(identity[0]), SourceModel.value == str(identity[1])
        )
    ).scalar_one_or_none()


def _existing_ioc(session: Session, row: dict[str, object]) -> IOCModel | None:
    return session.execute(
        select(IOCModel).where(
            IOCModel.ioc_type == str(row.get("ioc_type", "")),
            IOCModel.value == str(row.get("value", "")),
            IOCModel.is_warning == bool_from_row(row.get("is_warning")),
            IOCModel.warning_list == str(row.get("warning_list", "")),
            IOCModel.warning_description == str(row.get("warning_description", "")),
        )
    ).scalar_one_or_none()


def _existing_batch_job(session: Session, row: dict[str, object]) -> BatchJobModel | None:
    return session.execute(
        select(BatchJobModel).where(
            BatchJobModel.source_kind == str(row.get("source_kind", "")),
            BatchJobModel.started_at == row.get("started_at"),
            BatchJobModel.finished_at == row.get("finished_at"),
            BatchJobModel.total_inputs == int(row.get("total_inputs", 0)),  # type: ignore[call-overload]
            BatchJobModel.successful_inputs == int(row.get("successful_inputs", 0)),  # type: ignore[call-overload]
            BatchJobModel.failed_inputs == int(row.get("failed_inputs", 0)),  # type: ignore[call-overload]
            BatchJobModel.retry_attempt == int(row.get("retry_attempt", 0)),  # type: ignore[call-overload]
            BatchJobModel.status == str(row.get("status", "")),
            BatchJobModel.config_json == str(row.get("config_json", "{}")),
            BatchJobModel.error_summary_json == str(row.get("error_summary_json", "{}")),
            BatchJobModel.metrics_json == str(row.get("metrics_json", "{}")),
        )
    ).scalar_one_or_none()


def _same_origin_archive(session: Session, payload: dict[str, object]) -> bool:
    raw_origin_id = payload.get(HISTORY_ORIGIN_ID_KEY)
    if not isinstance(raw_origin_id, str) or not raw_origin_id.strip():
        return False
    return _history_origin_id(session) == raw_origin_id.strip()


def _batch_job_signature(row: dict[str, object]) -> tuple[object, ...]:
    return (
        str(row.get("source_kind", "")),
        row.get("started_at"),
        row.get("finished_at"),
        int(row.get("total_inputs", 0)),  # type: ignore[call-overload]
        int(row.get("successful_inputs", 0)),  # type: ignore[call-overload]
        int(row.get("failed_inputs", 0)),  # type: ignore[call-overload]
        int(row.get("retry_attempt", 0)),  # type: ignore[call-overload]
        str(row.get("status", "")),
        str(row.get("config_json", "{}")),
        str(row.get("error_summary_json", "{}")),
        str(row.get("metrics_json", "{}")),
    )


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


def _run_ioc_signature(session: Session, *, run_id: int) -> tuple[tuple[int, str, str, str], ...]:
    rows = session.execute(
        select(
            RunIOCModel.ioc_id,
            RunIOCModel.severity,
            RunIOCModel.tags_json,
            RunIOCModel.evidence_json,
        )
        .where(RunIOCModel.run_id == run_id)
        .order_by(
            RunIOCModel.ioc_id.asc(),
            RunIOCModel.severity.asc(),
            RunIOCModel.tags_json.asc(),
            RunIOCModel.evidence_json.asc(),
        )
    ).all()
    return tuple(
        (
            int(ioc_id),  # type: ignore[call-overload]
            str(severity),
            str(tags_json),
            str(evidence_json),
        )
        for ioc_id, severity, tags_json, evidence_json in rows
    )


def _existing_run(
    session: Session,
    row: dict[str, object],
    *,
    source_id: int,
    batch_job_id: int | None,
    ioc_signature: tuple[tuple[int, str, str, str], ...],
    archive_id: str,
    original_id: int | None,
    same_origin: bool,
) -> RunModel | None:
    candidates = (
        session.execute(
            select(RunModel).where(
                RunModel.source_id == source_id,
                RunModel.batch_job_id == batch_job_id,
                RunModel.started_at == row.get("started_at"),
                RunModel.finished_at == row.get("finished_at"),
                RunModel.tool_version == str(row.get("tool_version", "")),
                RunModel.normal_ioc_count == int(row.get("normal_ioc_count", 0)),  # type: ignore[call-overload]
                RunModel.warning_ioc_count == int(row.get("warning_ioc_count", 0)),  # type: ignore[call-overload]
                RunModel.processed_items == int(row.get("processed_items", 0)),  # type: ignore[call-overload]
                RunModel.successful_items == int(row.get("successful_items", 0)),  # type: ignore[call-overload]
                RunModel.failed_items == int(row.get("failed_items", 0)),  # type: ignore[call-overload]
                RunModel.partial_error_count == int(row.get("partial_error_count", 0)),  # type: ignore[call-overload]
                RunModel.duration_ms == int(row.get("duration_ms", 0)),  # type: ignore[call-overload]
                RunModel.status == str(row.get("status", "")),
                RunModel.error_message == str(row.get("error_message", "")),
            )
        )
        .scalars()
        .all()
    )
    for candidate in candidates:
        if _json_without_import_marker(candidate.options_json) != _json_without_import_marker(
            row.get("options_json", "{}")
        ):
            continue
        marker = _json_import_marker(candidate.options_json)
        if marker is not None and marker == {"archive_id": archive_id, "original_id": original_id}:
            return candidate
        if (
            same_origin
            and marker is None
            and _run_ioc_signature(session, run_id=candidate.id) == ioc_signature
        ):
            return candidate
    return None


def _existing_run_ioc(session: Session, *, run_id: int, ioc_id: int) -> RunIOCModel | None:
    return session.execute(
        select(RunIOCModel).where(RunIOCModel.run_id == run_id, RunIOCModel.ioc_id == ioc_id)
    ).scalar_one_or_none()


def _existing_failed_batch_item(
    session: Session,
    row: dict[str, object],
    *,
    batch_job_id: int,
) -> FailedBatchItemModel | None:
    return session.execute(
        select(FailedBatchItemModel).where(
            FailedBatchItemModel.batch_job_id == batch_job_id,
            FailedBatchItemModel.source_value == str(row.get("source_value", "")),
            FailedBatchItemModel.error_type == str(row.get("error_type", "")),
            FailedBatchItemModel.error_message == str(row.get("error_message", "")),
            FailedBatchItemModel.retry_attempt == int(row.get("retry_attempt", 0)),  # type: ignore[call-overload]
            FailedBatchItemModel.created_at == row.get("created_at"),
        )
    ).scalar_one_or_none()


def _existing_distributed_job(
    session: Session,
    row: dict[str, object],
    *,
    archive_id: str,
    same_origin: bool,
) -> DistributedJobModel | None:
    original_id = row.get("id")
    public_job_id = str(row.get("job_id", ""))
    candidates = (
        session.execute(
            select(DistributedJobModel).where(
                DistributedJobModel.job_id.in_(
                    (
                        public_job_id,
                        _distributed_internal_job_id(job_id=public_job_id, archive_id=archive_id),
                    )
                )
            )
        )
        .scalars()
        .all()
    )
    for candidate in candidates:
        marker = _json_import_marker(candidate.payload_json or "{}")
        if marker == {"archive_id": archive_id, "original_id": original_id}:
            return candidate
        if same_origin and marker is None and candidate.job_id == public_job_id:
            return candidate
    return None


def _existing_dead_letter_job(
    session: Session,
    row: dict[str, object],
    *,
    archive_id: str,
    same_origin: bool,
) -> DeadLetterJobModel | None:
    original_id = row.get("id")
    public_job_id = str(row.get("job_id", ""))
    candidates = (
        session.execute(
            select(DeadLetterJobModel).where(
                DeadLetterJobModel.job_id.in_(
                    (
                        public_job_id,
                        _distributed_internal_job_id(job_id=public_job_id, archive_id=archive_id),
                    )
                ),
                DeadLetterJobModel.dead_lettered_at == row.get("dead_lettered_at"),
                DeadLetterJobModel.correlation_id == str(row.get("correlation_id", "")),
                DeadLetterJobModel.queue_backend == str(row.get("queue_backend", "")),
                DeadLetterJobModel.queue_name == str(row.get("queue_name", "")),
                DeadLetterJobModel.source_value == str(row.get("source_value", "")),
                DeadLetterJobModel.attempts == int(row.get("attempts", 0)),  # type: ignore[call-overload]
                DeadLetterJobModel.max_attempts == int(row.get("max_attempts", 0)),  # type: ignore[call-overload]
                DeadLetterJobModel.error_code == str(row.get("error_code", "")),
                DeadLetterJobModel.error_category == str(row.get("error_category", "")),
                DeadLetterJobModel.error_message == str(row.get("error_message", "")),
                DeadLetterJobModel.retryable == bool_from_row(row.get("retryable")),
            )
        )
        .scalars()
        .all()
    )
    for candidate in candidates:
        marker = _json_import_marker(candidate.payload_json or "{}")
        if _json_without_import_marker(
            candidate.payload_json or "{}"
        ) != _json_without_import_marker(row.get("payload_json", "{}")):
            continue
        if marker == {"archive_id": archive_id, "original_id": original_id}:
            return candidate
        if same_origin and marker is None and candidate.job_id == public_job_id:
            return candidate
    return None


def _import_sources(session: Session, rows: list[dict[str, object]]) -> tuple[int, dict[int, int]]:
    inserted = 0
    source_map: dict[int, int] = {}
    for row in rows:
        typed = typed_row(row)
        if str(typed.get("kind", "")) == "url":
            typed["original_url"] = typed.get("original_url") or typed.get("value")
            typed["normalized_url"] = _source_identity(typed)[1]
        typed["dedup_hash"] = source_dedup_hash(
            str(typed.get("kind", "")), str(typed.get("value", ""))
        )
        existing = _existing_source(session, typed)
        if existing is None:
            source = SourceModel(**{key: value for key, value in typed.items() if key != "id"})
            session.add(source)
            session.flush()
            existing = source
            inserted += 1
        else:
            for field in ("last_seen", "content_hash", "fingerprint", "mime_type", "input_size"):
                imported_val = typed.get(field)
                if imported_val is not None:
                    current_val = getattr(existing, field, None)
                    if current_val is None or (field == "last_seen" and imported_val > current_val):
                        setattr(existing, field, imported_val)
        original_id = typed.get("id")
        if isinstance(original_id, int):
            source_map[original_id] = existing.id
    return inserted, source_map


def _import_iocs(session: Session, rows: list[dict[str, object]]) -> tuple[int, dict[int, int]]:
    inserted = 0
    ioc_map: dict[int, int] = {}
    for row in rows:
        typed = typed_row(row)
        search_value = normalize_ioc_search(str(typed.get("value", "")))
        typed["value_search"] = search_value
        typed["dedup_hash"] = ioc_dedup_hash(
            str(typed.get("ioc_type", "")),
            str(typed.get("value", "")),
            bool(typed.get("is_warning")),
            str(typed.get("warning_list", "")),
            str(typed.get("warning_description", "")),
        )
        existing = _existing_ioc(session, typed)
        if existing is None:
            ioc = IOCModel(**{key: value for key, value in typed.items() if key != "id"})
            session.add(ioc)
            session.flush()
            existing = ioc
            inserted += 1
        elif existing.value_search != search_value:
            existing.value_search = search_value
        original_id = typed.get("id")
        if isinstance(original_id, int):
            ioc_map[original_id] = existing.id
    return inserted, ioc_map


def _import_batch_jobs(
    session: Session,
    rows: list[dict[str, object]],
    *,
    archive_id: str,
    same_origin: bool,
) -> tuple[int, dict[int, int]]:
    inserted = 0
    batch_map: dict[int, int] = {}
    for row in rows:
        typed = typed_row(row)
        original_id = typed.get("id")
        import_marker = {
            "archive_id": archive_id,
            "original_id": original_id,
        }
        existing_matches = (
            session.execute(
                select(BatchJobModel.id)
                .where(
                    BatchJobModel.source_kind == str(typed.get("source_kind", "")),
                    BatchJobModel.started_at == typed.get("started_at"),
                    BatchJobModel.finished_at == typed.get("finished_at"),
                    BatchJobModel.total_inputs == int(typed.get("total_inputs", 0)),  # type: ignore[call-overload]
                    BatchJobModel.successful_inputs == int(typed.get("successful_inputs", 0)),  # type: ignore[call-overload]
                    BatchJobModel.failed_inputs == int(typed.get("failed_inputs", 0)),  # type: ignore[call-overload]
                    BatchJobModel.retry_attempt == int(typed.get("retry_attempt", 0)),  # type: ignore[call-overload]
                    BatchJobModel.status == str(typed.get("status", "")),
                    BatchJobModel.error_summary_json == str(typed.get("error_summary_json", "{}")),
                    BatchJobModel.metrics_json == str(typed.get("metrics_json", "{}")),
                )
                .order_by(BatchJobModel.id.asc())
            )
            .scalars()
            .all()
        )
        existing = None
        for batch_job_id in existing_matches:
            candidate = session.get(BatchJobModel, batch_job_id)
            if candidate is None:
                continue
            if _json_without_import_marker(candidate.config_json) != _json_without_import_marker(
                typed.get("config_json", "{}")
            ):
                continue
            candidate_config = _json_object(candidate.config_json)
            if candidate_config.get(HISTORY_IMPORT_MARKER_KEY) == import_marker:
                existing = candidate
                break
            if same_origin and HISTORY_IMPORT_MARKER_KEY not in candidate_config:
                existing = candidate
                break
        if existing is None:
            batch_job = BatchJobModel(
                **{key: value for key, value in typed.items() if key not in {"id", "config_json"}},
                config_json=_json_with_import_marker(
                    typed.get("config_json"),
                    archive_id=archive_id,
                    original_id=original_id if isinstance(original_id, int) else None,
                ),
            )
            session.add(batch_job)
            session.flush()
            existing = batch_job
            inserted += 1
        if isinstance(original_id, int):
            batch_map[original_id] = existing.id
    return inserted, batch_map


def _import_runs(
    session: Session,
    rows: list[dict[str, object]],
    *,
    archive_id: str,
    same_origin: bool,
    source_map: dict[int, int],
    batch_map: dict[int, int],
    run_ioc_rows: list[dict[str, object]],
    ioc_map: dict[int, int],
) -> tuple[int, dict[int, int]]:
    inserted = 0
    run_map: dict[int, int] = {}
    imported_signatures: dict[int, list[tuple[int, str, str, str]]] = {}
    for run_ioc_row in run_ioc_rows:
        typed_run_ioc = typed_row(run_ioc_row)
        original_run_id = typed_run_ioc.get("run_id")
        original_ioc_id = typed_run_ioc.get("ioc_id")
        if not isinstance(original_run_id, int) or not isinstance(original_ioc_id, int):
            continue
        mapped_ioc_id = ioc_map.get(original_ioc_id)
        if mapped_ioc_id is None:
            continue
        imported_signatures.setdefault(original_run_id, [])
        imported_signatures[original_run_id].append(
            (
                mapped_ioc_id,
                str(typed_run_ioc.get("severity", "")),
                str(typed_run_ioc.get("tags_json", "[]")),
                str(typed_run_ioc.get("evidence_json", "[]")),
            )
        )
    for row in rows:
        typed = typed_row(row)
        source_id = source_map.get(int_from_row(typed.get("source_id"), default=0) or 0)
        if source_id is None:
            continue
        original_batch_id = typed.get("batch_job_id")
        batch_job_id = (
            batch_map.get(int(original_batch_id)) if isinstance(original_batch_id, int) else None
        )
        original_id = typed.get("id")
        ioc_signature = (
            tuple(
                sorted(
                    imported_signatures.get(original_id, []),
                    key=lambda item: (item[0], item[1], item[2], item[3]),
                )
            )
            if isinstance(original_id, int)
            else ()
        )
        existing = _existing_run(
            session,
            typed,
            source_id=source_id,
            batch_job_id=batch_job_id,
            ioc_signature=ioc_signature,
            archive_id=archive_id,
            original_id=original_id if isinstance(original_id, int) else None,
            same_origin=same_origin,
        )
        if existing is None:
            run = RunModel(
                **{
                    key: value
                    for key, value in typed.items()
                    if key not in {"id", "source_id", "batch_job_id", "options_json"}
                },
                source_id=source_id,
                batch_job_id=batch_job_id,
                options_json=_json_with_import_marker(
                    typed.get("options_json"),
                    archive_id=archive_id,
                    original_id=original_id if isinstance(original_id, int) else None,
                ),
            )
            session.add(run)
            session.flush()
            existing = run
            inserted += 1
        if isinstance(original_id, int):
            run_map[original_id] = existing.id
    return inserted, run_map


def _import_run_iocs(
    session: Session,
    rows: list[dict[str, object]],
    *,
    run_map: dict[int, int],
    ioc_map: dict[int, int],
) -> int:
    inserted = 0
    for row in rows:
        typed = typed_row(row)
        run_id = run_map.get(int_from_row(typed.get("run_id"), default=0) or 0)
        ioc_id = ioc_map.get(int_from_row(typed.get("ioc_id"), default=0) or 0)
        if run_id is None or ioc_id is None:
            continue
        if _existing_run_ioc(session, run_id=run_id, ioc_id=ioc_id) is not None:
            continue
        session.add(
            RunIOCModel(
                **{
                    key: value
                    for key, value in typed.items()
                    if key not in {"id", "run_id", "ioc_id", "tags_search"}
                },
                run_id=run_id,
                ioc_id=ioc_id,
                # Recompute the derived column; older archives stored a different format.
                tags_search=build_tags_search(tags_from_json(typed.get("tags_json"))),
            )
        )
        inserted += 1
    return inserted


def _import_failed_batch_items(
    session: Session,
    rows: list[dict[str, object]],
    *,
    batch_map: dict[int, int],
) -> int:
    inserted = 0
    seen_signatures: dict[tuple[int, str, str, str, int, object], int] = {}
    for row in rows:
        typed = typed_row(row)
        batch_job_id = batch_map.get(int_from_row(typed.get("batch_job_id"), default=0) or 0)
        if batch_job_id is None:
            continue
        signature = (
            batch_job_id,
            str(typed.get("source_value", "")),
            str(typed.get("error_type", "")),
            str(typed.get("error_message", "")),
            int_from_row(typed.get("retry_attempt"), default=0) or 0,
            typed.get("created_at"),
        )
        existing_matches = (
            session.execute(
                select(FailedBatchItemModel.id)
                .where(
                    FailedBatchItemModel.batch_job_id == batch_job_id,
                    FailedBatchItemModel.source_value == signature[1],
                    FailedBatchItemModel.error_type == signature[2],
                    FailedBatchItemModel.error_message == signature[3],
                    FailedBatchItemModel.retry_attempt == signature[4],
                    FailedBatchItemModel.created_at == signature[5],
                )
                .order_by(FailedBatchItemModel.id.asc())
            )
            .scalars()
            .all()
        )
        seen_count = seen_signatures.get(signature, 0)
        if seen_count < len(existing_matches):
            seen_signatures[signature] = seen_count + 1
            continue
        session.add(
            FailedBatchItemModel(
                **{key: value for key, value in typed.items() if key not in {"id", "batch_job_id"}},
                batch_job_id=batch_job_id,
            )
        )
        seen_signatures[signature] = seen_count + 1
        inserted += 1
    return inserted


def _import_distributed_jobs(
    session: Session,
    rows: list[dict[str, object]],
    *,
    archive_id: str,
    same_origin: bool,
    run_map: dict[int, int],
) -> int:
    inserted = 0
    for row in rows:
        typed = typed_row(row)
        existing = _existing_distributed_job(
            session, typed, archive_id=archive_id, same_origin=same_origin
        )
        if existing is not None:
            continue
        original_run_id = typed.get("run_id")
        run_id = run_map.get(int(original_run_id)) if isinstance(original_run_id, int) else None
        original_id = typed.get("id")
        session.add(
            DistributedJobModel(
                **{
                    key: value
                    for key, value in typed.items()
                    if key not in {"id", "run_id", "job_id", "payload_json"}
                },
                job_id=_distributed_internal_job_id(
                    job_id=str(typed.get("job_id", "")),
                    archive_id=archive_id,
                ),
                payload_json=_json_with_import_marker(
                    typed.get("payload_json"),
                    archive_id=archive_id,
                    original_id=original_id if isinstance(original_id, int) else None,
                ),
                run_id=run_id,
            )
        )
        inserted += 1
    return inserted


def _import_dead_letter_jobs(
    session: Session,
    rows: list[dict[str, object]],
    *,
    archive_id: str,
    same_origin: bool,
) -> int:
    inserted = 0
    for row in rows:
        typed = typed_row(row)
        if (
            _existing_dead_letter_job(
                session, typed, archive_id=archive_id, same_origin=same_origin
            )
            is not None
        ):
            continue
        original_id = typed.get("id")
        session.add(
            DeadLetterJobModel(
                **{
                    key: value
                    for key, value in typed.items()
                    if key not in {"id", "job_id", "payload_json"}
                },
                job_id=_distributed_internal_job_id(
                    job_id=str(typed.get("job_id", "")),
                    archive_id=archive_id,
                ),
                payload_json=_json_with_import_marker(
                    typed.get("payload_json"),
                    archive_id=archive_id,
                    original_id=original_id if isinstance(original_id, int) else None,
                ),
            )
        )
        inserted += 1
    return inserted


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


def import_history(db_uri: str, payload: dict[str, object]) -> dict[str, int]:
    with _managed_session(db_uri) as session:
        same_origin = _same_origin_archive(session, payload)
        archive_id = _archive_id(payload)
        if _is_legacy_archive(payload) and _has_legacy_archive_collision(
            session, archive_id=archive_id
        ):
            raise ValueError(AMBIGUOUS_LEGACY_HISTORY_ARCHIVE)
        run_ioc_rows = _payload_rows(payload, "run_iocs")
        source_count, source_map = _import_sources(session, _payload_rows(payload, "sources"))
        ioc_count, ioc_map = _import_iocs(session, _payload_rows(payload, "iocs"))
        batch_count, batch_map = _import_batch_jobs(
            session,
            _payload_rows(payload, "batch_jobs"),
            archive_id=archive_id,
            same_origin=same_origin,
        )
        run_count, run_map = _import_runs(
            session,
            _payload_rows(payload, "runs"),
            archive_id=archive_id,
            same_origin=same_origin,
            source_map=source_map,
            batch_map=batch_map,
            run_ioc_rows=run_ioc_rows,
            ioc_map=ioc_map,
        )
        counts = {
            "sources": source_count,
            "runs": run_count,
            "iocs": ioc_count,
            "run_iocs": _import_run_iocs(
                session,
                run_ioc_rows,
                run_map=run_map,
                ioc_map=ioc_map,
            ),
            "batch_jobs": batch_count,
            "failed_batch_items": _import_failed_batch_items(
                session,
                _payload_rows(payload, "failed_batch_items"),
                batch_map=batch_map,
            ),
            "distributed_jobs": _import_distributed_jobs(
                session,
                _payload_rows(payload, "distributed_jobs"),
                archive_id=archive_id,
                same_origin=same_origin,
                run_map=run_map,
            ),
            "dead_letter_jobs": _import_dead_letter_jobs(
                session,
                _payload_rows(payload, "dead_letter_jobs"),
                archive_id=archive_id,
                same_origin=same_origin,
            ),
        }
        session.commit()
        return counts


def archive_history(db_uri: str, output_path: str) -> str:
    path = Path(output_path)
    path.write_text(json.dumps(export_history(db_uri), indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def restore_history(db_uri: str, archive_path: str) -> dict[str, int]:
    payload: object = json.loads(Path(archive_path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(INVALID_HISTORY_ARCHIVE)
    return import_history(db_uri, _string_key_mapping(payload))


def compact_history(db_uri: str) -> None:
    with _managed_connection(db_uri) as connection:
        connection.exec_driver_sql("VACUUM")


def retain_history(db_uri: str, *, days: int, statuses: tuple[str, ...] = ()) -> int:
    cutoff = (datetime.now(UTC) - timedelta(days=max(0, days))).isoformat()
    with _managed_session(db_uri) as session:
        deleted = prune_runs(session, before=cutoff, statuses=statuses)
        session.commit()
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
