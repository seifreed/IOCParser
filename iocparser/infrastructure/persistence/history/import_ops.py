from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from iocparser.domain.sources import normalize_url_value
from iocparser.infrastructure.persistence.history.ops import (
    AMBIGUOUS_LEGACY_HISTORY_ARCHIVE,
    INVALID_HISTORY_ARCHIVE,
    _archive_id,
    _distributed_internal_job_id,
    _has_legacy_archive_collision,
    _is_legacy_archive,
    _json_import_marker,
    _json_object,
    _json_with_import_marker,
    _json_without_import_marker,
    _managed_session,
    _normalized_ioc_type,
    _normalized_text,
    _payload_rows,
    _same_origin_archive,
    _string_key_mapping,
)
from iocparser.infrastructure.persistence.history.row_values import (
    bool_from_row,
    int_from_row,
    typed_row,
)
from iocparser.infrastructure.persistence_batch import (
    BatchJobModel,
    FailedBatchItemModel,
)
from iocparser.infrastructure.persistence_distributed_records import HISTORY_IMPORT_MARKER_KEY
from iocparser.infrastructure.persistence_distributed_support import normalized_queue_backend
from iocparser.infrastructure.persistence_repository_support import (
    build_tags_search,
    ioc_dedup_hash,
    normalize_ioc_search,
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
from iocparser.infrastructure.persistence_support import (
    legacy_url_value_clause,
    normalized_source_filter,
)


def _source_identity(row: dict[str, object]) -> tuple[object, ...]:
    kind = normalized_source_filter(str(row.get("kind", "")))
    value = str(row.get("value", "")).strip()
    normalized_url = row.get("normalized_url")
    if kind == "url":
        normalized = normalize_url_value(str(normalized_url)) or normalize_url_value(value) or value
        return ("url", normalized)
    return (kind, value)


def _existing_source(session: Session, row: dict[str, object]) -> SourceModel | None:
    identity = _source_identity(row)
    if identity[0] == "url":
        value = str(row.get("value", "")).strip()
        normalized_url = str(identity[1])
        stmt = select(SourceModel).where(SourceModel.kind == "url")
        clauses = []
        if value:
            clauses.append(func.trim(SourceModel.value) == value)
        if normalized_url:
            clauses.append(SourceModel.normalized_url == normalized_url)
        clauses.append(
            and_(
                func.coalesce(func.trim(SourceModel.normalized_url), "") == "",
                legacy_url_value_clause(value),
            )
        )
        stmt = stmt.where(or_(*clauses)) if clauses else stmt.where(func.trim(SourceModel.value) == value)
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
    value = str(identity[1])
    return session.execute(
        select(SourceModel).where(
            SourceModel.kind == str(identity[0]), func.trim(SourceModel.value) == value
        )
    ).scalar_one_or_none()


def _existing_ioc(session: Session, row: dict[str, object]) -> IOCModel | None:
    ioc_type = _normalized_ioc_type(str(row.get("ioc_type", "")))
    value = str(row.get("value", "")).strip()
    return session.execute(
        select(IOCModel).where(
            IOCModel.ioc_type == ioc_type,
            IOCModel.value == value,
            IOCModel.is_warning == bool_from_row(row.get("is_warning")),
            IOCModel.warning_list == str(row.get("warning_list", "")).strip(),
            IOCModel.warning_description == str(row.get("warning_description", "")).strip(),
        )
    ).scalar_one_or_none()


def _batch_job_signature(row: dict[str, object]) -> tuple[object, ...]:
    return (str(row.get("source_kind", "")), row.get("started_at"), row.get("finished_at"), int_from_row(row.get("total_inputs"), default=0) or 0, int_from_row(row.get("successful_inputs"), default=0) or 0, int_from_row(row.get("failed_inputs"), default=0) or 0, int_from_row(row.get("retry_attempt"), default=0) or 0, _normalized_text(row.get("status"), default="queued"), _normalized_text(row.get("config_json"), default="{}"), _normalized_text(row.get("error_summary_json"), default="{}"), _normalized_text(row.get("metrics_json"), default="{}"))


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
    tool_version = str(row.get("tool_version", "")).strip()
    status = _normalized_text(row.get("status"), default="success")
    error_message = _normalized_text(row.get("error_message"), default="")
    candidates = (
        session.execute(
            select(RunModel).where(
                RunModel.source_id == source_id,
                RunModel.batch_job_id == batch_job_id,
                RunModel.started_at == row.get("started_at"),
                RunModel.finished_at == row.get("finished_at"),
                RunModel.tool_version == tool_version,
                RunModel.normal_ioc_count == int(row.get("normal_ioc_count", 0)),  # type: ignore[call-overload]
                RunModel.warning_ioc_count == int(row.get("warning_ioc_count", 0)),  # type: ignore[call-overload]
                RunModel.processed_items == int(row.get("processed_items", 0)),  # type: ignore[call-overload]
                RunModel.successful_items == int(row.get("successful_items", 0)),  # type: ignore[call-overload]
                RunModel.failed_items == int(row.get("failed_items", 0)),  # type: ignore[call-overload]
                RunModel.partial_error_count == int(row.get("partial_error_count", 0)),  # type: ignore[call-overload]
                RunModel.duration_ms == int(row.get("duration_ms", 0)),  # type: ignore[call-overload]
                RunModel.status == status,
                RunModel.error_message == error_message,
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


def _existing_distributed_job(
    session: Session,
    row: dict[str, object],
    *,
    archive_id: str,
    same_origin: bool,
) -> DistributedJobModel | None:
    original_id = row.get("id")
    public_job_id = str(row.get("job_id", "")).strip()
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
    public_job_id = str(row.get("job_id", "")).strip()
    queue_backend = normalized_queue_backend(str(row.get("queue_backend", "")))
    queue_name = str(row.get("queue_name", "")).strip()
    source_value = str(row.get("source_value", "")).strip()
    correlation_id = str(row.get("correlation_id", "")).strip()
    error_code = str(row.get("error_code", "")).strip()
    error_category = str(row.get("error_category", "")).strip()
    error_message = str(row.get("error_message", "")).strip()
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
                DeadLetterJobModel.correlation_id == correlation_id,
                DeadLetterJobModel.queue_backend == queue_backend,
                DeadLetterJobModel.queue_name == queue_name,
                DeadLetterJobModel.source_value == source_value,
                DeadLetterJobModel.attempts == int(row.get("attempts", 0)),  # type: ignore[call-overload]
                DeadLetterJobModel.max_attempts == int(row.get("max_attempts", 0)),  # type: ignore[call-overload]
                DeadLetterJobModel.error_code == error_code,
                DeadLetterJobModel.error_category == error_category,
                DeadLetterJobModel.error_message == error_message,
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
        if not all(isinstance(typed.get(key), str) for key in ("kind", "value")) or not all(
            isinstance(typed.get(key), datetime) for key in ("first_seen", "last_seen")
        ):
            continue
        kind = normalized_source_filter(str(typed.get("kind", "")))
        if not kind:
            continue
        typed["kind"] = kind
        if kind == "url":
            typed["value"] = str(typed.get("value", "")).strip()
            typed["original_url"] = typed.get("original_url") or typed.get("value")
            typed["normalized_url"] = normalize_url_value(str(typed.get("normalized_url", ""))) or normalize_url_value(str(typed.get("value", "")))
        typed["dedup_hash"] = source_dedup_hash(
            kind, str(typed.get("value", ""))
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
        if not isinstance(typed.get("ioc_type"), str) or not isinstance(typed.get("value"), str):
            continue
        ioc_type = _normalized_ioc_type(str(typed.get("ioc_type", "")))
        typed["ioc_type"] = ioc_type
        typed["value"] = str(typed.get("value", "")).strip()
        if not typed["value"]:
            continue
        typed["warning_list"] = str(typed.get("warning_list", "")).strip()
        typed["warning_description"] = str(typed.get("warning_description", "")).strip()
        search_value = normalize_ioc_search(str(typed.get("value", "")))
        typed["value_search"] = search_value
        typed["dedup_hash"] = ioc_dedup_hash(
            ioc_type,
            str(typed["value"]),
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


def _find_existing_batch_job(
    session: Session,
    candidate_ids: list[int],
    *,
    typed: dict[str, object],
    import_marker: dict[str, object],
    same_origin: bool,
) -> BatchJobModel | None:
    for batch_job_id in candidate_ids:
        candidate = session.get(BatchJobModel, batch_job_id)
        if candidate is None:
            continue
        if _json_without_import_marker(candidate.config_json) != _json_without_import_marker(
            typed.get("config_json", "{}")
        ):
            continue
        candidate_config = _json_object(candidate.config_json)
        if candidate_config.get(HISTORY_IMPORT_MARKER_KEY) == import_marker:
            return candidate
        if same_origin and HISTORY_IMPORT_MARKER_KEY not in candidate_config:
            return candidate
    return None


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
        if not isinstance(typed.get("source_kind"), str) or not all(
            isinstance(typed.get(key), datetime) for key in ("started_at", "finished_at")
        ):
            continue
        typed["source_kind"] = normalized_source_filter(str(typed.get("source_kind", "")))
        if not typed["source_kind"]:
            continue
        typed["status"] = _normalized_text(typed.get("status"), default="queued")
        typed["error_summary_json"] = _json_without_import_marker(
            _normalized_text(typed.get("error_summary_json"), default="{}")
        )
        typed["metrics_json"] = _json_without_import_marker(
            _normalized_text(typed.get("metrics_json"), default="{}")
        )
        original_id = typed.get("id")
        import_marker = {
            "archive_id": archive_id,
            "original_id": original_id,
        }
        existing_matches = (
            session.execute(
                select(BatchJobModel.id)
                .where(
                    BatchJobModel.source_kind == typed["source_kind"],
                    BatchJobModel.started_at == typed.get("started_at"),
                    BatchJobModel.finished_at == typed.get("finished_at"),
                    BatchJobModel.total_inputs == int(typed.get("total_inputs", 0)),  # type: ignore[call-overload]
                    BatchJobModel.successful_inputs == int(typed.get("successful_inputs", 0)),  # type: ignore[call-overload]
                    BatchJobModel.failed_inputs == int(typed.get("failed_inputs", 0)),  # type: ignore[call-overload]
                    BatchJobModel.retry_attempt == int(typed.get("retry_attempt", 0)),  # type: ignore[call-overload]
                    BatchJobModel.status == typed["status"],
                    BatchJobModel.error_summary_json == typed["error_summary_json"],
                    BatchJobModel.metrics_json == typed["metrics_json"],
                )
                .order_by(BatchJobModel.id.asc())
            )
            .scalars()
            .all()
        )
        existing = _find_existing_batch_job(
            session,
            list(existing_matches),
            typed=typed,
            import_marker=import_marker,
            same_origin=same_origin,
        )
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
        if not isinstance(typed.get("tool_version"), str) or not all(
            isinstance(typed.get(key), datetime) for key in ("started_at", "finished_at")
        ):
            continue
        typed["tool_version"] = str(typed.get("tool_version", "")).strip()
        if not typed["tool_version"]:
            continue
        typed["status"] = _normalized_text(typed.get("status"), default="success")
        typed["error_message"] = _normalized_text(typed.get("error_message"), default="")
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
    seen_signatures: dict[tuple[object, ...], int] = {}
    for row in rows:
        typed = typed_row(row)
        batch_job_id = batch_map.get(int_from_row(typed.get("batch_job_id"), default=0) or 0)
        if batch_job_id is None:
            continue
        if not all(
            isinstance(value := typed.get(key), str) and value.strip()
            for key in ("source_value", "error_type", "error_message")
        ) or not isinstance(typed.get("created_at"), datetime):
            continue
        typed["source_value"] = str(typed.get("source_value", "")).strip()
        typed["error_type"] = str(typed.get("error_type", "")).strip()
        typed["error_message"] = str(typed.get("error_message", "")).strip()
        signature = (
            batch_job_id,
            typed["source_value"],
            typed["error_type"],
            typed["error_message"],
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
        if not all(
            isinstance(value := typed.get(key), str) and value.strip()
            for key in ("correlation_id", "queue_backend", "queue_name", "input_kind", "source_value")
        ) or not isinstance(typed.get("submitted_at"), datetime):
            continue
        typed["job_id"] = _normalized_text(typed.get("job_id"), default="")
        if not typed["job_id"]:
            continue
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
            not all(
                isinstance(value := typed.get(key), str) and value.strip()
                for key in ("correlation_id", "queue_backend", "queue_name", "source_value")
            )
            or not all(
                isinstance(value := typed.get(key), str) and value.strip()
                for key in ("error_code", "error_category", "error_message")
            )
            or not isinstance(typed.get("dead_lettered_at"), datetime)
        ):
            continue
        typed["job_id"] = _normalized_text(typed.get("job_id"), default="")
        if not typed["job_id"]:
            continue
        typed["queue_backend"] = normalized_queue_backend(str(typed.get("queue_backend", "")))
        typed["queue_name"] = str(typed.get("queue_name", "")).strip()
        typed["source_value"] = str(typed.get("source_value", "")).strip()
        typed["correlation_id"] = str(typed.get("correlation_id", "")).strip()
        typed["error_code"] = str(typed.get("error_code", "")).strip()
        typed["error_category"] = str(typed.get("error_category", "")).strip()
        typed["error_message"] = str(typed.get("error_message", "")).strip()
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


def restore_history(db_uri: str, archive_path: str) -> dict[str, int]:
    try:
        payload: object = json.loads(Path(archive_path).expanduser().read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TypeError(INVALID_HISTORY_ARCHIVE) from exc
    if not isinstance(payload, dict):
        raise TypeError(INVALID_HISTORY_ARCHIVE)
    return import_history(db_uri, _string_key_mapping(payload))
