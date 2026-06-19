from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import ClauseElement, Select, delete, func, or_, select
from sqlalchemy.orm import Session

from iocparser.domain.models import (
    IOC,
    ExtractionResult,
    IOCEvidence,
    PersistedRunQueryHit,
    PersistedRunSummary,
    WarningMatch,
    classify_ioc,
)
from iocparser.domain.sources import normalize_url_value
from iocparser.errors import ValidationError
from iocparser.infrastructure.persistence_schema import IOCModel, RunIOCModel, RunModel, SourceModel

INVALID_DATETIME_FILTER = (
    "Invalid date/datetime value: {value!r} (expected ISO 8601, e.g. 2024-01-31 or "
    "2024-01-31T12:00:00)"
)

SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


def _json_list(raw_value: str) -> list[object]:
    try:
        decoded: object = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON array") from exc
    if not isinstance(decoded, list):
        raise ValueError("Expected JSON array")
    return list(decoded)


def _evidence_from_json(raw_value: str) -> tuple[IOCEvidence, ...]:
    evidences: list[IOCEvidence] = []
    for entry in _json_list(raw_value or "[]"):
        if not isinstance(entry, dict):
            continue
        line_number_raw = entry.get("line_number")
        if isinstance(line_number_raw, bool):
            raise TypeError(f"Expected line_number to be int, got {type(line_number_raw).__name__}")
        line_number = line_number_raw if isinstance(line_number_raw, int) else None
        excerpt = entry.get("excerpt")
        source = entry.get("source")
        if not isinstance(excerpt, str) or not isinstance(source, str):
            continue
        evidences.append(
            IOCEvidence(
                excerpt=excerpt,
                line_number=line_number,
                source=source,
            ),
        )
    return tuple(evidences)


def _tags_from_json(raw_value: str) -> tuple[str, ...]:
    return tuple(tag for tag in _json_list(raw_value or "[]") if isinstance(tag, str))


def _evidence_records_from_json(raw_value: str) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for entry in _json_list(raw_value or "[]"):
        if isinstance(entry, dict):
            records.append({key: value for key, value in entry.items() if isinstance(key, str)})
    return tuple(records)


def parse_datetime(value: str | None) -> datetime | None:
    """Parse an ISO timestamp when present, normalized to naive UTC.

    Stored timestamps are naive UTC, so a tz-aware filter value (e.g. ...+05:00
    or ...Z) must be converted to UTC and made naive before comparison;
    otherwise its wall-clock numbers are compared directly, off by the offset.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    # fromisoformat raises a bare ValueError on bad input (e.g. --date-from garbage);
    # translate it to a ValidationError so the CLI reports a clean message instead of
    # dumping a stack trace for what is just bad user input.
    try:
        parsed = datetime.fromisoformat(stripped)
    except ValueError as exc:
        raise ValidationError(INVALID_DATETIME_FILTER.format(value=value)) from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed

def normalized_source_filter(value: str) -> str:
    return value.strip().lower()

def normalized_url_filter(value: str) -> str | None:
    return normalize_url_value(value)

def _url_filter_variants(value: str) -> tuple[str, ...]:
    normalized = normalize_url_value(value)
    if normalized is None:
        return ()
    parsed = urlsplit(normalized)
    variants = [normalized]
    if not parsed.query and not parsed.fragment:
        if parsed.path.endswith("/") and parsed.path != "/":
            variants.append(urlunsplit(parsed._replace(path=parsed.path.rstrip("/"))))
        elif parsed.path == "/":
            variants.append(urlunsplit(parsed._replace(path="")))
        elif parsed.path:
            variants.append(urlunsplit(parsed._replace(path=f"{parsed.path}/")))
        else:
            variants.append(urlunsplit(parsed._replace(path="/")))
    return tuple(dict.fromkeys(variants))


def source_value_clause(*, source_kind: str | None, source_value: str) -> ClauseElement:
    if source_kind is not None and not isinstance(source_kind, str):
        raise TypeError(f"Expected source_kind to be string-like, got {type(source_kind).__name__}")
    if not isinstance(source_value, str):
        raise TypeError(f"Expected source_value to be string-like, got {type(source_value).__name__}")
    normalized_kind = source_kind.strip().lower() if source_kind is not None else ""
    exact_value = source_value.strip()
    if normalized_kind != "url":
        return SourceModel.value == exact_value
    clauses: list[ClauseElement] = [SourceModel.value == exact_value]
    clauses.extend(func.coalesce(SourceModel.normalized_url, "") == candidate for candidate in _url_filter_variants(exact_value))
    return or_(*clauses) if len(clauses) > 1 else clauses[0]


def build_summary(session: Session, run: RunModel) -> PersistedRunSummary:
    """Build a persisted run summary from ORM state."""
    return PersistedRunSummary(
        run_id=run.id,
        source_kind=run.source.kind,
        source_value=run.source.value,
        tool_version=run.tool_version,
        started_at=run.started_at,
        finished_at=run.finished_at,
        normal_ioc_count=run.normal_ioc_count,
        warning_ioc_count=run.warning_ioc_count,
        counts_by_type=load_result(session, run.id).counts_by_type(),
        original_url=run.source.original_url,
        normalized_url=run.source.normalized_url,
        mime_type=run.source.mime_type,
        input_size=run.source.input_size,
        content_hash=run.source.content_hash,
        fingerprint=run.source.fingerprint,
        duration_ms=run.duration_ms,
        processed_items=run.processed_items,
        successful_items=run.successful_items,
        failed_items=run.failed_items,
        partial_error_count=run.partial_error_count,
        status=run.status,
        error_message=run.error_message,
    )


def load_result(session: Session, run_id: int) -> ExtractionResult:
    """Rehydrate a normalized extraction result from ORM state."""
    stmt = (
        select(IOCModel, RunIOCModel)
        .join(RunIOCModel, RunIOCModel.ioc_id == IOCModel.id)
        .where(RunIOCModel.run_id == run_id)
    )
    rows = session.execute(stmt).all()
    normal_iocs: list[IOC] = []
    warnings: list[WarningMatch] = []
    for model, run_ioc in rows:
        evidence = _evidence_from_json(run_ioc.evidence_json or "[]")
        tags = _tags_from_json(run_ioc.tags_json or "[]")
        if model.is_warning:
            inferred_type = IOC.from_raw(model.ioc_type, model.value).ioc_type
            warning_severity, warning_tags = classify_ioc(inferred_type, is_warning=True)
            warnings.append(
                WarningMatch(
                    ioc=IOC.from_raw(
                        model.ioc_type,
                        model.value,
                        evidence=evidence,
                        severity=run_ioc.severity or warning_severity,
                        tags=tags or warning_tags,
                    ),
                    warning_list=model.warning_list,
                    description=model.warning_description,
                ),
            )
        else:
            normal_iocs.append(
                IOC.from_raw(
                    model.ioc_type,
                    model.value,
                    evidence=evidence,
                    severity=run_ioc.severity or None,
                    tags=tags,
                ),
            )
    return ExtractionResult(iocs=tuple(normal_iocs), warnings=tuple(warnings))


def build_query_hits(
    rows: list[tuple[RunModel, SourceModel, IOCModel, RunIOCModel]],
) -> list[PersistedRunQueryHit]:
    """Build persisted query hits from joined ORM rows."""
    return [
        PersistedRunQueryHit(
            run_id=run.id,
            source_kind=source.kind,
            source_value=source.value,
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            is_warning=ioc.is_warning,
            severity=run_ioc.severity,
            tags=_tags_from_json(run_ioc.tags_json or "[]"),
            evidence=_evidence_records_from_json(run_ioc.evidence_json or "[]"),
        )
        for run, source, ioc, run_ioc in rows
    ]


def matches_advanced_filters(
    hit: PersistedRunQueryHit,
    *,
    tags: tuple[str, ...],
    exclude_tags: tuple[str, ...],
    min_severity: str | None,
    tag_mode: str,
) -> bool:
    """Evaluate advanced in-memory filters for persisted IOC hits."""
    if tags:
        tag_set = set(hit.tags)
        required = set(tags)
        if tag_mode == "any":
            if not tag_set.intersection(required):
                return False
        elif not required.issubset(tag_set):
            return False
    if exclude_tags and any(tag in hit.tags for tag in exclude_tags):
        return False
    if min_severity is None:
        return True
    return SEVERITY_ORDER.get((hit.severity or "").lower(), -1) >= SEVERITY_ORDER.get(
        min_severity.lower(), 0
    )


def delete_run(session: Session, run_id: int) -> bool:
    """Delete a persisted run and its join rows."""
    run = session.get(RunModel, run_id)
    if run is None:
        return False
    session.execute(delete(RunIOCModel).where(RunIOCModel.run_id == run_id))
    session.delete(run)
    return True


def cleanup_orphaned_records(session: Session) -> int:
    """Remove IOC and source records that are no longer referenced by any run."""
    from sqlalchemy import exists

    orphaned_iocs = (
        session.execute(
            select(IOCModel.id).where(
                ~exists(select(RunIOCModel.id).where(RunIOCModel.ioc_id == IOCModel.id))
            )
        )
        .scalars()
        .all()
    )
    deleted = 0
    if orphaned_iocs:
        session.execute(delete(IOCModel).where(IOCModel.id.in_(orphaned_iocs)))
        deleted += len(orphaned_iocs)

    orphaned_sources = (
        session.execute(
            select(SourceModel.id).where(
                ~exists(select(RunModel.id).where(RunModel.source_id == SourceModel.id))
            )
        )
        .scalars()
        .all()
    )
    if orphaned_sources:
        session.execute(delete(SourceModel).where(SourceModel.id.in_(orphaned_sources)))
        deleted += len(orphaned_sources)

    return deleted


def _build_prune_query(
    *,
    before: str | None,
    source_kind: str | None,
    source_value: str | None,
    statuses: tuple[str, ...],
) -> Select[RunModel]:
    stmt = select(RunModel).join(SourceModel, RunModel.source_id == SourceModel.id)
    if before:
        stmt = stmt.where(RunModel.started_at < parse_datetime(before))
    if source_kind:
        stmt = stmt.where(SourceModel.kind == source_kind)
    if source_value:
        stmt = stmt.where(source_value_clause(source_kind=source_kind, source_value=source_value))
    if statuses:
        stmt = stmt.where(RunModel.status.in_(statuses))
    return stmt.order_by(RunModel.started_at.desc(), RunModel.id.desc())


def _select_deletable(runs: list[RunModel], keep_latest: int) -> list[RunModel]:
    if keep_latest <= 0:
        return list(runs)
    runs_by_source: dict[int, list[RunModel]] = {}
    for run in runs:
        runs_by_source.setdefault(run.source_id, []).append(run)
    deletable: list[RunModel] = []
    for source_runs in runs_by_source.values():
        deletable.extend(source_runs[keep_latest:])
    return deletable


def prune_runs(
    session: Session,
    *,
    before: str | None = None,
    keep_latest: int = 0,
    source_kind: str | None = None,
    source_value: str | None = None,
    statuses: tuple[str, ...] = (),
) -> int:
    """Prune persisted runs and return the number of deleted rows."""
    stmt = _build_prune_query(
        before=before, source_kind=source_kind, source_value=source_value, statuses=statuses
    )
    runs = session.execute(stmt).scalars().all()
    deletable = _select_deletable(runs, keep_latest)
    deleted = sum(1 for run in deletable if delete_run(session, run.id))
    if deleted > 0:
        session.flush()
        cleanup_orphaned_records(session)
    return deleted
