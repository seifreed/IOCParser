from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import override

from sqlalchemy import ClauseElement, Select, and_, func, or_, select, text

from iocparser.domain.models import (
    BatchJobDetail,
    BatchJobSummary,
    DeadLetterRecord,
    DistributedJobRecord,
    ExtractionResult,
    FailedBatchItem,
    PersistedIOCSearchPage,
    PersistedRunDiff,
    PersistedRunExport,
    PersistedRunQueryHit,
    PersistedRunsPage,
    PersistedRunSummary,
    PersistOptions,
)
from iocparser.domain.sources import Source
from iocparser.infrastructure.persistence.history import (
    compact_history as _compact_history,
)
from iocparser.infrastructure.persistence.history import (
    export_history as _export_history,
)
from iocparser.infrastructure.persistence.history import (
    get_batch_job as _get_batch_job,
)
from iocparser.infrastructure.persistence.history import (
    import_history as _import_history,
)
from iocparser.infrastructure.persistence.history import (
    list_batch_jobs as _list_batch_jobs,
)
from iocparser.infrastructure.persistence.history import (
    list_batch_runs as _list_batch_runs,
)
from iocparser.infrastructure.persistence.history import (
    list_failed_batch_items as _list_failed_batch_items,
)
from iocparser.infrastructure.persistence.history import (
    list_failed_batches as _list_failed_batches,
)
from iocparser.infrastructure.persistence.history import (
    retain_history as _retain_history,
)
from iocparser.infrastructure.persistence.query.diff import diff_run_exports
from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService
from iocparser.infrastructure.persistence_fts import build_fts_query, has_fts_table
from iocparser.infrastructure.persistence_repository_support import normalize_ioc_search
from iocparser.infrastructure.persistence_schema import (
    IOCModel,
    RunIOCModel,
    RunModel,
    SourceModel,
    SQLAlchemyUnitOfWork,
)
from iocparser.infrastructure.persistence_support import (
    SEVERITY_ORDER,
    build_query_hits,
    build_summary,
    delete_run,
    load_result,
    parse_datetime,
    prune_runs,
    source_value_clause,
)
from iocparser.interfaces.ports import PersistenceQueryService
from iocparser.shared_utils import normalize_tokens

RUN_NOT_FOUND_TEMPLATE = "Run not found: {run_id}"
PREVIOUS_RUN_NOT_FOUND_TEMPLATE = "No previous run found for source of run {run_id}"

FTS_QUERY_REQUIRED = "FTS search requires at least one alphanumeric term"
SEARCH_QUERY_REQUIRED = "IOC search requires a non-empty value"
RunSelect = Select[RunModel]
SearchSelect = Select[tuple[RunModel, SourceModel, IOCModel, RunIOCModel]]


@dataclass(frozen=True)
class RunPageQuery:
    db_uri: str
    limit: int = 20
    offset: int = 0
    date_from: str | None = None
    date_to: str | None = None
    source_kind: str | None = None
    source_value: str | None = None
    sort_by: str = "newest"


@dataclass(frozen=True)
class IOCSearchPageQuery:
    db_uri: str
    value: str
    limit: int = 50
    offset: int = 0
    date_from: str | None = None
    date_to: str | None = None
    source_kind: str | None = None
    source_value: str | None = None
    ioc_type: str | None = None
    severity: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    exclude_tags: tuple[str, ...] = ()
    min_severity: str | None = None
    tag_mode: str = "all"
    sort_by: str = "newest"
    search_backend: str = "auto"


def query_runs_page(query: RunPageQuery) -> PersistedRunsPage:
    unit_of_work = SQLAlchemyUnitOfWork(query.db_uri)
    try:
        stmt: RunSelect = select(RunModel).join(SourceModel, RunModel.source_id == SourceModel.id)
        count_stmt = (
            select(func.count())
            .select_from(RunModel)
            .join(SourceModel, RunModel.source_id == SourceModel.id)
        )
        for clause in _run_filter_clauses(
            date_from=query.date_from,
            date_to=query.date_to,
            source_kind=query.source_kind,
            source_value=query.source_value,
        ):
            stmt = stmt.where(clause)
            count_stmt = count_stmt.where(clause)
        stmt = _order_run_query_stmt(stmt, sort_by=query.sort_by)
        total = _coerce_count(unit_of_work.session.execute(count_stmt).scalar_one())
        limit = max(0, query.limit)
        offset = max(0, query.offset)
        runs = unit_of_work.session.execute(stmt.offset(offset).limit(limit)).scalars().all()
        return PersistedRunsPage(
            items=tuple(build_summary(unit_of_work.session, run) for run in runs),
            total=total,
            limit=limit,
            offset=offset,
        )
    finally:
        unit_of_work.close()


def search_iocs_page(query: IOCSearchPageQuery) -> PersistedIOCSearchPage:
    unit_of_work = SQLAlchemyUnitOfWork(query.db_uri)
    try:
        normalized_value = normalize_ioc_search(query.value)
        if not normalized_value:
            raise ValueError(SEARCH_QUERY_REQUIRED)
        stmt = (
            select(RunModel, SourceModel, IOCModel, RunIOCModel)
            .join(SourceModel, RunModel.source_id == SourceModel.id)
            .join(RunIOCModel, RunIOCModel.run_id == RunModel.id)
            .join(IOCModel, IOCModel.id == RunIOCModel.ioc_id)
        )
        stmt = _apply_search_backend(
            stmt,
            unit_of_work=unit_of_work,
            normalized_value=normalized_value,
            search_backend=query.search_backend,
        )
        for clause in _run_filter_clauses(
            date_from=query.date_from,
            date_to=query.date_to,
            source_kind=query.source_kind,
            source_value=query.source_value,
        ):
            stmt = stmt.where(clause)
        if query.ioc_type:
            stmt = stmt.where(IOCModel.ioc_type == query.ioc_type)
        if query.severity:
            stmt = stmt.where(RunIOCModel.severity.in_(query.severity))
        if query.tags:
            tag_filters = [_tag_search_clause(tag) for tag in normalize_tokens(query.tags)]
            if tag_filters:
                stmt = stmt.where(
                    or_(*tag_filters) if query.tag_mode == "any" else and_(*tag_filters)
                )
        for tag in query.exclude_tags:
            normalized_tag = tag.strip().lower()
            if normalized_tag:
                stmt = stmt.where(~_tag_search_clause(normalized_tag))
        if query.min_severity:
            threshold = SEVERITY_ORDER.get(query.min_severity.lower(), 0)
            allowed = tuple(name for name, rank in SEVERITY_ORDER.items() if rank >= threshold)
            stmt = stmt.where(RunIOCModel.severity.in_(allowed))
        stmt = _order_run_query_stmt(stmt, sort_by=query.sort_by)
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = _coerce_count(unit_of_work.session.execute(count_stmt).scalar_one())
        limit = max(0, query.limit)
        offset = max(0, query.offset)
        rows = unit_of_work.session.execute(stmt.offset(offset).limit(limit)).all()
        return PersistedIOCSearchPage(
            items=tuple(build_query_hits(rows)),
            total=total,
            limit=limit,
            offset=offset,
        )
    finally:
        unit_of_work.close()


def _run_filter_clauses(
    *,
    date_from: str | None,
    date_to: str | None,
    source_kind: str | None,
    source_value: str | None,
) -> tuple[ClauseElement, ...]:
    clauses: list[ClauseElement] = []
    if date_from:
        clauses.append(RunModel.started_at >= parse_datetime(date_from))
    if date_to:
        clauses.append(RunModel.started_at <= parse_datetime(date_to))
    if source_kind:
        clauses.append(SourceModel.kind == source_kind)
    if source_value:
        clauses.append(source_value_clause(source_kind=source_kind, source_value=source_value))
    return tuple(clauses)


def _order_run_query_stmt[SelectT: (RunSelect, SearchSelect)](
    stmt: SelectT, *, sort_by: str
) -> SelectT:
    if sort_by == "oldest":
        return stmt.order_by(RunModel.started_at.asc(), RunModel.id.asc())
    if sort_by == "source":
        return stmt.order_by(
            SourceModel.kind.asc(),
            SourceModel.value.asc(),
            RunModel.started_at.desc(),
            RunModel.id.desc(),
        )
    return stmt.order_by(RunModel.started_at.desc(), RunModel.id.desc())


def _escaped_like_value(normalized_value: str) -> str:
    return normalized_value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _tag_search_clause(normalized_tag: str) -> ClauseElement:
    escaped = _escaped_like_value(normalized_tag)
    return or_(
        RunIOCModel.tags_search == normalized_tag,
        RunIOCModel.tags_search.like(f"{escaped} %", escape="\\"),
        RunIOCModel.tags_search.like(f"% {escaped}", escape="\\"),
        RunIOCModel.tags_search.like(f"% {escaped} %", escape="\\"),
    )


def _apply_search_backend(
    stmt: SearchSelect,
    *,
    unit_of_work: SQLAlchemyUnitOfWork,
    normalized_value: str,
    search_backend: str,
) -> SearchSelect:
    use_sqlite_fts = search_backend in {"auto", "fts"} and has_fts_table(unit_of_work.engine)
    fts_query = build_fts_query(normalized_value) if use_sqlite_fts else None
    if search_backend == "fts" and not fts_query:
        raise ValueError(FTS_QUERY_REQUIRED)
    if fts_query:
        filter_clause: ClauseElement = text(
            "iocs.id IN (SELECT rowid FROM ioc_search_fts WHERE ioc_search_fts MATCH :fts_query)",
        )
        return stmt.where(filter_clause).params(fts_query=fts_query)
    return stmt.where(
        IOCModel.value_search.like(f"%{_escaped_like_value(normalized_value)}%", escape="\\")
    )


def _coerce_count(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    if value is None:
        return 0
    raise TypeError(f"Expected integer count, got {type(value).__name__}: {value!r}")


class SQLAlchemyPersistenceService(PersistenceQueryService):
    """Convenience service for batch persistence and queries."""

    _parse_datetime = staticmethod(parse_datetime)

    def __init__(self, db_uri: str) -> None:
        self.db_uri = db_uri

    def list_failed_batches(self, *, limit: int = 20) -> list[BatchJobSummary]:
        return _list_failed_batches(self.db_uri, limit=limit)

    def list_failed_batch_items(self, *, batch_job_id: int) -> list[FailedBatchItem]:
        return _list_failed_batch_items(self.db_uri, batch_job_id=batch_job_id)

    def list_batch_jobs(
        self, *, limit: int = 20, statuses: tuple[str, ...] = ()
    ) -> list[BatchJobSummary]:
        return _list_batch_jobs(self.db_uri, limit=limit, statuses=statuses)

    def get_batch_job(self, *, batch_job_id: int) -> BatchJobDetail | None:
        return _get_batch_job(self.db_uri, batch_job_id=batch_job_id)

    def persist_batch_job(
        self,
        *,
        source_kind: str,
        run_ids: tuple[int, ...],
        report: dict[str, object],
        config: dict[str, object],
    ) -> int:
        from iocparser.infrastructure.persistence_batch import create_batch_job
        from iocparser.infrastructure.persistence_schema import SQLAlchemyUnitOfWork

        unit = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            batch_job_id = create_batch_job(
                unit.session,
                source_kind=source_kind,
                run_ids=run_ids,
                report=report,
                config=config,
            )
            unit.commit()
            return batch_job_id
        finally:
            unit.close()

    def list_batch_runs(self, *, batch_job_id: int) -> list[PersistedRunSummary]:
        return _list_batch_runs(self.db_uri, batch_job_id=batch_job_id)

    def persist_multiple_runs(
        self,
        runs: Iterable[tuple[str, str, ExtractionResult]],
        tool_version: str,
        options: PersistOptions,
    ) -> list[int]:
        """Persist multiple runs, returning run IDs."""
        run_ids: list[int] = []
        for kind, value, result in runs:
            unit_of_work = SQLAlchemyUnitOfWork(self.db_uri)
            try:
                source = Source.from_raw(kind, value)
                source_id = unit_of_work.source_repository.get_or_create(
                    kind=kind,
                    value=value,
                    original_url=source.original_url,
                    normalized_url=source.normalized_url,
                    mime_type=source.mime_type,
                    input_size=source.input_size,
                    content_hash=source.content_hash,
                    fingerprint=source.fingerprint,
                )
                metadata: dict[str, int | str | None] = {
                    "normal_ioc_count": len(result.iocs),
                    "warning_ioc_count": len(result.warnings),
                    "processed_items": 1,
                    "successful_items": 1,
                    "failed_items": 0,
                    "partial_error_count": 0,
                }
                run_id = unit_of_work.run_repository.create_run(
                    source_id=source_id,
                    tool_version=tool_version,
                    options=options,
                    metadata=metadata,
                )
                ioc_ids = unit_of_work.ioc_repository.get_or_create_normal(result)
                ioc_ids.extend(unit_of_work.ioc_repository.get_or_create_warnings(result))
                unit_of_work.run_repository.attach_iocs(
                    run_id=run_id, ioc_ids=ioc_ids, result=result
                )
                unit_of_work.commit()
                run_ids.append(run_id)
            finally:
                unit_of_work.close()
        return run_ids

    @override
    def list_runs(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        date_from: str | None = None,
        date_to: str | None = None,
        source_kind: str | None = None,
        source_value: str | None = None,
        sort_by: str = "newest",
        search_backend: str = "auto",
    ) -> list[PersistedRunSummary]:
        """List persisted runs."""
        return list(
            query_runs_page(
                RunPageQuery(
                    db_uri=self.db_uri,
                    limit=limit,
                    offset=offset,
                    date_from=date_from,
                    date_to=date_to,
                    source_kind=source_kind,
                    source_value=source_value,
                    sort_by=sort_by,
                )
            ).items,
        )

    @override
    def query_runs_page(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        date_from: str | None = None,
        date_to: str | None = None,
        source_kind: str | None = None,
        source_value: str | None = None,
        sort_by: str = "newest",
    ) -> PersistedRunsPage:
        return query_runs_page(
            RunPageQuery(
                db_uri=self.db_uri,
                limit=limit,
                offset=offset,
                date_from=date_from,
                date_to=date_to,
                source_kind=source_kind,
                source_value=source_value,
                sort_by=sort_by,
            )
        )

    @override
    def search_iocs(
        self,
        *,
        value: str,
        limit: int = 50,
        offset: int = 0,
        date_from: str | None = None,
        date_to: str | None = None,
        source_kind: str | None = None,
        source_value: str | None = None,
        ioc_type: str | None = None,
        severity: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
        exclude_tags: tuple[str, ...] = (),
        min_severity: str | None = None,
        tag_mode: str = "all",
        sort_by: str = "newest",
        search_backend: str = "auto",
    ) -> list[PersistedRunQueryHit]:
        """Search persisted IOCs by value."""
        return list(
            search_iocs_page(
                IOCSearchPageQuery(
                    db_uri=self.db_uri,
                    value=value,
                    limit=limit,
                    offset=offset,
                    date_from=date_from,
                    date_to=date_to,
                    source_kind=source_kind,
                    source_value=source_value,
                    ioc_type=ioc_type,
                    severity=severity,
                    tags=tags,
                    exclude_tags=exclude_tags,
                    min_severity=min_severity,
                    tag_mode=tag_mode,
                    sort_by=sort_by,
                    search_backend=search_backend,
                )
            ).items,
        )

    @override
    def search_iocs_page(
        self,
        *,
        value: str,
        limit: int = 50,
        offset: int = 0,
        date_from: str | None = None,
        date_to: str | None = None,
        source_kind: str | None = None,
        source_value: str | None = None,
        ioc_type: str | None = None,
        severity: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
        exclude_tags: tuple[str, ...] = (),
        min_severity: str | None = None,
        tag_mode: str = "all",
        sort_by: str = "newest",
        search_backend: str = "auto",
    ) -> PersistedIOCSearchPage:
        return search_iocs_page(
            IOCSearchPageQuery(
                db_uri=self.db_uri,
                value=value,
                limit=limit,
                offset=offset,
                date_from=date_from,
                date_to=date_to,
                source_kind=source_kind,
                source_value=source_value,
                ioc_type=ioc_type,
                severity=severity,
                tags=tags,
                exclude_tags=exclude_tags,
                min_severity=min_severity,
                tag_mode=tag_mode,
                sort_by=sort_by,
                search_backend=search_backend,
            )
        )

    def find_existing_run(
        self,
        *,
        fingerprint: str | None = None,
        content_hash: str | None = None,
        status: str = "success",
    ) -> PersistedRunSummary | None:
        """Find the latest persisted run for a fingerprint/content hash."""
        if not fingerprint and not content_hash:
            return None
        unit_of_work = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            stmt = (
                select(RunModel)
                .join(SourceModel, RunModel.source_id == SourceModel.id)
                .where(RunModel.status == status)
            )
            if fingerprint:
                stmt = stmt.where(SourceModel.fingerprint == fingerprint)
            if content_hash:
                stmt = stmt.where(SourceModel.content_hash == content_hash)
            stmt = stmt.order_by(RunModel.started_at.desc(), RunModel.id.desc()).limit(1)
            run = unit_of_work.session.execute(stmt).scalar_one_or_none()
            if run is None:
                return None
            return build_summary(unit_of_work.session, run)
        finally:
            unit_of_work.close()

    def export_run(self, *, run_id: int) -> PersistedRunExport:
        """Load a persisted run and rebuild its extraction result."""
        unit_of_work = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            run = unit_of_work.session.get(RunModel, run_id)
            if run is None:
                raise ValueError(RUN_NOT_FOUND_TEMPLATE.format(run_id=run_id))
            return PersistedRunExport(
                summary=build_summary(unit_of_work.session, run),
                result=load_result(unit_of_work.session, run_id),
            )
        finally:
            unit_of_work.close()

    def diff_runs(self, *, left_run_id: int, right_run_id: int) -> PersistedRunDiff:
        """Diff two persisted runs."""
        left = self.export_run(run_id=left_run_id)
        right = self.export_run(run_id=right_run_id)
        return diff_run_exports(
            left,
            right,
            left_run_id=left_run_id,
            right_run_id=right_run_id,
        )

    def diff_run_against_previous_source(self, *, run_id: int) -> PersistedRunDiff:
        """Diff a run against the latest successful prior run from the same source."""
        unit_of_work = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            run = unit_of_work.session.get(RunModel, run_id)
            if run is None:
                raise ValueError(RUN_NOT_FOUND_TEMPLATE.format(run_id=run_id))
            if run.status in ("failed", "partial"):
                raise ValueError(
                    f"Run {run_id} has status '{run.status}' — diffing a {run.status} run is "
                    "misleading because missing IOCs reflect extraction failure, "
                    "not actual absence from the source."
                )
            stmt = (
                select(RunModel)
                .where(
                    RunModel.source_id == run.source_id,
                    RunModel.status == "success",
                    or_(
                        RunModel.started_at < run.started_at,
                        and_(RunModel.started_at == run.started_at, RunModel.id < run.id),
                    ),
                )
                .order_by(RunModel.started_at.desc(), RunModel.id.desc())
                .limit(1)
            )
            previous_run = unit_of_work.session.execute(stmt).scalar_one_or_none()
            if previous_run is None:
                raise ValueError(PREVIOUS_RUN_NOT_FOUND_TEMPLATE.format(run_id=run_id))
            diff = self.diff_runs(left_run_id=previous_run.id, right_run_id=run.id)
            return PersistedRunDiff(
                left_run_id=diff.left_run_id,
                right_run_id=diff.right_run_id,
                added=diff.added,
                removed=diff.removed,
                compared_to_previous_source_run_id=previous_run.id,
            )
        finally:
            unit_of_work.close()

    def _distributed_service(self) -> SQLAlchemyDistributedJobService:
        return SQLAlchemyDistributedJobService(self.db_uri)

    def get_distributed_job(self, *, job_id: str) -> DistributedJobRecord | None:
        return self._distributed_service().get_job(job_id=job_id)

    def list_distributed_jobs(
        self,
        *,
        limit: int = 50,
        statuses: tuple[str, ...] = (),
        queue_backend: str | None = None,
    ) -> list[DistributedJobRecord]:
        return self._distributed_service().list_jobs(
            limit=limit, statuses=statuses, queue_backend=queue_backend
        )

    def list_dead_letters(
        self, *, limit: int = 50, queue_backend: str | None = None
    ) -> list[DeadLetterRecord]:
        return self._distributed_service().list_dead_letters(
            limit=limit, queue_backend=queue_backend
        )

    def delete_run(self, *, run_id: int) -> bool:
        """Delete a persisted run by id."""
        unit_of_work = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            deleted = delete_run(unit_of_work.session, run_id)
            unit_of_work.commit()
            return deleted
        finally:
            unit_of_work.close()

    def prune_runs(
        self,
        *,
        before: str | None = None,
        keep_latest: int = 0,
        source_kind: str | None = None,
        source_value: str | None = None,
        statuses: tuple[str, ...] = (),
    ) -> int:
        """Prune persisted runs and return deleted count."""
        unit_of_work = SQLAlchemyUnitOfWork(self.db_uri)
        try:
            deleted = prune_runs(
                unit_of_work.session,
                before=before,
                keep_latest=keep_latest,
                source_kind=source_kind,
                source_value=source_value,
                statuses=statuses,
            )
            unit_of_work.commit()
            return deleted
        finally:
            unit_of_work.close()

    def export_history(self) -> dict[str, object]:
        return _export_history(self.db_uri)

    def import_history(self, payload: dict[str, object]) -> dict[str, int]:
        return _import_history(self.db_uri, payload)

    def compact_history(self) -> None:
        _compact_history(self.db_uri)

    def retain_history(self, *, days: int, statuses: tuple[str, ...] = ()) -> int:
        return _retain_history(self.db_uri, days=days, statuses=statuses)
