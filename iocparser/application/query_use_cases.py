from __future__ import annotations

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
from iocparser.domain.models import (
    BatchJobDetail,
    BatchJobSummary,
    ExtractionResult,
    PersistedIOCSearchPage,
    PersistedRunDiff,
    PersistedRunExport,
    PersistedRunQueryHit,
    PersistedRunsPage,
    PersistedRunSummary,
)
from iocparser.interfaces.ports import PersistenceQueryService


def query_runs(
    request: QueryRunsInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> list[PersistedRunSummary]:
    """List persisted runs."""
    return persistence_query_service.list_runs(
        limit=request.limit,
        offset=request.offset,
        date_from=request.date_from,
        date_to=request.date_to,
        source_kind=request.source_kind,
        source_value=request.source_value,
        sort_by=request.sort_by,
    )


def search_persisted_iocs(
    request: SearchPersistedIOCsInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> list[PersistedRunQueryHit]:
    """Search persisted IOCs by value."""
    return persistence_query_service.search_iocs(
        value=request.value,
        limit=request.limit,
        offset=request.offset,
        date_from=request.date_from,
        date_to=request.date_to,
        source_kind=request.source_kind,
        source_value=request.source_value,
        ioc_type=request.ioc_type,
        severity=request.severity,
        tags=request.tags,
        exclude_tags=request.exclude_tags,
        min_severity=request.min_severity,
        tag_mode=request.tag_mode,
        sort_by=request.sort_by,
        search_backend=request.search_backend,
    )


def query_runs_page(
    request: QueryRunsInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> PersistedRunsPage:
    """List persisted runs with pagination metadata."""
    return persistence_query_service.query_runs_page(
        limit=request.limit,
        offset=request.offset,
        date_from=request.date_from,
        date_to=request.date_to,
        source_kind=request.source_kind,
        source_value=request.source_value,
        sort_by=request.sort_by,
    )


def search_persisted_iocs_page(
    request: SearchPersistedIOCsInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> PersistedIOCSearchPage:
    """Search persisted IOCs with pagination metadata."""
    return persistence_query_service.search_iocs_page(
        value=request.value,
        limit=request.limit,
        offset=request.offset,
        date_from=request.date_from,
        date_to=request.date_to,
        source_kind=request.source_kind,
        source_value=request.source_value,
        ioc_type=request.ioc_type,
        severity=request.severity,
        tags=request.tags,
        exclude_tags=request.exclude_tags,
        min_severity=request.min_severity,
        tag_mode=request.tag_mode,
        sort_by=request.sort_by,
        search_backend=request.search_backend,
    )


def export_persisted_run(
    request: ExportPersistedRunInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> PersistedRunExport:
    """Export a stored run."""
    export = persistence_query_service.export_run(run_id=request.run_id)
    return PersistedRunExport(
        summary=export.summary,
        result=export.result.filter_analyst_view(
            severities=request.severity,
            tags=request.tags,
            include_normal=request.include_normal,
            include_warnings=request.include_warnings,
            max_evidence=request.max_evidence,
            sort_by=request.sort_by,
        ),
    )


def diff_persisted_runs(
    request: DiffPersistedRunsInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> PersistedRunDiff:
    """Diff two stored runs."""
    diff = persistence_query_service.diff_runs(
        left_run_id=request.left_run_id,
        right_run_id=request.right_run_id,
    )
    return _filter_diff(diff, request)


def diff_latest_source_run(
    request: DiffLatestSourceRunInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> PersistedRunDiff:
    """Diff a stored run against the previous run from the same source."""
    diff = persistence_query_service.diff_run_against_previous_source(run_id=request.run_id)
    return _filter_diff(diff, request)


def _filter_diff(
    diff: PersistedRunDiff,
    request: DiffPersistedRunsInput | DiffLatestSourceRunInput,
) -> PersistedRunDiff:
    include_normal = not request.only_warnings
    include_warnings = True
    filtered_added = diff.added.filter_analyst_view(
        severities=request.severity,
        tags=request.tags,
        include_normal=include_normal,
        include_warnings=include_warnings,
    )
    filtered_removed = diff.removed.filter_analyst_view(
        severities=request.severity,
        tags=request.tags,
        include_normal=include_normal,
        include_warnings=include_warnings,
    )
    if request.ioc_types:
        from iocparser.domain.models import IOCType

        include_types = tuple(IOCType.from_name(name) for name in request.ioc_types)
        filtered_added = filtered_added.filter_types(include_types=include_types)
        filtered_removed = filtered_removed.filter_types(include_types=include_types)
    if request.only_added:
        filtered_removed = ExtractionResult()
    if request.only_removed:
        filtered_added = ExtractionResult()
    return PersistedRunDiff(
        left_run_id=diff.left_run_id,
        right_run_id=diff.right_run_id,
        added=filtered_added,
        removed=filtered_removed,
        compared_to_previous_source_run_id=diff.compared_to_previous_source_run_id,
    )


def delete_persisted_run(
    request: DeletePersistedRunInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> bool:
    """Delete a persisted run."""
    return persistence_query_service.delete_run(run_id=request.run_id)


def prune_persisted_runs(
    request: PrunePersistedRunsInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> int:
    """Prune persisted runs and return deleted count."""
    return persistence_query_service.prune_runs(
        before=request.before,
        keep_latest=request.keep_latest,
        source_kind=request.source_kind,
        source_value=request.source_value,
        statuses=request.statuses,
    )


def list_batch_jobs(
    request: ListBatchJobsInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> list[BatchJobSummary]:
    """List persisted batch jobs."""
    return persistence_query_service.list_batch_jobs(limit=request.limit, statuses=request.statuses)


def get_batch_job(
    request: BatchJobInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> BatchJobDetail | None:
    """Load a persisted batch job."""
    return persistence_query_service.get_batch_job(batch_job_id=request.batch_job_id)


def list_batch_runs(
    request: BatchJobInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> list[PersistedRunSummary]:
    """List persisted runs belonging to a batch job."""
    return persistence_query_service.list_batch_runs(batch_job_id=request.batch_job_id)
