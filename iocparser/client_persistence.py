from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict, Unpack

from iocparser.api_persistence_query import (
    optional_str,
    parse_string_filters,
    validated_ioc_type_filter,
    validated_iso_datetime,
    validated_min_severity,
    validated_non_negative_int,
    validated_run_sort,
    validated_search_backend,
    validated_search_sort,
    validated_tag_mode,
)
from iocparser.application.contracts import QueryRunsInput, SearchPersistedIOCsInput
from iocparser.domain.models import (
    BatchJobDetail,
    BatchJobSummary,
    DeadLetterRecord,
    DistributedJobRecord,
    PersistedIOCSearchPage,
    PersistedRunDiff,
    PersistedRunExport,
    PersistedRunsPage,
    PersistedRunSummary,
)
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService


class QueryRunsOptions(TypedDict, total=False):
    limit: int
    offset: int
    date_from: str | None
    date_to: str | None
    source_kind: str | None
    source_value: str | None
    sort_by: str | None


class SearchIOCsOptions(TypedDict, total=False):
    limit: int
    offset: int
    date_from: str | None
    date_to: str | None
    source_kind: str | None
    source_value: str | None
    ioc_type: str | None
    severity: tuple[str, ...]
    tags: tuple[str, ...]
    exclude_tags: tuple[str, ...]
    min_severity: str | None
    tag_mode: str | None
    sort_by: str | None
    search_backend: str | None


def validated_severity_values(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        severity = validated_min_severity(str(value))
        if severity is not None:
            normalized.append(severity)
    return tuple(normalized)


@dataclass(frozen=True)
class PersistenceClient:
    """Reusable persistence/query client with a shared query service."""

    db_uri: str
    _service: SQLAlchemyPersistenceService = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_service", SQLAlchemyPersistenceService(self.db_uri))

    @property
    def _typed_service(self) -> SQLAlchemyPersistenceService:
        return self._service

    def query_runs(self, **options: Unpack[QueryRunsOptions]) -> PersistedRunsPage:
        query = QueryRunsInput(
            limit=validated_non_negative_int(options.get("limit", 50), field="limit"),
            offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
            date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
            date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
            source_kind=options.get("source_kind"),
            source_value=options.get("source_value"),
            sort_by=validated_run_sort(optional_str(options.get("sort_by")) or "newest"),
        )
        return self._typed_service.query_runs_page(
            limit=query.limit,
            offset=query.offset,
            date_from=query.date_from,
            date_to=query.date_to,
            source_kind=query.source_kind,
            source_value=query.source_value,
            sort_by=query.sort_by,
        )

    def search_iocs(
        self, *, value: str, **options: Unpack[SearchIOCsOptions]
    ) -> PersistedIOCSearchPage:
        query = SearchPersistedIOCsInput(
            value=value,
            limit=validated_non_negative_int(options.get("limit", 50), field="limit"),
            offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
            date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
            date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
            source_kind=options.get("source_kind"),
            source_value=options.get("source_value"),
            ioc_type=validated_ioc_type_filter(optional_str(options.get("ioc_type"))),
            severity=validated_severity_values(tuple(options.get("severity", ()))),
            tags=tuple(options.get("tags", ())),
            exclude_tags=tuple(options.get("exclude_tags", ())),
            min_severity=validated_min_severity(optional_str(options.get("min_severity"))),
            tag_mode=validated_tag_mode(optional_str(options.get("tag_mode")) or "all"),
            sort_by=validated_search_sort(optional_str(options.get("sort_by")) or "newest"),
            search_backend=validated_search_backend(
                optional_str(options.get("search_backend")) or "auto"
            ),
        )
        return self._typed_service.search_iocs_page(
            value=query.value,
            limit=query.limit,
            offset=query.offset,
            date_from=query.date_from,
            date_to=query.date_to,
            source_kind=query.source_kind,
            source_value=query.source_value,
            ioc_type=query.ioc_type,
            severity=query.severity,
            tags=query.tags,
            exclude_tags=query.exclude_tags,
            min_severity=query.min_severity,
            tag_mode=query.tag_mode,
            sort_by=query.sort_by,
            search_backend=query.search_backend,
        )

    def export_run(self, *, run_id: int) -> PersistedRunExport:
        return self._typed_service.export_run(run_id=run_id)

    def diff_runs(self, *, left_run_id: int, right_run_id: int) -> PersistedRunDiff:
        return self._typed_service.diff_runs(left_run_id=left_run_id, right_run_id=right_run_id)

    def export_history(self) -> dict[str, object]:
        return self._typed_service.export_history()

    def import_history(self, payload: dict[str, object]) -> dict[str, int]:
        return self._typed_service.import_history(payload)

    def list_failed_batches(self, *, limit: int = 20) -> list[BatchJobSummary]:
        return self._typed_service.list_failed_batches(limit=limit)

    def list_batch_jobs(
        self, *, limit: int = 20, statuses: tuple[str, ...] = ()
    ) -> list[BatchJobSummary]:
        return self._typed_service.list_batch_jobs(limit=limit, statuses=statuses)

    def get_batch_job(self, *, batch_job_id: int) -> BatchJobDetail | None:
        return self._typed_service.get_batch_job(batch_job_id=batch_job_id)

    def list_batch_runs(self, *, batch_job_id: int) -> list[PersistedRunSummary]:
        return self._typed_service.list_batch_runs(batch_job_id=batch_job_id)

    def retain_history(self, *, days: int, statuses: str | None = None) -> int:
        return self._typed_service.retain_history(
            days=days, statuses=parse_string_filters(statuses)
        )

    def get_distributed_job(self, *, job_id: str) -> DistributedJobRecord | None:
        return self._typed_service.get_distributed_job(job_id=job_id)

    def list_distributed_jobs(
        self,
        *,
        limit: int = 50,
        statuses: tuple[str, ...] = (),
        queue_backend: str | None = None,
    ) -> list[DistributedJobRecord]:
        return self._typed_service.list_distributed_jobs(
            limit=limit,
            statuses=statuses,
            queue_backend=queue_backend,
        )

    def list_dead_letters(
        self, *, limit: int = 50, queue_backend: str | None = None
    ) -> list[DeadLetterRecord]:
        return self._typed_service.list_dead_letters(limit=limit, queue_backend=queue_backend)


def _parse_string_filters(value: str | None) -> tuple[str, ...]:
    return parse_string_filters(value)
