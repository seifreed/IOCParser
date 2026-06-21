from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict, Unpack

from iocparser.api_persistence_query import (
    optional_str,
    reject_unknown_options,
    validated_ioc_type_filters,
    validated_iso_datetime,
    validated_min_severity,
    validated_non_negative_days,
    validated_non_negative_int,
    validated_optional_str,
    validated_required_id,
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
    FailedBatchItem,
    PersistedIOCSearchPage,
    PersistedRunDiff,
    PersistedRunExport,
    PersistedRunsPage,
    PersistedRunSummary,
)
from iocparser.errors import InvalidFieldError, ValidationError
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
from iocparser.shared_utils import parse_string_filters

IMPORT_PAYLOAD_OBJECT_REQUIRED = "history import payload must be a mapping (JSON object)"


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
    ioc_type: str | tuple[str, ...] | None
    severity: str | tuple[str, ...]
    tags: str | tuple[str, ...]
    exclude_tags: str | tuple[str, ...]
    min_severity: str | None
    tag_mode: str | None
    sort_by: str | None
    search_backend: str | None


_RUNS_OPTION_KEYS = frozenset(QueryRunsOptions.__annotations__)
_SEARCH_OPTION_KEYS = frozenset(SearchIOCsOptions.__annotations__)


def validated_severity_values(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise InvalidFieldError("severity", value)
        severity = validated_min_severity(value)
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
        reject_unknown_options(options, _RUNS_OPTION_KEYS, context="run query")
        query = QueryRunsInput(
            limit=validated_non_negative_int(options.get("limit", 50), field="limit"),
            offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
            date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
            date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
            source_kind=validated_optional_str(options.get("source_kind"), field="source_kind"),
            source_value=validated_optional_str(options.get("source_value"), field="source_value"),
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

    def list_runs(self, **options: Unpack[QueryRunsOptions]) -> list[PersistedRunSummary]:
        reject_unknown_options(options, _RUNS_OPTION_KEYS, context="run query")
        return self._typed_service.list_runs(
            limit=validated_non_negative_int(options.get("limit", 20), field="limit"),
            offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
            date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
            date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
            source_kind=validated_optional_str(options.get("source_kind"), field="source_kind"),
            source_value=validated_optional_str(options.get("source_value"), field="source_value"),
            sort_by=validated_run_sort(optional_str(options.get("sort_by")) or "newest"),
        )

    def query_runs_page(self, **options: Unpack[QueryRunsOptions]) -> PersistedRunsPage:
        reject_unknown_options(options, _RUNS_OPTION_KEYS, context="run query")
        return self._typed_service.query_runs_page(
            limit=validated_non_negative_int(options.get("limit", 20), field="limit"),
            offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
            date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
            date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
            source_kind=validated_optional_str(options.get("source_kind"), field="source_kind"),
            source_value=validated_optional_str(options.get("source_value"), field="source_value"),
            sort_by=validated_run_sort(optional_str(options.get("sort_by")) or "newest"),
        )

    def search_iocs(
        self, *, value: str, **options: Unpack[SearchIOCsOptions]
    ) -> PersistedIOCSearchPage:
        reject_unknown_options(options, _SEARCH_OPTION_KEYS, context="IOC search")
        query = SearchPersistedIOCsInput(
            value=value,
            limit=validated_non_negative_int(options.get("limit", 50), field="limit"),
            offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
            date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
            date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
            source_kind=validated_optional_str(options.get("source_kind"), field="source_kind"),
            source_value=validated_optional_str(options.get("source_value"), field="source_value"),
            ioc_type=validated_ioc_type_filters(options.get("ioc_type"))
            or None,
            # parse_string_filters accepts a comma-separated string as well as a pre-split
            # tuple; a bare string like severity="high"/tags="foo" otherwise became
            # tuple("high")=('h','i','g','h'), corrupting the filter into single characters.
            severity=validated_severity_values(parse_string_filters(options.get("severity"))),
            tags=parse_string_filters(options.get("tags")),
            exclude_tags=parse_string_filters(options.get("exclude_tags")),
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

    def search_iocs_page(
        self, *, value: str, **options: Unpack[SearchIOCsOptions]
    ) -> PersistedIOCSearchPage:
        reject_unknown_options(options, _SEARCH_OPTION_KEYS, context="IOC search")
        query = SearchPersistedIOCsInput(
            value=value,
            limit=validated_non_negative_int(options.get("limit", 50), field="limit"),
            offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
            date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
            date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
            source_kind=validated_optional_str(options.get("source_kind"), field="source_kind"),
            source_value=validated_optional_str(options.get("source_value"), field="source_value"),
            ioc_type=validated_ioc_type_filters(options.get("ioc_type"))
            or None,
            severity=validated_severity_values(parse_string_filters(options.get("severity"))),
            tags=parse_string_filters(options.get("tags")),
            exclude_tags=parse_string_filters(options.get("exclude_tags")),
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
        return self._typed_service.export_run(
            run_id=validated_required_id(run_id, field="run_id")
        )

    def delete_run(self, *, run_id: int) -> bool:
        return self._typed_service.delete_run(
            run_id=validated_required_id(run_id, field="run_id")
        )

    def diff_runs(self, *, left_run_id: int, right_run_id: int) -> PersistedRunDiff:
        return self._typed_service.diff_runs(
            left_run_id=validated_required_id(left_run_id, field="left_run_id"),
            right_run_id=validated_required_id(right_run_id, field="right_run_id"),
        )

    def diff_run_against_previous_source(self, *, run_id: int) -> PersistedRunDiff:
        return self._typed_service.diff_run_against_previous_source(
            run_id=validated_required_id(run_id, field="run_id")
        )

    def export_history(self) -> dict[str, object]:
        return self._typed_service.export_history()

    def import_history(self, payload: dict[str, object]) -> dict[str, int]:
        if not isinstance(payload, dict):
            raise ValidationError(IMPORT_PAYLOAD_OBJECT_REQUIRED)
        return self._typed_service.import_history(payload)

    def compact_history(self) -> None:
        self._typed_service.compact_history()

    def list_failed_batches(self, *, limit: int = 20) -> list[BatchJobSummary]:
        return self._typed_service.list_failed_batches(
            limit=validated_non_negative_int(limit, field="limit")
        )

    def list_batch_jobs(
        self, *, limit: int = 20, statuses: str | tuple[str, ...] | None = None
    ) -> list[BatchJobSummary]:
        return self._typed_service.list_batch_jobs(
            limit=validated_non_negative_int(limit, field="limit"),
            statuses=parse_string_filters(statuses),
        )

    def get_batch_job(self, *, batch_job_id: int) -> BatchJobDetail | None:
        return self._typed_service.get_batch_job(
            batch_job_id=validated_required_id(batch_job_id, field="batch_job_id")
        )

    def list_batch_runs(self, *, batch_job_id: int) -> list[PersistedRunSummary]:
        return self._typed_service.list_batch_runs(
            batch_job_id=validated_required_id(batch_job_id, field="batch_job_id")
        )

    def list_failed_batch_items(self, *, batch_job_id: int) -> list[FailedBatchItem]:
        return self._typed_service.list_failed_batch_items(
            batch_job_id=validated_required_id(batch_job_id, field="batch_job_id")
        )

    def retain_history(self, *, days: int, statuses: str | None = None) -> int:
        return self._typed_service.retain_history(
            days=validated_non_negative_days(days), statuses=parse_string_filters(statuses)
        )

    def prune_runs(
        self,
        *,
        before: str | None = None,
        keep_latest: int = 0,
        source_kind: str | None = None,
        source_value: str | None = None,
        statuses: str | tuple[str, ...] | None = None,
    ) -> int:
        return self._typed_service.prune_runs(
            before=before,
            keep_latest=_validated_keep_latest(keep_latest),
            source_kind=validated_optional_str(source_kind, field="source_kind"),
            source_value=validated_optional_str(source_value, field="source_value"),
            statuses=parse_string_filters(statuses),
        )

    def get_distributed_job(self, *, job_id: str) -> DistributedJobRecord | None:
        return self._typed_service.get_distributed_job(job_id=job_id)

    def list_distributed_jobs(
        self,
        *,
        limit: int = 50,
        statuses: str | tuple[str, ...] | None = None,
        queue_backend: str | None = None,
    ) -> list[DistributedJobRecord]:
        return self._typed_service.list_distributed_jobs(
            limit=validated_non_negative_int(limit, field="limit"),
            # A bare string statuses must parse like the sibling functions, not reach
            # SQLAlchemy's .in_() as a raw string (cryptic ArgumentError).
            statuses=parse_string_filters(statuses),
            queue_backend=queue_backend,
        )

    def list_dead_letters(
        self, *, limit: int = 50, queue_backend: str | None = None
    ) -> list[DeadLetterRecord]:
        return self._typed_service.list_dead_letters(
            limit=validated_non_negative_int(limit, field="limit"), queue_backend=queue_backend
        )


def _parse_string_filters(value: str | None) -> tuple[str, ...]:
    return parse_string_filters(value)


def _validated_keep_latest(value: object) -> int:
    try:
        return validated_non_negative_int(value, field="offset")
    except ValidationError as exc:
        raise _invalid_keep_latest(value) from exc


def _invalid_keep_latest(value: object) -> ValidationError:
    return ValidationError(f"Invalid keep_latest: {value}")
