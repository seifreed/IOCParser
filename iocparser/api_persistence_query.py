from __future__ import annotations

from collections.abc import Callable, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import TypedDict, Unpack

from iocparser.application.contracts import (
    DiffLatestSourceRunInput,
    DiffPersistedRunsInput,
    ExportPersistedRunInput,
    QueryRunsInput,
    SearchPersistedIOCsInput,
)
from iocparser.application.query_use_cases import diff_latest_source_run as _diff_latest_source_run
from iocparser.application.query_use_cases import diff_persisted_runs as _diff_persisted_runs
from iocparser.application.query_use_cases import export_persisted_run as _export_persisted_run
from iocparser.application.query_use_cases import query_runs as _query_runs
from iocparser.application.query_use_cases import query_runs_page as _query_runs_page
from iocparser.application.query_use_cases import search_persisted_iocs as _search_persisted_iocs
from iocparser.application.query_use_cases import (
    search_persisted_iocs_page as _search_persisted_iocs_page,
)
from iocparser.domain.models import (
    DeadLetterRecord,
    DistributedJobRecord,
    ExtractionResult,
    IOCType,
    PersistedIOCSearchPage,
    PersistedRunDiff,
    PersistedRunExport,
    PersistedRunQueryHit,
    PersistedRunsPage,
    PersistedRunSummary,
    ioc_type_name,
)
from iocparser.domain.type_filters import parse_ioc_types
from iocparser.errors import ValidationError
from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
from iocparser.interfaces.ports import OutputRenderer
from iocparser.plugins import get_renderer
from iocparser.shared_utils import (
    VALID_SEVERITIES,
    parse_bool_token,
    parse_string_filters,
    validated_diff_only,
    validated_severity_filters,
)


class QueryRunsOptions(TypedDict, total=False):
    limit: int
    offset: int
    date_from: str | None
    date_to: str | None
    source_kind: str | None
    source_value: str | None
    sort_by: str


class SearchPersistedIOCOptions(TypedDict, total=False):
    limit: int
    offset: int
    date_from: str | None
    date_to: str | None
    source_kind: str | None
    source_value: str | None
    ioc_type: str | tuple[str, ...] | None
    severity: str | None
    tag: str | None
    exclude_tag: str | None
    min_severity: str | None
    tag_mode: str
    sort_by: str
    search_backend: str


class PersistedDiffOptions(TypedDict, total=False):
    diff_only: str
    only_warnings: bool
    only_normal: bool
    ioc_type: str | tuple[str, ...] | None
    severity: str | None
    tag: str | None


UNKNOWN_OPTION_ERROR = "Unknown {context} option(s): {names}"

_RUNS_OPTION_KEYS = frozenset(QueryRunsOptions.__annotations__)
_SEARCH_OPTION_KEYS = frozenset(SearchPersistedIOCOptions.__annotations__)
_DIFF_OPTION_KEYS = frozenset(PersistedDiffOptions.__annotations__)


def reject_unknown_options(
    options: Mapping[str, object], allowed: AbstractSet[str], *, context: str
) -> None:
    """Fail loudly on an unrecognized keyword option.

    ``**options: Unpack[TypedDict]`` only constrains keys for mypy; at runtime a typo'd
    keyword (e.g. ``min_severty=``) is silently swallowed and its filter never applies,
    so the caller gets unfiltered results with no error. Reject unknown keys instead.
    """
    unknown = set(options) - allowed
    if unknown:
        raise ValidationError(
            UNKNOWN_OPTION_ERROR.format(context=context, names=", ".join(sorted(unknown)))
        )


@dataclass(frozen=True)
class PersistedRenderOptions:
    output_format: str = "json"
    with_context: bool = False
    stix_types: str | None = None


@dataclass(frozen=True)
class PersistedExportFilters:
    severity: str | None = None
    tag: str | None = None
    only_warnings: bool = False
    only_normal: bool = False


@dataclass(frozen=True)
class PersistedDiffFilters(PersistedExportFilters):
    diff_only: str = "all"
    ioc_type: str | tuple[str, ...] | None = None


MISSING_DIFF_TARGET_ERROR = "Missing diff target"
INVALID_DATE_ERROR = "Invalid ISO date: {value}"
INVALID_IOC_TYPE_ERROR = "Invalid ioc_type: {value}"
INVALID_STRING_FILTER_ERROR = "Invalid {field}: {value}"
INVALID_MIN_SEVERITY_ERROR = "Invalid min_severity: {value}"
INVALID_TAG_MODE_ERROR = "Invalid tag_mode: {value}"
INVALID_SORT_BY_ERROR = "Invalid sort_by: {value}"
INVALID_SEARCH_BACKEND_ERROR = "Invalid search_backend: {value}"
INVALID_LIMIT_ERROR = "Invalid limit: {value}"
INVALID_OFFSET_ERROR = "Invalid offset: {value}"
INVALID_DAYS_ERROR = "Invalid days: {value}"
INVALID_ID_ERROR = "Invalid {field}: {value}"
INVALID_BOOLEAN_ERROR = "Invalid boolean option: {value}"
VALID_TAG_MODES = {"all", "any"}
VALID_RUN_SORT_VALUES = {"newest", "oldest", "source"}
VALID_SEARCH_SORT_VALUES = {"newest", "oldest", "source"}
VALID_SEARCH_BACKENDS = {"auto", "fts", "like"}
INVALID_FTS_QUERY_ERROR = "Invalid FTS query: {value}"
INVALID_EMPTY_SEARCH_QUERY_ERROR = "Invalid search value: {value}"


def query_service(db_uri: str) -> SQLAlchemyPersistenceService:
    return SQLAlchemyPersistenceService(db_uri)


def optional_str(value: object | None) -> str | None:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped or None


def validated_optional_str(value: object | None, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(INVALID_STRING_FILTER_ERROR.format(field=field, value=value))
    stripped = value.strip()
    return stripped or None


def bool_option(value: object | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        parsed = parse_bool_token(value)
        if parsed is not None:
            return parsed
        raise ValidationError(INVALID_BOOLEAN_ERROR.format(value=value))
    raise ValidationError(INVALID_BOOLEAN_ERROR.format(value=value))


def runs_input(options: QueryRunsOptions) -> QueryRunsInput:
    reject_unknown_options(options, _RUNS_OPTION_KEYS, context="run query")
    return QueryRunsInput(
        **{  # type: ignore[arg-type]
            **options,
            "limit": validated_non_negative_int(options.get("limit", 20), field="limit"),
            "offset": validated_non_negative_int(options.get("offset", 0), field="offset"),
            "date_from": validated_iso_datetime(optional_str(options.get("date_from"))),
            "date_to": validated_iso_datetime(optional_str(options.get("date_to"))),
            "source_kind": validated_optional_str(options.get("source_kind"), field="source_kind"),
            "source_value": validated_optional_str(options.get("source_value"), field="source_value"),
            "sort_by": validated_run_sort(optional_str(options.get("sort_by")) or "newest"),
        }
    )


def search_input(value: str, options: SearchPersistedIOCOptions) -> SearchPersistedIOCsInput:
    reject_unknown_options(options, _SEARCH_OPTION_KEYS, context="IOC search")
    return SearchPersistedIOCsInput(
        value=value,
        limit=validated_non_negative_int(options.get("limit", 50), field="limit"),
        offset=validated_non_negative_int(options.get("offset", 0), field="offset"),
        date_from=validated_iso_datetime(optional_str(options.get("date_from"))),
        date_to=validated_iso_datetime(optional_str(options.get("date_to"))),
        source_kind=validated_optional_str(options.get("source_kind"), field="source_kind"),
        source_value=validated_optional_str(options.get("source_value"), field="source_value"),
        ioc_type=validated_ioc_type_filters(options.get("ioc_type")) or None,
        severity=validated_severity_filters(options.get("severity")),
        tags=parse_string_filters(options.get("tag")),
        exclude_tags=parse_string_filters(options.get("exclude_tag")),
        min_severity=validated_min_severity(optional_str(options.get("min_severity"))),
        tag_mode=validated_tag_mode(optional_str(options.get("tag_mode")) or "all"),
        sort_by=validated_search_sort(optional_str(options.get("sort_by")) or "newest"),
        search_backend=validated_search_backend(
            optional_str(options.get("search_backend")) or "auto"
        ),
    )


def validated_iso_datetime(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    from datetime import datetime

    try:
        datetime.fromisoformat(stripped)
    except ValueError as exc:
        raise ValidationError(INVALID_DATE_ERROR.format(value=value)) from exc
    return stripped


def _validated_choice(value: str, *, valid: AbstractSet[str], error: str) -> str:
    normalized = value.strip().lower()
    if normalized not in valid:
        raise ValidationError(error.format(value=value))
    return normalized


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"Invalid {field}: {value}")
    return value


def validated_min_severity(value: object | None) -> str | None:
    if value is None:
        return None
    value = _require_str(value, field="min_severity")
    stripped = value.strip()
    if not stripped:
        return None
    return _validated_choice(stripped, valid=VALID_SEVERITIES, error=INVALID_MIN_SEVERITY_ERROR)


def validated_ioc_type_filter(value: object | None) -> str | None:
    if value is None:
        return None
    value = _require_str(value, field="ioc_type")
    normalized = value.strip()
    if not normalized:
        return None
    try:
        return ioc_type_name(IOCType.from_name(normalized))
    except ValueError as exc:
        raise ValidationError(INVALID_IOC_TYPE_ERROR.format(value=value)) from exc


def validated_ioc_type_filters(value: object | None) -> tuple[str, ...]:
    if value is None:
        return ()
    try:
        if isinstance(value, (list, tuple)):
            if not all(isinstance(item, str) for item in value):
                raise TypeError
            normalized = [
                ioc_type_name(ioc_type)
                for item in value
                for ioc_type in parse_ioc_types(item)
            ]
        elif not isinstance(value, str):
            raise TypeError
        else:
            normalized = [ioc_type_name(ioc_type) for ioc_type in parse_ioc_types(value)]
    except (TypeError, ValueError) as exc:
        raise ValidationError(INVALID_IOC_TYPE_ERROR.format(value=value)) from exc
    return tuple(dict.fromkeys(normalized))


def validated_stix_types(value: object | None) -> str | None:
    if value is None:
        return None
    value = _require_str(value, field="stix_types")
    stripped = value.strip()
    if not stripped:
        return None
    try:
        parse_ioc_types(stripped)
    except ValueError as exc:
        raise ValidationError(INVALID_IOC_TYPE_ERROR.format(value=value)) from exc
    return stripped


def validated_tag_mode(value: object) -> str:
    value = _require_str(value, field="tag_mode")
    return _validated_choice(value, valid=VALID_TAG_MODES, error=INVALID_TAG_MODE_ERROR)


def validated_run_sort(value: object) -> str:
    value = _require_str(value, field="sort_by")
    return _validated_choice(value, valid=VALID_RUN_SORT_VALUES, error=INVALID_SORT_BY_ERROR)


def validated_search_sort(value: object) -> str:
    value = _require_str(value, field="sort_by")
    return _validated_choice(value, valid=VALID_SEARCH_SORT_VALUES, error=INVALID_SORT_BY_ERROR)


def validated_search_backend(value: object) -> str:
    value = _require_str(value, field="search_backend")
    return _validated_choice(value, valid=VALID_SEARCH_BACKENDS, error=INVALID_SEARCH_BACKEND_ERROR)


def validated_non_negative_int(value: object, *, field: str) -> int:
    try:
        if isinstance(value, bool):
            raise TypeError
        if isinstance(value, int):
            parsed = value
        elif isinstance(value, str):
            if not value.strip():
                raise TypeError
            parsed = int(value.strip())
        else:
            raise TypeError
    except (TypeError, ValueError) as exc:
        if field == "limit":
            raise ValidationError(INVALID_LIMIT_ERROR.format(value=value)) from exc
        raise ValidationError(INVALID_OFFSET_ERROR.format(value=value)) from exc
    if parsed < 0:
        if field == "limit":
            raise ValidationError(INVALID_LIMIT_ERROR.format(value=value))
        raise ValidationError(INVALID_OFFSET_ERROR.format(value=value))
    return parsed


def validated_non_negative_days(value: object) -> int:
    try:
        return validated_non_negative_int(value, field="limit")
    except ValidationError as exc:
        raise ValidationError(INVALID_DAYS_ERROR.format(value=value)) from exc


def validated_required_id(value: object, *, field: str) -> int:
    try:
        return validated_non_negative_int(value, field="limit")
    except ValidationError as exc:
        raise ValidationError(INVALID_ID_ERROR.format(field=field, value=value)) from exc


def _validated_search_call[T](value: str, call: Callable[[], T]) -> T:
    try:
        return call()
    except ValueError as exc:
        if str(exc) == "FTS search requires at least one alphanumeric term":
            raise ValidationError(INVALID_FTS_QUERY_ERROR.format(value=value)) from exc
        if str(exc) == "IOC search requires a non-empty value":
            raise ValidationError(INVALID_EMPTY_SEARCH_QUERY_ERROR.format(value=value)) from exc
        raise


def persisted_diff_input(
    *,
    left_run_id: int,
    right_run_id: int,
    options: PersistedDiffOptions,
) -> DiffPersistedRunsInput:
    reject_unknown_options(options, _DIFF_OPTION_KEYS, context="diff")
    diff_only = validated_diff_only(optional_str(options.get("diff_only")))
    return DiffPersistedRunsInput(
        left_run_id=validated_required_id(left_run_id, field="left_run_id"),
        right_run_id=validated_required_id(right_run_id, field="right_run_id"),
        only_added=diff_only == "added",
        only_removed=diff_only == "removed",
        only_warnings=bool_option(options.get("only_warnings")),
        only_normal=bool_option(options.get("only_normal")),
        ioc_types=validated_ioc_type_filters(options.get("ioc_type")),
        severity=validated_severity_filters(options.get("severity")),
        tags=parse_string_filters(options.get("tag")),
    )


def latest_source_diff_input(
    *,
    run_id: int,
    options: PersistedDiffOptions,
) -> DiffLatestSourceRunInput:
    reject_unknown_options(options, _DIFF_OPTION_KEYS, context="diff")
    diff_only = validated_diff_only(optional_str(options.get("diff_only")))
    return DiffLatestSourceRunInput(
        run_id=validated_required_id(run_id, field="run_id"),
        only_added=diff_only == "added",
        only_removed=diff_only == "removed",
        only_warnings=bool_option(options.get("only_warnings")),
        only_normal=bool_option(options.get("only_normal")),
        ioc_types=validated_ioc_type_filters(options.get("ioc_type")),
        severity=validated_severity_filters(options.get("severity")),
        tags=parse_string_filters(options.get("tag")),
    )


def renderer_for_format(
    output_format: str,
    *,
    with_context: bool = False,
    stix_types: str | None = None,
) -> OutputRenderer:
    return get_renderer(
        str(output_format).strip(),
        with_context=with_context,
        stix_types=validated_stix_types(stix_types),
    )


def coerce_render_options(
    options: PersistedRenderOptions | None,
    option_overrides: dict[str, object],
) -> PersistedRenderOptions:
    if options is not None:
        return options
    return PersistedRenderOptions(
        output_format=str(option_overrides.pop("output_format", "json")),
        with_context=bool_option(option_overrides.pop("with_context", False)),
        stix_types=optional_str(option_overrides.pop("stix_types", None)),
    )


def coerce_export_filters(
    filters: PersistedExportFilters | None,
    option_overrides: dict[str, object],
) -> PersistedExportFilters:
    if filters is not None:
        return filters
    return PersistedExportFilters(
        severity=optional_str(option_overrides.pop("severity", None)),
        tag=optional_str(option_overrides.pop("tag", None)),
        only_warnings=bool_option(option_overrides.pop("only_warnings", False)),
        only_normal=bool_option(option_overrides.pop("only_normal", False)),
    )


def coerce_diff_filters(
    filters: PersistedDiffFilters | None,
    option_overrides: dict[str, object],
) -> PersistedDiffFilters:
    if filters is not None:
        return filters
    return PersistedDiffFilters(
        severity=optional_str(option_overrides.pop("severity", None)),
        tag=optional_str(option_overrides.pop("tag", None)),
        only_warnings=bool_option(option_overrides.pop("only_warnings", False)),
        only_normal=bool_option(option_overrides.pop("only_normal", False)),
        diff_only=validated_diff_only(optional_str(option_overrides.pop("diff_only", None))),
        ioc_type=validated_ioc_type_filters(option_overrides.pop("ioc_type", None)) or None,
    )


def diff_render_result(diff: PersistedRunDiff, diff_only: str) -> ExtractionResult:
    diff_only = validated_diff_only(diff_only)
    if diff_only == "added":
        return diff.added
    if diff_only == "removed":
        return diff.removed
    return ExtractionResult(
        iocs=diff.added.iocs + diff.removed.iocs,
        warnings=diff.added.warnings + diff.removed.warnings,
    )


def reject_unused_render_overrides(option_overrides: Mapping[str, object]) -> None:
    reject_unknown_options(option_overrides, frozenset(), context="render/filter")


def export_persisted_run(*, db_uri: str, run_id: int) -> PersistedRunExport:
    return _export_persisted_run(
        ExportPersistedRunInput(run_id=validated_required_id(run_id, field="run_id")),
        persistence_query_service=query_service(db_uri),
    )


def diff_persisted_runs(
    *,
    db_uri: str,
    left_run_id: int,
    right_run_id: int,
    **options: Unpack[PersistedDiffOptions],
) -> PersistedRunDiff:
    return _diff_persisted_runs(
        persisted_diff_input(left_run_id=left_run_id, right_run_id=right_run_id, options=options),
        persistence_query_service=query_service(db_uri),
    )


def diff_run_against_previous_source(
    *,
    db_uri: str,
    run_id: int,
    **options: Unpack[PersistedDiffOptions],
) -> PersistedRunDiff:
    return _diff_latest_source_run(
        latest_source_diff_input(run_id=run_id, options=options),
        persistence_query_service=query_service(db_uri),
    )


def export_structured_persisted_diff(
    *,
    db_uri: str,
    left_run_id: int | None = None,
    right_run_id: int | None = None,
    run_id: int | None = None,
    **options: Unpack[PersistedDiffOptions],
) -> dict[str, object]:
    if run_id is not None:
        diff = diff_run_against_previous_source(db_uri=db_uri, run_id=run_id, **options)
    else:
        if left_run_id is None or right_run_id is None:
            raise ValueError(MISSING_DIFF_TARGET_ERROR)
        diff = diff_persisted_runs(
            db_uri=db_uri, left_run_id=left_run_id, right_run_id=right_run_id, **options
        )
    return diff.to_record()


def list_persisted_runs(
    *,
    db_uri: str,
    **options: Unpack[QueryRunsOptions],
) -> list[PersistedRunSummary]:
    return _query_runs(runs_input(options), persistence_query_service=query_service(db_uri))


def query_persisted_runs(
    *,
    db_uri: str,
    **options: Unpack[QueryRunsOptions],
) -> PersistedRunsPage:
    return _query_runs_page(runs_input(options), persistence_query_service=query_service(db_uri))


def search_persisted_iocs(
    *,
    db_uri: str,
    value: str,
    **options: Unpack[SearchPersistedIOCOptions],
) -> list[PersistedRunQueryHit]:
    return _validated_search_call(
        value,
        lambda: _search_persisted_iocs(
            search_input(value, options), persistence_query_service=query_service(db_uri)
        ),
    )


def query_persisted_iocs(
    *,
    db_uri: str,
    value: str,
    **options: Unpack[SearchPersistedIOCOptions],
) -> PersistedIOCSearchPage:
    return _validated_search_call(
        value,
        lambda: _search_persisted_iocs_page(
            search_input(value, options), persistence_query_service=query_service(db_uri)
        ),
    )


def get_distributed_job(*, db_uri: str, job_id: str) -> DistributedJobRecord | None:
    return query_service(db_uri).get_distributed_job(job_id=job_id)


def list_distributed_jobs(
    *,
    db_uri: str,
    limit: int = 50,
    statuses: str | tuple[str, ...] | None = None,
    queue_backend: str | None = None,
) -> list[DistributedJobRecord]:
    return query_service(db_uri).list_distributed_jobs(
        limit=validated_non_negative_int(limit, field="limit"),
        # Accept a comma-separated string like the sibling list/retain/prune functions;
        # a bare string would otherwise reach SQLAlchemy's .in_() and raise ArgumentError.
        statuses=parse_string_filters(statuses),
        queue_backend=queue_backend,
    )


def list_dead_letters(
    *, db_uri: str, limit: int = 50, queue_backend: str | None = None
) -> list[DeadLetterRecord]:
    return query_service(db_uri).list_dead_letters(
        limit=validated_non_negative_int(limit, field="limit"), queue_backend=queue_backend
    )


def render_persisted_diff(
    *,
    db_uri: str,
    left_run_id: int | None = None,
    right_run_id: int | None = None,
    run_id: int | None = None,
    render: PersistedRenderOptions | None = None,
    filters: PersistedDiffFilters | None = None,
    **option_overrides: object,
) -> str:
    render_options = coerce_render_options(render, option_overrides)
    diff_filters = coerce_diff_filters(filters, option_overrides)
    reject_unused_render_overrides(option_overrides)
    if run_id is not None:
        diff = diff_run_against_previous_source(
            db_uri=db_uri,
            run_id=run_id,
            diff_only=diff_filters.diff_only,
            only_warnings=diff_filters.only_warnings,
            only_normal=diff_filters.only_normal,
            ioc_type=diff_filters.ioc_type,
            severity=diff_filters.severity,
            tag=diff_filters.tag,
        )
    else:
        if left_run_id is None or right_run_id is None:
            raise ValueError(MISSING_DIFF_TARGET_ERROR)
        diff = diff_persisted_runs(
            db_uri=db_uri,
            left_run_id=left_run_id,
            right_run_id=right_run_id,
            diff_only=diff_filters.diff_only,
            only_warnings=diff_filters.only_warnings,
            only_normal=diff_filters.only_normal,
            ioc_type=diff_filters.ioc_type,
            severity=diff_filters.severity,
            tag=diff_filters.tag,
        )
    return renderer_for_format(
        render_options.output_format,
        with_context=render_options.with_context,
        stix_types=render_options.stix_types,
    ).render(diff_render_result(diff, diff_filters.diff_only))


def render_persisted_run(
    *,
    db_uri: str,
    run_id: int,
    render: PersistedRenderOptions | None = None,
    filters: PersistedExportFilters | None = None,
    **option_overrides: object,
) -> str:
    render_options = coerce_render_options(render, option_overrides)
    export_filters = coerce_export_filters(filters, option_overrides)
    reject_unused_render_overrides(option_overrides)
    export = export_persisted_run(db_uri=db_uri, run_id=run_id)
    if (
        export_filters.severity is not None
        or export_filters.tag is not None
        or export_filters.only_warnings
        or export_filters.only_normal
    ):
        filtered = export.result.filter_analyst_view(
            severities=validated_severity_filters(export_filters.severity),
            tags=parse_string_filters(export_filters.tag),
            include_normal=not export_filters.only_warnings,
            include_warnings=not export_filters.only_normal,
        )
    else:
        filtered = export.result
    return renderer_for_format(
        render_options.output_format,
        with_context=render_options.with_context,
        stix_types=render_options.stix_types,
    ).render(filtered)


__all__ = [
    "diff_persisted_runs",
    "diff_run_against_previous_source",
    "export_persisted_run",
    "export_structured_persisted_diff",
    "get_distributed_job",
    "list_dead_letters",
    "list_distributed_jobs",
    "list_persisted_runs",
    "query_persisted_iocs",
    "query_persisted_runs",
    "render_persisted_diff",
    "render_persisted_run",
    "search_persisted_iocs",
]
