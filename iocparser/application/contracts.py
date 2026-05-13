from __future__ import annotations

from dataclasses import dataclass

from iocparser.domain.models import ExtractionOptions, ExtractionResult, PersistOptions, Source


@dataclass(frozen=True)
class ExtractTextInput:
    """Input DTO for text extraction."""

    text_content: str
    options: ExtractionOptions


@dataclass(frozen=True)
class ExtractFileInput:
    """Input DTO for file extraction."""

    file_path: str
    options: ExtractionOptions


@dataclass(frozen=True)
class ExtractURLInput:
    """Input DTO for URL extraction."""

    url: str
    options: ExtractionOptions


@dataclass(frozen=True)
class PersistRunInput:
    """Input DTO for persistence use case."""

    source: Source
    result: ExtractionResult
    tool_version: str
    options: PersistOptions
    duration_ms: int | None = None
    processed_items: int = 1
    successful_items: int = 1
    failed_items: int = 0
    partial_error_count: int = 0
    status: str | None = None
    error_message: str = ""


@dataclass(frozen=True)
class QueryRunsInput:
    """Input DTO for listing persisted runs."""

    limit: int = 20
    offset: int = 0
    date_from: str | None = None
    date_to: str | None = None
    source_kind: str | None = None
    source_value: str | None = None
    sort_by: str = "newest"


@dataclass(frozen=True)
class SearchPersistedIOCsInput:
    """Input DTO for querying persisted IOCs."""

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


@dataclass(frozen=True)
class ExportPersistedRunInput:
    """Input DTO for exporting a stored run."""

    run_id: int
    severity: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    include_normal: bool = True
    include_warnings: bool = True
    max_evidence: int | None = None
    sort_by: str = "type"


@dataclass(frozen=True)
class DiffPersistedRunsInput:
    """Input DTO for diffing persisted runs."""

    left_run_id: int
    right_run_id: int
    only_added: bool = False
    only_removed: bool = False
    only_warnings: bool = False
    only_normal: bool = False
    ioc_types: tuple[str, ...] = ()
    severity: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiffLatestSourceRunInput:
    """Input DTO for diffing a run against the previous run from the same source."""

    run_id: int
    only_added: bool = False
    only_removed: bool = False
    only_warnings: bool = False
    only_normal: bool = False
    ioc_types: tuple[str, ...] = ()
    severity: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeletePersistedRunInput:
    """Input DTO for deleting a persisted run."""

    run_id: int


@dataclass(frozen=True)
class PrunePersistedRunsInput:
    """Input DTO for pruning persisted runs."""

    before: str | None = None
    keep_latest: int = 0
    source_kind: str | None = None
    source_value: str | None = None
    statuses: tuple[str, ...] = ()


@dataclass(frozen=True)
class RetainHistoryInput:
    """Input DTO for retention policies over persisted history."""

    days: int
    statuses: tuple[str, ...] = ()


@dataclass(frozen=True)
class ListFailedBatchesInput:
    """Input DTO for listing failed batch jobs."""

    limit: int = 20


@dataclass(frozen=True)
class ListBatchJobsInput:
    """Input DTO for listing persisted batch jobs."""

    limit: int = 20
    statuses: tuple[str, ...] = ()


@dataclass(frozen=True)
class BatchJobInput:
    """Input DTO for batch-job inspection commands."""

    batch_job_id: int
