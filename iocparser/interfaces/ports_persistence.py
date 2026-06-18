from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

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


class SourceRepository(Protocol):
    """Repository for sources."""

    def get_or_create(
        self,
        *,
        kind: str,
        value: str,
        original_url: str | None = None,
        normalized_url: str | None = None,
        mime_type: str | None = None,
        input_size: int | None = None,
        content_hash: str | None = None,
        fingerprint: str | None = None,
    ) -> int:
        """Return the source identifier for a source."""


class IOCRepository(Protocol):
    """Repository for IOC entities."""

    def get_or_create_normal(self, result: ExtractionResult) -> list[int]:
        """Create or resolve IOC ids for normal result entries."""

    def get_or_create_warnings(self, result: ExtractionResult) -> list[int]:
        """Create or resolve IOC ids for warning matches."""


class RunRepository(Protocol):
    """Repository for extraction runs."""

    def create_run(
        self,
        *,
        source_id: int,
        tool_version: str,
        options: PersistOptions,
        metadata: Mapping[str, int | str | None] | None = None,
    ) -> int:
        """Create a new extraction run and return its id."""

    def attach_iocs(
        self, *, run_id: int, ioc_ids: list[int], result: ExtractionResult | None = None
    ) -> None:
        """Attach IOC ids to a run."""


class UnitOfWork(Protocol):
    """Transaction boundary for persistence."""

    @property
    def source_repository(self) -> SourceRepository:
        """Repository for sources."""

    @property
    def ioc_repository(self) -> IOCRepository:
        """Repository for IOCs."""

    @property
    def run_repository(self) -> RunRepository:
        """Repository for runs."""

    def commit(self) -> None:
        """Commit the current transaction."""

    def rollback(self) -> None:
        """Rollback the current transaction."""

    def close(self) -> None:
        """Close the unit of work and release resources."""


class ProcessedRunLookup(Protocol):
    """Port for resolving already-processed inputs in worker paths."""

    def find_existing_run(
        self,
        *,
        fingerprint: str | None = None,
        content_hash: str | None = None,
        status: str = "success",
    ) -> PersistedRunSummary | None:
        """Find a matching persisted run for the current input."""

    def export_run(self, *, run_id: int) -> PersistedRunExport:
        """Rehydrate a persisted run payload for skip-fast paths."""


class PersistenceQueryService(Protocol):
    """Port for querying persisted runs and IOCs."""

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
    ) -> list[PersistedRunSummary]:
        """List persisted runs."""

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
        ioc_type: tuple[str, ...] | None = None,
        severity: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
        exclude_tags: tuple[str, ...] = (),
        min_severity: str | None = None,
        tag_mode: str = "all",
        sort_by: str = "newest",
        search_backend: str = "auto",
    ) -> list[PersistedRunQueryHit]:
        """Search persisted IOCs by value."""

    def export_run(self, *, run_id: int) -> PersistedRunExport:
        """Load a persisted run and rebuild its extraction result."""

    def diff_runs(self, *, left_run_id: int, right_run_id: int) -> PersistedRunDiff:
        """Diff two persisted runs."""

    def diff_run_against_previous_source(self, *, run_id: int) -> PersistedRunDiff:
        """Diff a run against the previous run from the same source."""

    def delete_run(self, *, run_id: int) -> bool:
        """Delete a persisted run by id."""

    def prune_runs(
        self,
        *,
        before: str | None = None,
        keep_latest: int = 0,
        source_kind: str | None = None,
        source_value: str | None = None,
        statuses: tuple[str, ...] = (),
    ) -> int:
        """Prune persisted runs and return the number of deleted runs."""

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
        """List persisted runs with pagination metadata."""

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
        ioc_type: tuple[str, ...] | None = None,
        severity: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
        exclude_tags: tuple[str, ...] = (),
        min_severity: str | None = None,
        tag_mode: str = "all",
        sort_by: str = "newest",
        search_backend: str = "auto",
    ) -> PersistedIOCSearchPage:
        """Search persisted IOCs with pagination metadata."""

    def export_history(self) -> dict[str, object]:
        """Export the full persisted history."""

    def import_history(self, payload: dict[str, object]) -> dict[str, int]:
        """Import a persisted history payload."""

    def compact_history(self) -> None:
        """Compact the persistence store."""

    def retain_history(self, *, days: int, statuses: tuple[str, ...] = ()) -> int:
        """Prune history according to a retention policy."""

    def list_failed_batches(self, *, limit: int = 20) -> list[BatchJobSummary]:
        """List recent failed batch jobs."""

    def list_failed_batch_items(self, *, batch_job_id: int) -> list[FailedBatchItem]:
        """List failed items for a batch job."""

    def list_batch_jobs(
        self, *, limit: int = 20, statuses: tuple[str, ...] = ()
    ) -> list[BatchJobSummary]:
        """List persisted batch jobs."""

    def get_batch_job(self, *, batch_job_id: int) -> BatchJobDetail | None:
        """Load details for a persisted batch job."""

    def list_batch_runs(self, *, batch_job_id: int) -> list[PersistedRunSummary]:
        """List persisted runs that belong to a batch job."""

    def get_distributed_job(self, *, job_id: str) -> DistributedJobRecord | None:
        """Load a persisted distributed job by its external job id."""

    def list_distributed_jobs(
        self,
        *,
        limit: int = 50,
        statuses: tuple[str, ...] = (),
        queue_backend: str | None = None,
    ) -> list[DistributedJobRecord]:
        """List persisted distributed jobs."""

    def list_dead_letters(
        self,
        *,
        limit: int = 50,
        queue_backend: str | None = None,
    ) -> list[DeadLetterRecord]:
        """List persisted dead-lettered jobs."""
