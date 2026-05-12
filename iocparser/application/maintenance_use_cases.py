from __future__ import annotations

from iocparser.application.contracts import ListFailedBatchesInput, RetainHistoryInput
from iocparser.domain.models import BatchJobSummary
from iocparser.interfaces.ports import PersistenceQueryService


def export_persisted_history(
    *, persistence_query_service: PersistenceQueryService
) -> dict[str, object]:
    """Export all persisted history."""
    return persistence_query_service.export_history()


def import_persisted_history(
    payload: dict[str, object],
    *,
    persistence_query_service: PersistenceQueryService,
) -> dict[str, int]:
    """Import all persisted history from a structured payload."""
    return persistence_query_service.import_history(payload)


def compact_persisted_history(*, persistence_query_service: PersistenceQueryService) -> None:
    """Compact the underlying persistence store."""
    persistence_query_service.compact_history()


def retain_persisted_history(
    request: RetainHistoryInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> int:
    """Apply a retention policy to persisted history."""
    return persistence_query_service.retain_history(days=request.days, statuses=request.statuses)


def list_failed_batch_jobs(
    request: ListFailedBatchesInput,
    *,
    persistence_query_service: PersistenceQueryService,
) -> list[BatchJobSummary]:
    """List recent failed batch jobs."""
    return persistence_query_service.list_failed_batches(limit=request.limit)
