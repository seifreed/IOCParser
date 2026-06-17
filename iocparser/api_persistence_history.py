from __future__ import annotations

from iocparser.api_persistence_query import query_service
from iocparser.application.contracts import (
    BatchJobInput,
    DeletePersistedRunInput,
    ListBatchJobsInput,
    ListFailedBatchesInput,
    PrunePersistedRunsInput,
    RetainHistoryInput,
)
from iocparser.application.maintenance_use_cases import (
    compact_persisted_history as _compact_persisted_history,
)
from iocparser.application.maintenance_use_cases import (
    export_persisted_history as _export_persisted_history,
)
from iocparser.application.maintenance_use_cases import (
    import_persisted_history as _import_persisted_history,
)
from iocparser.application.maintenance_use_cases import (
    list_failed_batch_jobs as _list_failed_batch_jobs,
)
from iocparser.application.maintenance_use_cases import (
    retain_persisted_history as _retain_persisted_history,
)
from iocparser.application.query_use_cases import (
    delete_persisted_run as _delete_persisted_run,
)
from iocparser.application.query_use_cases import (
    get_batch_job as _get_batch_job,
)
from iocparser.application.query_use_cases import (
    list_batch_jobs as _list_batch_jobs,
)
from iocparser.application.query_use_cases import (
    list_batch_runs as _list_batch_runs,
)
from iocparser.application.query_use_cases import (
    prune_persisted_runs as _prune_persisted_runs,
)
from iocparser.domain.models import BatchJobDetail, BatchJobSummary, PersistedRunSummary
from iocparser.errors import ValidationError
from iocparser.shared_utils import parse_string_filters

IMPORT_PAYLOAD_OBJECT_REQUIRED = "history import payload must be a mapping (JSON object)"


def list_failed_batch_jobs(*, db_uri: str, limit: int = 20) -> list[BatchJobSummary]:
    return _list_failed_batch_jobs(
        ListFailedBatchesInput(limit=limit),
        persistence_query_service=query_service(db_uri),
    )


def list_batch_jobs(
    *, db_uri: str, limit: int = 20, statuses: str | None = None
) -> list[BatchJobSummary]:
    return _list_batch_jobs(
        ListBatchJobsInput(limit=limit, statuses=parse_string_filters(statuses)),
        persistence_query_service=query_service(db_uri),
    )


def get_batch_job(*, db_uri: str, batch_job_id: int) -> BatchJobDetail | None:
    return _get_batch_job(
        BatchJobInput(batch_job_id=batch_job_id),
        persistence_query_service=query_service(db_uri),
    )


def list_batch_runs(*, db_uri: str, batch_job_id: int) -> list[PersistedRunSummary]:
    return _list_batch_runs(
        BatchJobInput(batch_job_id=batch_job_id),
        persistence_query_service=query_service(db_uri),
    )


def delete_persisted_run(*, db_uri: str, run_id: int) -> bool:
    return _delete_persisted_run(
        DeletePersistedRunInput(run_id=run_id),
        persistence_query_service=query_service(db_uri),
    )


def prune_persisted_runs(
    *,
    db_uri: str,
    before: str | None = None,
    keep_latest: int = 0,
    source_kind: str | None = None,
    source_value: str | None = None,
    statuses: str | tuple[str, ...] | None = None,
) -> int:
    return _prune_persisted_runs(
        PrunePersistedRunsInput(
            before=before,
            keep_latest=keep_latest,
            source_kind=source_kind,
            source_value=source_value,
            # Accept a comma-separated string (like retain_persisted_history /
            # list_batch_jobs) as well as a pre-split tuple; passing a bare string used to
            # reach SQLAlchemy's .in_() and raise a cryptic ArgumentError.
            statuses=parse_string_filters(statuses),
        ),
        persistence_query_service=query_service(db_uri),
    )


def export_persisted_history(*, db_uri: str) -> dict[str, object]:
    return _export_persisted_history(persistence_query_service=query_service(db_uri))


def import_persisted_history(*, db_uri: str, payload: dict[str, object]) -> dict[str, int]:
    # The use case reads payload like a mapping (payload.get(...)); a non-dict argument
    # otherwise surfaces a cryptic "'str' object has no attribute 'get'". The CLI already
    # rejects a non-object import file, so mirror that for direct API callers.
    if not isinstance(payload, dict):
        raise ValidationError(IMPORT_PAYLOAD_OBJECT_REQUIRED)
    return _import_persisted_history(payload, persistence_query_service=query_service(db_uri))


def compact_persisted_history(*, db_uri: str) -> None:
    _compact_persisted_history(persistence_query_service=query_service(db_uri))


def retain_persisted_history(*, db_uri: str, days: int, statuses: str | None = None) -> int:
    return _retain_persisted_history(
        RetainHistoryInput(days=days, statuses=parse_string_filters(statuses)),
        persistence_query_service=query_service(db_uri),
    )


__all__ = [
    "compact_persisted_history",
    "delete_persisted_run",
    "export_persisted_history",
    "get_batch_job",
    "import_persisted_history",
    "list_batch_jobs",
    "list_batch_runs",
    "list_failed_batch_jobs",
    "prune_persisted_runs",
    "retain_persisted_history",
]
