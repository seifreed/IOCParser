"""Shared helpers for coverage-gap test files."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine


def fresh_db(tmp_path: Path, name: str = "test.db") -> str:
    """Create a temporary SQLite database, run migrations, and return its URI."""
    db_path = tmp_path / name
    db_uri = f"sqlite:///{db_path}"
    engine = create_engine(db_uri, future=True)
    from iocparser.infrastructure.persistence_migration_runtime import migrate_engine

    try:
        migrate_engine(engine)
    finally:
        engine.dispose()
    return db_uri


def persist_run_into(
    db_uri: str,
    *,
    source_kind: str = "file",
    source_value: str = "f.txt",
    ioc_type: str = "domains",
    ioc_value: str = "x.com",
) -> int:
    """Persist a minimal run and return the run_id."""
    from iocparser.application.contracts import PersistRunInput
    from iocparser.application.use_cases import persist_run
    from iocparser.domain.models import IOC, ExtractionResult, PersistOptions, Source
    from iocparser.infrastructure.persistence import SQLAlchemyUnitOfWork

    unit = SQLAlchemyUnitOfWork(db_uri)
    try:
        result = persist_run(
            PersistRunInput(
                source=Source.from_raw(source_kind, source_value),
                result=ExtractionResult(
                    iocs=(IOC.from_raw(ioc_type, ioc_value),),
                    warnings=(),
                ),
                tool_version="5.0.0",
                options=PersistOptions(
                    defang=True,
                    check_warnings=False,
                    force_update=False,
                    output_format="text",
                ),
            ),
            unit_of_work=unit,
        )
        return result.run_id
    except Exception:
        unit.rollback()
        raise
    finally:
        unit.close()


def complete_distributed_job(
    db_uri: str,
    *,
    source_value: str,
    run_id: int,
    receipt_prefix: str = "r",
) -> str:
    """Create a distributed job for source_value and mark it running then completed.

    Returns the public job id.
    """
    from iocparser.domain.distributed import QueueEnvelope
    from iocparser.domain.pipeline import PipelineJobRequest
    from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService

    service = SQLAlchemyDistributedJobService(db_uri)
    request = PipelineJobRequest(input_kind="url", source_value=source_value)
    envelope = QueueEnvelope(request=request, queue_backend="filesystem", queue_name="default")
    created = service.create_or_get_job(envelope=envelope, receipt_id=f"{receipt_prefix}0")
    service.mark_running(job_id=created.job_id, receipt_id=f"{receipt_prefix}1", attempts=1)
    service.mark_completed(
        job_id=created.job_id,
        attempts=1,
        run_id=run_id,
        result_json={"ok": True},
        metrics={"parse_ms": 10},
    )
    return created.job_id
