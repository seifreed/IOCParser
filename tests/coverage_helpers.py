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

    migrate_engine(engine)
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
