#!/usr/bin/env python3

"""
Tests for SQLite persistence.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from iocparser.domain.models import ExtractionResult, PersistOptions
from iocparser.infrastructure.persistence import (
    IOCModel,
    SQLAlchemyPersistenceService,
    SQLAlchemyUnitOfWork,
)
from iocparser.infrastructure.persistence import (
    RunIOCModel as RunIOC,
)
from iocparser.infrastructure.persistence import (
    RunModel as Run,
)
from iocparser.infrastructure.persistence import (
    SourceModel as Source,
)


def test_persist_run_sqlite(tmp_path) -> None:
    """Persist a run in SQLite and verify records."""
    db_path = tmp_path / "iocparser.db"
    unit_of_work = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")

    normal_iocs = {
        "domains": ["example.com"],
        "md5": ["5f4dcc3b5aa765d61d8327deb882cf99"],
    }
    warning_iocs = {
        "domains": [
            {"value": "google.com", "warning_list": "top", "description": "popular"},
        ],
    }

    options = PersistOptions(
        defang=True,
        check_warnings=True,
        force_update=False,
        output_format="stix",
    )

    result = ExtractionResult.from_grouped_payload(normal_iocs, warning_iocs)
    source_id = unit_of_work.source_repository.get_or_create(
        kind="url",
        value="https://example.com/report",
    )
    run_id = unit_of_work.run_repository.create_run(
        source_id=source_id,
        tool_version="5.0.0",
        options=options,
    )
    ioc_ids = unit_of_work.ioc_repository.get_or_create_normal(result)
    ioc_ids.extend(unit_of_work.ioc_repository.get_or_create_warnings(result))
    unit_of_work.run_repository.attach_iocs(run_id=run_id, ioc_ids=ioc_ids)
    unit_of_work.commit()

    with Session(unit_of_work.engine) as session:
        run = session.execute(select(Run).where(Run.id == run_id)).scalar_one()
        ioc_count = session.execute(select(IOCModel)).scalars().all()
        run_iocs = session.execute(select(RunIOC).where(RunIOC.run_id == run.id)).scalars().all()

    assert run.source_id is not None
    assert len(ioc_count) == 3
    assert len(run_iocs) == 3


def test_repositories_reuse_existing_source_and_iocs(tmp_path) -> None:
    db_path = tmp_path / "iocparser-reuse.db"
    unit_of_work = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    result = ExtractionResult.from_grouped_payload(
        {"domains": ["example.com"]},
        {"domains": [{"value": "google.com", "warning_list": "top", "description": "popular"}]},
    )

    source_id = unit_of_work.source_repository.get_or_create(kind="file", value="/tmp/sample.txt")
    first_ids = unit_of_work.ioc_repository.get_or_create_normal(result)
    first_warning_ids = unit_of_work.ioc_repository.get_or_create_warnings(result)
    unit_of_work.commit()

    same_source_id = unit_of_work.source_repository.get_or_create(
        kind="file", value="/tmp/sample.txt"
    )
    second_ids = unit_of_work.ioc_repository.get_or_create_normal(result)
    second_warning_ids = unit_of_work.ioc_repository.get_or_create_warnings(result)
    unit_of_work.commit()

    assert same_source_id == source_id
    assert second_ids == first_ids
    assert second_warning_ids == first_warning_ids
    unit_of_work.close()


def test_unit_of_work_rollback_discards_uncommitted_changes(tmp_path) -> None:
    db_path = tmp_path / "iocparser-rollback.db"
    unit_of_work = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")

    unit_of_work.source_repository.get_or_create(kind="text", value="transient value")
    unit_of_work.rollback()
    unit_of_work.close()

    verifier = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(verifier.engine) as session:
        persisted = session.execute(select(Run)).scalars().all()
        sources = session.execute(select(Source)).scalars().all()

    assert persisted == []
    assert sources == []
    verifier.close()


def test_persistence_service_persists_multiple_runs(tmp_path) -> None:
    db_path = tmp_path / "iocparser-batch.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    result = ExtractionResult.from_grouped_payload(
        {"domains": ["example.com"]},
        {"ips": [{"value": "198.51.100.7", "warning_list": "known", "description": "benign"}]},
    )
    options = PersistOptions(
        defang=False,
        check_warnings=True,
        force_update=False,
        output_format="json",
    )

    run_ids = service.persist_multiple_runs(
        [
            ("file", "/tmp/a.txt", result),
            ("url", "https://example.test/report", result),
        ],
        tool_version="9.9.9",
        options=options,
    )

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        runs = session.execute(select(Run)).scalars().all()
        sources = session.execute(select(Source)).scalars().all()
        iocs = session.execute(select(IOCModel)).scalars().all()

    assert len(run_ids) == 2
    assert len(runs) == 2
    assert len(sources) == 2
    assert len(iocs) == 2
    checker.close()
