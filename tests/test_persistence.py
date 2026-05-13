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

    try:
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
            run_iocs = (
                session.execute(select(RunIOC).where(RunIOC.run_id == run.id)).scalars().all()
            )
    finally:
        unit_of_work.close()

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


def test_ioc_repository_refreshes_legacy_defanged_search_value(tmp_path) -> None:
    db_path = tmp_path / "iocparser-legacy-search.db"
    unit_of_work = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    try:
        legacy_ioc = IOCModel(
            ioc_type="urls",
            value="hxxps://Example[.]COM/a",
            value_search="hxxps://example[.]com/a",
            is_warning=False,
            warning_list="",
            warning_description="",
        )
        unit_of_work.session.add(legacy_ioc)
        unit_of_work.session.flush()
        legacy_id = legacy_ioc.id

        ids = unit_of_work.ioc_repository.get_or_create_normal(
            ExtractionResult.from_grouped_payload(
                {"urls": ["hxxps://Example[.]COM/a"]},
                {},
            )
        )
        unit_of_work.commit()

        refreshed = unit_of_work.session.get(IOCModel, legacy_id)
        assert ids == [legacy_id]
        assert refreshed is not None
        assert refreshed.value_search == "https://example.com/a"
    finally:
        unit_of_work.close()


def test_import_history_normalizes_imported_ioc_search_values(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-search.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    timestamp = "2026-05-13T00:00:00"
    payload: dict[str, object] = {
        "sources": [
            {
                "id": 1,
                "kind": "file",
                "value": "archive.txt",
                "value_search": "archive.txt",
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        ],
        "iocs": [
            {
                "id": 1,
                "ioc_type": "urls",
                "value": "hxxps://Example[.]COM/a",
                "value_search": "hxxps://example[.]com/a",
                "is_warning": False,
                "warning_list": "",
                "warning_description": "",
            }
        ],
        "runs": [
            {
                "id": 1,
                "source_id": 1,
                "started_at": timestamp,
                "finished_at": timestamp,
                "tool_version": "5.0.0",
                "options_json": "{}",
                "normal_ioc_count": 1,
                "warning_ioc_count": 0,
                "processed_items": 1,
                "successful_items": 1,
                "failed_items": 0,
                "partial_error_count": 0,
                "duration_ms": 0,
                "status": "success",
                "error_message": "",
            }
        ],
        "run_iocs": [
            {
                "id": 1,
                "run_id": 1,
                "ioc_id": 1,
                "severity": "low",
                "tags_json": "[]",
                "tags_search": "",
                "evidence_json": "[]",
            }
        ],
    }

    counts = service.import_history(payload)
    page = service.search_iocs_page(value="https://example.com/a", search_backend="like")

    assert counts["iocs"] == 1
    assert page.total == 1
    assert page.items[0].value == "hxxps://Example[.]COM/a"


def test_persisted_diff_compares_canonical_ioc_values(tmp_path) -> None:
    db_path = tmp_path / "iocparser-diff-canonical.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    options = PersistOptions(
        defang=False,
        check_warnings=True,
        force_update=False,
        output_format="json",
    )
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload(
                    {
                        "domains": ["Example[.]COM"],
                        "urls": ["hxxps://Example[.]COM/a"],
                    },
                    {
                        "domains": [
                            {
                                "value": "Warn[.]Example",
                                "warning_list": "Known",
                                "description": "",
                            }
                        ]
                    },
                ),
            ),
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload(
                    {
                        "domains": ["example.com"],
                        "urls": ["https://Example.COM/a"],
                    },
                    {
                        "domains": [
                            {
                                "value": "warn.example",
                                "warning_list": "Known",
                                "description": "",
                            }
                        ]
                    },
                ),
            ),
        ],
        tool_version="5.0.0",
        options=options,
    )

    diff = service.diff_runs(left_run_id=run_ids[0], right_run_id=run_ids[1])

    assert diff.added.total_count() == 0
    assert diff.removed.total_count() == 0


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


def test_persistence_service_handles_duplicate_iocs_in_run_result(tmp_path) -> None:
    db_path = tmp_path / "iocparser-duplicate-run-iocs.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    result = ExtractionResult.from_grouped_payload(
        {"domains": ["example.com", "example.com"]},
        {
            "domains": [
                {"value": "google.com", "warning_list": "top", "description": "popular"},
                {"value": "google.com", "warning_list": "top", "description": "popular"},
            ],
        },
    )
    options = PersistOptions(
        defang=False,
        check_warnings=True,
        force_update=False,
        output_format="json",
    )

    (run_id,) = service.persist_multiple_runs(
        [("file", "/tmp/duplicates.txt", result)],
        tool_version="9.9.9",
        options=options,
    )

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        run_iocs = session.execute(select(RunIOC).where(RunIOC.run_id == run_id)).scalars().all()
    checker.close()

    assert len(run_iocs) == 2


def test_persistence_service_preserves_direct_url_source_metadata(tmp_path) -> None:
    db_path = tmp_path / "iocparser-direct-url-source.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    options = PersistOptions(
        defang=False,
        check_warnings=False,
        force_update=False,
        output_format="json",
    )

    service.persist_multiple_runs(
        [
            (
                "url",
                "HTTPS://Example.COM/report#section",
                ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {}),
            )
        ],
        tool_version="9.9.9",
        options=options,
    )

    run = service.list_runs(limit=1)[0]

    assert run.original_url == "HTTPS://Example.COM/report#section"
    assert run.normalized_url == "https://example.com/report"
