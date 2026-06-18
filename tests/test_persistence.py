#!/usr/bin/env python3

"""
Tests for SQLite persistence.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from iocparser.api_persistence_history import export_persisted_history
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


def test_import_history_matches_existing_url_sources_by_normalized_identity(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-url-source.db"
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
                "https://example.test/report",
                ExtractionResult.from_grouped_payload({"domains": ["existing.example"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=options,
    )
    timestamp = "2026-05-13T00:00:00"
    payload: dict[str, object] = {
        "sources": [
            {
                "id": 99,
                "kind": "url",
                "value": "HTTPS://Example.TEST/report#section",
                "value_search": "https://example.test/report#section",
                "original_url": "HTTPS://Example.TEST/report#section",
                "normalized_url": "HTTPS://Example.TEST/report#section",
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        ]
    }

    counts = service.import_history(payload)

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        sources = session.execute(select(Source)).scalars().all()
    checker.close()

    assert counts["sources"] == 0
    assert len(sources) == 1


def test_import_history_trims_replayed_source_kind_identity(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-source-kind.db"
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
                "https://example.test/report",
                ExtractionResult.from_grouped_payload({"domains": ["existing.example"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=options,
    )
    timestamp = "2026-05-13T00:00:00"
    payload: dict[str, object] = {
        "sources": [
            {
                "id": 99,
                "kind": " url ",
                "value": "HTTPS://Example.TEST/report#section",
                "value_search": "https://example.test/report#section",
                "original_url": "HTTPS://Example.TEST/report#section",
                "normalized_url": "HTTPS://Example.TEST/report#section",
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        ]
    }

    counts = service.import_history(payload)

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        sources = session.execute(select(Source)).scalars().all()
    checker.close()

    assert counts["sources"] == 0
    assert len(sources) == 1


def test_import_history_trims_replayed_non_url_source_value(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-source-value.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    result = ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {})
    service.persist_multiple_runs(
        [("file", "f.txt", result)],
        tool_version="5.0.0",
        options=PersistOptions(defang=False, check_warnings=False, force_update=False, output_format="json"),
    )
    payload = export_persisted_history(db_uri=f"sqlite:///{db_path}")
    payload["sources"][0]["value"] = " f.txt "

    counts = service.import_history(payload)

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        sources = session.execute(select(Source)).scalars().all()
    checker.close()

    assert counts["sources"] == 0
    assert len(sources) == 1


def test_import_history_trims_replayed_ioc_type_identity(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-ioc-type.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    result = ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {})
    service.persist_multiple_runs(
        [("file", "f.txt", result)],
        tool_version="5.0.0",
        options=PersistOptions(defang=False, check_warnings=False, force_update=False, output_format="json"),
    )
    payload = {
        "iocs": [
            {
                "id": 99,
                "ioc_type": " domains ",
                "value": "example.com",
                "value_search": "example.com",
                "is_warning": False,
                "warning_list": "",
                "warning_description": "",
            }
        ]
    }

    counts = service.import_history(payload)

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        iocs = session.execute(select(IOCModel)).scalars().all()
    checker.close()

    assert counts["iocs"] == 0
    assert len(iocs) == 1


def test_import_history_trims_replayed_warning_ioc_metadata(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-warning-ioc.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    result = ExtractionResult.from_grouped_payload(
        {"domains": ["example.com"]},
        {"domains": [{"value": "bad.example", "warning_list": "top", "description": "popular"}]},
    )
    service.persist_multiple_runs(
        [("file", "f.txt", result)],
        tool_version="5.0.0",
        options=PersistOptions(defang=False, check_warnings=True, force_update=False, output_format="json"),
    )
    payload = export_persisted_history(db_uri=f"sqlite:///{db_path}")
    payload["iocs"][1]["warning_list"] = " top "
    payload["iocs"][1]["warning_description"] = " popular "

    counts = service.import_history(payload)

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        iocs = session.execute(select(IOCModel)).scalars().all()
    checker.close()

    assert counts["iocs"] == 0
    assert len(iocs) == 2


def test_import_history_trims_replayed_ioc_value(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-ioc-value.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    result = ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {})
    service.persist_multiple_runs(
        [("file", "f.txt", result)],
        tool_version="5.0.0",
        options=PersistOptions(defang=False, check_warnings=False, force_update=False, output_format="json"),
    )
    payload = export_persisted_history(db_uri=f"sqlite:///{db_path}")
    payload["iocs"][0]["value"] = " example.com "

    counts = service.import_history(payload)

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        iocs = session.execute(select(IOCModel)).scalars().all()
    checker.close()

    assert counts["iocs"] == 0
    assert len(iocs) == 1


def test_import_history_normalizes_new_url_source_metadata(tmp_path) -> None:
    db_path = tmp_path / "iocparser-import-new-url-source.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    timestamp = "2026-05-13T00:00:00"
    payload: dict[str, object] = {
        "sources": [
            {
                "id": 99,
                "kind": "url",
                "value": "HTTPS://Example.TEST/report#section",
                "value_search": "https://example.test/report#section",
                "normalized_url": "HTTPS://Example.TEST/report#section",
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
        ]
    }

    counts = service.import_history(payload)

    checker = SQLAlchemyUnitOfWork(f"sqlite:///{db_path}")
    with Session(checker.engine) as session:
        (source,) = session.execute(select(Source)).scalars().all()
    checker.close()

    assert counts["sources"] == 1
    assert source.original_url == "HTTPS://Example.TEST/report#section"
    assert source.normalized_url == "https://example.test/report"


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


def test_prune_keep_latest_uses_newest_run_id_as_timestamp_tiebreaker(tmp_path) -> None:
    db_path = tmp_path / "iocparser-prune-tiebreaker.db"
    db_uri = f"sqlite:///{db_path}"
    service = SQLAlchemyPersistenceService(db_uri)
    options = PersistOptions(
        defang=False,
        check_warnings=False,
        force_update=False,
        output_format="json",
    )
    run_ids = service.persist_multiple_runs(
        [
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload({"domains": ["old.example"]}, {}),
            ),
            (
                "file",
                "same.txt",
                ExtractionResult.from_grouped_payload({"domains": ["new.example"]}, {}),
            ),
        ],
        tool_version="5.0.0",
        options=options,
    )
    verifier = SQLAlchemyUnitOfWork(db_uri)
    try:
        with Session(verifier.engine) as session:
            timestamp = session.get(Run, run_ids[0]).started_at
            for run_id in run_ids:
                session.get(Run, run_id).started_at = timestamp
            session.commit()
    finally:
        verifier.close()

    deleted = service.prune_runs(
        before="2999-01-01T00:00:00",
        keep_latest=1,
        source_kind="file",
        source_value="same.txt",
    )
    remaining = service.list_runs(limit=10, source_kind="file", source_value="same.txt")

    assert deleted == 1
    assert [run.run_id for run in remaining] == [run_ids[1]]


def test_query_service_trims_source_kind_filters(tmp_path) -> None:
    db_path = tmp_path / "iocparser-source-kind-filter.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    service.persist_multiple_runs(
        [
            (
                "file",
                "sample.txt",
                ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=PersistOptions(defang=False, check_warnings=False, force_update=False, output_format="json"),
    )

    assert service.query_runs_page(limit=10, source_kind="file").total == 1
    assert service.query_runs_page(limit=10, source_kind=" file ").total == 1
    assert service.search_iocs_page(value="example.com", source_kind="file").total == 1
    assert service.search_iocs_page(value="example.com", source_kind=" file ").total == 1


def test_query_service_normalizes_tuple_ioc_type_filters(tmp_path) -> None:
    db_path = tmp_path / "iocparser-ioc-type-filter.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    service.persist_multiple_runs(
        [
            (
                "file",
                "sample.txt",
                ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    assert service.search_iocs_page(value="example.com", ioc_type=("domain",)).total == 1
    assert service.search_iocs_page(value="example.com", ioc_type=("hashes",)).total == 0


def test_query_service_normalizes_source_value_filters(tmp_path) -> None:
    db_path = tmp_path / "iocparser-source-value-filter.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    service.persist_multiple_runs(
        [
            (
                "file",
                "sample.txt",
                ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=PersistOptions(
            defang=False, check_warnings=False, force_update=False, output_format="json"
        ),
    )

    assert service.query_runs_page(limit=10, source_value=1).total == 0
    assert service.search_iocs_page(value="example.com", source_value=1).total == 0


def test_query_service_trims_source_kind_and_preserves_url_value_matching(tmp_path) -> None:
    db_path = tmp_path / "iocparser-source-kind-url-filter.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    service.persist_multiple_runs(
        [
            (
                "url",
                "HTTPS://Example.TEST/report#frag",
                ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=PersistOptions(defang=False, check_warnings=False, force_update=False, output_format="json"),
    )

    assert (
        service.query_runs_page(
            limit=10, source_kind=" url ", source_value="https://example.test/report"
        ).total
        == 1
    )
    assert (
        service.search_iocs_page(
            value="example.com", source_kind=" url ", source_value="https://example.test/report"
        ).total
        == 1
    )


def test_query_service_ignores_blank_source_value_filters(tmp_path) -> None:
    db_path = tmp_path / "iocparser-blank-source-value.db"
    service = SQLAlchemyPersistenceService(f"sqlite:///{db_path}")
    service.persist_multiple_runs(
        [
            (
                "file",
                "sample.txt",
                ExtractionResult.from_grouped_payload({"domains": ["example.com"]}, {}),
            )
        ],
        tool_version="5.0.0",
        options=PersistOptions(defang=False, check_warnings=False, force_update=False, output_format="json"),
    )

    assert service.query_runs_page(limit=10, source_value="   ").total == 1
    assert service.search_iocs_page(value="example.com", source_value="   ").total == 1


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


def test_url_source_filter_preserves_path_case_identity(tmp_path) -> None:
    db_path = tmp_path / "iocparser-url-path-case.db"
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
                "https://example.test/Report",
                ExtractionResult.from_grouped_payload({"domains": ["upper.example"]}, {}),
            ),
            (
                "url",
                "https://example.test/report",
                ExtractionResult.from_grouped_payload({"domains": ["lower.example"]}, {}),
            ),
        ],
        tool_version="9.9.9",
        options=options,
    )

    page = service.query_runs_page(
        limit=10,
        source_kind="url",
        source_value="https://example.test/report",
    )

    assert page.total == 1
    assert page.items[0].source_value == "https://example.test/report"


def test_parse_datetime_normalizes_tz_aware_to_naive_utc() -> None:
    """A tz-aware ISO filter must be converted to naive UTC to match stored values.

    Regression: parse_datetime returned a tz-aware datetime whose offset was then
    stripped (not converted) at comparison time, shifting filters by the offset.
    """
    from iocparser.infrastructure.persistence_support import parse_datetime

    plus_five = parse_datetime("2024-01-01T14:00:00+05:00")
    assert plus_five is not None
    assert plus_five.tzinfo is None
    assert plus_five.isoformat() == "2024-01-01T09:00:00"

    zulu = parse_datetime("2024-01-01T12:00:00Z")
    assert zulu is not None
    assert zulu.tzinfo is None
    assert zulu.isoformat() == "2024-01-01T12:00:00"

    # Naive input is returned unchanged.
    naive = parse_datetime("2024-01-01T12:00:00")
    assert naive is not None
    assert naive.isoformat() == "2024-01-01T12:00:00"
    assert parse_datetime("   ") is None
    assert parse_datetime(None) is None


def test_parse_datetime_reports_invalid_input_cleanly() -> None:
    """A malformed --date-from/--date-to/--prune-before value must surface a clean
    ValidationError, not a bare ValueError stack trace from datetime.fromisoformat.
    """
    from iocparser.errors import ValidationError
    from iocparser.infrastructure.persistence_support import parse_datetime

    with pytest.raises(ValidationError, match="not-a-date"):
        parse_datetime("not-a-date")


def test_create_engine_for_uri_reports_bad_db_uri_cleanly() -> None:
    """A malformed or unsupported --db-uri must surface a clean ValidationError rather
    than an uncaught SQLAlchemy ArgumentError/NoSuchModuleError stack trace.
    """
    from iocparser.errors import ValidationError
    from iocparser.infrastructure.persistence_uow import create_engine_for_uri

    with pytest.raises(ValidationError, match="Invalid database URI"):
        create_engine_for_uri("mysql+nonexistentdriver://host/db")

    with pytest.raises(ValidationError, match="Invalid database URI"):
        create_engine_for_uri("::::not a uri::::")


def test_in_memory_unit_of_work_survives_close_and_reopen() -> None:
    """An in-memory sqlite UoW must keep its schema after close() + reopen.

    Regression: close() disposed the cached in-memory engine, destroying the DB,
    while migrate() stayed short-circuited, so the next UoW saw 'no such table'.
    """
    from sqlalchemy import text

    uri = "sqlite:///:memory:"
    first = SQLAlchemyUnitOfWork(uri)
    first.close()

    second = SQLAlchemyUnitOfWork(uri)
    try:
        # Without the fix this raises OperationalError: no such table: runs.
        count = second.session.execute(text("SELECT COUNT(*) FROM runs")).scalar()
    finally:
        second.close()
    assert count == 0


def test_in_memory_unit_of_work_is_usable_from_another_thread() -> None:
    """An in-memory sqlite DB must be shared across threads (StaticPool).

    Regression: the default pool gave each thread a separate empty database and
    pysqlite's check_same_thread blocked cross-thread reuse, so parallel persist
    / the worker pool against sqlite:///:memory: failed with 'no such table' or a
    same-thread ProgrammingError.
    """
    import threading

    from sqlalchemy import text

    uri = "sqlite:///:memory:?cross-thread"
    owner = SQLAlchemyUnitOfWork(uri)
    counts: list[int | None] = []

    def query_from_thread() -> None:
        worker = SQLAlchemyUnitOfWork(uri)
        try:
            counts.append(worker.session.execute(text("SELECT COUNT(*) FROM runs")).scalar())
        finally:
            worker.close()

    thread = threading.Thread(target=query_from_thread)
    thread.start()
    thread.join(timeout=5)
    owner.close()

    # A cross-thread failure (separate DB / check_same_thread) leaves counts empty.
    assert counts == [0]
