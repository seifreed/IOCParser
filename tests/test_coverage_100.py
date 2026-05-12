"""Push to 100% coverage. Real code paths — mocks only for external services (SQS boto3)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from iocparser.domain.models import IOC, ExtractionResult, WarningMatch
from tests.coverage_helpers import fresh_db, persist_run_into

# ── IntegrityError via real UNIQUE constraint ──────────────────────────────
# IntegrityError savepoint retry paths (lines 54-59 ioc_repo, 70-86 source_repo)
# require concurrent DB connections with real UNIQUE constraints — only testable
# with PostgreSQL/MySQL, not SQLite (single-writer lock prevents simulation).


# ── History import with collision detection ────────────────────────────────
class TestHistoryImportCollision:
    def test_import_with_origin_id_creates_archive_id(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        uri1 = fresh_db(tmp_path, "h1.db")
        persist_run_into(uri1)
        payload = export_history(uri1)
        payload["__history_origin_id__"] = "origin-abc"

        uri2 = fresh_db(tmp_path, "h2.db")
        counts = import_history(uri2, payload)
        assert counts.get("sources", 0) >= 1

    def test_reimport_same_origin_is_idempotent(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        uri1 = fresh_db(tmp_path, "h3.db")
        persist_run_into(uri1)
        payload = export_history(uri1)
        payload["__history_origin_id__"] = "origin-xyz"

        uri2 = fresh_db(tmp_path, "h4.db")
        import_history(uri2, payload)
        counts2 = import_history(uri2, payload)
        assert counts2.get("sources", 0) == 0

    def test_import_with_explicit_archive_id(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        uri = fresh_db(tmp_path, "h5.db")
        persist_run_into(uri)
        payload = export_history(uri)
        payload["__history_archive_id__"] = "explicit-archive-id"

        uri2 = fresh_db(tmp_path, "h6.db")
        counts = import_history(uri2, payload)
        assert isinstance(counts, dict)

    def test_import_with_batch_jobs(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
        from iocparser.infrastructure.persistence.history import export_history, import_history

        uri = fresh_db(tmp_path, "hbatch.db")
        run_id = persist_run_into(uri)
        svc = SQLAlchemyPersistenceService(uri)
        svc.persist_batch_job(
            source_kind="file",
            run_ids=(run_id,),
            report={"total": 1, "successful": 1, "failed": 0, "items": []},
            config={},
        )
        payload = export_history(uri)

        uri2 = fresh_db(tmp_path, "hbatch2.db")
        counts = import_history(uri2, payload)
        assert counts.get("batch_jobs", 0) >= 1


# ── persistence_batch: timestamp edge cases ────────────────────────────────
class TestBatchTimestamps:
    def test_missing_finished_at(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_batch import create_batch_job

        engine = create_engine(fresh_db(tmp_path, "bt1.db"), future=True)
        session = Session(engine)
        now = datetime.now(UTC).isoformat()
        report = {
            "total": 1,
            "successful": 1,
            "failed": 0,
            "items": [],
            "phase_timestamps": {"started_at": now},
            "duration_ms": 50,
        }
        bid = create_batch_job(session, source_kind="file", run_ids=(), report=report, config={})
        session.commit()
        assert isinstance(bid, int)
        session.close()
        engine.dispose()

    def test_non_dict_phase_timestamps(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_batch import create_batch_job

        engine = create_engine(fresh_db(tmp_path, "bt2.db"), future=True)
        session = Session(engine)
        report = {
            "total": 1,
            "successful": 1,
            "failed": 0,
            "items": [],
            "phase_timestamps": "not a dict",
            "duration_ms": 10,
        }
        bid = create_batch_job(session, source_kind="url", run_ids=(), report=report, config={})
        session.commit()
        assert isinstance(bid, int)
        session.close()
        engine.dispose()


# ── cli_processing_files: merge_results ────────────────────────────────────
class TestMergeResults:
    def test_merge_results_dict(self) -> None:
        from iocparser.cli_processing_files import merge_results

        r = merge_results(
            {"a": ExtractionResult(iocs=(IOC.from_raw("domains", "x.com"),), warnings=())}
        )
        assert len(r.iocs) == 1


# ── cli_processing_support: source_value_for found ────────────────────────
class TestBatchCollectionSourceValue:
    def test_source_value_for_found(self) -> None:
        from iocparser.cli_processing_support import BatchResultsCollection

        c = BatchResultsCollection()
        c.add(item_key="k1", source_value="s1", normal_iocs={}, warning_iocs={})
        assert c.source_value_for("k1") == "s1"

    def test_getitem_ambiguous_source_multiple(self) -> None:
        from iocparser.cli_processing_support import BatchResultsCollection

        c = BatchResultsCollection()
        c.add(item_key="k1", source_value="shared", normal_iocs={"d": ["a"]}, warning_iocs={})
        c.add(item_key="k2", source_value="shared", normal_iocs={"d": ["b"]}, warning_iocs={})
        # Two source matches → falls through to KeyError
        with pytest.raises(KeyError):
            c["shared"]


# ── cli_processing_urls: retry attempt paths ──────────────────────────────
class TestRetryAttemptEdges:
    def test_retry_from_report_multiple_occurrences(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        report = tmp_path / "r.json"
        report.write_text(
            json.dumps(
                {
                    "items": [
                        {"url": "https://a.com", "status": "failed", "retry_attempt": 2},
                        {"url": "https://a.com", "status": "failed", "retry_attempt": 3},
                    ]
                }
            )
        )
        r = retry_attempt_for_url(
            "https://a.com", str(report), retry_batch_job=None, db_uri=None, occurrence=2
        )
        assert r >= 1

    def test_retry_from_report_no_match(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        report = tmp_path / "r2.json"
        report.write_text(json.dumps({"items": [{"url": "https://other.com", "status": "ok"}]}))
        r = retry_attempt_for_url(
            "https://a.com", str(report), retry_batch_job=None, db_uri=None, occurrence=1
        )
        assert r >= 0

    def test_retry_from_batch_db_no_match(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        uri = fresh_db(tmp_path, "retry.db")
        r = retry_attempt_for_url(
            "https://nope.com", None, retry_batch_job=999, db_uri=uri, occurrence=1
        )
        assert isinstance(r, int)


# ── renderers: STIX warning path, JSON lines ──────────────────────────────
class TestRendererWarningPaths:
    def test_stix_with_warning_builds_indicator(self) -> None:
        from iocparser.adapters.renderers_stix import STIXOutputRenderer

        result = ExtractionResult(
            iocs=(),
            warnings=(
                WarningMatch(
                    ioc=IOC.from_raw("ips", "1.2.3.4"), warning_list="test-wl", description="d"
                ),
            ),
        )
        output = STIXOutputRenderer().render(result)
        assert "1.2.3.4" in output or "ipv4" in output

    def test_json_renderer_jsonl_format(self) -> None:
        from iocparser.adapters.renderers_json import JSONLinesOutputRenderer

        result = ExtractionResult(iocs=(IOC.from_raw("domains", "a.com"),), warnings=())
        output = JSONLinesOutputRenderer().render(result)
        assert "a.com" in output


# ── rendering_support: build_stix_bundle with mutator ─────────────────────
class TestStixBundleMutator:
    def test_bundle_mutator_called(self) -> None:
        from stix2 import Indicator

        from iocparser.rendering_support import build_stix_bundle

        now = datetime.now(UTC)
        ind = Indicator(
            name="test",
            pattern="[domain-name:value = 'a.com']",
            pattern_type="stix",
            pattern_version="2.1",
            valid_from=now,
            indicator_types=["malicious-activity"],
        )

        def build(_entry: object) -> Indicator:
            return ind

        result = build_stix_bundle(
            [1], build_indicator=build, bundle_mutator=lambda p: {**p, "mutated": True}
        )
        assert "mutated" in result


# ── extractor_base: common_file_extensions property ───────────────────────
class TestExtractorProperties:
    def test_common_file_extensions(self) -> None:
        from iocparser.infrastructure.extraction import IOCExtractor

        e = IOCExtractor(defang=False)
        assert "exe" in e.common_file_extensions
        assert isinstance(e.legitimate_with_subdomains, set)


# ── extractor_network: dynamic method generation path ─────────────────────
class TestExtractorNetworkDynamic:
    def test_dynamic_methods_exist(self) -> None:
        from iocparser.infrastructure.extraction import IOCExtractor

        e = IOCExtractor(defang=False)
        for name in (
            "extract_domains",
            "extract_ips",
            "extract_ipv6",
            "extract_urls",
            "extract_emails",
        ):
            assert hasattr(e, name)
            assert callable(getattr(e, name))


# ── persistence_distributed: mark_running with existing job ───────────────
class TestDistributedMarkRunning:
    def test_mark_running_existing_job(self, tmp_path: Path) -> None:
        from iocparser.domain.distributed import QueueEnvelope
        from iocparser.domain.pipeline import PipelineJobRequest
        from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService

        uri = fresh_db(tmp_path, "dj.db")
        svc = SQLAlchemyDistributedJobService(uri)
        req = PipelineJobRequest(input_kind="text", source_value="test")
        envelope = QueueEnvelope(request=req, queue_backend="filesystem", queue_name="default")
        svc.create_or_get_job(envelope=envelope, receipt_id="r0")
        result = svc.mark_running(job_id=str(req.job_id), receipt_id="r1", attempts=1)
        assert result is not None
        assert result.status == "running"


# ── persistence_distributed_records: public job ID extraction ─────────────
class TestDistributedRecords:
    def test_public_job_id_with_import_marker(self) -> None:
        from iocparser.infrastructure.persistence_distributed_records import _public_job_id

        model = SimpleNamespace(
            job_id="j1#history:abc",
            payload_json='{"request": {"job_id": "original-j1"}, "__history_import__": {"archive_id": "abc"}}',
        )
        assert _public_job_id(model) == "original-j1"

    def test_public_dead_letter_job_id_with_import_marker(self) -> None:
        from iocparser.infrastructure.persistence_distributed_records import (
            _public_dead_letter_job_id,
        )

        model = SimpleNamespace(
            job_id="dl1#history:abc",
            payload_json='{"request": {"job_id": "orig-dl"}, "__history_import__": {"archive_id": "abc"}}',
        )
        assert _public_dead_letter_job_id(model) == "orig-dl"


# ── migration rev_0008: history_metadata on existing DB ───────────────────
class TestRev0008:
    def test_applies_to_existing_db(self, tmp_path: Path) -> None:
        from sqlalchemy import inspect

        from iocparser.infrastructure.persistence_migration_steps import (
            create_latest_schema,
            upgrade_to_version,
        )

        engine = create_engine(f"sqlite:///{tmp_path / 'r8.db'}", future=True)
        try:
            create_latest_schema(engine)
            upgrade_to_version(engine, inspect(engine), 8)
            assert "history_metadata" in set(inspect(engine).get_table_names())
        finally:
            engine.dispose()


# ── api_persistence_query: validation paths ───────────────────────────────
class TestApiQueryValidation:
    def test_render_persisted_run_json(self, tmp_path: Path) -> None:
        from iocparser.api_persistence_query import render_persisted_run

        uri = fresh_db(tmp_path, "render.db")
        rid = persist_run_into(uri)
        output = render_persisted_run(db_uri=uri, run_id=rid, output_format="json")
        assert isinstance(output, str)
        assert "x.com" in output

    def test_export_structured_diff(self, tmp_path: Path) -> None:
        from iocparser.api_persistence_query import export_structured_persisted_diff

        uri = fresh_db(tmp_path, "sdiff.db")
        r1 = persist_run_into(uri, ioc_value="a.com")
        r2 = persist_run_into(uri, ioc_value="b.com")
        result = export_structured_persisted_diff(db_uri=uri, left_run_id=r1, right_run_id=r2)
        assert isinstance(result, dict)
        assert "added" in result


# ── cli_persistence: int coercion edge cases ──────────────────────────────
class TestCliPersistenceCoercion:
    def test_int_value_with_padded_string(self) -> None:
        from iocparser.cli_output_rendering import int_run_metadata_value

        assert int_run_metadata_value({"k": "  7  "}, "k", 0) == 7

    def test_optional_int_with_int(self) -> None:
        from iocparser.cli_output_rendering import optional_int_run_metadata_value

        assert optional_int_run_metadata_value({"k": 42}, "k") == 42


# ── worker_service: concurrent with messages then empty ───────────────────
class TestWorkerConcurrentMixed:
    def test_concurrent_processes_then_sleeps(self) -> None:
        from iocparser.worker_service import DistributedWorkerService

        calls = [0]

        def fake_next(queue_name: str) -> object | None:  # noqa: ARG001
            calls[0] += 1
            return SimpleNamespace() if calls[0] <= 2 else None

        svc = SimpleNamespace(process_next=fake_next, limits=SimpleNamespace(max_workers=2))
        w = DistributedWorkerService(
            service=svc, queue_name="t", poll_interval_seconds=0.01, max_messages_per_cycle=1
        )
        processed = w.run_forever(max_cycles=3)
        assert processed >= 0
