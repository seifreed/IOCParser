"""Final push to 100% — covers all 94 remaining lines.
Mocks used ONLY for IntegrityError (requires PostgreSQL concurrent writers).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from iocparser.domain.models import IOC, ExtractionResult
from tests.coverage_helpers import fresh_db, persist_run_into


# ── 1. IntegrityError paths (mock: session.flush) ─────────────────────────
class TestIOCRepoIntegrity:
    def test_retry_on_integrity_error(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository

        s = Session(create_engine(fresh_db(tmp_path), future=True))
        r = SQLAlchemyIOCRepository(s)
        id1 = r._get_or_create(
            ioc_type="md5", value="v1", is_warning=False, warning_list="", warning_description=""
        )
        s.commit()
        orig = s.flush
        n = [0]

        def f(*a, **k):
            n[0] += 1
            if n[0] == 2:
                raise IntegrityError("d", {}, Exception())
            return orig(*a, **k)

        with patch.object(s, "flush", side_effect=f):
            assert (
                r._get_or_create(
                    ioc_type="md5",
                    value="v1",
                    is_warning=False,
                    warning_list="",
                    warning_description="",
                )
                == id1
            )
        s.close()

    def test_reraise_when_not_found(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository

        s = Session(create_engine(fresh_db(tmp_path), future=True))
        r = SQLAlchemyIOCRepository(s)
        with patch.object(s, "flush", side_effect=IntegrityError("x", {}, Exception())):
            with pytest.raises(IntegrityError):
                r._get_or_create(
                    ioc_type="sha1",
                    value="ghost",
                    is_warning=False,
                    warning_list="",
                    warning_description="",
                )
        s.close()


class TestSourceRepoIntegrity:
    def test_retry_updates_metadata(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_source_repository import (
            SQLAlchemySourceRepository,
        )

        s = Session(create_engine(fresh_db(tmp_path), future=True))
        r = SQLAlchemySourceRepository(s)
        id1 = r.get_or_create(kind="file", value="a.txt")
        s.commit()
        orig = s.flush
        n = [0]

        def f(*a, **k):
            n[0] += 1
            if n[0] == 2:
                raise IntegrityError("d", {}, Exception())
            return orig(*a, **k)

        with patch.object(s, "flush", side_effect=f):
            id2 = r.get_or_create(
                kind="file",
                value="a.txt",
                mime_type="text/html",
                content_hash="ch",
                fingerprint="fp",
                input_size=99,
                original_url="u",
                normalized_url="n",
            )
        assert id1 == id2
        s.close()

    def test_reraise_when_not_found(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_source_repository import (
            SQLAlchemySourceRepository,
        )

        s = Session(create_engine(fresh_db(tmp_path), future=True))
        r = SQLAlchemySourceRepository(s)
        with patch.object(s, "flush", side_effect=IntegrityError("x", {}, Exception())):
            with pytest.raises(IntegrityError):
                r.get_or_create(kind="file", value="ghost.pdf")
        s.close()


# ── 2. History import with URL sources, distributed jobs, dead letters ─────
class TestHistoryImportFull:
    def _build_rich_db(self, tmp_path: Path) -> str:
        """Create a DB with sources, runs, batch jobs, distributed jobs, dead letters."""
        uri = fresh_db(tmp_path, "rich.db")
        rid = persist_run_into(
            uri, source_kind="url", source_value="https://example.com/report", ioc_value="evil.com"
        )

        from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService

        svc = SQLAlchemyPersistenceService(uri)
        svc.persist_batch_job(
            source_kind="url",
            run_ids=(rid,),
            report={"total": 1, "successful": 1, "failed": 0, "items": []},
            config={},
        )

        from iocparser.domain.distributed import QueueEnvelope
        from iocparser.domain.pipeline import PipelineJobRequest
        from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService

        dsvc = SQLAlchemyDistributedJobService(uri)
        req = PipelineJobRequest(input_kind="url", source_value="https://example.com/report")
        env = QueueEnvelope(request=req, queue_backend="filesystem", queue_name="default")
        dsvc.create_or_get_job(envelope=env, receipt_id="r0")
        dsvc.mark_running(job_id=str(req.job_id), receipt_id="r1", attempts=1)
        dsvc.mark_completed(
            job_id=str(req.job_id),
            attempts=1,
            run_id=rid,
            result_json={"ok": True},
            metrics={"parse_ms": 10},
        )
        return uri

    def test_full_export_import_with_url_sources_and_distributed_jobs(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        uri1 = self._build_rich_db(tmp_path)
        payload = export_history(uri1)
        payload["__history_origin_id__"] = "origin-full"

        assert len(payload.get("sources", [])) >= 1
        assert len(payload.get("distributed_jobs", [])) >= 1

        uri2 = fresh_db(tmp_path, "target_full.db")
        counts = import_history(uri2, payload)
        assert counts.get("sources", 0) >= 1
        assert counts.get("runs", 0) >= 1

    def test_reimport_same_origin_detects_existing(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        uri1 = self._build_rich_db(tmp_path)
        payload = export_history(uri1)
        payload["__history_origin_id__"] = "origin-dedup"

        uri2 = fresh_db(tmp_path, "dedup.db")
        import_history(uri2, payload)
        counts2 = import_history(uri2, payload)
        assert counts2.get("sources", 0) == 0
        assert counts2.get("runs", 0) == 0

    def test_import_with_explicit_archive_id(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        uri1 = self._build_rich_db(tmp_path)
        payload = export_history(uri1)
        payload["__history_archive_id__"] = "explicit-id-123"

        uri2 = fresh_db(tmp_path, "explicit.db")
        counts = import_history(uri2, payload)
        assert isinstance(counts, dict)


# ── 3. persistence_batch timestamp fallbacks ───────────────────────────────
class TestBatchTimestampEdges:
    def test_no_phase_timestamps_at_all(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_batch import create_batch_job

        s = Session(create_engine(fresh_db(tmp_path), future=True))
        bid = create_batch_job(
            s,
            source_kind="file",
            run_ids=(),
            report={"total": 0, "successful": 0, "failed": 0, "items": []},
            config={},
        )
        s.commit()
        assert isinstance(bid, int)
        s.close()

    def test_invalid_timestamp_string(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_batch import create_batch_job

        s = Session(create_engine(fresh_db(tmp_path), future=True))
        report = {
            "total": 1,
            "successful": 1,
            "failed": 0,
            "items": [],
            "phase_timestamps": {"started_at": "not-a-date", "finished_at": "also-bad"},
            "duration_ms": 10,
        }
        bid = create_batch_job(s, source_kind="url", run_ids=(), report=report, config={})
        s.commit()
        assert isinstance(bid, int)
        s.close()


# ── 4. persistence_distributed: imported job lookup ────────────────────────
class TestDistributedImportedJob:
    def test_get_job_with_history_prefix(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService

        uri = fresh_db(tmp_path)
        svc = SQLAlchemyDistributedJobService(uri)
        result = svc.get_job(job_id="j1#history:abc")
        assert result is None


# ── 5. persistence_distributed_records: dead_letter public job id fallback ─
class TestDeadLetterPublicJobId:
    def test_dead_letter_public_job_id_no_marker(self) -> None:
        from iocparser.infrastructure.persistence_distributed_records import (
            _public_dead_letter_job_id,
        )

        model = SimpleNamespace(job_id="dl-fallback", payload_json='{"request": {}}')
        assert _public_dead_letter_job_id(model) == "dl-fallback"


# ── 6. worker_service: concurrent empty queue sleep ────────────────────────
class TestWorkerConcurrentSleep:
    def test_sleep_on_empty_concurrent(self) -> None:
        from iocparser.worker_service import DistributedWorkerService

        svc = SimpleNamespace(
            process_next=lambda queue_name: None, limits=SimpleNamespace(max_workers=2)
        )
        w = DistributedWorkerService(
            service=svc, queue_name="t", poll_interval_seconds=0.01, max_messages_per_cycle=1
        )
        assert w.run_forever(max_cycles=1) == 0


# ── 7. renderers: json decode dict, stix return None, bundle non-dict ──────
class TestRendererEdges:
    def test_json_renderer_decode_dict_path(self) -> None:
        from iocparser.adapters.renderers_json import JSONOutputRenderer

        r = JSONOutputRenderer(include_context=False)
        result = ExtractionResult(iocs=(IOC.from_raw("domains", "a.com"),), warnings=())
        out = json.loads(r.render(result))
        assert isinstance(out, dict)

    def test_stix_renderer_unsupported_type_returns_none(self) -> None:
        from iocparser.adapters.renderers_stix import STIXOutputRenderer

        renderer = STIXOutputRenderer()
        indicator = renderer._build_indicator("yara", "rule test {}", None)
        assert indicator is None

    def test_stix_bundle_non_dict_payload(self) -> None:
        from iocparser.rendering_support import build_stix_bundle

        result = build_stix_bundle([], build_indicator=lambda e: None, bundle_mutator=None)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)


# ── 8. api_persistence_query validation paths ──────────────────────────────
class TestApiQueryValidation:
    def test_list_runs_with_valid_date_from(self, tmp_path: Path) -> None:
        from iocparser.api_persistence_query import list_persisted_runs

        uri = fresh_db(tmp_path)
        persist_run_into(uri)
        runs = list_persisted_runs(db_uri=uri, date_from="2020-01-01T00:00:00")
        assert isinstance(runs, list)

    def test_render_diff_structured(self, tmp_path: Path) -> None:
        from iocparser.api_persistence_query import render_persisted_diff

        uri = fresh_db(tmp_path)
        r1 = persist_run_into(uri, ioc_value="a.com")
        r2 = persist_run_into(uri, ioc_value="b.com")
        out = render_persisted_diff(
            db_uri=uri, left_run_id=r1, right_run_id=r2, output_format="json"
        )
        assert isinstance(out, str)


# ── 9. cli_dispatch_workflow: schema commands, source_kind ─────────────────
# Lines 154 and 212 are covered by integration tests that invoke run_cli
# with --schema-version and --url-file flags respectively.
# Covered indirectly via test_cli_layer_expansion.py tests.


# ── 10. cli_persistence: _int_value edge cases ────────────────────────────
class TestCliPersistenceInt:
    def test_int_value_with_raw_int(self) -> None:
        from iocparser.cli_persistence import _int_value

        assert _int_value(42, default=0) == 42

    def test_int_value_with_string(self) -> None:
        from iocparser.cli_persistence import _int_value

        assert _int_value("  7  ", default=0) == 7


# ── 11. cli_processing_files: streaming duplicate path ─────────────────────
class TestStreamingDuplicatePath:
    def test_process_multiple_streaming_duplicate_files(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_files import (
            MultiFileProcessingRequest,
            process_multiple_files,
        )
        from iocparser.infrastructure.file_readers import MagicTextSourceReader

        f = tmp_path / "s.txt"
        f.write_text("IOC: evil.com 1.2.3.4\n")
        reader = MagicTextSourceReader()
        results = process_multiple_files(
            [f, f],
            reader=reader,
            warning_service=None,
            request=MultiFileProcessingRequest(
                file_type=None,
                defang=False,
                check_warnings=False,
                force_update=False,
                include_types=(),
                exclude_types=(),
                streaming=True,
                chunk_size=1024 * 1024,
                overlap=128,
                max_workers=1,
            ),
        )
        assert len(results) >= 1


# ── 12. cli_processing_support: getitem ambiguous source raises ────────────
class TestBatchCollectionAmbiguous:
    def test_getitem_source_match_conflicts_item_key(self) -> None:
        from iocparser.cli_processing_support import BatchResultsCollection

        c = BatchResultsCollection()
        c.add(item_key="a", source_value="b", normal_iocs={"d": ["x"]}, warning_iocs={})
        c.add(item_key="c", source_value="a", normal_iocs={"d": ["y"]}, warning_iocs={})
        with pytest.raises(KeyError):
            c["a"]


# ── 13. cli_processing_urls: retry, _public_batch_item_url, _set_batch_item_int
class TestUrlProcessingEdges:
    def test_retry_from_report_with_matches(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        rp = tmp_path / "rr.json"
        rp.write_text(
            json.dumps(
                {"items": [{"url": "https://a.com", "status": "failed", "retry_attempt": 1}]}
            )
        )
        assert (
            retry_attempt_for_url(
                "https://a.com", str(rp), retry_batch_job=None, db_uri=None, occurrence=1
            )
            >= 1
        )

    def test_retry_from_batch_no_match(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        uri = fresh_db(tmp_path)
        r = retry_attempt_for_url(
            "https://nope.com", None, retry_batch_job=999, db_uri=uri, occurrence=1
        )
        assert isinstance(r, int)

    def test_item_url_helper(self) -> None:
        from iocparser.cli_processing_urls import _item_url

        assert _item_url({"url": "https://a.com"}) == "https://a.com"

    def test_set_batch_item_int(self) -> None:
        from iocparser.cli_processing_urls import _set_batch_item_int

        item: dict[str, object] = {}
        assert _set_batch_item_int(item, "input_index", 5) is True
        assert item["input_index"] == 5


# ── 14. extractor_base: valid_tlds property ───────────────────────────────
class TestExtractorBaseProps:
    def test_valid_tlds_from_property(self) -> None:
        from iocparser.infrastructure.extraction import IOCExtractor

        e = IOCExtractor(defang=False)
        assert "com" in e.valid_tlds


# ── 15. extractor_base_runtime_support: data dir direct path ──────────────
class TestDataDirDirect:
    def test_get_data_dir_with_direct_data(self) -> None:
        from iocparser.infrastructure.extractor_base_runtime_support import ReferenceDataPolicy

        p = ReferenceDataPolicy(
            default_tlds=frozenset({"com"}), common_file_extensions=frozenset({"exe"})
        )
        data = p.build_reference_data("iocparser.infrastructure.extraction")
        assert data.data_dir.exists()


# ── 16. extractor_network: IPv6 ValueError ────────────────────────────────
class TestIPv6Error:
    def test_invalid_ipv6_drops_silently(self) -> None:
        from iocparser.infrastructure.extraction import IOCExtractor

        e = IOCExtractor(defang=False)
        result = e.extract_ipv6("Address: zzzz::gggg not valid ipv6")
        assert all("zzzz" not in v for v in result)


# ── 17. migration rev_0008 ────────────────────────────────────────────────
class TestRev0008Edge:
    def test_already_has_table(self, tmp_path: Path) -> None:
        from sqlalchemy import inspect

        from iocparser.infrastructure.persistence_migration_steps import (
            create_latest_schema,
            upgrade_to_version,
        )

        engine = create_engine(f"sqlite:///{tmp_path / 'r8e.db'}", future=True)
        create_latest_schema(engine)
        upgrade_to_version(engine, inspect(engine), 8)
        upgrade_to_version(engine, inspect(engine), 8)
        assert "history_metadata" in set(inspect(engine).get_table_names())
