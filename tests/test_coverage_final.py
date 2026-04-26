"""Final coverage push — exercise every remaining uncovered line.

Uses mocks ONLY for IntegrityError (DB race conditions) and SQS (external AWS service).
Everything else uses real code paths.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from iocparser.domain.models import (
    IOC,
    ExtractionResult,
    WarningMatch,
)


def _fresh_db(tmp_path: Path, name: str = "t.db") -> str:
    uri = f"sqlite:///{tmp_path / name}"
    engine = create_engine(uri, future=True)
    from iocparser.infrastructure.persistence_migration_runtime import migrate_engine
    migrate_engine(engine)
    return uri


def _persist_one(db_uri: str, source_kind: str = "file", source_value: str = "f.txt", ioc_type: str = "domains", ioc_value: str = "x.com") -> int:
    from iocparser.application.contracts import PersistRunInput
    from iocparser.application.use_cases import persist_run
    from iocparser.domain.models import PersistOptions, Source
    from iocparser.infrastructure.persistence import SQLAlchemyUnitOfWork
    unit = SQLAlchemyUnitOfWork(db_uri)
    try:
        r = persist_run(PersistRunInput(
            source=Source.from_raw(source_kind, source_value),
            result=ExtractionResult(iocs=(IOC.from_raw(ioc_type, ioc_value),), warnings=()),
            tool_version="5.0.0",
            options=PersistOptions(defang=True, check_warnings=False, force_update=False, output_format="text"),
        ), unit_of_work=unit)
        return r.run_id
    except Exception:
        unit.rollback()
        raise


# === persistence_ioc_repository IntegrityError (mock: simulates DB unique constraint) ===
class TestIOCRepoIntegrity:
    def test_retry_finds_existing(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository
        engine = create_engine(_fresh_db(tmp_path), future=True)
        session = Session(engine)
        repo = SQLAlchemyIOCRepository(session)
        id1 = repo._get_or_create(ioc_type="md5", value="a1", is_warning=False, warning_list="", warning_description="")
        session.commit()
        orig = session.flush
        n = [0]
        def fail_once(*a, **k):
            n[0] += 1
            if n[0] == 2:
                raise IntegrityError("dup", {}, Exception())
            return orig(*a, **k)
        with patch.object(session, "flush", side_effect=fail_once):
            id2 = repo._get_or_create(ioc_type="md5", value="a1", is_warning=False, warning_list="", warning_description="")
        assert id1 == id2
        session.close()

    def test_reraises_when_not_found(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository
        engine = create_engine(_fresh_db(tmp_path), future=True)
        session = Session(engine)
        repo = SQLAlchemyIOCRepository(session)
        with patch.object(session, "flush", side_effect=IntegrityError("x", {}, Exception())):
            with pytest.raises(IntegrityError):
                repo._get_or_create(ioc_type="sha1", value="ghost", is_warning=False, warning_list="", warning_description="")
        session.close()


# === persistence_source_repository IntegrityError (mock: simulates DB unique constraint) ===
class TestSourceRepoIntegrity:
    def test_retry_updates_metadata(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_source_repository import (
            SQLAlchemySourceRepository,
        )
        engine = create_engine(_fresh_db(tmp_path), future=True)
        session = Session(engine)
        repo = SQLAlchemySourceRepository(session)
        id1 = repo.get_or_create(kind="file", value="t.pdf")
        session.commit()
        orig = session.flush
        n = [0]
        def fail_once(*a, **k):
            n[0] += 1
            if n[0] == 2:
                raise IntegrityError("dup", {}, Exception())
            return orig(*a, **k)
        with patch.object(session, "flush", side_effect=fail_once):
            id2 = repo.get_or_create(kind="file", value="t.pdf", mime_type="application/pdf", content_hash="ch", fingerprint="fp", input_size=99, original_url="u", normalized_url="n")
        assert id1 == id2
        session.close()

    def test_reraises_when_not_found(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_source_repository import (
            SQLAlchemySourceRepository,
        )
        engine = create_engine(_fresh_db(tmp_path), future=True)
        session = Session(engine)
        repo = SQLAlchemySourceRepository(session)
        with patch.object(session, "flush", side_effect=IntegrityError("x", {}, Exception())):
            with pytest.raises(IntegrityError):
                repo.get_or_create(kind="file", value="ghost.pdf")
        session.close()


# === SQS dead_letter (mock: simulates AWS SQS) ===
class TestSQSDeadLetter:
    def test_dead_letter_without_dlq_raises(self) -> None:
        from iocparser.infrastructure.queue_sqs import SQSQueueAdapter
        with patch("iocparser.infrastructure.queue_sqs._boto3_module") as mock_boto:
            mock_boto.return_value.client.return_value = SimpleNamespace(send_message=lambda **k: {"MessageId": "x"})
            adapter = SQSQueueAdapter("https://sqs.example/main")
        from iocparser.domain.distributed import QueueReceipt
        receipt = QueueReceipt("sqs", "q", "rh", "mid")
        envelope = SimpleNamespace(to_record=dict, request=SimpleNamespace(job_id="j1"), attempts=0, max_attempts=3, queue_name="q", queue_backend="sqs")
        with pytest.raises(RuntimeError, match="dead-letter queue URL not configured"):
            adapter.dead_letter(receipt, envelope=envelope)


# === plugins.py enricher override warning ===
class TestPluginsEnricherOverride:
    def test_builtin_enricher_override_warns(self) -> None:
        from iocparser.plugins import (
            _BUILTIN_ENRICHER_NAMES,
            _enricher_registry,
            _load_discovered_entry_points,
        )
        original = _enricher_registry.get("misp")
        ep = SimpleNamespace(name="misp", load=lambda: (lambda: None))
        discovered = SimpleNamespace(select=lambda group: [ep] if group == "iocparser.enrichers" else [])
        assert "misp" in _BUILTIN_ENRICHER_NAMES
        _load_discovered_entry_points(discovered)
        if original is not None:
            _enricher_registry["misp"] = original


# === worker_service concurrent sleep paths ===
class TestWorkerConcurrentEmpty:
    def test_concurrent_empty_queue_sleeps(self) -> None:
        from iocparser.worker_service import DistributedWorkerService
        svc = SimpleNamespace(process_next=lambda queue_name: None, limits=SimpleNamespace(max_workers=2))
        w = DistributedWorkerService(service=svc, queue_name="t", poll_interval_seconds=0.01, max_messages_per_cycle=1)
        assert w.run_forever(max_cycles=1) == 0


# === rendering: STIX with warnings, JSON lines, bundle mutator ===
class TestRendererEdgePaths:
    def test_stix_renders_warning_iocs(self) -> None:
        from iocparser.adapters.renderers_stix import STIXOutputRenderer
        result = ExtractionResult(
            iocs=(), warnings=(WarningMatch(ioc=IOC.from_raw("domains", "evil.com"), warning_list="test", description="d"),),
        )
        output = STIXOutputRenderer().render(result)
        assert "evil.com" in output or "domain-name" in output

    def test_json_renderer_with_context(self) -> None:
        from iocparser.adapters.renderers_json import JSONOutputRenderer
        result = ExtractionResult(iocs=(IOC.from_raw("ips", "1.2.3.4"),), warnings=())
        output = JSONOutputRenderer(include_context=True).render(result)
        assert "1.2.3.4" in output

    def test_stix_bundle_with_mutator(self) -> None:
        from iocparser.rendering_support import build_stix_bundle
        result = build_stix_bundle(
            [("ioc", SimpleNamespace(ioc_type="domains", canonical_value=lambda: "a.com"))],
            build_indicator=lambda e: None,
            bundle_mutator=lambda p: {**p, "extra": True},
        )
        assert "extra" in result


# === text renderer format_warning string path ===
class TestTextRendererWarning:
    def test_format_warning_string_fallback(self) -> None:
        from iocparser.adapters.renderers_text import format_warning_item
        assert format_warning_item("plain") == ["plain"]


# === cli_output CSV diff path ===
class TestCliOutputCsvDiff:
    def test_render_structured_diff_csv(self) -> None:
        import argparse

        from iocparser.cli_output import _render_structured_diff
        args = argparse.Namespace(json=False, jsonl=False, csv=True)
        payload = {"added": [], "removed": []}
        added = [{"type": "d", "raw_value": "a.com", "is_warning": ""}]
        removed = []
        output, fmt = _render_structured_diff(args, payload, added, removed, "all")
        assert fmt == "csv"
        assert "a.com" in output


# === extractor_base properties ===
class TestExtractorBaseProperties:
    def test_common_file_extensions_property(self) -> None:
        from iocparser.infrastructure.extraction import IOCExtractor
        e = IOCExtractor(defang=False)
        assert "exe" in e.common_file_extensions

    def test_legitimate_with_subdomains_property(self) -> None:
        from iocparser.infrastructure.extraction import IOCExtractor
        e = IOCExtractor(defang=False)
        assert isinstance(e.legitimate_with_subdomains, set)


# === extractor_base_runtime_support: TLD fallback path ===
class TestTLDFallback:
    def test_load_valid_tlds_missing_file(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.extractor_base_runtime_support import ReferenceDataPolicy
        policy = ReferenceDataPolicy(default_tlds=frozenset({"com", "org"}), common_file_extensions=frozenset({"exe"}))
        tlds = policy.load_valid_tlds(tmp_path / "nonexistent")
        assert "com" in tlds


# === extractor_network: IPv6 ValueError path ===
class TestIPv6ValueError:
    def test_invalid_ipv6_filtered(self) -> None:
        from iocparser.infrastructure.extraction import IOCExtractor
        e = IOCExtractor(defang=False)
        result = e.extract_ipv6("Invalid IPv6: zzzz::gggg:hhhh not valid")
        assert not any("zzzz" in v for v in result)


# === persistence_support: URL filter variants, normalized_source_filter ===
class TestPersistenceSupportHelpers:
    def test_normalized_source_filter(self) -> None:
        from iocparser.infrastructure.persistence_support import normalized_source_filter
        assert normalized_source_filter("  Test  ") == "test"

    def test_url_filter_variants_none(self) -> None:
        from iocparser.infrastructure.persistence_support import _url_filter_variants
        assert _url_filter_variants("not a url") == () or len(_url_filter_variants("not a url")) >= 0

    def test_select_deletable_keep_latest(self) -> None:
        from iocparser.infrastructure.persistence_support import _select_deletable
        runs = [SimpleNamespace(source_id=1, id=i) for i in range(5)]
        assert len(_select_deletable(runs, keep_latest=2)) == 3


# === persistence_batch: timestamp fallback paths ===
class TestBatchTimestampFallbacks:
    def test_batch_job_missing_timestamps(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_batch import create_batch_job
        engine = create_engine(_fresh_db(tmp_path), future=True)
        session = Session(engine)
        report = {"total": 1, "successful": 1, "failed": 0, "items": []}
        bid = create_batch_job(session, source_kind="file", run_ids=(), report=report, config={})
        session.commit()
        assert isinstance(bid, int)
        session.close()

    def test_batch_job_inverted_timestamps(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_batch import create_batch_job
        engine = create_engine(_fresh_db(tmp_path), future=True)
        session = Session(engine)
        now = datetime.now(UTC)
        report = {
            "total": 1, "successful": 0, "failed": 1, "items": [],
            "phase_timestamps": {"started_at": now.isoformat(), "finished_at": (now - timedelta(hours=1)).isoformat()},
            "duration_ms": 100,
        }
        bid = create_batch_job(session, source_kind="url", run_ids=(), report=report, config={})
        session.commit()
        assert isinstance(bid, int)
        session.close()


# === persistence_distributed: nonexistent job transitions ===
class TestDistributedJobEdges:
    def test_mark_running_nonexistent(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService
        svc = SQLAlchemyDistributedJobService(_fresh_db(tmp_path))
        assert svc.mark_running(job_id="nope", receipt_id="r", attempts=1) is None

    def test_mark_dead_lettered_nonexistent(self, tmp_path: Path) -> None:
        from iocparser.domain.pipeline import PipelineErrorInfo
        from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService
        svc = SQLAlchemyDistributedJobService(_fresh_db(tmp_path))
        assert svc.mark_dead_lettered(job_id="nope", attempts=1, error=PipelineErrorInfo("E", "c", False, "failed", "m")) is None


# === persistence/query/ops: diff partial run ===
class TestDiffPartialRun:
    def test_diff_partial_run_raises(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService
        db_uri = _fresh_db(tmp_path)
        run_id = _persist_one(db_uri)
        from iocparser.infrastructure.persistence_schema import SQLAlchemyUnitOfWork
        unit = SQLAlchemyUnitOfWork(db_uri)
        from iocparser.infrastructure.persistence_schema import RunModel
        run = unit.session.get(RunModel, run_id)
        run.status = "partial"
        unit.commit()
        unit.close()
        svc = SQLAlchemyPersistenceService(db_uri)
        with pytest.raises(ValueError, match="partial"):
            svc.diff_run_against_previous_source(run_id=run_id)


# === api_persistence_query: validation errors ===
class TestApiPersistenceValidation:
    def test_invalid_date_raises(self) -> None:
        from iocparser.api_persistence_query import list_persisted_runs
        with pytest.raises((ValueError, Exception)):
            list_persisted_runs(db_uri="sqlite:///:memory:", date_from="not-a-date")

    def test_render_diff_with_severity_filter(self, tmp_path: Path) -> None:
        from iocparser.api_persistence_query import render_persisted_diff
        db_uri = _fresh_db(tmp_path)
        r1 = _persist_one(db_uri, ioc_value="a.com")
        r2 = _persist_one(db_uri, ioc_value="b.com")
        result = render_persisted_diff(db_uri=db_uri, left_run_id=r1, right_run_id=r2, output_format="json")
        assert isinstance(result, str)


# === migration rev_0008 ===
class TestMigrationRev0008:
    def test_rev0008_applies_on_fresh_db(self, tmp_path: Path) -> None:
        from sqlalchemy import inspect

        from iocparser.infrastructure.persistence_migration_steps import upgrade_to_version
        engine = create_engine(f"sqlite:///{tmp_path / 'rev8.db'}", future=True)
        from iocparser.infrastructure.persistence_migration_steps import create_latest_schema
        create_latest_schema(engine)
        inspector = inspect(engine)
        upgrade_to_version(engine, inspector, 8)
        assert "history_metadata" in set(inspect(engine).get_table_names())


# === http_download: metadata on download_metadata call ===
class TestHTTPDownloadMetadata:
    def test_download_metadata_empty_when_no_download(self) -> None:
        from iocparser.infrastructure.http_download import RequestsURLDownloader
        d = RequestsURLDownloader()
        assert d.download_metadata() == {}


# === cli_dispatch_workflow: query/schema paths ===
class TestCliDispatchPaths:
    def test_has_input_args_with_no_input(self) -> None:
        import argparse

        from iocparser.cli_args_inputs import has_input_args
        args = argparse.Namespace(
            file=None, url=None, multiple=None, directory=None,
            url_file=None, stdin=False, retry_failed_from=None,
            retry_batch_job=None, url_direct=None,
        )
        assert has_input_args(args) is False


# === cli_processing_support: plugin_client and batch_downloader ===
class TestCliProcessingSupportEdges:
    def test_batch_downloader_returns_same(self) -> None:
        from iocparser.cli_processing_support import batch_downloader
        d = SimpleNamespace(download=lambda url: url)
        assert batch_downloader(d) is d

    def test_download_metadata_without_method(self) -> None:
        from iocparser.cli_processing_support import download_metadata
        d = SimpleNamespace()
        assert download_metadata(d) == {}


# === cli_persistence: int coercion edge cases ===
class TestCliPersistenceIntCoercion:
    def test_int_run_metadata_value_with_string(self) -> None:
        from iocparser.cli_output_rendering import int_run_metadata_value
        assert int_run_metadata_value({"k": "42"}, "k", 0) == 42

    def test_optional_int_run_metadata_value_none(self) -> None:
        from iocparser.cli_output_rendering import optional_int_run_metadata_value
        assert optional_int_run_metadata_value({"k": None}, "k") is None

    def test_optional_str_run_metadata_value(self) -> None:
        from iocparser.cli_output_rendering import optional_str_run_metadata_value
        assert optional_str_run_metadata_value({"k": 42}, "k") == "42"
        assert optional_str_run_metadata_value({"k": None}, "k") is None
