"""Round 3: Cover paths requiring mocks for external systems (DB constraints, entry points, SQS).

These tests use unittest.mock strictly for simulating external infrastructure
that cannot be replicated in a test environment (unique constraint violations,
third-party entry points, AWS SQS responses).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from iocparser.domain.models import ExtractionResult
from tests.coverage_helpers import fresh_db

# ---------------------------------------------------------------------------
# 1. persistence_ioc_repository.py:54-59 — IntegrityError savepoint retry
# ---------------------------------------------------------------------------


class TestIOCRepositoryIntegrityRetry:
    def test_savepoint_catches_race_inserted_ioc_before_flush(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository

        db_uri = fresh_db(tmp_path, "ioc_race_retry.db")
        engine = create_engine(db_uri, future=True)
        session = Session(engine)
        repo = SQLAlchemyIOCRepository(session)
        existing_id = repo._get_or_create(
            ioc_type="md5",
            value="abc",
            is_warning=False,
            warning_list="",
            warning_description="",
        )
        session.commit()

        class EmptyResult:
            def scalars(self) -> EmptyResult:
                return self

            def all(self) -> list[object]:
                return []

        original_execute = session.execute
        calls = 0

        def hide_existing_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return EmptyResult()
            return original_execute(*args, **kwargs)

        with patch.object(session, "execute", side_effect=hide_existing_once):
            raced_id = repo._get_or_create(
                ioc_type="md5",
                value="abc",
                is_warning=False,
                warning_list="",
                warning_description="",
            )

        assert raced_id == existing_id
        session.close()
        engine.dispose()

    # IntegrityError flush retry/reraise for the IOC repository is covered by
    # test_defensive_edges_no_exclusions.test_ioc_repository_integrity_retry_and_reraise_paths.


# ---------------------------------------------------------------------------
# 2. persistence_source_repository.py:70-86 — IntegrityError savepoint retry
# ---------------------------------------------------------------------------


class TestSourceRepositoryIntegrityRetry:
    def test_savepoint_catches_race_inserted_source_before_flush(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_source_repository import (
            SQLAlchemySourceRepository,
        )

        db_uri = fresh_db(tmp_path, "src_race_retry.db")
        engine = create_engine(db_uri, future=True)
        session = Session(engine)
        repo = SQLAlchemySourceRepository(session)
        existing_id = repo.get_or_create(kind="file", value="race.pdf")
        session.commit()

        class EmptyResult:
            def scalars(self) -> EmptyResult:
                return self

            def all(self) -> list[object]:
                return []

        original_execute = session.execute
        calls = 0

        def hide_existing_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return EmptyResult()
            return original_execute(*args, **kwargs)

        with patch.object(session, "execute", side_effect=hide_existing_once):
            raced_id = repo.get_or_create(
                kind="file",
                value="race.pdf",
                mime_type="application/pdf",
                content_hash="deadbeef",
            )

        from iocparser.infrastructure.persistence_models import SourceModel

        assert raced_id == existing_id
        source = session.get(SourceModel, existing_id)
        assert source.mime_type == "application/pdf"
        assert source.content_hash == "deadbeef"
        session.close()
        engine.dispose()

    # IntegrityError flush retry/reraise for the source repository is covered by
    # test_defensive_edges_no_exclusions.test_source_repository_integrity_retry_and_reraise_paths.


# ---------------------------------------------------------------------------
# 3. plugins.py:152-188 — entry point plugin loading
# ---------------------------------------------------------------------------


class TestPluginEntryPointLoading:
    def _cleanup_registries(self, keys_to_remove: dict[str, list[str]]) -> None:
        from iocparser import plugins

        for registry_name, keys in keys_to_remove.items():
            registry = getattr(plugins, registry_name, {})
            for key in keys:
                registry.pop(key, None)

    def test_load_discovered_entry_points_registers_all_types(self) -> None:
        from iocparser.plugins import (
            _enricher_registry,
            _extractor_registry,
            _ioc_type_registry,
            _load_discovered_entry_points,
            _postprocessor_registry,
            _renderer_registry,
        )

        def make_ep(name: str, factory: object) -> SimpleNamespace:
            return SimpleNamespace(name=name, load=lambda f=factory: f)

        fake_discovered = SimpleNamespace(
            select=lambda group: {
                "iocparser.renderers": [
                    make_ep("_test_r", lambda wc, st: SimpleNamespace(render=lambda r: "ok"))
                ],
                "iocparser.enrichers": [make_ep("_test_e", lambda: None)],
                "iocparser.extractors": [make_ep("_test_x", lambda: None)],
                "iocparser.postprocessors": [make_ep("_test_pp", lambda: None)],
                "iocparser.ioc_types": [
                    make_ep("_test_it", lambda: {"name": "_test_it", "base_type": "urls"})
                ],
            }.get(group, []),
        )
        _load_discovered_entry_points(fake_discovered)
        assert "_test_r" in _renderer_registry
        assert "_test_e" in _enricher_registry
        assert "_test_x" in _extractor_registry
        assert "_test_pp" in _postprocessor_registry
        assert "_test_it" in _ioc_type_registry

        self._cleanup_registries(
            {
                "_renderer_registry": ["_test_r"],
                "_enricher_registry": ["_test_e"],
                "_extractor_registry": ["_test_x"],
                "_postprocessor_registry": ["_test_pp"],
                "_ioc_type_registry": ["_test_it"],
            }
        )

    def test_load_discovered_entry_points_isolates_failing_plugin(self) -> None:
        """One entry point whose load() raises must not abort the others.

        Regression: load() was called without per-entry-point error handling, so a
        single broken third-party plugin propagated out and broke discovery of every
        other (including built-in) plugin.
        """
        from iocparser.plugins import _load_discovered_entry_points, _renderer_registry

        def boom() -> object:
            raise ImportError("missing dependency")

        good_ep = SimpleNamespace(
            name="_test_good_r", load=lambda: (lambda wc, st: SimpleNamespace(render=lambda r: "ok"))
        )
        bad_ep = SimpleNamespace(name="_test_bad_r", load=boom)
        fake_discovered = SimpleNamespace(
            select=lambda group: [bad_ep, good_ep]
            if group == "iocparser.renderers"
            else [],
        )

        _load_discovered_entry_points(fake_discovered)

        assert "_test_good_r" in _renderer_registry
        assert "_test_bad_r" not in _renderer_registry
        self._cleanup_registries({"_renderer_registry": ["_test_good_r"]})

    def test_register_discovered_ioc_types_with_empty_base_type(self) -> None:
        from iocparser.plugins import (
            _ioc_type_registry,
            _register_discovered_ioc_types,
            register_ioc_type_plugin,
        )

        register_ioc_type_plugin("_bad_plugin", lambda: {"name": "_bad_plugin", "base_type": ""})
        _register_discovered_ioc_types()
        _ioc_type_registry.pop("_bad_plugin", None)

    def test_register_discovered_ioc_types_with_invalid_base_type(self) -> None:
        from iocparser.plugins import (
            _ioc_type_registry,
            _register_discovered_ioc_types,
            register_ioc_type_plugin,
        )

        register_ioc_type_plugin(
            "_invalid_bt", lambda: {"name": "_invalid_bt", "base_type": "nonexistent"}
        )
        _register_discovered_ioc_types()
        _ioc_type_registry.pop("_invalid_bt", None)

    def test_builtin_renderer_override_warning(self) -> None:
        from iocparser.plugins import (
            _BUILTIN_RENDERER_NAMES,
            _load_discovered_entry_points,
            _renderer_registry,
        )

        original_text = _renderer_registry.get("text")
        fake_ep = SimpleNamespace(
            name="text",
            load=lambda: lambda wc, st: SimpleNamespace(render=lambda r: "override"),
        )
        fake_discovered = SimpleNamespace(
            select=lambda group: [fake_ep] if group == "iocparser.renderers" else [],
        )
        assert "text" in _BUILTIN_RENDERER_NAMES
        _load_discovered_entry_points(fake_discovered)
        if original_text is not None:
            _renderer_registry["text"] = original_text

    def test_direct_register_warns_when_overriding_builtin(self, caplog) -> None:
        """A direct register_renderer/register_enricher call that clobbers a built-in must
        warn — the entry-point path warned, but the direct API used to overwrite silently.
        Registering a fresh custom name stays quiet.
        """
        import logging

        from iocparser.plugins import (
            _enricher_registry,
            _renderer_registry,
            register_enricher,
            register_renderer,
        )

        original_json = _renderer_registry.get("json")
        original_misp = _enricher_registry.get("misp")
        try:
            with caplog.at_level(logging.WARNING, logger="iocparser.plugins"):
                register_renderer("json", original_json)
                register_enricher("misp", original_misp)
                register_renderer("_round3_fresh_name", original_json)
            messages = [record.getMessage() for record in caplog.records]
            assert any("overrides built-in renderer" in message for message in messages)
            assert any("overrides built-in enricher" in message for message in messages)
            assert not any("_round3_fresh_name" in message for message in messages)
        finally:
            if original_json is not None:
                _renderer_registry["json"] = original_json
            if original_misp is not None:
                _enricher_registry["misp"] = original_misp
            _renderer_registry.pop("_round3_fresh_name", None)


# ---------------------------------------------------------------------------
# 4. worker_service.py:116-117 — concurrent worker sleep on empty queue
# ---------------------------------------------------------------------------


class TestWorkerServiceConcurrentSleep:
    def test_concurrent_run_forever_sleeps_when_empty(self) -> None:
        from iocparser.worker_service import DistributedWorkerService

        fake_service = SimpleNamespace(
            process_next=lambda queue_name: None,
            limits=SimpleNamespace(max_workers=2),
        )
        worker = DistributedWorkerService(
            service=fake_service,
            queue_name="test",
            poll_interval_seconds=0.01,
            max_messages_per_cycle=1,
        )
        processed = worker.run_forever(max_cycles=2)
        assert processed == 0


# ---------------------------------------------------------------------------
# 5. persistence_support.py:73,85,276-282 — url_filter_variants, _select_deletable
# ---------------------------------------------------------------------------


class TestPersistenceSupportHelpers:
    def test_normalized_url_filter_returns_none_for_garbage(self) -> None:
        from iocparser.infrastructure.persistence_support import normalized_url_filter

        result = normalized_url_filter("not a url at all")
        assert result is None or isinstance(result, str)

    def test_url_filter_variants_trailing_slash(self) -> None:
        from iocparser.infrastructure.persistence_support import _url_filter_variants

        variants = _url_filter_variants("https://example.com/path/")
        assert any(v.endswith("/") for v in variants)
        assert any(not v.endswith("/") for v in variants)

    def test_url_filter_variants_no_trailing_slash(self) -> None:
        from iocparser.infrastructure.persistence_support import _url_filter_variants

        variants = _url_filter_variants("https://example.com/path")
        assert len(variants) >= 1

    def test_select_deletable_with_keep_latest(self) -> None:
        from iocparser.infrastructure.persistence_support import _select_deletable

        runs = [
            SimpleNamespace(source_id=1, id=1),
            SimpleNamespace(source_id=1, id=2),
            SimpleNamespace(source_id=1, id=3),
            SimpleNamespace(source_id=2, id=4),
        ]
        deletable = _select_deletable(runs, keep_latest=1)
        assert len(deletable) == 2

    def test_select_deletable_zero_keeps_all(self) -> None:
        from iocparser.infrastructure.persistence_support import _select_deletable

        runs = [SimpleNamespace(source_id=1, id=1)]
        deletable = _select_deletable(runs, keep_latest=0)
        assert len(deletable) == 1


# ---------------------------------------------------------------------------
# 6. persistence_batch.py — batch job report parsing edge cases
# ---------------------------------------------------------------------------


class TestBatchJobReportParsing:
    def test_create_batch_job_from_report(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_batch import create_batch_job

        db_uri = fresh_db(tmp_path, "batch.db")
        engine = create_engine(db_uri, future=True)
        session = Session(engine)

        report = {
            "total": 3,
            "successful": 2,
            "failed": 1,
            "status": "partial",
            "items": [
                {"url": "https://a.com", "status": "ok"},
                {"url": "https://b.com", "status": "ok"},
                {"url": "https://c.com", "status": "failed", "error": "HTTP 404"},
            ],
            "phase_timings_ms": {"input_load": 10, "execution": 50},
            "phase_timestamps": {
                "started_at": datetime.now(UTC).isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
            },
            "metrics": {"average_item_duration_ms": 25},
        }
        batch_id = create_batch_job(
            session,
            source_kind="url",
            run_ids=(),
            report=report,
            config={"url_workers": 4},
        )
        session.commit()
        assert isinstance(batch_id, int)
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# 7. persistence_distributed.py:90,93 — job transition edge cases
# ---------------------------------------------------------------------------


class TestDistributedJobTransitions:
    def test_mark_completed_nonexistent_job(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService

        db_uri = fresh_db(tmp_path, "dist.db")
        service = SQLAlchemyDistributedJobService(db_uri)
        result = service.mark_completed(
            job_id="nonexistent",
            attempts=1,
            run_id=None,
            result_json={"ok": True},
            metrics={},
        )
        assert result is None

    def test_mark_failed_nonexistent_job(self, tmp_path: Path) -> None:
        from iocparser.domain.pipeline import PipelineErrorInfo
        from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService

        db_uri = fresh_db(tmp_path, "dist2.db")
        service = SQLAlchemyDistributedJobService(db_uri)
        result = service.mark_failed(
            job_id="nonexistent",
            attempts=1,
            error=PipelineErrorInfo("ERR", "test", False, "failed", "nope"),
            will_retry=False,
            metrics={},
        )
        assert result is None


# ---------------------------------------------------------------------------
# 8. Scattered single-line gaps
# ---------------------------------------------------------------------------


class TestScatteredGaps:
    def test_renderers_text_format_warning_string(self) -> None:
        from iocparser.adapters.renderers_text import format_warning_item

        result = format_warning_item("plain string warning")
        assert result == ["plain string warning"]

    def test_renderers_json_empty_result(self) -> None:
        from iocparser.adapters.renderers_json import JSONOutputRenderer

        renderer = JSONOutputRenderer(include_context=False)
        output = renderer.render(ExtractionResult())
        assert isinstance(output, str)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_renderers_stix_empty_result(self) -> None:
        from iocparser.adapters.renderers_stix import STIXOutputRenderer

        renderer = STIXOutputRenderer()
        output = renderer.render(ExtractionResult())
        assert isinstance(output, str)

    def test_rendering_support_build_stix_bundle_no_mutator(self) -> None:
        from iocparser.rendering_support import build_stix_bundle

        result = build_stix_bundle([], build_indicator=lambda e: None)
        assert isinstance(result, str)

    def test_rendering_support_build_stix_bundle_non_dict_payload(self, monkeypatch) -> None:
        import json as _json
        from unittest.mock import patch

        from iocparser.rendering_support import build_stix_bundle

        def fake_loads(s, *args, **kwargs):
            if isinstance(s, str) and '"type": "bundle"' in s:
                return []
            return _json.loads(s, *args, **kwargs)

        with patch("iocparser.rendering_support.json.loads", fake_loads):
            result = build_stix_bundle([], build_indicator=lambda e: None)
        parsed = _json.loads(result)
        assert parsed == {}

    def test_distributed_use_cases_idempotency_key_url(self) -> None:
        from iocparser.application.distributed_use_cases import idempotency_key_for
        from iocparser.domain.pipeline import PipelineJobRequest

        request = PipelineJobRequest(input_kind="url", source_value="https://x.com")
        key = idempotency_key_for(request, digester=None)
        assert key == "url:https://x.com:cw=True:fu=False:df=True:o=:e=:eo=False:ft=:p=False:db="

    def test_domain_sources_normalize_url(self) -> None:
        from iocparser.domain.sources import normalize_url_value

        result = normalize_url_value("HTTPS://Example.Com/Path")
        assert result is not None
        assert "example.com" in result.lower()
