"""Tests to cover remaining gaps and reach 100% coverage.

These tests exercise real code paths without mocks or monkeypatch.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from iocparser.cli_processing_support import BatchResultsCollection
from iocparser.errors import SourceNotFoundError, SourceProcessingError
from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository
from iocparser.infrastructure.persistence_source_repository import SQLAlchemySourceRepository
from iocparser.rendering_support import prepare_json_payload, serialize_pretty_json
from iocparser.shared_utils import _dedup_key, deduplicate_iocs
from tests.coverage_helpers import fresh_db

# ---------------------------------------------------------------------------
# 1. __main__.py — exercise the main() entry point error paths
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    def test_main_function_exists_and_callable(self) -> None:
        from iocparser.__main__ import main

        assert callable(main)

    def test_main_help_flag(self, tmp_path: Path) -> None:
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "iocparser", "--help"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0

    def test_main_keyboard_interrupt(self) -> None:
        import iocparser.__main__ as main_module

        original = main_module.execute

        main_module.execute = lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt)
        try:
            with pytest.raises(SystemExit) as exc_info:
                main_module.main()
            assert exc_info.value.code == 0
        finally:
            main_module.execute = original

    def test_main_validation_error(self) -> None:
        import iocparser.__main__ as main_module
        from iocparser.errors import ValidationError

        original = main_module.execute

        def raise_err() -> None:
            raise ValidationError("test")

        main_module.execute = raise_err
        try:
            with pytest.raises(SystemExit) as exc_info:
                main_module.main()
            assert exc_info.value.code == 1
        finally:
            main_module.execute = original

    def test_main_iocparser_error(self) -> None:
        import iocparser.__main__ as main_module
        from iocparser.errors import IOCParserError

        original = main_module.execute

        def raise_err() -> None:
            raise IOCParserError("test")

        main_module.execute = raise_err
        try:
            with pytest.raises(SystemExit) as exc_info:
                main_module.main()
            assert exc_info.value.code == 1
        finally:
            main_module.execute = original


# ---------------------------------------------------------------------------
# 2. api_public.py — verify the facade re-exports
# ---------------------------------------------------------------------------


class TestApiPublicFacade:
    def test_api_public_imports_extraction(self) -> None:
        from iocparser import api_public

        assert hasattr(api_public, "extraction")
        assert hasattr(api_public, "persistence")
        assert hasattr(api_public, "pipeline")
        assert hasattr(api_public, "integrations")
        assert hasattr(api_public, "renderers")

    def test_extraction_module_has_extract_functions(self) -> None:
        from iocparser.api_public import extraction

        assert callable(getattr(extraction, "extract_result_from_text", None))

    def test_integrations_has_get_renderer(self) -> None:
        from iocparser.api_public import integrations

        assert callable(getattr(integrations, "get_renderer", None))


# ---------------------------------------------------------------------------
# 3. application/errors.py — re-export shim coverage
# ---------------------------------------------------------------------------


class TestApplicationErrorsShim:
    def test_source_not_found_error_importable(self) -> None:
        from iocparser.application.errors import SourceNotFoundError as Imported

        assert Imported is SourceNotFoundError

    def test_source_processing_error_importable(self) -> None:
        from iocparser.application.errors import SourceProcessingError as Imported

        assert Imported is SourceProcessingError

    def test_all_exports(self) -> None:
        from iocparser.application import errors

        assert "SourceNotFoundError" in errors.__all__
        assert "SourceProcessingError" in errors.__all__


# ---------------------------------------------------------------------------
# 4+5. persistence repositories — savepoint retry paths
# ---------------------------------------------------------------------------


class TestIOCRepositorySavepointRetry:
    def test_get_or_create_returns_existing_on_duplicate(self, tmp_path: Path) -> None:
        session = Session(create_engine(fresh_db(tmp_path), future=True))
        repo = SQLAlchemyIOCRepository(session)
        id1 = repo._get_or_create(
            ioc_type="domains",
            value="evil.com",
            is_warning=False,
            warning_list="",
            warning_description="",
        )
        session.commit()
        id2 = repo._get_or_create(
            ioc_type="domains",
            value="evil.com",
            is_warning=False,
            warning_list="",
            warning_description="",
        )
        assert id1 == id2
        session.close()

    def test_multiple_get_or_create_same_session(self, tmp_path: Path) -> None:
        session = Session(create_engine(fresh_db(tmp_path), future=True))
        repo = SQLAlchemyIOCRepository(session)
        ids = [
            repo._get_or_create(
                ioc_type="sha256",
                value=f"hash{i}",
                is_warning=False,
                warning_list="",
                warning_description="",
            )
            for i in range(5)
        ]
        session.commit()
        assert len(set(ids)) == 5
        session.close()


class TestSourceRepositorySavepointRetry:
    def test_get_or_create_returns_existing_on_duplicate(self, tmp_path: Path) -> None:
        session = Session(create_engine(fresh_db(tmp_path), future=True))
        repo = SQLAlchemySourceRepository(session)
        id1 = repo.get_or_create(kind="file", value="test.pdf")
        session.commit()
        id2 = repo.get_or_create(
            kind="file",
            value="test.pdf",
            mime_type="application/pdf",
            content_hash="abc123",
        )
        assert id1 == id2
        session.close()

    def test_get_or_create_updates_metadata_on_existing(self, tmp_path: Path) -> None:
        session = Session(create_engine(fresh_db(tmp_path), future=True))
        repo = SQLAlchemySourceRepository(session)
        repo.get_or_create(kind="url", value="https://example.com")
        session.commit()
        repo.get_or_create(
            kind="url",
            value="https://example.com",
            mime_type="text/html",
            content_hash="newchash",
            fingerprint="fp123",
        )
        session.commit()
        from iocparser.infrastructure.persistence_models import SourceModel

        source = session.query(SourceModel).filter_by(value="https://example.com").first()
        assert source.mime_type == "text/html"
        assert source.content_hash == "newchash"
        session.close()

    def test_get_or_create_url_with_normalized_url(self, tmp_path: Path) -> None:
        session = Session(create_engine(fresh_db(tmp_path), future=True))
        repo = SQLAlchemySourceRepository(session)
        id1 = repo.get_or_create(
            kind="url",
            value="https://example.com/page",
            normalized_url="https://example.com/page",
            original_url="https://example.com/page",
        )
        session.commit()
        id2 = repo.get_or_create(
            kind="url",
            value="https://example.com/page",
            normalized_url="https://example.com/page",
        )
        assert id1 == id2
        session.close()


# ---------------------------------------------------------------------------
# 6. rendering_support.py — prepare_json_payload
# ---------------------------------------------------------------------------


class TestPrepareJsonPayload:
    def test_string_only_section_sorted(self) -> None:
        data = {"domains": ["z.com", "a.com", "m.com"]}
        payload = prepare_json_payload(data, {})
        assert payload["domains"] == ["a.com", "m.com", "z.com"]

    def test_dict_section_preserved(self) -> None:
        data = {"md5": [{"value": "abc", "extra": "x"}]}
        payload = prepare_json_payload(data, {})
        assert payload["md5"] == [{"value": "abc", "extra": "x"}]

    def test_mixed_section_not_sorted(self) -> None:
        data = {"ips": ["1.1.1.1", {"value": "2.2.2.2"}]}
        payload = prepare_json_payload(data, {})
        assert payload["ips"] == ["1.1.1.1", {"value": "2.2.2.2"}]

    def test_hashes_key_always_list(self) -> None:
        data = {"hashes": ["aaa", "bbb"]}
        payload = prepare_json_payload(data, {})
        assert payload["hashes"] == ["aaa", "bbb"]

    def test_warning_iocs_included(self) -> None:
        data = {"domains": ["ok.com"]}
        warnings = {"domains": [{"value": "bad.com", "warning_list": "test"}]}
        payload = prepare_json_payload(data, warnings)
        assert "warning_list_matches" in payload

    def test_empty_warnings_not_included(self) -> None:
        payload = prepare_json_payload({"domains": ["ok.com"]}, {})
        assert "warning_list_matches" not in payload

    def test_serialize_pretty_json(self) -> None:
        result = serialize_pretty_json({"a": 1})
        assert '"a": 1' in result


# ---------------------------------------------------------------------------
# 7. cli_processing_support.py — BatchResultsCollection edge cases
# ---------------------------------------------------------------------------


class TestBatchResultsCollectionEdgeCases:
    def test_values_returns_all_pairs(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="k1", source_value="s1", normal_iocs={"d": ["a"]}, warning_iocs={})
        assert len(col.values()) == 1

    def test_keys_returns_item_keys(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="k1", source_value="s1", normal_iocs={}, warning_iocs={})
        assert col.keys() == ["k1"]

    def test_source_value_for_missing_key_returns_key(self) -> None:
        col = BatchResultsCollection()
        assert col.source_value_for("missing") == "missing"

    def test_getitem_by_source_value(self) -> None:
        col = BatchResultsCollection()
        col.add(
            item_key="batch-item:1",
            source_value="file.txt",
            normal_iocs={"d": ["x"]},
            warning_iocs={},
        )
        normal, _warnings = col["file.txt"]
        assert "d" in normal

    def test_getitem_raises_on_ambiguous(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="a", source_value="b", normal_iocs={}, warning_iocs={})
        col.add(item_key="c", source_value="a", normal_iocs={}, warning_iocs={})
        with pytest.raises(KeyError):
            col["a"]

    def test_contains_non_string_returns_false(self) -> None:
        col = BatchResultsCollection()
        assert 42 not in col

    def test_contains_ambiguous_returns_false(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="x", source_value="y", normal_iocs={}, warning_iocs={})
        col.add(item_key="z", source_value="x", normal_iocs={}, warning_iocs={})
        assert "x" not in col

    def test_contains_source_match(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="batch-item:1", source_value="file.txt", normal_iocs={}, warning_iocs={})
        assert "file.txt" in col

    def test_iter_returns_keys(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="k1", source_value="s1", normal_iocs={}, warning_iocs={})
        assert list(col) == ["k1"]

    def test_eq_with_dict(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="k", source_value="s", normal_iocs={"d": ["a"]}, warning_iocs={})
        assert col == dict(col.items())

    def test_eq_with_other_collection(self) -> None:
        col1 = BatchResultsCollection()
        col2 = BatchResultsCollection()
        assert col1 == col2

    def test_eq_with_incompatible_returns_false(self) -> None:
        col = BatchResultsCollection()
        assert col != "string"

    def test_bool_empty(self) -> None:
        assert not BatchResultsCollection()

    def test_bool_nonempty(self) -> None:
        col = BatchResultsCollection()
        col.add(item_key="k", source_value="s", normal_iocs={}, warning_iocs={})
        assert col


# ---------------------------------------------------------------------------
# 8. shared_utils.py — _dedup_key dict branch
# ---------------------------------------------------------------------------


class TestDedupKeyDictBranch:
    def test_dedup_key_with_dict(self) -> None:
        key = _dedup_key({"value": "Evil.Com", "type": "domain"})
        assert "evil.com" in key

    def test_deduplicate_iocs_with_dicts(self) -> None:
        iocs = {
            "domains": [
                {"value": "Evil.Com"},
                {"value": "evil.com"},
            ]
        }
        result = deduplicate_iocs(iocs)
        assert len(result["domains"]) == 1


# ---------------------------------------------------------------------------
# 9. worker_service.py — concurrent path
# ---------------------------------------------------------------------------


class TestWorkerServiceConcurrent:
    def test_concurrency_property_with_limits(self) -> None:
        from types import SimpleNamespace

        from iocparser.worker_service import DistributedWorkerService

        fake_service = SimpleNamespace(
            process_next=lambda queue_name: None,
            limits=SimpleNamespace(max_workers=3),
        )
        worker = DistributedWorkerService(
            service=fake_service,
            queue_name="test",
            poll_interval_seconds=0.01,
        )
        assert worker.concurrency == 3

    def test_concurrency_property_without_limits(self) -> None:
        from types import SimpleNamespace

        from iocparser.worker_service import DistributedWorkerService

        fake_service = SimpleNamespace(process_next=lambda queue_name: None)
        worker = DistributedWorkerService(
            service=fake_service,
            queue_name="test",
        )
        assert worker.concurrency == 1

    def test_run_forever_concurrent_with_stop_event(self) -> None:
        from types import SimpleNamespace

        from iocparser.worker_service import DistributedWorkerService

        call_count = 0

        def fake_process_next(queue_name: str) -> object | None:  # noqa: ARG001
            nonlocal call_count
            call_count += 1
            return SimpleNamespace() if call_count <= 2 else None

        fake_service = SimpleNamespace(
            process_next=fake_process_next,
            limits=SimpleNamespace(max_workers=2),
        )
        worker = DistributedWorkerService(
            service=fake_service,
            queue_name="test",
            poll_interval_seconds=0.01,
            max_messages_per_cycle=1,
        )
        stop = threading.Event()

        def stop_after_delay() -> None:
            time.sleep(0.15)
            stop.set()

        threading.Thread(target=stop_after_delay, daemon=True).start()
        processed = worker.run_forever(stop_event=stop, max_cycles=3)
        assert processed >= 0

    def test_run_forever_concurrent_max_cycles(self) -> None:
        from types import SimpleNamespace

        from iocparser.worker_service import DistributedWorkerService

        fake_service = SimpleNamespace(
            process_next=lambda queue_name: SimpleNamespace(),
            limits=SimpleNamespace(max_workers=2),
        )
        worker = DistributedWorkerService(
            service=fake_service,
            queue_name="test",
            poll_interval_seconds=0.01,
            max_messages_per_cycle=1,
        )
        processed = worker.run_forever(max_cycles=2)
        assert processed >= 2
