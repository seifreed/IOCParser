"""Round 2: Cover remaining gaps in history ops, cli_output, persistence_support, plugins, cli_processing_urls.

Real tests only — no mocks, no monkeypatch.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from iocparser.domain.models import (
    IOC,
    ExtractionResult,
    PersistedRunDiff,
)
from tests.coverage_helpers import fresh_db

# ---------------------------------------------------------------------------
# 1. persistence/history/ops.py — full export/import round-trip
# ---------------------------------------------------------------------------


class TestHistoryExportImportRoundTrip:
    def test_export_empty_database(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history

        db_uri = fresh_db(tmp_path)
        payload = export_history(db_uri)
        assert isinstance(payload, dict)
        assert "sources" in payload
        assert "runs" in payload
        assert "iocs" in payload

    def test_import_into_fresh_database(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        db_uri_source = fresh_db(tmp_path, "source.db")

        from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService

        SQLAlchemyPersistenceService(db_uri_source)
        from iocparser.application.contracts import PersistRunInput
        from iocparser.application.use_cases import persist_run
        from iocparser.domain.models import PersistOptions, Source
        from iocparser.infrastructure.persistence import SQLAlchemyUnitOfWork

        result = ExtractionResult(
            iocs=(IOC.from_raw("domains", "evil.com"),),
            warnings=(),
        )
        unit = SQLAlchemyUnitOfWork(db_uri_source)
        try:
            persist_run(
                PersistRunInput(
                    source=Source.from_raw("file", "test.txt"),
                    result=result,
                    tool_version="5.0.0",
                    options=PersistOptions(
                        defang=True, check_warnings=False, force_update=False, output_format="text"
                    ),
                ),
                unit_of_work=unit,
            )
        except Exception:
            unit.rollback()
            raise
        finally:
            unit.close()

        payload = export_history(db_uri_source)
        assert len(payload["sources"]) >= 1
        assert len(payload["runs"]) >= 1
        assert len(payload["iocs"]) >= 1

        db_uri_target = fresh_db(tmp_path, "target.db")
        counts = import_history(db_uri_target, payload)
        assert isinstance(counts, dict)
        assert counts.get("sources", 0) >= 1

    def test_import_same_data_twice_is_idempotent(self, tmp_path: Path) -> None:
        from iocparser.infrastructure.persistence.history import export_history, import_history

        db_uri = fresh_db(tmp_path, "idempotent.db")
        from iocparser.application.contracts import PersistRunInput
        from iocparser.application.use_cases import persist_run
        from iocparser.domain.models import PersistOptions, Source
        from iocparser.infrastructure.persistence import SQLAlchemyUnitOfWork

        unit = SQLAlchemyUnitOfWork(db_uri)
        try:
            persist_run(
                PersistRunInput(
                    source=Source.from_raw("text", "inline"),
                    result=ExtractionResult(iocs=(IOC.from_raw("ips", "1.2.3.4"),), warnings=()),
                    tool_version="5.0.0",
                    options=PersistOptions(
                        defang=True, check_warnings=False, force_update=False, output_format="text"
                    ),
                ),
                unit_of_work=unit,
            )
        except Exception:
            unit.rollback()
            raise
        finally:
            unit.close()

        payload = export_history(db_uri)
        db_uri2 = fresh_db(tmp_path, "target2.db")
        import_history(db_uri2, payload)
        counts2 = import_history(db_uri2, payload)
        assert counts2.get("sources", 0) == 0


class TestHistoryHelpers:
    def test_is_int_like_with_int(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _is_int_like

        assert _is_int_like(42) is True

    def test_is_int_like_with_negative_string(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _is_int_like

        assert _is_int_like("-5") is True

    def test_is_int_like_with_non_numeric(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _is_int_like

        assert _is_int_like("abc") is False
        assert _is_int_like(3.14) is False

    def test_typed_row_with_malformed_datetime(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _typed_row

        row = {"started_at": "not-a-date", "value": "ok"}
        result = _typed_row(row)
        assert result["started_at"] == "not-a-date"
        assert result["value"] == "ok"

    def test_typed_row_with_empty_datetime(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _typed_row

        row = {"finished_at": "", "last_seen": ""}
        result = _typed_row(row)
        assert result["finished_at"] == ""

    def test_typed_row_with_valid_datetime(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _typed_row

        now = datetime.now(UTC).isoformat()
        row = {"started_at": now}
        result = _typed_row(row)
        assert isinstance(result["started_at"], datetime)

    def test_source_identity_url(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _source_identity

        result = _source_identity(
            {
                "kind": "url",
                "value": "https://example.com",
                "normalized_url": "https://example.com/",
            }
        )
        assert result[0] == "url"

    def test_source_identity_file(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _source_identity

        result = _source_identity({"kind": "file", "value": "test.pdf"})
        assert result == ("file", "test.pdf")

    def test_json_int_map_with_negatives(self) -> None:
        from iocparser.infrastructure.persistence.history.ops import _json_int_map

        result = _json_int_map('{"a": 5, "b": -1, "c": "3", "d": "not_a_number", "e": true}')
        assert result["a"] == 5
        assert result["b"] == -1
        assert result["c"] == 3
        assert "d" not in result
        assert "e" not in result


# ---------------------------------------------------------------------------
# 2. cli_output.py — _render_diff_csv and save_diff_output structured paths
# ---------------------------------------------------------------------------


class TestRenderDiffCsv:
    def test_csv_all(self) -> None:
        from iocparser.cli_output import _render_diff_csv

        added = [{"type": "domains", "raw_value": "evil.com", "is_warning": False}]
        removed = [{"type": "ips", "raw_value": "1.2.3.4", "is_warning": False}]
        csv_text = _render_diff_csv(added, removed, "all")
        assert "evil.com" in csv_text
        assert "1.2.3.4" in csv_text
        assert "change" in csv_text

    def test_csv_added_only(self) -> None:
        from iocparser.cli_output import _render_diff_csv

        csv_text = _render_diff_csv(
            [{"type": "domains", "raw_value": "a.com", "is_warning": ""}],
            [{"type": "ips", "raw_value": "9.9.9.9", "is_warning": ""}],
            "added",
        )
        assert "a.com" in csv_text
        assert "9.9.9.9" not in csv_text

    def test_csv_removed_only(self) -> None:
        from iocparser.cli_output import _render_diff_csv

        csv_text = _render_diff_csv(
            [{"type": "domains", "raw_value": "a.com", "is_warning": ""}],
            [{"type": "ips", "raw_value": "9.9.9.9", "is_warning": ""}],
            "removed",
        )
        assert "a.com" not in csv_text
        assert "9.9.9.9" in csv_text


class TestBuildDiffPayload:
    def test_build_diff_payload_all(self) -> None:
        from iocparser.cli_output import _build_diff_payload

        diff = PersistedRunDiff(
            left_run_id=1,
            right_run_id=2,
            added=ExtractionResult(iocs=(IOC.from_raw("domains", "new.com"),), warnings=()),
            removed=ExtractionResult(iocs=(IOC.from_raw("ips", "1.1.1.1"),), warnings=()),
        )
        payload, _added, _removed = _build_diff_payload(diff, "all")
        assert "added" in payload
        assert "removed" in payload

    def test_build_diff_payload_added_only(self) -> None:
        from iocparser.cli_output import _build_diff_payload

        diff = PersistedRunDiff(
            left_run_id=1,
            right_run_id=2,
            added=ExtractionResult(iocs=(IOC.from_raw("domains", "new.com"),), warnings=()),
            removed=ExtractionResult(iocs=(), warnings=()),
        )
        payload, _, _ = _build_diff_payload(diff, "added")
        assert "removed" not in payload

    def test_build_diff_payload_removed_only(self) -> None:
        from iocparser.cli_output import _build_diff_payload

        diff = PersistedRunDiff(
            left_run_id=1,
            right_run_id=2,
            added=ExtractionResult(iocs=(), warnings=()),
            removed=ExtractionResult(iocs=(IOC.from_raw("ips", "1.1.1.1"),), warnings=()),
        )
        payload, _, _ = _build_diff_payload(diff, "removed")
        assert "added" not in payload


# ---------------------------------------------------------------------------
# 3. persistence_support.py — prune_runs branches
# ---------------------------------------------------------------------------


class TestPruneRunsBranches:
    def test_prune_with_source_kind_filter(self, tmp_path: Path) -> None:
        db_uri = fresh_db(tmp_path)
        from iocparser.application.contracts import PersistRunInput
        from iocparser.application.use_cases import persist_run
        from iocparser.domain.models import PersistOptions, Source
        from iocparser.infrastructure.persistence import (
            SQLAlchemyPersistenceService,
            SQLAlchemyUnitOfWork,
        )

        unit = SQLAlchemyUnitOfWork(db_uri)
        try:
            persist_run(
                PersistRunInput(
                    source=Source.from_raw("file", "test.txt"),
                    result=ExtractionResult(iocs=(IOC.from_raw("domains", "x.com"),), warnings=()),
                    tool_version="5.0.0",
                    options=PersistOptions(
                        defang=True, check_warnings=False, force_update=False, output_format="text"
                    ),
                ),
                unit_of_work=unit,
            )
        except Exception:
            unit.rollback()
            raise
        finally:
            unit.close()

        service = SQLAlchemyPersistenceService(db_uri)
        deleted = service.prune_runs(source_kind="file")
        assert deleted >= 1

    def test_prune_with_source_value_filter(self, tmp_path: Path) -> None:
        db_uri = fresh_db(tmp_path)
        from iocparser.application.contracts import PersistRunInput
        from iocparser.application.use_cases import persist_run
        from iocparser.domain.models import PersistOptions, Source
        from iocparser.infrastructure.persistence import (
            SQLAlchemyPersistenceService,
            SQLAlchemyUnitOfWork,
        )

        unit = SQLAlchemyUnitOfWork(db_uri)
        try:
            persist_run(
                PersistRunInput(
                    source=Source.from_raw("file", "specific.txt"),
                    result=ExtractionResult(iocs=(IOC.from_raw("domains", "z.com"),), warnings=()),
                    tool_version="5.0.0",
                    options=PersistOptions(
                        defang=True, check_warnings=False, force_update=False, output_format="text"
                    ),
                ),
                unit_of_work=unit,
            )
        except Exception:
            unit.rollback()
            raise
        finally:
            unit.close()

        service = SQLAlchemyPersistenceService(db_uri)
        deleted = service.prune_runs(source_kind="file", source_value="specific.txt")
        assert deleted >= 1

    def test_prune_with_statuses_filter(self, tmp_path: Path) -> None:
        db_uri = fresh_db(tmp_path)
        from iocparser.infrastructure.persistence import SQLAlchemyPersistenceService

        service = SQLAlchemyPersistenceService(db_uri)
        deleted = service.prune_runs(statuses=("failed",))
        assert deleted == 0


# ---------------------------------------------------------------------------
# 4. plugins.py — register/load paths
# ---------------------------------------------------------------------------


class TestPluginRegistration:
    def test_register_and_get_renderer(self) -> None:
        from iocparser.plugins import get_renderer, register_renderer

        register_renderer(
            "test_custom_renderer", lambda wc, st: type("R", (), {"render": lambda self, r: "ok"})()
        )
        renderer = get_renderer("test_custom_renderer")
        assert renderer.render(ExtractionResult()) == "ok"

    def test_register_and_get_enricher(self) -> None:
        from iocparser.plugins import enricher_names, register_enricher

        register_enricher("test_enricher_x", lambda: None)
        assert "test_enricher_x" in enricher_names()

    def test_register_and_get_extractor(self) -> None:
        from iocparser.plugins import extractor_names, register_extractor

        register_extractor("test_ext_x", lambda: None)
        assert "test_ext_x" in extractor_names()

    def test_register_and_get_postprocessor(self) -> None:
        from iocparser.plugins import postprocessor_names, register_postprocessor

        register_postprocessor("test_pp_x", lambda: None)
        assert "test_pp_x" in postprocessor_names()

    def test_register_ioc_type_plugin_and_resolve(self) -> None:
        from iocparser.plugins import get_ioc_type_plugin, register_ioc_type_plugin

        register_ioc_type_plugin(
            "test_ioc_type_x", lambda: {"name": "test_ioc_type_x", "base_type": "urls"}
        )
        definition = get_ioc_type_plugin("test_ioc_type_x")
        assert definition["name"] == "test_ioc_type_x"


# ---------------------------------------------------------------------------
# 5. cli_processing_urls.py — retry_attempt helpers
# ---------------------------------------------------------------------------


class TestRetryAttemptHelpers:
    def test_retry_attempt_from_report_file(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        report_path = tmp_path / "batch_report.json"
        report = {
            "items": [
                {"url": "https://a.com", "status": "failed", "retry_attempt": 0},
                {"url": "https://b.com", "status": "ok", "retry_attempt": 0},
            ]
        }
        report_path.write_text(json.dumps(report))

        result = retry_attempt_for_url(
            "https://a.com",
            str(report_path),
            retry_batch_job=None,
            db_uri=None,
            occurrence=1,
        )
        assert result >= 1

    def test_retry_attempt_no_report_no_db(self) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        result = retry_attempt_for_url(
            "https://a.com",
            None,
            retry_batch_job=None,
            db_uri=None,
            occurrence=1,
        )
        assert result == 0

    def test_retry_attempt_from_db(self, tmp_path: Path) -> None:
        from iocparser.cli_processing_urls import retry_attempt_for_url

        db_uri = fresh_db(tmp_path, "retry.db")
        result = retry_attempt_for_url(
            "https://nonexistent.com",
            None,
            retry_batch_job=999,
            db_uri=db_uri,
            occurrence=1,
        )
        assert isinstance(result, int)
