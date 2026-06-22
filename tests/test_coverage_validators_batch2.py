"""Second batch of small edge-branch coverage (part of the 100% coverage repair)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iocparser.errors import SourceNotFoundError, TypeValidationError, ValidationError


def test_validated_ioc_type_filters_rejects_non_str_non_list() -> None:
    from iocparser.api_persistence_query import validated_ioc_type_filters

    assert validated_ioc_type_filters(None) == ()
    assert validated_ioc_type_filters("md5") == ("md5",)
    # A non-str/non-list value raises TypeError internally, surfaced as ValidationError.
    with pytest.raises(ValidationError):
        validated_ioc_type_filters(123)


def test_load_valid_batch_report_payload_rejects_empty(tmp_path: Path) -> None:
    from iocparser.cli_processing_urls import _load_valid_batch_report_payload

    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ValidationError):
        _load_valid_batch_report_payload(report)


def test_parse_json_http_mapping_rejects_non_str_value() -> None:
    from iocparser.cli_runtime_defaults import _parse_json_http_mapping

    assert _parse_json_http_mapping('{"X-Token": "abc"}') == {"X-Token": "abc"}
    with pytest.raises(ValidationError):
        _parse_json_http_mapping(json.dumps({"X-Token": 123}))


def test_normalized_ioc_type_falls_back_for_unknown() -> None:
    from iocparser.infrastructure.persistence.history.ops import _normalized_ioc_type

    assert _normalized_ioc_type("MD5") == "md5"
    # An unknown type cannot be resolved, so it is lowercased/stripped verbatim.
    assert _normalized_ioc_type("  Custom-Thing  ") == "custom-thing"


def test_normalized_text_rejects_non_string() -> None:
    from iocparser.infrastructure.persistence.history.ops import _normalized_text

    assert _normalized_text("  v ", default="d") == "v"
    assert _normalized_text(None, default="d") == "d"
    with pytest.raises(TypeValidationError):
        _normalized_text(123, default="d")


def test_typed_row_skips_unparseable_timestamp() -> None:
    from iocparser.infrastructure.persistence.history.row_values import typed_row

    row = typed_row({"created_at": "not-a-real-date", "name": "x"})
    # The bad timestamp is left as the original string (fromisoformat suppressed).
    assert row["created_at"] == "not-a-real-date"


def test_typed_row_leaves_whitespace_only_timestamp_untouched() -> None:
    from iocparser.infrastructure.persistence.history.row_values import typed_row

    # A truthy-but-whitespace timestamp strips to empty and is skipped (continue).
    row = typed_row({"created_at": "   "})
    assert row["created_at"] == "   "


def test_resolve_config_path_empty_returns_none() -> None:
    from iocparser.worker_config_support import resolve_config_path

    assert resolve_config_path("   ") is None


def test_resolve_config_path_missing_env_file_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from iocparser.worker_config_support import resolve_config_path

    monkeypatch.setenv("IOCPARSER_CONFIG", "/definitely/not/here/iocparser.ini")
    with pytest.raises(SourceNotFoundError):
        resolve_config_path(None)


def test_url_filter_variants_handles_empty_path() -> None:
    from iocparser.infrastructure.persistence_support import _url_filter_variants

    variants = _url_filter_variants("http://host.example")
    assert "http://host.example/" in variants


def test_resolve_config_path_raises_for_missing_file(tmp_path: Path) -> None:
    from iocparser.worker_config_support import resolve_config_path

    with pytest.raises(SourceNotFoundError):
        resolve_config_path(str(tmp_path / "nope.ini"))


def test_pipeline_request_validates_only_and_exclude() -> None:
    from iocparser.domain.pipeline import PipelineJobRequest

    request = PipelineJobRequest(
        input_kind="text",
        source_value="x",
        only="md5",
        exclude="domains",
        correlation_id="corr-1",
    )
    assert request.only == "md5"
    assert request.exclude == "domains"
    assert request.correlation_id == "corr-1"
