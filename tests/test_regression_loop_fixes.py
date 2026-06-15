"""Regression contracts for bugs found during the bug-hunt loop."""

from __future__ import annotations

import argparse
import codecs
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from iocparser.adapters.renderers_stix import STIXOutputRenderer
from iocparser.application.distributed_idempotency import idempotency_key_for
from iocparser.cli_output import _build_diff_payload, _render_structured_diff
from iocparser.domain.models import (
    IOC,
    ExtractionOptions,
    ExtractionResult,
    IOCType,
    PersistedRunDiff,
)
from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.infrastructure.extraction import IOCExtractor
from iocparser.infrastructure.file_parser import decode_file_bytes
from iocparser.infrastructure.file_readers import MagicTextSourceReader
from iocparser.infrastructure.migration_revisions import rev_0005_fts_metrics
from iocparser.infrastructure.persistence_fts import build_fts_query
from iocparser.worker_config_support import load_worker_file_values


def test_stix_asn_pattern_emits_integer_not_quoted_string() -> None:
    """autonomous-system:number is an integer property in STIX 2.1.

    The previous builder emitted ``[autonomous-system:number = 'AS12345']`` —
    a quoted string including the AS prefix, which is not spec-compliant.
    """
    renderer = STIXOutputRenderer()
    indicator = renderer._build_indicator(IOCType.ASN, "AS12345", None)

    assert indicator is not None
    assert indicator.pattern == "[autonomous-system:number = 12345]"


def test_diff_jsonl_marks_added_and_removed() -> None:
    """JSONL run-diff output must distinguish added from removed records.

    Previously both sets were merged into one stream with no change marker,
    so a consumer could not tell which IOCs were added vs removed.
    """
    diff = PersistedRunDiff(
        left_run_id=1,
        right_run_id=2,
        added=ExtractionResult(iocs=(IOC.from_raw("domains", "beta.example"),)),
        removed=ExtractionResult(iocs=(IOC.from_raw("domains", "alpha.example"),)),
    )
    payload, added_records, removed_records = _build_diff_payload(diff, "all")
    args = argparse.Namespace(jsonl=True, csv=False, json=False)

    output, chosen_format = _render_structured_diff(
        args, payload, added_records, removed_records, "all"
    )

    assert chosen_format == "jsonl"
    rows = [json.loads(line) for line in output.splitlines()]
    changes = {(row["raw_value"], row["change"]) for row in rows}
    assert changes == {("beta.example", "added"), ("alpha.example", "removed")}


class _FixedDigester:
    """Digester whose output ignores the path, isolating file_type as the variable."""

    def digest_text(self, value: str) -> str:
        return "fixed"

    def digest_file(self, file_path: str) -> str:
        return "fixed"


def test_idempotency_key_distinguishes_file_type() -> None:
    """The same bytes parsed under a different file_type must not be deduplicated.

    file_type forces the parser (pdf/html/text) and changes the extracted IOCs,
    so it must be part of the idempotency key.
    """
    digester = _FixedDigester()
    pdf_key = idempotency_key_for(
        PipelineJobRequest(input_kind="file", source_value="/tmp/sample.bin", file_type="pdf"),
        digester=digester,
    )
    html_key = idempotency_key_for(
        PipelineJobRequest(input_kind="file", source_value="/tmp/sample.bin", file_type="html"),
        digester=digester,
    )

    assert pdf_key != html_key


def test_fts_rebuild_indexes_normalized_value_search() -> None:
    """The FTS rebuild on schema upgrade must index value_search, not raw value.

    The external-content 'rebuild' command repopulated the index from
    iocs.value (raw/defanged), but triggers and search use the refanged
    value_search column, so pre-existing rows were silently unsearchable
    after an upgrade.
    """
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE iocs ("
                "id INTEGER PRIMARY KEY, value TEXT, value_search TEXT, ioc_type TEXT)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO iocs(value, value_search, ioc_type) "
                "VALUES ('hxxp://evil.com', 'http://evil.com', 'urls')"
            )
        )

    rev_0005_fts_metrics.apply(engine, inspect(engine))

    match_query = build_fts_query("http://evil.com")
    assert match_query is not None
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT rowid FROM ioc_search_fts WHERE ioc_search_fts MATCH :q"),
            {"q": match_query},
        ).fetchall()
    assert [row[0] for row in rows] == [1]


def test_extract_ipv6_addresses_ending_in_double_colon() -> None:
    """Valid IPv6 addresses ending in '::' must be extracted.

    The trailing-'::' regex branch consumed the final colon with its hex groups,
    so addresses like fe80:: or 2001:db8:: were never matched.
    """
    for sample_text, expected in (
        ("beacon to 2001:db8:: now", "2001:db8::"),
        ("host fe80:: link", "fe80::"),
        ("addr 2001:db8:85a3:: end", "2001:db8:85a3::"),
    ):
        result = IOCExtractor(defang=False).extract_all(sample_text)
        assert result.get("ipv6") == [expected], (sample_text, result.get("ipv6"))


def test_stix_custom_pattern_overrides_base_type_builder() -> None:
    """A custom IOC type's explicit stix_pattern must win over its base type's builder.

    register_custom_ioc_type defaults base_type to URL (which has a builder), so a
    custom type registered with only a stix_pattern was always rendered with the
    URL pattern instead of its own.
    """
    import iocparser.domain.enums as enums_module
    from iocparser.domain.enums import register_custom_ioc_type

    enums_module._custom_ioc_types.pop("loopfix_custom", None)
    try:
        register_custom_ioc_type("loopfix_custom", stix_pattern="[x-custom:value = '{value}']")
        indicator = STIXOutputRenderer()._build_indicator(
            "loopfix_custom", "evil.example.com", None
        )
        assert indicator is not None
        assert indicator.pattern == "[x-custom:value = 'evil.example.com']"
    finally:
        enums_module._custom_ioc_types.pop("loopfix_custom", None)


def test_worker_config_empty_ini_values_use_defaults(tmp_path: Path) -> None:
    """Present-but-empty INI numeric/boolean values must fall back to defaults.

    ConfigParser.getint/getfloat/getboolean only apply the fallback when the option
    is absent; an empty value (``key =``) reached the converter and raised
    ValueError. The shipped deploy/iocparser.scale.example.ini has ``max_cycles =``,
    so the worker crashed on its own example config.
    """
    config_file = tmp_path / "worker.ini"
    config_file.write_text(
        "[network]\n"
        "max_input_seconds =\n"
        "max_queue_size =\n"
        "skip_processed =\n"
        "[worker]\n"
        "poll_interval_seconds =\n"
        "max_messages_per_cycle =\n"
        "max_cycles =\n"
        "concurrency =\n",
        encoding="utf-8",
    )

    values = load_worker_file_values(config_file)

    assert values["max_cycles"] is None
    assert values["max_queue_size"] == 64
    assert values["skip_processed"] is False
    assert values["poll_interval_seconds"] == 1.0
    assert values["max_messages_per_cycle"] == 1
    assert values["concurrency"] == 1
    assert values["max_input_seconds"] is None


def test_worker_config_populated_ini_values_are_parsed(tmp_path: Path) -> None:
    """Non-empty INI values are still parsed (guards the converter branch)."""
    config_file = tmp_path / "worker.ini"
    config_file.write_text(
        "[network]\n"
        "max_input_seconds = 2.5\n"
        "skip_processed = true\n"
        "[worker]\n"
        "max_cycles = 7\n"
        "concurrency = 3\n",
        encoding="utf-8",
    )

    values = load_worker_file_values(config_file)

    assert values["max_input_seconds"] == 2.5
    assert values["skip_processed"] is True
    assert values["max_cycles"] == 7
    assert values["concurrency"] == 3


@pytest.mark.parametrize(
    "encoding_bytes",
    [
        b"",  # no BOM -> utf-8 default
        codecs.BOM_UTF8,
        codecs.BOM_UTF16_LE,
        codecs.BOM_UTF16_BE,
        codecs.BOM_UTF32_LE,
        codecs.BOM_UTF32_BE,
    ],
)
def test_decode_file_bytes_honors_bom(encoding_bytes: bytes) -> None:
    """decode_file_bytes must round-trip text for each BOM and BOM-less UTF-8."""
    sample = "IP 203.0.113.5 evil.example.com"
    codec = {
        b"": "utf-8",
        codecs.BOM_UTF8: "utf-8",
        codecs.BOM_UTF16_LE: "utf-16-le",
        codecs.BOM_UTF16_BE: "utf-16-be",
        codecs.BOM_UTF32_LE: "utf-32-le",
        codecs.BOM_UTF32_BE: "utf-32-be",
    }[encoding_bytes]

    decoded = decode_file_bytes(encoding_bytes + sample.encode(codec))

    assert "203.0.113.5" in decoded
    assert "evil.example.com" in decoded


def test_reader_extracts_iocs_from_utf16_file(tmp_path: Path) -> None:
    """A UTF-16 text file (BOM) must yield its IOCs, not lose them to utf-8 decode.

    The read path assumed UTF-8 with errors='ignore', so UTF-16's interleaved
    NUL bytes were dropped and every IOC vanished.
    """
    target = tmp_path / "report.txt"
    target.write_bytes("Malicious IP: 203.0.113.5\n".encode("utf-16"))

    text_content = MagicTextSourceReader().read(str(target), ExtractionOptions())

    assert "203.0.113.5" in text_content
