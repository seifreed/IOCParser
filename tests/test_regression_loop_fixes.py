"""Regression contracts for bugs found during the bug-hunt loop."""

from __future__ import annotations

import argparse
import json

from sqlalchemy import create_engine, inspect, text

from iocparser.adapters.renderers_stix import STIXOutputRenderer
from iocparser.application.distributed_idempotency import idempotency_key_for
from iocparser.cli_output import _build_diff_payload, _render_structured_diff
from iocparser.domain.models import IOC, ExtractionResult, IOCType, PersistedRunDiff
from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.infrastructure.migration_revisions import rev_0005_fts_metrics
from iocparser.infrastructure.persistence_fts import build_fts_query


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
