"""Regression contracts for bugs found during the bug-hunt loop."""

from __future__ import annotations

import argparse
import codecs
import json
import sys
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from iocparser.adapters.renderers_stix import STIXOutputRenderer
from iocparser.application.distributed_idempotency import idempotency_key_for
from iocparser.cli_output import _build_diff_payload, _render_structured_diff
from iocparser.cli_processing_url_reports import build_batch_report
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
from iocparser.infrastructure.persistence.history.row_values import typed_row
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


def test_stix_render_skips_non_ascii_digit_asn_without_aborting_bundle() -> None:
    """Regression: an ASN containing non-ASCII digits (str.isdigit() accepts them)
    must be skipped, not emitted as an invalid integer pattern that aborts
    serialization of the entire bundle and drops every other valid indicator."""
    arabic_indic_asn = "AS" + "".join(chr(code) for code in (0x661, 0x662, 0x663))
    renderer = STIXOutputRenderer()
    result = ExtractionResult(
        iocs=(IOC.from_raw("domains", "good.example"), IOC.from_raw("asn", arabic_indic_asn))
    )

    rendered = renderer.render(result)

    assert "good.example" in rendered
    assert chr(0x661) not in rendered


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


def test_idempotency_key_distinguishes_persist_and_db_uri() -> None:
    """A persist=True job must not be deduplicated against a prior persist=False job for
    the same source (the run would silently never be written), nor against the same job
    targeting a different db_uri."""
    digester = _FixedDigester()
    no_persist = idempotency_key_for(
        PipelineJobRequest(input_kind="text", source_value="x", persist=False),
        digester=digester,
    )
    persist = idempotency_key_for(
        PipelineJobRequest(input_kind="text", source_value="x", persist=True),
        digester=digester,
    )
    other_db = idempotency_key_for(
        PipelineJobRequest(
            input_kind="text", source_value="x", persist=True, db_uri="sqlite:///other.db"
        ),
        digester=digester,
    )

    assert no_persist != persist
    assert persist != other_db


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


def test_service_names_suffix_branch_keeps_full_name() -> None:
    """The bareword service form must keep the Service/Svc suffix in the value.

    The suffix was outside the capture group, so BackgroundService was emitted
    as 'Background' and AcmeSvc as 'Acme'.
    """
    result = IOCExtractor(defang=False).extract_all("installs BackgroundService and AcmeSvc here")
    assert sorted(result.get("service_names") or []) == ["AcmeSvc", "BackgroundService"]


def test_ja4_matches_no_alpn_fingerprints() -> None:
    """JA4 fingerprints with the literal '00' ALPN field must be extracted.

    The ALPN field is two alphanumerics; the old pattern required letter+digit,
    so every no-ALPN fingerprint (the common case) was missed.
    """
    for value in (
        "t12d190800_d83cc789557e_7af1ed941c26",
        "t13i190900_e8f1e7e78f70_1f22a2ca17c4",
    ):
        result = IOCExtractor(defang=False).extract_all(f"fingerprint {value} seen")
        assert result.get("ja4") == [value]


def test_url_with_userinfo_is_extracted() -> None:
    """A URL carrying embedded credentials must be kept, not truncated and dropped.

    Without userinfo support the regex stopped at the first ':' (http://user),
    which has no dotted host and was then rejected, losing the IOC entirely.
    """
    result = IOCExtractor(defang=False).extract_all("visit http://user:pass@evil.com/path now")
    assert result.get("urls") == ["http://user:pass@evil.com/path"]


def test_docker_image_keeps_registry_host_and_port() -> None:
    """The registry host (and optional port) must be retained in docker IOCs."""
    digest = "a" * 64
    host = IOCExtractor(defang=False).extract_all(
        f"img myregistry.io/library/nginx@sha256:{digest}"
    )
    assert host.get("docker_images") == [f"myregistry.io/library/nginx@sha256:{digest}"]
    port = IOCExtractor(defang=False).extract_all(f"img myregistry.io:5000/nginx@sha256:{digest}")
    assert port.get("docker_images") == [f"myregistry.io:5000/nginx@sha256:{digest}"]


def test_typed_row_preserves_nullable_retryable() -> None:
    """retryable is tri-state; a NULL value must survive history import as None.

    It was in the blanket BOOL_FIELDS coercion, so None collapsed to False on
    export/import, conflating 'not yet determined' with 'not retryable'.
    """
    assert typed_row({"retryable": None})["retryable"] is None
    assert typed_row({"retryable": "true"})["retryable"] is True
    assert typed_row({"retryable": 0})["retryable"] is False
    # Non-nullable is_warning still coerces a missing/None value to False.
    assert typed_row({"is_warning": None})["is_warning"] is False


@pytest.mark.parametrize("label", ["ja3", "ja3s", "hassh", "hassh_server", "imphash"])
def test_labelled_fingerprint_not_duplicated_as_md5(label: str) -> None:
    """A context-labelled 32-hex fingerprint must not also surface as an md5 hash.

    The md5 pattern matches any standalone 32-hex string; only imphash was being
    stripped from the md5 bucket, so ja3/ja3s/hassh/hassh_server were reported
    both correctly and as a spurious file hash.
    """
    digest = "deadbeefcafe1234567890abfedc5678"
    result = IOCExtractor(defang=False).extract_all(f"observed {label}={digest} here")
    assert result.get(label) == [digest]
    assert result.get("md5") is None


def test_valid_sha256_with_file_magic_prefix_is_kept() -> None:
    """A real SHA-256 must not be dropped because its first bytes spell a file magic.

    The hash validator used to unhexlify the digest and reject it when the decoded
    bytes started with MZ/PK/7z/PNG/JPEG signatures. A cryptographic digest is
    pseudo-random, so ~1 in 22,000 valid SHA-256 hashes (those whose first two
    bytes happened to be 0x4d5a/0x504b/0x377a) were silently lost.
    """
    # Decodes to bytes beginning 0x37 0x7a -> the "7z" magic.
    digest = "377adeb4cd4096adc7ca64b533938cffc6294a9b3534f883b2336a26252cda9a"
    result = IOCExtractor(defang=False).extract_all(f"Indicator hash {digest} observed")
    assert result.get("sha256") == [digest]


def test_bare_tlsh_digest_lowercase_is_extracted() -> None:
    """A bare TLSH digest must match regardless of hex case.

    The labelled form accepted both cases but the bare alternative only matched
    uppercase T1 + uppercase hex, so lowercase digests (emitted by many tools)
    were missed unless prefixed with a 'tlsh' keyword.
    """
    bare_tlsh = "t1" + "a" * 68
    result = IOCExtractor(defang=False).extract_all(f"Hash value: {bare_tlsh}")
    assert result.get("tlsh") == [bare_tlsh]


def test_sqs_dequeue_does_not_hold_lock_during_long_poll() -> None:
    """The SQS long poll must not run under the adapter lock.

    Holding self._lock across receive_message (WaitTimeSeconds=20) blocked
    ack/enqueue/requeue on every other worker thread for the whole poll and
    could delay a finished job's ack past the visibility timeout, causing the
    already-processed message to be redelivered. boto3 clients are thread-safe,
    so the blocking receive must run lock-free.
    """
    from unittest.mock import patch

    from iocparser.infrastructure.queue_sqs import SQSQueueAdapter

    lock_free_during_poll: list[bool] = []

    class _Client:
        adapter: SQSQueueAdapter

        def receive_message(self, **_kwargs: object) -> dict[str, object]:
            acquired = self.adapter._lock.acquire(blocking=False)
            lock_free_during_poll.append(acquired)
            if acquired:
                self.adapter._lock.release()
            return {}

    class _Boto3:
        def __init__(self) -> None:
            self._client = _Client()

        def client(self, service_name: str) -> _Client:
            assert service_name == "sqs"
            return self._client

    fake = _Boto3()
    with patch("iocparser.infrastructure.queue_sqs._boto3_module", return_value=fake):
        adapter = SQSQueueAdapter("https://sqs.example/jobs")
        fake._client.adapter = adapter
        assert adapter.dequeue(queue_name="jobs") is None

    assert lock_free_during_poll == [True]


def test_unlabelled_md5_still_extracted() -> None:
    """A bare 32-hex hash with no fingerprint label is still an md5 IOC."""
    digest = "5d41402abc4b2a76b9719d911017c592"
    result = IOCExtractor(defang=False).extract_all(f"file md5 {digest} dropped")
    assert result.get("md5") == [digest]


def test_gcp_default_service_accounts_are_extracted() -> None:
    """Default GCP service accounts (not just user-managed .iam ones) must match.

    The pattern required '<id>.iam.gserviceaccount.com' and a letter-leading local
    part, so the common default SAs were missed entirely.
    """
    for sample_text, expected in (
        (
            "sa deploy-bot@my-project.iam.gserviceaccount.com x",
            "deploy-bot@my-project.iam.gserviceaccount.com",
        ),
        (
            "sa 123456789012-compute@developer.gserviceaccount.com x",
            "123456789012-compute@developer.gserviceaccount.com",
        ),
        (
            "sa my-project-id@appspot.gserviceaccount.com x",
            "my-project-id@appspot.gserviceaccount.com",
        ),
    ):
        result = IOCExtractor(defang=False).extract_all(sample_text)
        assert result.get("gcp_service_accounts") == [expected]


def test_p95_item_duration_excludes_the_maximum() -> None:
    """p95 must not return the absolute maximum when n is a multiple of 20.

    The floor-index int(n*0.95) landed one rank too high, so for 20 samples the
    reported p95 was the 100th-percentile value.
    """
    item_reports = [
        {
            "item_key": f"batch-item:{i}",
            "input_index": i,
            "url": f"https://host{i}.example",
            "status": "ok",
            "duration_ms": i,
        }
        for i in range(1, 21)
    ]
    report = build_batch_report(
        {
            "urls": [item["url"] for item in item_reports],
            "results": {},
            "failures": {},
            "item_reports": item_reports,
            "source_metadata_map": {},
            "run_metadata_map": {},
            "job_id": "job-p95",
            "correlation_id": "corr-p95",
            "input_load_ms": 0,
            "batch_started": time.perf_counter(),
            "batch_started_wall": time.time(),
        }
    )

    # Durations are 1..20; nearest-rank p95 is the 19th value, not the max (20).
    assert report["metrics"]["p95_item_duration_ms"] == 19


def test_snort_rule_extracted_when_sid_precedes_msg() -> None:
    """A complete rule whose sid: comes before msg: must still be extracted.

    The header-then-sid regex shape consumed past an early sid, dropping the
    rule. The msg: requirement (intentional) is preserved.
    """
    rule = 'alert tcp any any -> any any (sid:2001; msg:"x"; content:"a";)'
    result = IOCExtractor(defang=False).extract_all(rule)
    assert result.get("snort_rules") == [rule]
    # A complete rule without msg: is still rejected (intentional behaviour).
    no_msg = IOCExtractor(defang=False).extract_all(
        "alert tcp any any -> any 80 (sid:1000001; rev:1;)"
    )
    assert no_msg.get("snort_rules") is None


def test_url_canonical_defaults_path_and_drops_fragment() -> None:
    """Equivalent URLs must share one canonical value so they dedup to one IOC.

    UrlValue.canonical() used geturl() directly, leaving an empty path and the
    fragment in place, so http://x.com and http://x.com/ (and #frag variants)
    produced distinct canonical values and duplicate IOC rows.
    """
    assert IOC.from_raw("urls", "http://example.com").canonical_value() == "http://example.com/"
    assert IOC.from_raw("urls", "http://example.com/").canonical_value() == "http://example.com/"
    assert (
        IOC.from_raw("urls", "http://example.com/a#frag").canonical_value()
        == "http://example.com/a"
    )
    # Query strings are part of the resource identity and must be preserved.
    assert (
        IOC.from_raw("urls", "http://example.com/p?q=1").canonical_value()
        == "http://example.com/p?q=1"
    )


def test_hostname_type_warning_lists_match() -> None:
    """MISP 'hostname'-type warning lists (e.g. Alexa) must produce matches.

    Only string/regex/cidr list types were indexed, so the 19 shipped
    hostname-type lists were inert and never flagged a value.
    """
    from iocparser.infrastructure.warninglists_service import MISPWarningListService

    warning_lists = MISPWarningListService()._get_lists(force_update=False)
    matched, _info = warning_lists.check_value("google.com", "domains")
    assert matched is True


def test_url_batch_file_honors_bom_and_utf16(tmp_path: Path) -> None:
    """A URL list file with a BOM or UTF-16 encoding must parse cleanly.

    The reader used read_text(encoding='utf-8'), so a UTF-8 BOM left a stray
    \\ufeff on the first URL and a UTF-16 file raised UnicodeDecodeError.
    """
    import argparse as _argparse

    from iocparser.cli_processing_urls import _load_batch_urls

    body = "https://example.com/a\n# comment\nhttps://example.com/b\n"
    bom_file = tmp_path / "urls_bom.txt"
    bom_file.write_bytes(codecs.BOM_UTF8 + body.encode("utf-8"))
    utf16_file = tmp_path / "urls_utf16.txt"
    utf16_file.write_bytes(body.encode("utf-16"))

    for path in (bom_file, utf16_file):
        args = _argparse.Namespace(url_file=str(path))
        urls, _label, _ms = _load_batch_urls(
            args, retry_report=None, retry_batch_job=None, db_uri=None
        )
        assert urls == ["https://example.com/a", "https://example.com/b"]


def test_get_warnings_for_iocs_matches_email_domain() -> None:
    """get_warnings_for_iocs must flag an email whose domain is warning-listed.

    separate_iocs_by_warnings already did this; get_warnings_for_iocs did not,
    so the two public methods disagreed on email IOCs.
    """
    from iocparser.infrastructure.warninglists import MISPWarningLists

    warning_lists = MISPWarningLists()
    warning_lists.warning_lists = {
        "bad-domains": {
            "name": "Bad Domains",
            "description": "phishing",
            "type": "string",
            "matching_attributes": ["domain", "hostname"],
            "list": ["phish.com"],
        }
    }
    warning_lists._preprocess_lists()
    iocs: dict[str, list[str | dict[str, str]]] = {"emails": ["user@phish.com", "ok@good.test"]}

    warnings = warning_lists.get_warnings_for_iocs(iocs)
    _normal, separated = warning_lists.separate_iocs_by_warnings(iocs)

    assert [w["value"] for w in warnings.get("emails", [])] == ["user@phish.com"]
    # The two public methods must agree on which emails are warning-listed.
    assert [w["value"] for w in warnings.get("emails", [])] == [
        w["value"] for w in separated.get("emails", [])
    ]


def test_retry_batch_job_conflicts_with_input_source() -> None:
    """--retry-batch-job is an input source and must not silently override -f.

    It was outside the input mutually-exclusive group, so it could be combined
    with -f/-u/-m/-d and silently won, dropping the user's real input.
    """
    from iocparser.cli_args_parser import create_argument_parser

    parser = create_argument_parser()
    # Standalone still parses.
    assert parser.parse_args(["--retry-batch-job", "5"]).retry_batch_job == 5
    # Combined with a primary input source is now rejected.
    with pytest.raises(SystemExit):
        parser.parse_args(["-f", "report.pdf", "--retry-batch-job", "5"])


def test_job_record_preserves_error_with_empty_message() -> None:
    """A persisted failure whose message is empty must keep its code/category.

    job_record gated error reconstruction on all three columns being truthy, so
    an empty message (e.g. str(RuntimeError()) == "") dropped the whole error.
    """
    from iocparser.domain.pipeline import PipelineErrorInfo
    from iocparser.infrastructure.persistence_distributed_records import job_record
    from iocparser.infrastructure.persistence_models import DistributedJobModel

    model = DistributedJobModel(
        job_id="job-empty-error",
        status="failed",
        attempts=1,
        max_attempts=1,
        retryable=False,
        last_error_code="UNEXPECTED_FAILURE",
        last_error_category="non_retryable",
        last_error_message="",
    )

    record = job_record(model)

    assert isinstance(record.last_error, PipelineErrorInfo)
    assert record.last_error.code == "UNEXPECTED_FAILURE"
    assert record.last_error.category == "non_retryable"
    assert record.last_error.message == ""


def test_cli_search_normalizes_ioc_type_and_severity() -> None:
    """The CLI search filters must be normalized like the API/diff handlers.

    --ioc-type ip (alias of 'ips') and --severity HIGH were passed raw to a
    case-sensitive exact SQL comparison, silently returning zero hits.
    """
    from iocparser.api_persistence_query import validated_ioc_type_filter
    from iocparser.shared_utils import validated_severity_filters

    assert validated_ioc_type_filter("ip") == "ips"
    assert validated_ioc_type_filter("domain") == "domains"
    assert validated_severity_filters("HIGH") == ("high",)


def test_dialect_replace_into_uses_mysql_syntax() -> None:
    """The PK upsert must use REPLACE INTO on MySQL/MariaDB, not SQLite-only syntax.

    INSERT OR REPLACE is SQLite grammar; emitting it on MariaDB raised a syntax
    error, breaking every migration and history write on that backend.
    """
    from iocparser.infrastructure.persistence_repository_support import dialect_replace_into

    columns = "t(a, b) VALUES (:a, :b)"
    assert dialect_replace_into("sqlite", columns) == f"INSERT OR REPLACE INTO {columns}"
    assert dialect_replace_into("mysql", columns) == f"REPLACE INTO {columns}"
    assert dialect_replace_into("mariadb", columns) == f"REPLACE INTO {columns}"


def test_worker_config_path_accepts_equals_form_and_any_position() -> None:
    """The worker must honor --config=path and --config path in any argv position.

    The parser only matched '--config' as argv[1], silently ignoring the GNU
    '--config=path' form and any non-first-position --config.
    """
    from iocparser.worker_main import _config_path_from_argv

    assert _config_path_from_argv(["worker", "--config", "a.ini"]) == "a.ini"
    assert _config_path_from_argv(["worker", "--config=b.ini"]) == "b.ini"
    assert _config_path_from_argv(["worker", "--verbose", "--config", "c.ini"]) == "c.ini"
    assert _config_path_from_argv(["worker", "--verbose", "--config=d.ini"]) == "d.ini"
    assert _config_path_from_argv(["worker"]) is None
    assert _config_path_from_argv(["worker", "--config"]) is None


def test_worker_main_help_prints_usage_and_exits(capsys: pytest.CaptureFixture[str]) -> None:
    """`iocparser-worker --help` must print usage and exit, not start a forever poll.

    The worker had no flag handling, so -h/--help was treated as an unknown arg and
    the service began polling the queue indefinitely instead of showing usage.
    """
    from iocparser import worker_main

    original_argv = sys.argv
    try:
        for flag in ("--help", "-h"):
            sys.argv = ["iocparser-worker", flag]
            assert worker_main.main() == 0
            assert "usage: iocparser-worker" in capsys.readouterr().out
    finally:
        sys.argv = original_argv


def test_rev_0009_backfills_dedup_hash_on_legacy_tables() -> None:
    """The dedup_hash migration must add and backfill the column on legacy DBs.

    Legacy SQLite databases predate dedup_hash; rev_0009 adds it, backfills from
    the identity columns, and creates the unique index that enforces the
    MySQL-compatible uniqueness.
    """
    from sqlalchemy import inspect as sa_inspect

    from iocparser.infrastructure.migration_revisions import rev_0009_dedup_hash
    from iocparser.infrastructure.persistence_repository_support import (
        ioc_dedup_hash,
        source_dedup_hash,
    )

    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE sources (id INTEGER PRIMARY KEY, kind TEXT, value TEXT)")
        )
        connection.execute(
            text("INSERT INTO sources(kind, value) VALUES ('url', 'http://evil.example/a')")
        )
        connection.execute(
            text(
                "CREATE TABLE iocs (id INTEGER PRIMARY KEY, ioc_type TEXT, value TEXT, "
                "is_warning INTEGER, warning_list TEXT, warning_description TEXT)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO iocs(ioc_type, value, is_warning, warning_list, warning_description) "
                "VALUES ('domains', 'evil.example', 0, '', '')"
            )
        )

    rev_0009_dedup_hash.apply(engine, sa_inspect(engine))

    with engine.connect() as connection:
        source_hash = connection.execute(text("SELECT dedup_hash FROM sources")).scalar_one()
        ioc_hash = connection.execute(text("SELECT dedup_hash FROM iocs")).scalar_one()
        unique_keys = {uc["name"] for uc in sa_inspect(engine).get_unique_constraints("iocs")} | {
            idx["name"] for idx in sa_inspect(engine).get_indexes("iocs")
        }

    assert source_hash == source_dedup_hash("url", "http://evil.example/a")
    assert ioc_hash == ioc_dedup_hash("domains", "evil.example", False, "", "")
    assert "uq_iocs_dedup_hash" in unique_keys


def test_schema_ddl_is_valid_for_mysql() -> None:
    """The iocs/sources schema must compile to valid MySQL DDL (no TEXT in keys).

    MySQL/MariaDB rejects TEXT columns in a key (error 1170); the unique
    constraints now use a bounded dedup_hash and the search indexes carry a
    prefix length, so create_all no longer aborts on MySQL.
    """
    from sqlalchemy.dialects import mysql
    from sqlalchemy.schema import CreateIndex, CreateTable

    from iocparser.infrastructure.persistence_schema import IOCModel, SourceModel

    for model in (IOCModel, SourceModel):
        table_ddl = str(CreateTable(model.__table__).compile(dialect=mysql.dialect()))
        assert "UNIQUE (dedup_hash)" in table_ddl
        # No bare TEXT column appears inside a UNIQUE(...) key clause.
        assert "value, is_warning" not in table_ddl
        for index in model.__table__.indexes:
            index_ddl = str(CreateIndex(index).compile(dialect=mysql.dialect()))
            if "value_search" in index_ddl:
                assert "value_search(255)" in index_ddl


def test_quote_identifier_per_dialect() -> None:
    """The reserved word 'key' must be backtick-quoted on MySQL, double-quoted else.

    rev_0008's history_metadata and its read/write previously used the bare,
    reserved word 'key', a syntax error on MySQL/MariaDB.
    """
    from iocparser.infrastructure.persistence_repository_support import quote_identifier

    assert quote_identifier("sqlite", "key") == '"key"'
    assert quote_identifier("mysql", "key") == "`key`"
    assert quote_identifier("mariadb", "key") == "`key`"


def test_refang_handles_bracketed_scheme_separator() -> None:
    """The bracketed scheme defang [://] must refang to ://.

    Regression: refang only handled the alphabetic scheme spellings (hxxp:// ...)
    and the [:]/[//] pieces, so a fully-defanged http[://]evil.com stayed defanged
    and deduped separately from its refanged form.
    """
    from iocparser.shared_utils import refang_ioc

    assert refang_ioc("http[://]evil.com") == "http://evil.com"
    assert refang_ioc("hxxps[://]bad[.]com") == "https://bad.com"
    assert refang_ioc("ftp(://)host[.]net") == "ftp://host.net"
    # Existing alphabetic scheme refang still works.
    assert refang_ioc("hxxp://still[.]works") == "http://still.works"
