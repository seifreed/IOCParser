"""Coverage repair for branches the bug-hunt loop left uncovered.

Each test targets a specific previously-uncovered production line; see the
inline references. These restore the enforced 100% coverage gate.
"""

from __future__ import annotations


def test_is_legitimate_domain_subdomain_branches() -> None:
    """Cover DomainValidationPolicy.is_legitimate_domain subdomain suffix branch.

    extractor_base.py:156-158 — a non-suspicious subdomain of a legitimate domain
    is itself treated as legitimate (True), while a suspicious subdomain stays a
    real IOC (False). Both flow through the matching-suffix branch.
    """
    from iocparser.infrastructure.extractor_base import DEFAULT_DOMAIN_VALIDATION_POLICY
    from iocparser.infrastructure.extractor_base_runtime_support import build_reference_data

    rd = build_reference_data("iocparser.infrastructure.extractor_network")
    policy = DEFAULT_DOMAIN_VALIDATION_POLICY
    legit = rd.legitimate_domains
    assert "google.com" in legit  # guard: fixture domain is present

    kwargs = {
        "legitimate_domains": legit,
        "legitimate_with_subdomains": rd.legitimate_with_subdomains,
    }
    # Non-suspicious subdomain -> legitimate.
    assert policy.is_legitimate_domain("mail.google.com", **kwargs) is True
    # Suspicious subdomain -> NOT legitimate (stays a real IOC).
    assert policy.is_legitimate_domain("malware.google.com", **kwargs) is False


def test_is_valid_match_boundary_ip_subtoken_rejected() -> None:
    """Cover the ips/cidr start-boundary rejection in streaming_matching.

    streaming_matching.py:30 — a match preceded by a digit/dot is a sub-token of a
    longer dotted address (e.g. "3.0.113.45" inside "203.0.113.45"), so the start
    boundary is invalid.
    """
    from iocparser.infrastructure.streaming_matching import is_valid_match_boundary

    # "3.0.113.45" inside "203.0.113.45" starts at index 2, preceded by digit "0".
    assert is_valid_match_boundary("ips", "203.0.113.45", 2, 12) is False
    # Trailing digit also rejects (sub-token at the front).
    assert is_valid_match_boundary("cidr", "10.0.0.0/811", 0, 10) is False
    # A cleanly delimited IP is accepted.
    assert is_valid_match_boundary("ips", " 10.0.0.1 ", 1, 9) is True


def test_url_filter_variants_path_branches() -> None:
    """Cover the path-variant branches of _url_filter_variants.

    persistence_support.py — normalize_url_value always yields a non-empty path,
    so a rooted "/" URL also gets its bare form, and a non-slash path also gets a
    trailing-slash variant, letting either form match in a search.
    """
    from iocparser.infrastructure.persistence_support import _url_filter_variants

    rooted = _url_filter_variants("http://example.com")  # path "/" branch
    assert "http://example.com" in rooted
    assert "http://example.com/" in rooted

    pathed = _url_filter_variants("http://example.com/a")  # non-slash path branch
    assert "http://example.com/a" in pathed
    assert "http://example.com/a/" in pathed


def test_read_chunks_reraises_deferred_lookahead_error_on_empty_chunk() -> None:
    """Cover the empty-chunk + deferred-error raise in the chunk reader.

    streaming_chunks.py:86 — when a chunk decodes to empty (here a lone UTF-8
    continuation byte under errors='ignore') and the look-ahead read already
    failed, the deferred error is raised rather than silently swallowed.
    """
    import pytest

    from iocparser.infrastructure.streaming_chunks import read_chunks_with_prefix

    class FakeBinary:
        def __init__(self) -> None:
            self.reads = 0

        def read(self, _size: int) -> bytes:
            self.reads += 1
            if self.reads == 1:
                return b"\x80"  # lone continuation byte -> decodes to "" (errors=ignore)
            raise OSError("lookahead boom")

        def seek(self, *_args: int) -> int:
            raise OSError  # skip the seekable total_size probe without consuming a read

        def tell(self) -> int:
            return 0

    with pytest.raises(OSError, match="lookahead boom"):
        list(
            read_chunks_with_prefix(
                file_obj=FakeBinary(),  # type: ignore[arg-type]
                chunk_size=4,
                overlap=2,
                progress_callback=None,
                is_text=False,
            )
        )


def test_batch_plugin_client_reraises_validation_error(tmp_path, monkeypatch) -> None:
    """Cover the ValidationError re-raise in the plugin-client batch loop.

    cli_processing_files.py:589 — a ValidationError from a configured plugin
    client must propagate (abort the batch) rather than being recorded as a
    per-item failure like ordinary processing errors.
    """
    from types import SimpleNamespace

    import pytest

    import iocparser.cli_processing_files as cpf
    from iocparser.cli_args import create_argument_parser
    from iocparser.errors import ValidationError

    file_a = tmp_path / "a.txt"
    file_a.write_text("alpha")
    file_b = tmp_path / "b.txt"
    file_b.write_text("beta")
    args = create_argument_parser().parse_args(
        ["-m", str(file_a), str(file_b), "--no-check-warnings"]
    )

    class RaisingClient:
        def extract_result_from_file(self, *_args: object, **_kwargs: object) -> object:
            raise ValidationError("invalid plugin input")

    monkeypatch.setattr(cpf, "_plugin_client", lambda *_a, **_k: RaisingClient())

    with pytest.raises(ValidationError, match="invalid plugin input"):
        cpf.process_multiple_files_payload(args, reader=SimpleNamespace(), warning_service=None)


class _ScalarResult:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarResult:
        return self

    def all(self) -> list[object]:
        return self._rows


class _Savepoint:
    def rollback(self) -> None:
        return None


class _RaceSession:
    """Simulates a concurrent-insert race: empty initial query, IntegrityError on
    flush, then the conflicting row appears on refetch."""

    def __init__(self, retry_rows: list[object]) -> None:
        self.retry_rows = retry_rows
        self.execute_calls = 0

    def execute(self, _stmt: object) -> _ScalarResult:
        self.execute_calls += 1
        return _ScalarResult([] if self.execute_calls == 1 else self.retry_rows)

    def add(self, _model: object) -> None:
        return None

    def begin_nested(self) -> _Savepoint:
        return _Savepoint()

    def flush(self) -> None:
        from sqlalchemy.exc import IntegrityError

        raise IntegrityError("duplicate", {}, Exception("duplicate"))


def test_source_repository_url_conflict_refreshes_value() -> None:
    """Cover the kind=='url' branch of the source-repository conflict handler.

    persistence_source_repository.py:115 — on a concurrent-insert race for a URL
    source, the existing row's value is refreshed to the new (canonical) value.
    The initial query is broader than the refetch, so this branch is only reachable
    under a genuine race, simulated here.
    """
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from iocparser.infrastructure.persistence_source_repository import SQLAlchemySourceRepository

    existing = SimpleNamespace(
        id=7,
        value="http://stale.example.com",
        last_seen=datetime(2020, 1, 1, tzinfo=UTC),
        original_url=None,
        normalized_url=None,
        mime_type=None,
        input_size=None,
        content_hash=None,
        fingerprint=None,
        value_search="",
    )
    session = _RaceSession([existing])
    result_id = SQLAlchemySourceRepository(session).get_or_create(  # type: ignore[arg-type]
        kind="url",
        value="http://fresh.example.com",
    )
    assert result_id == 7
    # The url branch refreshed the stored value to the new one.
    assert existing.value == "http://fresh.example.com"
