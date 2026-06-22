"""Coverage for small validation/edge helpers (part of the 100% coverage repair)."""

from __future__ import annotations

import pytest

from iocparser.errors import TypeValidationError, ValidationError


def test_jobs_require_str_rejects_blank_when_non_empty() -> None:
    from iocparser.domain.jobs import _require_str

    assert _require_str("  ok  ", field="x", non_empty=True) == "ok"
    with pytest.raises(TypeValidationError):
        _require_str("   ", field="x", non_empty=True)


def test_persisted_require_str_rejects_blank_when_non_empty() -> None:
    from iocparser.domain.persisted import _require_str

    assert _require_str(" v ", field="x", non_empty=True) == "v"
    with pytest.raises(TypeValidationError):
        _require_str("", field="x", non_empty=True)


def test_distributed_require_str_rejects_blank_when_non_empty() -> None:
    from iocparser.domain.distributed import _require_str

    assert _require_str(" v ", field="x", non_empty=True) == "v"
    with pytest.raises(TypeValidationError):
        _require_str("   ", field="x", non_empty=True)


def test_distributed_int_from_payload_rejects_bool() -> None:
    from iocparser.domain.distributed import _int_from_payload

    assert _int_from_payload({"n": 5}, "n", 0) == 5
    assert _int_from_payload({}, "n", 7) == 7
    with pytest.raises(TypeError):
        _int_from_payload({"n": True}, "n", 0)


def test_validated_diff_only_rejects_unknown_value() -> None:
    from iocparser.shared_utils import validated_diff_only

    assert validated_diff_only(None) == "all"
    assert validated_diff_only("   ") == "all"
    assert validated_diff_only("added") == "added"
    with pytest.raises(ValidationError):
        validated_diff_only("sideways")


def test_streaming_canonical_dedup_key_falls_back_to_raw_on_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iocparser.infrastructure import streaming

    def _raise(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        raise ValueError("uncanonicalisable")

    # When canonicalisation raises ValueError the raw value is used as the dedup key.
    monkeypatch.setattr(streaming, "indicator_value_for", _raise)
    assert streaming._canonical_dedup_key("md5", "raw-value") == "raw-value"


def test_queue_factory_filesystem_honours_visibility_timeout(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from iocparser.infrastructure.queue_factory import create_queue_adapter
    from iocparser.infrastructure.queue_filesystem import FilesystemQueueAdapter

    adapter = create_queue_adapter(
        "filesystem", queue_path=str(tmp_path), visibility_timeout_seconds=42.0
    )
    assert isinstance(adapter, FilesystemQueueAdapter)
    assert adapter.visibility_timeout_seconds == 42.0


def test_cli_non_negative_int_rejects_negative() -> None:
    import argparse

    from iocparser.cli_args_parser import _non_negative_int

    assert _non_negative_int("3") == 3
    with pytest.raises(argparse.ArgumentTypeError):
        _non_negative_int("-5")
    with pytest.raises(argparse.ArgumentTypeError):
        _non_negative_int("not-int")
