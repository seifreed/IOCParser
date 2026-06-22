"""Coverage for the filesystem queue's stale-lease reclaim edge paths."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from iocparser.infrastructure.queue_filesystem import FilesystemQueueAdapter


def _processing_file(root: Path, name: str = "msg-1-abc.json", *, stale: bool = False) -> Path:
    processing = root / "jobs" / "processing"
    processing.mkdir(parents=True, exist_ok=True)
    path = processing / name
    path.write_text("{}", encoding="utf-8")
    if stale:
        old = path.stat().st_mtime - 10_000
        os.utime(path, (old, old))
    return path


def test_reclaim_skips_fresh_in_flight_message(tmp_path: Path) -> None:
    """A processing message whose lease has not expired must be left in place."""
    adapter = FilesystemQueueAdapter(tmp_path, visibility_timeout_seconds=300.0)
    fresh = _processing_file(tmp_path)  # just written -> mtime newer than the cutoff

    adapter._reclaim_stale_leases("jobs")

    assert fresh.exists()
    assert not list((tmp_path / "jobs" / "pending").glob("*.json"))


def test_reclaim_ignores_file_vanishing_before_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = FilesystemQueueAdapter(tmp_path, visibility_timeout_seconds=0.0001)
    _processing_file(tmp_path)

    real_stat = Path.stat

    def _missing_stat(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        # Only the in-flight message races away; directory stats still work.
        if self.suffix == ".json" and self.parent.name == "processing":
            raise FileNotFoundError
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _missing_stat)
    # Must not raise even though the file disappears between glob and stat.
    adapter._reclaim_stale_leases("jobs")


def test_reclaim_ignores_file_vanishing_before_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = FilesystemQueueAdapter(tmp_path, visibility_timeout_seconds=1.0)
    _processing_file(tmp_path, stale=True)

    def _missing_rename(self: Path, target: object) -> Path:
        raise FileNotFoundError

    monkeypatch.setattr(Path, "rename", _missing_rename)
    # The lease is stale so reclaim tries to rename; the race must be swallowed.
    adapter._reclaim_stale_leases("jobs")
    assert not list((tmp_path / "jobs" / "pending").glob("*.json"))
