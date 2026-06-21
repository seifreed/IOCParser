from __future__ import annotations

from iocparser.infrastructure.queue_filesystem import FilesystemQueueAdapter


def pending_count(adapter: FilesystemQueueAdapter, *, queue_name: str) -> int:
    """Count pending job files for a queue (formerly a production method)."""
    return len(list(adapter._queue_dir(queue_name, "pending").glob("*.json")))


def dead_count(adapter: FilesystemQueueAdapter, *, queue_name: str) -> int:
    """Count dead-letter job files for a queue (formerly a production method)."""
    return len(list(adapter._queue_dir(queue_name, "dead").glob("*.json")))
