from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.infrastructure.queue_records import (
    load_queue_record,
    materialize_queue_envelope,
    serialize_queue_record,
)

INVALID_QUEUE_NAME_ERROR = "Invalid queue name"
INVALID_RECEIPT_PATH_ERROR = "Invalid filesystem queue receipt"

# Default lease before an in-flight (processing/) message is considered abandoned and
# redelivered. A crashed worker leaves its message in processing/ with no SQS-style
# visibility timeout to reclaim it, so without this the job is stranded forever.
DEFAULT_VISIBILITY_TIMEOUT_SECONDS = 300.0


def _safe_filename_component(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return normalized or str(uuid4())


def _validate_queue_name(queue_name: str) -> None:
    if not queue_name or Path(queue_name).is_absolute() or "/" in queue_name or "\\" in queue_name:
        raise ValueError(INVALID_QUEUE_NAME_ERROR)
    if any(part in {"", ".", ".."} for part in Path(queue_name).parts):
        raise ValueError(INVALID_QUEUE_NAME_ERROR)


class FilesystemQueueAdapter:
    """Simple filesystem-backed queue for local staging and test environments."""

    def __init__(
        self,
        root_dir: str | Path,
        *,
        visibility_timeout_seconds: float = DEFAULT_VISIBILITY_TIMEOUT_SECONDS,
    ) -> None:
        self.root_dir = Path(root_dir).expanduser()
        self.root_dir.mkdir(parents=True, exist_ok=True)
        # <= 0 disables reclaim (in-flight messages are never redelivered). A positive
        # value redelivers a message whose lease has been held past the timeout, which is
        # at-least-once: a slow-but-alive worker may have its job redelivered and processed
        # twice. The pipeline's idempotency layer dedups that, and reclaim renames the
        # message with a fresh id so the original lease's late ack cannot delete the
        # redelivered copy.
        self.visibility_timeout_seconds = visibility_timeout_seconds
        self._lock = threading.Lock()

    def _atomic_write_record(self, target: Path, envelope: QueueEnvelope) -> None:
        # Stage under a suffix the dequeue/count globs ("*.json") never match, then
        # rename into place. A staging file matching "*.json" could be grabbed by a
        # concurrent dequeue mid-write, which would both crash the rename here (leaking
        # the source record in processing/) and surface a half-staged message.
        temp_path = target.with_name(f".staging-{uuid4().hex}-{target.name}.part")
        temp_path.write_text(serialize_queue_record(envelope), encoding="utf-8")
        temp_path.rename(target)

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        envelope = materialize_queue_envelope(envelope)
        message_id = envelope.request.job_id or str(uuid4())
        queue_dir = self._queue_dir(queue_name, "pending")
        receipt_path = queue_dir / f"{_safe_filename_component(message_id)}-{uuid4().hex}.json"
        self._atomic_write_record(receipt_path, envelope)
        return QueueReceipt(
            queue_backend="filesystem",
            queue_name=queue_name,
            receipt_id=str(receipt_path),
            message_id=message_id,
        )

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        with self._lock:
            self._reclaim_stale_leases(queue_name)
            pending_dir = self._queue_dir(queue_name, "pending")
            processing_dir = self._queue_dir(queue_name, "processing")
            for path in sorted(pending_dir.glob("*.json")):
                target = processing_dir / path.name
                try:
                    path.rename(target)
                except FileNotFoundError:
                    continue
                # Stamp the lease start so reclaim measures time-held, not time-enqueued
                # (rename preserves the original write mtime, which could be arbitrarily old).
                try:
                    os.utime(target, None)
                except OSError:
                    pass
                try:
                    payload = load_queue_record(target.read_text(encoding="utf-8"))
                    envelope = QueueEnvelope.from_record(payload)
                except (json.JSONDecodeError, TypeError, ValueError):
                    self._quarantine_invalid_payload(queue_name, target)
                    continue
                return (
                    QueueReceipt(
                        queue_backend="filesystem",
                        queue_name=queue_name,
                        receipt_id=str(target),
                        message_id=str(envelope.request.job_id or target.stem),
                    ),
                    envelope,
                )
            return None

    def ack(self, receipt: QueueReceipt) -> None:
        self._receipt_path(receipt).unlink(missing_ok=True)

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        envelope = materialize_queue_envelope(envelope)
        queue_dir = self._queue_dir(receipt.queue_name, "pending")
        processing_path = self._receipt_path(receipt)
        message_name = _safe_filename_component(envelope.request.job_id or str(uuid4()))
        new_path = queue_dir / f"{message_name}-{uuid4().hex}.json"
        self._atomic_write_record(new_path, envelope)
        try:
            processing_path.unlink(missing_ok=True)
        except OSError:
            new_path.unlink(missing_ok=True)
            raise
        return QueueReceipt(
            queue_backend="filesystem",
            queue_name=receipt.queue_name,
            receipt_id=str(new_path),
            message_id=receipt.message_id,
        )

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        envelope = materialize_queue_envelope(envelope)
        processing_path = self._receipt_path(receipt)
        dead_dir = self._queue_dir(receipt.queue_name, "dead")
        target = dead_dir / processing_path.name
        if target.exists():
            target = dead_dir / f"{processing_path.stem}-{uuid4().hex}{processing_path.suffix}"
        self._atomic_write_record(target, envelope)
        try:
            processing_path.unlink(missing_ok=True)
        except OSError:
            target.unlink(missing_ok=True)
            raise
        return QueueReceipt(
            queue_backend="filesystem",
            queue_name=receipt.queue_name,
            receipt_id=str(target),
            message_id=receipt.message_id,
        )

    def _reclaim_stale_leases(self, queue_name: str) -> None:
        """Redeliver in-flight messages whose lease has outlived the visibility timeout.

        Called while holding ``self._lock`` from dequeue. Each stale processing/ file is
        renamed back into pending/ with a fresh id so the next scan re-leases it. The fresh
        id is critical: the original lease's receipt still points at the old processing/
        path, so a late ack/requeue from a slow-but-alive worker only unlinks that stale
        path (a no-op) and cannot delete the redelivered copy.
        """
        if self.visibility_timeout_seconds <= 0:
            return
        processing_dir = self._queue_dir(queue_name, "processing")
        pending_dir = self._queue_dir(queue_name, "pending")
        cutoff = time.time() - self.visibility_timeout_seconds
        for path in sorted(processing_dir.glob("*.json")):
            try:
                if path.stat().st_mtime > cutoff:
                    continue
            except FileNotFoundError:
                continue
            target = pending_dir / f"{_safe_filename_component(path.stem)}-{uuid4().hex}.json"
            try:
                path.rename(target)
            except FileNotFoundError:
                continue

    def _quarantine_invalid_payload(self, queue_name: str, path: Path) -> None:
        dead_dir = self._queue_dir(queue_name, "dead")
        target = dead_dir / path.name
        if target.exists():
            target = dead_dir / f"{path.stem}-{uuid4().hex}{path.suffix}"
        path.rename(target)

    def _queue_dir(self, queue_name: str, state: str) -> Path:
        _validate_queue_name(queue_name)
        path = self.root_dir / queue_name / state
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _receipt_path(self, receipt: QueueReceipt) -> Path:
        receipt_path = Path(receipt.receipt_id)
        expected_dir = (self.root_dir / receipt.queue_name / "processing").resolve()
        try:
            resolved = receipt_path.resolve()
            resolved.relative_to(self.root_dir.resolve())
            resolved.relative_to(expected_dir)
        except ValueError as exc:
            raise ValueError(INVALID_RECEIPT_PATH_ERROR) from exc
        return receipt_path
