from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import cast
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt


def _load_queue_record(payload: str) -> dict[str, object]:
    decoded = cast("object", json.loads(payload))
    if not isinstance(decoded, dict):
        raise _queue_payload_type_error()
    return cast("dict[str, object]", decoded)


def _queue_payload_type_error() -> TypeError:
    return TypeError("Queue payload must be a JSON object")


class FilesystemQueueAdapter:
    """Simple filesystem-backed queue for local staging and test environments."""

    def __init__(self, root_dir: str | Path) -> None:
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        message_id = envelope.request.job_id or str(uuid4())
        queue_dir = self._queue_dir(queue_name, "pending")
        receipt_path = queue_dir / f"{message_id}-{uuid4().hex}.json"
        receipt_path.write_text(json.dumps(envelope.to_record(), sort_keys=True), encoding="utf-8")
        return QueueReceipt(
            queue_backend="filesystem",
            queue_name=queue_name,
            receipt_id=str(receipt_path),
            message_id=message_id,
        )

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        with self._lock:
            pending_dir = self._queue_dir(queue_name, "pending")
            processing_dir = self._queue_dir(queue_name, "processing")
            for path in sorted(pending_dir.glob("*.json")):
                target = processing_dir / path.name
                try:
                    path.rename(target)
                except FileNotFoundError:
                    continue
                payload = _load_queue_record(target.read_text(encoding="utf-8"))
                envelope = QueueEnvelope.from_record(payload)
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
        Path(receipt.receipt_id).unlink(missing_ok=True)

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        queue_dir = self._queue_dir(receipt.queue_name, "pending")
        temp_path = queue_dir / f"tmp-{uuid4().hex}.json"
        new_path = queue_dir / f"{envelope.request.job_id or uuid4()}-{uuid4().hex}.json"
        temp_path.write_text(json.dumps(envelope.to_record(), sort_keys=True), encoding="utf-8")
        temp_path.rename(new_path)
        processing_path = Path(receipt.receipt_id)
        processing_path.unlink(missing_ok=True)
        return QueueReceipt(
            queue_backend="filesystem",
            queue_name=receipt.queue_name,
            receipt_id=str(new_path),
            message_id=receipt.message_id,
        )

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        processing_path = Path(receipt.receipt_id)
        dead_dir = self._queue_dir(receipt.queue_name, "dead")
        temp_path = dead_dir / f"tmp-{uuid4().hex}.json"
        target = dead_dir / processing_path.name
        temp_path.write_text(json.dumps(envelope.to_record(), sort_keys=True), encoding="utf-8")
        temp_path.rename(target)
        processing_path.unlink(missing_ok=True)
        return QueueReceipt(
            queue_backend="filesystem",
            queue_name=receipt.queue_name,
            receipt_id=str(target),
            message_id=receipt.message_id,
        )

    def pending_count(self, *, queue_name: str) -> int:
        return len(list(self._queue_dir(queue_name, "pending").glob("*.json")))

    def dead_count(self, *, queue_name: str) -> int:
        return len(list(self._queue_dir(queue_name, "dead").glob("*.json")))

    def _queue_dir(self, queue_name: str, state: str) -> Path:
        path = self.root_dir / queue_name / state
        path.mkdir(parents=True, exist_ok=True)
        return path
