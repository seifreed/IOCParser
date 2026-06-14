from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.infrastructure.queue_records import load_queue_record, serialize_queue_record

INVALID_QUEUE_NAME_ERROR = "Invalid queue name"
INVALID_RECEIPT_PATH_ERROR = "Invalid filesystem queue receipt"


def _safe_filename_component(value: object) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._")
    return normalized or str(uuid4())


def _validate_queue_name(queue_name: str) -> None:
    if not queue_name or Path(queue_name).is_absolute() or "/" in queue_name or "\\" in queue_name:
        raise ValueError(INVALID_QUEUE_NAME_ERROR)
    if any(part in {"", ".", ".."} for part in Path(queue_name).parts):
        raise ValueError(INVALID_QUEUE_NAME_ERROR)


class FilesystemQueueAdapter:
    """Simple filesystem-backed queue for local staging and test environments."""

    def __init__(self, root_dir: str | Path) -> None:
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        message_id = envelope.request.job_id or str(uuid4())
        queue_dir = self._queue_dir(queue_name, "pending")
        receipt_path = queue_dir / f"{_safe_filename_component(message_id)}-{uuid4().hex}.json"
        receipt_path.write_text(serialize_queue_record(envelope), encoding="utf-8")
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
        queue_dir = self._queue_dir(receipt.queue_name, "pending")
        processing_path = self._receipt_path(receipt)
        temp_path = queue_dir / f"tmp-{uuid4().hex}.json"
        message_name = _safe_filename_component(envelope.request.job_id or uuid4())
        new_path = queue_dir / f"{message_name}-{uuid4().hex}.json"
        temp_path.write_text(serialize_queue_record(envelope), encoding="utf-8")
        temp_path.rename(new_path)
        processing_path.unlink(missing_ok=True)
        return QueueReceipt(
            queue_backend="filesystem",
            queue_name=receipt.queue_name,
            receipt_id=str(new_path),
            message_id=receipt.message_id,
        )

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        processing_path = self._receipt_path(receipt)
        dead_dir = self._queue_dir(receipt.queue_name, "dead")
        temp_path = dead_dir / f"tmp-{uuid4().hex}.json"
        target = dead_dir / processing_path.name
        temp_path.write_text(serialize_queue_record(envelope), encoding="utf-8")
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
