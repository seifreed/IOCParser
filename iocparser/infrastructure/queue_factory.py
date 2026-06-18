from __future__ import annotations

from pathlib import Path

from iocparser.infrastructure.queue_celery import CeleryQueueAdapter
from iocparser.infrastructure.queue_filesystem import FilesystemQueueAdapter
from iocparser.infrastructure.queue_rabbitmq import RabbitMQQueueAdapter
from iocparser.infrastructure.queue_sqs import SQSQueueAdapter
from iocparser.interfaces.ports import QueueAdapter


def _missing_queue_url_error(backend: str) -> ValueError:
    return ValueError(f"{backend} backend requires queue_url")


def _unsupported_backend_error(backend: str) -> ValueError:
    return ValueError(f"Unsupported queue backend: {backend}")


def _require_queue_url(backend: str, queue_url: str | None) -> str:
    if isinstance(queue_url, str):
        queue_url = queue_url.strip()
    if queue_url:
        return queue_url
    raise _missing_queue_url_error(backend)


def create_queue_adapter(
    backend: str = "filesystem",
    *,
    queue_url: str | None = None,
    queue_path: str | None = None,
    dead_letter_queue_url: str | None = None,
) -> QueueAdapter:
    """Create a queue adapter for the selected backend."""
    normalized = backend.strip().lower()
    if normalized == "filesystem":
        root = Path(queue_path.strip() if isinstance(queue_path, str) and queue_path.strip() else ".iocparser-queue")
        return FilesystemQueueAdapter(root)
    if normalized == "rabbitmq":
        return RabbitMQQueueAdapter(_require_queue_url("rabbitmq", queue_url))
    if normalized == "sqs":
        return SQSQueueAdapter(
            _require_queue_url("sqs", queue_url),
            dead_letter_queue_url=dead_letter_queue_url,
        )
    if normalized == "celery":
        return CeleryQueueAdapter(_require_queue_url("celery", queue_url))
    raise _unsupported_backend_error(backend)
