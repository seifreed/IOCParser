from __future__ import annotations

import json
import threading
from collections.abc import Callable
from typing import Protocol, cast
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.queue_records import (
    build_invalid_payload_record,
    import_optional_backend_module,
    load_queue_record,
    materialize_queue_envelope,
    serialize_queue_record,
)
from iocparser.shared_utils import close_and_log


class _RabbitMQMethodFrame(Protocol):
    delivery_tag: int


class _RabbitMQProperties(Protocol):
    message_id: str | None


class _RabbitMQChannel(Protocol):
    def queue_declare(self, *, queue: str, durable: bool) -> object: ...

    def basic_publish(
        self,
        *,
        exchange: str,
        routing_key: str,
        body: bytes,
        properties: object,
    ) -> bool: ...

    def basic_get(
        self,
        *,
        queue: str,
        auto_ack: bool,
    ) -> tuple[_RabbitMQMethodFrame | None, _RabbitMQProperties | None, bytes | None]: ...

    def basic_ack(self, *, delivery_tag: int) -> object: ...

    def close(self) -> object: ...


class _RabbitMQConnection(Protocol):
    def channel(self) -> _RabbitMQChannel: ...

    def close(self) -> object: ...


class _BasicPropertiesFactory(Protocol):
    def __call__(self, **kwargs: object) -> object: ...


class _PikaModule(Protocol):
    URLParameters: Callable[[str], object]
    BlockingConnection: Callable[[object], _RabbitMQConnection]
    BasicProperties: _BasicPropertiesFactory


logger = get_logger(__name__)


def _pika_module() -> _PikaModule:
    return cast("_PikaModule", import_optional_backend_module("pika", backend="rabbitmq"))


def _load_queue_record(payload: bytes) -> dict[str, object]:
    return load_queue_record(payload.decode("utf-8"))


def _payload_text(payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return repr(payload)


def _invalid_payload_body(
    *, payload: bytes, queue_name: str, message_id: str, error: Exception
) -> bytes:
    return build_invalid_payload_record(
        payload=_payload_text(payload),
        queue_name=queue_name,
        message_id=message_id,
        error=error,
    ).encode("utf-8")


class RabbitMQQueueAdapter:
    """RabbitMQ adapter using pika when installed."""

    def __init__(self, url: str, *, dead_letter_suffix: str = ".dead") -> None:
        self.url = url
        self.dead_letter_suffix = dead_letter_suffix
        self._connection: _RabbitMQConnection | None = None
        self._channel: _RabbitMQChannel | None = None
        # pika BlockingConnection/channel objects are not thread-safe, and this
        # adapter is shared across worker threads when concurrency > 1. RLock
        # (not Lock) because requeue/dead_letter call enqueue+ack reentrantly.
        self._lock = threading.RLock()
        # Validate the optional dependency eagerly so a missing 'pika' fails at worker
        # setup (reported cleanly by worker_main, like the sqs/celery adapters) instead
        # of spamming a traceback from the poll loop on every dequeue. The broker
        # connection itself stays lazy in _channel_for.
        _pika_module()

    def _channel_for(self) -> _RabbitMQChannel:
        channel = self._channel
        if channel is not None:
            return channel
        pika = _pika_module()
        params = pika.URLParameters(self.url)
        try:
            connection = pika.BlockingConnection(params)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self._connection = None
            self._channel = None
            raise
        try:
            channel = connection.channel()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            close_and_log(
                connection, logger=logger, message="Close failed while opening RabbitMQ channel"
            )
            self._connection = None
            self._channel = None
            raise
        self._connection = connection
        self._channel = channel
        return channel

    def _reset_connection(self) -> None:
        channel = self._channel
        if channel is not None:
            close_and_log(
                channel, logger=logger, message="Close failed while resetting RabbitMQ channel"
            )
        connection = self._connection
        if connection is not None:
            close_and_log(
                connection,
                logger=logger,
                message="Close failed while resetting RabbitMQ connection",
            )
        self._channel = None
        self._connection = None

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            try:
                pika = _pika_module()
                channel = self._channel_for()
                channel.queue_declare(queue=queue_name, durable=True)
                envelope = materialize_queue_envelope(envelope)
                message_id = envelope.request.job_id or str(uuid4())
                channel.basic_publish(
                    exchange="",
                    routing_key=queue_name,
                    body=serialize_queue_record(envelope).encode("utf-8"),
                    properties=pika.BasicProperties(delivery_mode=2, message_id=message_id),
                )
                return QueueReceipt("rabbitmq", queue_name, message_id, message_id)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self._reset_connection()
                raise

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        with self._lock:
            receipt: QueueReceipt | None = None
            payload: bytes | None = None
            try:
                channel = self._channel_for()
                channel.queue_declare(queue=queue_name, durable=True)
                method, properties, body = channel.basic_get(queue=queue_name, auto_ack=False)
                if method is None or properties is None or body is None:
                    return None
                payload = body
                receipt = QueueReceipt(
                    "rabbitmq",
                    queue_name,
                    str(method.delivery_tag),
                    str(properties.message_id or uuid4()),
                )
                envelope = QueueEnvelope.from_record(_load_queue_record(payload))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                if receipt is None or payload is None:
                    self._reset_connection()
                    raise
                self._quarantine_invalid_payload(receipt, payload=payload, error=exc)
                return None
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self._reset_connection()
                raise
            return receipt, envelope

    def ack(self, receipt: QueueReceipt) -> None:
        with self._lock:
            try:
                self._basic_ack(receipt, receipt.queue_name)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self._reset_connection()
                raise

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            try:
                envelope = materialize_queue_envelope(envelope)
                new_receipt = self.enqueue(queue_name=receipt.queue_name, envelope=envelope)
                self.ack(receipt)
                return new_receipt
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self._reset_connection()
                raise

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            try:
                envelope = materialize_queue_envelope(envelope)
                new_receipt = self.enqueue(
                    queue_name=f"{receipt.queue_name}{self.dead_letter_suffix}",
                    envelope=envelope,
                )
                self.ack(receipt)
                return new_receipt
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self._reset_connection()
                raise

    def _quarantine_invalid_payload(
        self, receipt: QueueReceipt, *, payload: bytes, error: Exception
    ) -> None:
        try:
            pika = _pika_module()
            channel = self._channel_for()
            dead_queue_name = f"{receipt.queue_name}{self.dead_letter_suffix}"
            channel.queue_declare(queue=dead_queue_name, durable=True)
            channel.basic_publish(
                exchange="",
                routing_key=dead_queue_name,
                body=_invalid_payload_body(
                    payload=payload,
                    queue_name=receipt.queue_name,
                    message_id=receipt.message_id,
                    error=error,
                ),
                properties=pika.BasicProperties(delivery_mode=2, message_id=receipt.message_id),
            )
            self._basic_ack(receipt, receipt.queue_name)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self._reset_connection()
            raise

    def _basic_ack(self, receipt: QueueReceipt, queue_name: str) -> None:
        channel = self._channel_for()
        channel.queue_declare(queue=queue_name, durable=True)
        channel.basic_ack(delivery_tag=int(receipt.receipt_id))

    def close(self) -> None:
        with self._lock:
            close_error: Exception | None = None
            channel = self._channel
            if channel is not None:
                try:
                    channel.close()
                except Exception as exc:
                    close_error = exc
            connection = self._connection
            if connection is not None:
                try:
                    connection.close()
                except Exception as exc:
                    if close_error is None:
                        close_error = exc
                    else:
                        close_error.add_note(f"connection.close() also failed: {exc!r}")
            self._channel = None
            self._connection = None
            if close_error is not None:
                raise close_error
