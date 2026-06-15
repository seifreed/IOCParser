from __future__ import annotations

import json
import threading
from collections.abc import Callable
from importlib import import_module
from typing import Protocol, cast
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.infrastructure.queue_records import (
    build_invalid_payload_record,
    load_queue_record,
    serialize_queue_record,
)


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


def _pika_module() -> _PikaModule:
    return cast("_PikaModule", import_module("pika"))


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
            connection.close()
            self._connection = None
            self._channel = None
            raise
        self._connection = connection
        self._channel = channel
        return channel

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            pika = _pika_module()
            channel = self._channel_for()
            channel.queue_declare(queue=queue_name, durable=True)
            message_id = envelope.request.job_id or str(uuid4())
            channel.basic_publish(
                exchange="",
                routing_key=queue_name,
                body=serialize_queue_record(envelope).encode("utf-8"),
                properties=pika.BasicProperties(delivery_mode=2, message_id=message_id),
            )
            return QueueReceipt("rabbitmq", queue_name, message_id, message_id)

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        with self._lock:
            channel = self._channel_for()
            channel.queue_declare(queue=queue_name, durable=True)
            method, properties, body = channel.basic_get(queue=queue_name, auto_ack=False)
            if method is None or properties is None or body is None:
                return None
            receipt = QueueReceipt(
                "rabbitmq",
                queue_name,
                str(method.delivery_tag),
                str(properties.message_id or uuid4()),
            )
            try:
                envelope = QueueEnvelope.from_record(_load_queue_record(body))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self._quarantine_invalid_payload(receipt, payload=body, error=exc)
                return None
            return receipt, envelope

    def ack(self, receipt: QueueReceipt) -> None:
        with self._lock:
            self._basic_ack(receipt, receipt.queue_name)

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            new_receipt = self.enqueue(queue_name=receipt.queue_name, envelope=envelope)
            self.ack(receipt)
            return new_receipt

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            new_receipt = self.enqueue(
                queue_name=f"{receipt.queue_name}{self.dead_letter_suffix}", envelope=envelope
            )
            self.ack(receipt)
            return new_receipt

    def _quarantine_invalid_payload(
        self, receipt: QueueReceipt, *, payload: bytes, error: Exception
    ) -> None:
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

    def _basic_ack(self, receipt: QueueReceipt, queue_name: str) -> None:
        channel = self._channel_for()
        channel.queue_declare(queue=queue_name, durable=True)
        channel.basic_ack(delivery_tag=int(receipt.receipt_id))

    def close(self) -> None:
        with self._lock:
            channel = self._channel
            if channel is not None:
                channel.close()
                self._channel = None
            connection = self._connection
            if connection is not None:
                connection.close()
                self._connection = None
