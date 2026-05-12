from __future__ import annotations

import json
from collections.abc import Callable
from importlib import import_module
from typing import Protocol, cast
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt


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
    decoded = cast("object", json.loads(payload.decode("utf-8")))
    if not isinstance(decoded, dict):
        raise _queue_payload_type_error()
    return cast("dict[str, object]", decoded)


def _queue_payload_type_error() -> TypeError:
    return TypeError("Queue payload must be a JSON object")


class RabbitMQQueueAdapter:
    """RabbitMQ adapter using pika when installed."""

    def __init__(self, url: str, *, dead_letter_suffix: str = ".dead") -> None:
        self.url = url
        self.dead_letter_suffix = dead_letter_suffix
        self._connection: _RabbitMQConnection | None = None
        self._channel: _RabbitMQChannel | None = None

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
        pika = _pika_module()
        channel = self._channel_for()
        channel.queue_declare(queue=queue_name, durable=True)
        message_id = envelope.request.job_id or str(uuid4())
        channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=json.dumps(envelope.to_record(), sort_keys=True).encode("utf-8"),
            properties=pika.BasicProperties(delivery_mode=2, message_id=message_id),
        )
        return QueueReceipt("rabbitmq", queue_name, message_id, message_id)

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        channel = self._channel_for()
        channel.queue_declare(queue=queue_name, durable=True)
        method, properties, body = channel.basic_get(queue=queue_name, auto_ack=False)
        if method is None or properties is None or body is None:
            return None
        receipt = QueueReceipt("rabbitmq", queue_name, str(method.delivery_tag), str(properties.message_id or uuid4()))
        return receipt, QueueEnvelope.from_record(_load_queue_record(body))

    def ack(self, receipt: QueueReceipt) -> None:
        self._basic_ack(receipt, receipt.queue_name)

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        new_receipt = self.enqueue(queue_name=receipt.queue_name, envelope=envelope)
        self.ack(receipt)
        return new_receipt

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        new_receipt = self.enqueue(queue_name=f"{receipt.queue_name}{self.dead_letter_suffix}", envelope=envelope)
        self.ack(receipt)
        return new_receipt

    def _basic_ack(self, receipt: QueueReceipt, queue_name: str) -> None:
        channel = self._channel_for()
        channel.queue_declare(queue=queue_name, durable=True)
        channel.basic_ack(delivery_tag=int(receipt.receipt_id))

    def close(self) -> None:
        channel = self._channel
        if channel is not None:
            channel.close()
            self._channel = None
        connection = self._connection
        if connection is not None:
            connection.close()
            self._connection = None
