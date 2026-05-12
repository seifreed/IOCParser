from __future__ import annotations

import json
import threading
from importlib import import_module
from typing import NotRequired, Protocol, TypedDict, cast
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt


class _SQSMessageAttribute(TypedDict):
    StringValue: str
    DataType: str


class _SQSSendMessageResponse(TypedDict):
    MessageId: str


class _SQSReceivedMessage(TypedDict):
    ReceiptHandle: str
    Body: str
    MessageId: NotRequired[str]


class _SQSReceiveMessageResponse(TypedDict):
    Messages: NotRequired[list[_SQSReceivedMessage]]


class _SQSClient(Protocol):
    def send_message(self, **kwargs: object) -> _SQSSendMessageResponse: ...

    def receive_message(self, **kwargs: object) -> _SQSReceiveMessageResponse: ...

    def delete_message(self, **kwargs: object) -> object: ...


class _Boto3Module(Protocol):
    def client(self, service_name: str) -> _SQSClient: ...


def _boto3_module() -> _Boto3Module:
    return cast("_Boto3Module", import_module("boto3"))


def _load_queue_record(payload: str) -> dict[str, object]:
    decoded = cast("object", json.loads(payload))
    if not isinstance(decoded, dict):
        raise _queue_payload_type_error()
    return cast("dict[str, object]", decoded)


def _queue_payload_type_error() -> TypeError:
    return TypeError("Queue payload must be a JSON object")


class SQSQueueAdapter:
    """AWS SQS adapter using boto3 when installed."""

    def __init__(
        self,
        queue_url: str,
        *,
        dead_letter_queue_url: str | None = None,
        queue_urls: dict[str, str] | None = None,
    ) -> None:
        self.queue_url = queue_url
        self.dead_letter_queue_url = dead_letter_queue_url
        self._queue_urls: dict[str, str] = dict(queue_urls or {})
        self.client: _SQSClient = _boto3_module().client("sqs")
        self._lock = threading.Lock()

    def _resolve_queue_url(self, queue_name: str) -> str:
        return self._queue_urls.get(queue_name, self.queue_url)

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            resolved_url = self._resolve_queue_url(queue_name)
            response = self.client.send_message(
                QueueUrl=resolved_url,
                MessageBody=json.dumps(envelope.to_record(), sort_keys=True),
                MessageAttributes={
                    "job_id": {
                        "StringValue": str(envelope.request.job_id or uuid4()),
                        "DataType": "String",
                    },
                },
            )
            message_id = str(response["MessageId"])
            return QueueReceipt("sqs", queue_name, message_id, message_id)

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        with self._lock:
            resolved_url = self._resolve_queue_url(queue_name)
            response = self.client.receive_message(
                QueueUrl=resolved_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
                MessageAttributeNames=["All"],
            )
            messages = response.get("Messages", [])
            if not messages:
                return None
            message = messages[0]
            receipt = QueueReceipt(
                "sqs",
                queue_name,
                message["ReceiptHandle"],
                str(message.get("MessageId", uuid4())),
            )
            return receipt, QueueEnvelope.from_record(_load_queue_record(message["Body"]))

    def ack(self, receipt: QueueReceipt) -> None:
        with self._lock:
            resolved_url = self._resolve_queue_url(receipt.queue_name)
            self.client.delete_message(QueueUrl=resolved_url, ReceiptHandle=receipt.receipt_id)

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            resolved_url = self._resolve_queue_url(receipt.queue_name)
            response = self.client.send_message(
                QueueUrl=resolved_url,
                MessageBody=json.dumps(envelope.to_record(), sort_keys=True),
                MessageAttributes={
                    "job_id": {
                        "StringValue": str(envelope.request.job_id or uuid4()),
                        "DataType": "String",
                    },
                },
            )
            message_id = str(response["MessageId"])
            self.client.delete_message(QueueUrl=resolved_url, ReceiptHandle=receipt.receipt_id)
            return QueueReceipt("sqs", receipt.queue_name, message_id, message_id)

    def close(self) -> None:
        with self._lock:
            self.client = None  # type: ignore[assignment]

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            if not self.dead_letter_queue_url:
                raise RuntimeError(
                    "SQS dead-letter queue URL not configured; refusing to re-enqueue to the main "
                    "queue which would cause an infinite processing loop. Set dead_letter_queue_url."
                )
            target_queue = self.dead_letter_queue_url
            dead_queue_name = f"{receipt.queue_name}.dead"
            self._queue_urls[dead_queue_name] = target_queue
            response = self.client.send_message(
                QueueUrl=target_queue,
                MessageBody=json.dumps(envelope.to_record(), sort_keys=True),
            )
            message_id = str(response["MessageId"])
            resolved_url = self._resolve_queue_url(receipt.queue_name)
            self.client.delete_message(QueueUrl=resolved_url, ReceiptHandle=receipt.receipt_id)
            return QueueReceipt("sqs", dead_queue_name, message_id, message_id)
