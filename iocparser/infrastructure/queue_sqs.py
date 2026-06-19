from __future__ import annotations

import json
import threading
from typing import NotRequired, Protocol, TypedDict, cast
from uuid import uuid4

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.infrastructure.queue_records import (
    build_invalid_payload_record,
    import_optional_backend_module,
    materialize_queue_envelope,
    load_queue_record,
    serialize_queue_record,
)


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
    return cast("_Boto3Module", import_optional_backend_module("boto3", backend="sqs"))


MISSING_DEAD_LETTER_QUEUE_ERROR = (
    "SQS dead-letter queue URL not configured; refusing to re-enqueue to the main "
    "queue which would cause an infinite processing loop. Set dead_letter_queue_url."
)


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

    def _send_envelope(self, *, queue_url: str, envelope: QueueEnvelope) -> str:
        envelope = materialize_queue_envelope(envelope)
        response = self.client.send_message(
            QueueUrl=queue_url,
            MessageBody=serialize_queue_record(envelope),
            MessageAttributes={
                "job_id": {
                    "StringValue": str(envelope.request.job_id or uuid4()),
                    "DataType": "String",
                },
            },
        )
        return str(response["MessageId"])

    def enqueue(self, *, queue_name: str, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            resolved_url = self._resolve_queue_url(queue_name)
            message_id = self._send_envelope(queue_url=resolved_url, envelope=envelope)
            return QueueReceipt("sqs", queue_name, message_id, message_id)

    def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope] | None:
        # boto3 clients are thread-safe, so the blocking long poll must NOT run
        # under self._lock: holding it would stall ack/enqueue/requeue on every
        # other worker thread for up to WaitTimeSeconds and could delay a
        # completed job's ack past the SQS visibility timeout, causing the
        # already-processed message to be redelivered and reprocessed.
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
        body = message.get("Body", "")
        payload = body if isinstance(body, str) else ""
        try:
            envelope = QueueEnvelope.from_record(load_queue_record(payload))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            self._quarantine_invalid_payload(receipt, payload=payload, error=exc)
            return None
        return receipt, envelope

    def ack(self, receipt: QueueReceipt) -> None:
        with self._lock:
            resolved_url = self._resolve_queue_url(receipt.queue_name)
            self.client.delete_message(QueueUrl=resolved_url, ReceiptHandle=receipt.receipt_id)

    def requeue(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            envelope = materialize_queue_envelope(envelope)
            resolved_url = self._resolve_queue_url(receipt.queue_name)
            message_id = self._send_envelope(queue_url=resolved_url, envelope=envelope)
            self.client.delete_message(QueueUrl=resolved_url, ReceiptHandle=receipt.receipt_id)
            return QueueReceipt("sqs", receipt.queue_name, message_id, message_id)

    def close(self) -> None:
        with self._lock:
            self.client = None  # type: ignore[assignment]

    def _quarantine_invalid_payload(
        self, receipt: QueueReceipt, *, payload: str, error: Exception
    ) -> None:
        if self.dead_letter_queue_url:
            self.client.send_message(
                QueueUrl=self.dead_letter_queue_url,
                MessageBody=build_invalid_payload_record(
                    payload=payload,
                    queue_name=receipt.queue_name,
                    message_id=receipt.message_id,
                    error=error,
                ),
            )
        resolved_url = self._resolve_queue_url(receipt.queue_name)
        self.client.delete_message(QueueUrl=resolved_url, ReceiptHandle=receipt.receipt_id)
        if self.dead_letter_queue_url:
            self._queue_urls[f"{receipt.queue_name}.dead"] = self.dead_letter_queue_url

    def dead_letter(self, receipt: QueueReceipt, *, envelope: QueueEnvelope) -> QueueReceipt:
        with self._lock:
            if not self.dead_letter_queue_url:
                raise RuntimeError(MISSING_DEAD_LETTER_QUEUE_ERROR)
            envelope = materialize_queue_envelope(envelope)
            target_queue = self.dead_letter_queue_url
            dead_queue_name = f"{receipt.queue_name}.dead"
            response = self.client.send_message(
                QueueUrl=target_queue,
                MessageBody=serialize_queue_record(envelope),
            )
            message_id = str(response["MessageId"])
            resolved_url = self._resolve_queue_url(receipt.queue_name)
            self.client.delete_message(QueueUrl=resolved_url, ReceiptHandle=receipt.receipt_id)
            self._queue_urls[dead_queue_name] = target_queue
            return QueueReceipt("sqs", dead_queue_name, message_id, message_id)
