"""Error-path coverage for the RabbitMQ queue adapter.

These exercise the exception handlers (reset-and-raise, KeyboardInterrupt
re-raise, the receipt-less decode failure, the dead-letter quarantine path, and
the double-close error note) with an in-memory fake pika channel that can be told
to raise on a chosen operation. No real broker is involved.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.infrastructure.queue_records import materialize_queue_envelope


@contextmanager
def _installed_pika(module: object) -> Iterator[None]:
    previous = sys.modules.get("pika")
    sys.modules["pika"] = module
    try:
        yield
    finally:
        if previous is None:
            sys.modules.pop("pika", None)
        else:
            sys.modules["pika"] = previous


def _envelope() -> QueueEnvelope:
    return materialize_queue_envelope(
        QueueEnvelope(
            request=PipelineJobRequest(input_kind="text", source_value="x", job_id=str(uuid4())),
            queue_backend="rabbitmq",
            queue_name="jobs",
            attempts=0,
            max_attempts=2,
            idempotency_key=None,
        )
    )


class _FakeChannel:
    def __init__(self, *, fail_on: str = "", exc: BaseException | None = None, body: bytes = b""):
        self.fail_on = fail_on
        self.exc = exc or RuntimeError("boom")
        self.body = body
        self.acked: list[int] = []
        self.closed = False

    def _maybe_fail(self, op: str) -> None:
        if self.fail_on == op:
            raise self.exc

    def queue_declare(self, *, queue: str, durable: bool) -> None:
        del queue, durable
        self._maybe_fail("queue_declare")

    def basic_publish(
        self, *, exchange: str, routing_key: str, body: bytes, properties: object
    ) -> None:
        del exchange, routing_key, body, properties
        self._maybe_fail("basic_publish")

    def basic_get(self, *, queue: str, auto_ack: bool):  # type: ignore[no-untyped-def]
        del queue, auto_ack
        self._maybe_fail("basic_get")
        props = SimpleNamespace(message_id="m1")
        return SimpleNamespace(delivery_tag=1), props, self.body

    def basic_ack(self, *, delivery_tag: int) -> None:
        self._maybe_fail("basic_ack")
        self.acked.append(delivery_tag)

    def close(self) -> None:
        self._maybe_fail("close")
        self.closed = True


class _FakeConnection:
    def __init__(self, channel: _FakeChannel, *, fail_close: BaseException | None = None) -> None:
        self._channel = channel
        self._fail_close = fail_close

    def channel(self) -> _FakeChannel:
        return self._channel

    def close(self) -> None:
        if self._fail_close is not None:
            raise self._fail_close


class _FakePika:
    def __init__(self, channel: _FakeChannel, *, fail_close: BaseException | None = None) -> None:
        self._channel = channel
        self._fail_close = fail_close

    class URLParameters:
        def __init__(self, url: str) -> None:
            self.url = url

    class BasicProperties:
        def __init__(self, *, delivery_mode: int, message_id: str) -> None:
            self.delivery_mode = delivery_mode
            self.message_id = message_id

    def BlockingConnection(self, params: object) -> _FakeConnection:  # noqa: N802
        del params
        return _FakeConnection(self._channel, fail_close=self._fail_close)


def _adapter(channel: _FakeChannel, *, fail_close: BaseException | None = None):  # type: ignore[no-untyped-def]
    from iocparser.infrastructure.queue_rabbitmq import RabbitMQQueueAdapter

    with _installed_pika(_FakePika(channel, fail_close=fail_close)):
        return RabbitMQQueueAdapter("amqp://localhost")


def _receipt() -> QueueReceipt:
    return QueueReceipt("rabbitmq", "jobs", "1", "m1")


@pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyboardInterrupt()])
def test_enqueue_resets_or_reraises_on_failure(exc: BaseException) -> None:
    channel = _FakeChannel(fail_on="basic_publish", exc=exc)
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(type(exc)):
        adapter.enqueue(queue_name="jobs", envelope=_envelope())


@pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyboardInterrupt()])
def test_dequeue_resets_or_reraises_on_failure(exc: BaseException) -> None:
    channel = _FakeChannel(fail_on="basic_get", exc=exc)
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(type(exc)):
        adapter.dequeue(queue_name="jobs")


def test_dequeue_resets_when_decode_fails_before_receipt() -> None:
    # message_id access raises ValueError while the receipt is still None, so the
    # decode-except branch takes the reset-and-raise path (receipt is None).
    class _BadProps:
        @property
        def message_id(self) -> str:
            raise ValueError("bad props")

    class _BadChannel(_FakeChannel):
        def basic_get(self, *, queue: str, auto_ack: bool):  # type: ignore[no-untyped-def]
            del queue, auto_ack
            return SimpleNamespace(delivery_tag=1), _BadProps(), b"{}"

    channel = _BadChannel()
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(ValueError, match="bad props"):
        adapter.dequeue(queue_name="jobs")


def test_dequeue_quarantines_undecodable_payload() -> None:
    channel = _FakeChannel(body=b"not-json")
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)):
        assert adapter.dequeue(queue_name="jobs") is None
    # The bad message was acked off the main queue after publishing to the dead queue.
    assert channel.acked == [1]


def test_quarantine_reraises_on_publish_failure() -> None:
    class _QuarantineChannel(_FakeChannel):
        def basic_publish(self, *, exchange, routing_key, body, properties):  # type: ignore[no-untyped-def]
            raise RuntimeError("dead-letter publish failed")

    channel = _QuarantineChannel(body=b"not-json")
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(RuntimeError):
        adapter.dequeue(queue_name="jobs")


@pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyboardInterrupt()])
def test_ack_resets_or_reraises_on_failure(exc: BaseException) -> None:
    channel = _FakeChannel(fail_on="basic_ack", exc=exc)
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(type(exc)):
        adapter.ack(_receipt())


@pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyboardInterrupt()])
def test_requeue_resets_or_reraises_on_failure(exc: BaseException) -> None:
    channel = _FakeChannel(fail_on="basic_publish", exc=exc)
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(type(exc)):
        adapter.requeue(_receipt(), envelope=_envelope())


@pytest.mark.parametrize("exc", [RuntimeError("boom"), KeyboardInterrupt()])
def test_dead_letter_resets_or_reraises_on_failure(exc: BaseException) -> None:
    channel = _FakeChannel(fail_on="basic_publish", exc=exc)
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(type(exc)):
        adapter.dead_letter(_receipt(), envelope=_envelope())


def test_quarantine_reraises_keyboard_interrupt() -> None:
    class _QuarantineChannel(_FakeChannel):
        def basic_publish(self, *, exchange, routing_key, body, properties):  # type: ignore[no-untyped-def]
            raise KeyboardInterrupt

    channel = _QuarantineChannel(body=b"not-json")
    adapter = _adapter(channel)
    with _installed_pika(_FakePika(channel)), pytest.raises(KeyboardInterrupt):
        adapter.dequeue(queue_name="jobs")


def test_close_reraises_connection_error_when_channel_closes_cleanly() -> None:
    # Only the connection.close() fails, so close_error is set from that branch
    # (channel.close() succeeded, leaving close_error None until then).
    channel = _FakeChannel()
    adapter = _adapter(channel, fail_close=RuntimeError("connection close failed"))
    with _installed_pika(_FakePika(channel, fail_close=RuntimeError("connection close failed"))):
        adapter.enqueue(queue_name="jobs", envelope=_envelope())
        with pytest.raises(RuntimeError, match="connection close failed"):
            adapter.close()
    assert channel.closed is True


def test_close_aggregates_channel_and_connection_errors() -> None:
    channel = _FakeChannel(fail_on="close", exc=RuntimeError("channel close failed"))
    adapter = _adapter(channel, fail_close=RuntimeError("connection close failed"))
    # Open a connection/channel so close() has something to close.
    with _installed_pika(_FakePika(channel, fail_close=RuntimeError("connection close failed"))):
        adapter.enqueue(queue_name="jobs", envelope=_envelope())
        with pytest.raises(RuntimeError, match="channel close failed") as excinfo:
            adapter.close()
    assert any("connection.close() also failed" in note for note in excinfo.value.__notes__)
