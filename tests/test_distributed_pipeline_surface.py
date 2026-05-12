from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError

from iocparser.api_persistence import get_distributed_job, list_dead_letters, list_distributed_jobs
from iocparser.client import PersistenceClient
from iocparser.distributed_pipeline import DistributedPipelineService
from iocparser.domain.models import (
    JOB_STATUS_DEAD_LETTERED,
    JOB_STATUS_QUEUED,
    DeadLetterRecord,
    DistributedJobRecord,
    QueueEnvelope,
    TelemetryEvent,
)
from iocparser.domain.pipeline import PipelineErrorInfo, PipelineJobRequest
from iocparser.errors import IOCTimeoutError
from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService
from iocparser.infrastructure.persistence_schema import SQLAlchemyUnitOfWork
from iocparser.infrastructure.queue_celery import CeleryQueueAdapter, build_celery_task_payload
from iocparser.infrastructure.queue_factory import create_queue_adapter
from iocparser.infrastructure.queue_filesystem import FilesystemQueueAdapter
from iocparser.infrastructure.queue_rabbitmq import RabbitMQQueueAdapter
from iocparser.infrastructure.queue_sqs import SQSQueueAdapter
from iocparser.infrastructure.runtime.telemetry import LoggingTelemetrySink, NoOpTelemetrySink
from iocparser.pipeline_client import DistributedPipelineClient
from iocparser.pipeline_worker import PipelineWorker


class TimeoutClient:
    downloader = SimpleNamespace(download=lambda value: value)

    def extract_result_from_text(self, text_content: str, **kwargs: object):  # type: ignore[no-untyped-def]
        del text_content, kwargs
        raise IOCTimeoutError("Distributed pipeline", "retryable-input")


@contextmanager
def installed_module(name: str, module: object):
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        yield
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


def _envelope(
    job_id: str | None = None, *, attempts: int = 0, idempotency_key: str | None = None
) -> QueueEnvelope:
    return QueueEnvelope(
        request=PipelineJobRequest(
            input_kind="text",
            source_value="indicator text",
            persist=False,
            job_id=job_id or str(uuid4()),
            correlation_id="corr-1",
        ),
        queue_backend="filesystem",
        queue_name="jobs",
        attempts=attempts,
        max_attempts=2,
        idempotency_key=idempotency_key,
    )


def test_domain_distributed_records_and_telemetry_sinks() -> None:
    envelope = _envelope("job-1", idempotency_key="idem-1")
    restored = QueueEnvelope.from_record(envelope.to_record())
    assert restored.request.job_id == "job-1"
    assert QueueEnvelope.from_record({"request": "bad-payload"}).request.input_kind == ""

    job = DistributedJobRecord(
        job_id="job-1",
        correlation_id="corr-1",
        queue_backend="filesystem",
        queue_name="jobs",
        input_kind="text",
        source_value="src",
        status=JOB_STATUS_QUEUED,
        attempts=0,
        max_attempts=2,
    )
    dead = DeadLetterRecord(
        job_id="job-1",
        correlation_id="corr-1",
        queue_backend="filesystem",
        queue_name="jobs",
        source_value="src",
        attempts=2,
        max_attempts=2,
        error=PipelineErrorInfo(
            code="INPUT_TIMEOUT",
            category="timeout",
            retryable=True,
            status="failed",
            message="timeout",
        ),
        dead_lettered_at="2026-01-01T00:00:00+00:00",
    )
    assert job.to_record()["schema_version"] == "1.0"
    assert dead.to_record()["schema_version"] == "1.0"

    event = TelemetryEvent(
        name="job_started",
        job_id="job-1",
        correlation_id="corr-1",
        queue_backend="filesystem",
        queue_name="jobs",
        attributes={"attempt": 1},
    )
    NoOpTelemetrySink().emit(event)
    LoggingTelemetrySink().emit(event)


def test_queue_envelope_from_record_parses_bool_compatible_values() -> None:
    payload = _envelope("job-bool").to_record()
    request_payload = payload["request"]
    assert isinstance(request_payload, dict)
    request_payload.update(
        {
            "persist": "false",
            "check_warnings": "0",
            "force_update": "yes",
            "defang": 0,
            "emit_only": 1,
        }
    )

    restored = QueueEnvelope.from_record(payload)

    assert restored.request.persist is False
    assert restored.request.check_warnings is False
    assert restored.request.force_update is True
    assert restored.request.defang is False
    assert restored.request.emit_only is True


def test_filesystem_queue_empty_and_race_branch(tmp_path: Path) -> None:
    adapter = FilesystemQueueAdapter(tmp_path / "queue")
    assert adapter.dequeue(queue_name="empty") is None

    receipt = adapter.enqueue(queue_name="race", envelope=_envelope("race-job"))
    original_rename = Path.rename

    def flaky_rename(path_obj: Path, target: Path) -> Path:
        if path_obj.name in Path(receipt.receipt_id).name:
            path_obj.unlink(missing_ok=True)
            raise FileNotFoundError
        return original_rename(path_obj, target)

    Path.rename = flaky_rename  # type: ignore[assignment]
    try:
        assert adapter.dequeue(queue_name="race") is None
    finally:
        Path.rename = original_rename  # type: ignore[assignment]


def test_distributed_pipeline_without_database_covers_empty_and_retry_paths(tmp_path: Path) -> None:
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    service = DistributedPipelineService(queue_adapter=queue)
    request = PipelineJobRequest(
        input_kind="text", source_value="ioc", persist=False, check_warnings=False
    )

    queued = service.submit(request, queue_name="volatile")
    assert queued["queue_backend"] == "filesystem"
    processed = service.process_next(queue_name="volatile")
    assert processed is not None
    assert service.process_next(queue_name="volatile") is None
    assert service.drain(queue_name="volatile", limit=5) == []
    assert service.get_job(job_id="missing") is None
    assert service.list_jobs(limit=5) == []
    assert service.list_dead_letters(limit=5) == []

    retry_service = DistributedPipelineService(
        queue_adapter=FilesystemQueueAdapter(tmp_path / "retry"),
        worker=PipelineWorker(client=TimeoutClient()),
    )
    retry_service.submit(request, queue_name="retry", max_attempts=2)
    first_retry = retry_service.process_next(queue_name="retry")
    assert first_retry is not None
    assert first_retry.status == "failed"
    second_retry = retry_service.process_next(queue_name="retry")
    assert second_retry is not None
    assert second_retry.status == "failed"


def test_distributed_pipeline_file_and_url_idempotency_keys(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.txt"
    file_path.write_text("same bytes", encoding="utf-8")
    service = DistributedPipelineService(queue_adapter=FilesystemQueueAdapter(tmp_path / "queue"))
    file_request = PipelineJobRequest(input_kind="file", source_value=str(file_path), persist=False)
    url_request = PipelineJobRequest(
        input_kind="url", source_value="https://example.invalid/path", persist=False
    )
    assert len(service._idempotency_key(file_request)) == 64
    assert len(service._idempotency_key(url_request)) == 64


def test_persistence_service_and_public_distributed_wrappers(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'distributed.sqlite'}"
    service = SQLAlchemyDistributedJobService(db_uri)
    first = service.create_or_get_job(
        envelope=_envelope("job-1", idempotency_key="idem-1"), receipt_id="r1"
    )
    updated = service.create_or_get_job(
        envelope=_envelope("job-1", idempotency_key="idem-1"), receipt_id="r2"
    )
    assert first.job_id == updated.job_id
    assert updated.receipt_id == "r2"

    duplicate = service.create_or_get_job(
        envelope=_envelope("job-2", idempotency_key="idem-1"), receipt_id="r3"
    )
    assert duplicate.job_id == "job-1"
    assert service.mark_running(job_id="missing", attempts=1, receipt_id="x") is None

    running = service.mark_running(job_id="job-1", attempts=1, receipt_id="r2")
    assert running is not None
    assert running.status == "running"
    failed = service.mark_failed(
        job_id="job-1",
        attempts=1,
        error=PipelineErrorInfo(
            code="INPUT_TIMEOUT",
            category="timeout",
            retryable=True,
            status="failed",
            message="timeout",
        ),
        will_retry=False,
        metrics={"extract": 1},
    )
    assert failed is not None
    assert failed.status == "failed"
    assert (
        service.mark_dead_lettered(
            job_id="job-1",
            attempts=2,
            error=PipelineErrorInfo(
                code="INPUT_TIMEOUT",
                category="timeout",
                retryable=True,
                status="failed",
                message="timeout",
            ),
        ).status
        == JOB_STATUS_DEAD_LETTERED
    )
    assert (
        service.mark_dead_lettered(
            job_id="missing",
            attempts=1,
            error=PipelineErrorInfo(
                code="INPUT_TIMEOUT",
                category="timeout",
                retryable=True,
                status="failed",
                message="timeout",
            ),
        )
        is None
    )

    assert (
        len(
            service.list_jobs(
                limit=10, statuses=(JOB_STATUS_DEAD_LETTERED,), queue_backend="filesystem"
            )
        )
        == 1
    )
    assert len(service.list_dead_letters(limit=10, queue_backend="filesystem")) == 1

    client = PersistenceClient(db_uri)
    assert client.get_distributed_job(job_id="job-1").status == JOB_STATUS_DEAD_LETTERED
    assert len(client.list_distributed_jobs(limit=10, statuses=(JOB_STATUS_DEAD_LETTERED,))) == 1
    assert len(client.list_dead_letters(limit=10, queue_backend="filesystem")) == 1

    assert get_distributed_job(db_uri=db_uri, job_id="job-1").status == JOB_STATUS_DEAD_LETTERED
    assert (
        len(list_distributed_jobs(db_uri=db_uri, limit=10, statuses=(JOB_STATUS_DEAD_LETTERED,)))
        == 1
    )
    assert len(list_dead_letters(db_uri=db_uri, limit=10, queue_backend="filesystem")) == 1


def test_commit_new_job_or_fetch_handles_integrity_error(tmp_path: Path) -> None:
    from iocparser.infrastructure.persistence_distributed_support import (
        build_new_job,
        commit_new_job_or_fetch,
    )

    db_uri = f"sqlite:///{tmp_path / 'race.sqlite'}"
    unit = SQLAlchemyUnitOfWork(db_uri)
    envelope = _envelope("job-race")
    model = build_new_job(envelope=envelope, receipt_id="r1")

    # First, create the job normally so it exists in the DB
    unit.session.add(model)
    unit.commit()
    unit.close()

    # Now start a new unit of work and simulate a race:
    # the initial query returns None (stale read), but commit fails
    # because another transaction inserted the row.
    unit2 = SQLAlchemyUnitOfWork(db_uri)
    model2 = build_new_job(envelope=envelope, receipt_id="r2")

    call_count = [0]
    original_commit = SQLAlchemyUnitOfWork.commit

    def racing_commit(self):
        call_count[0] += 1
        if call_count[0] == 1:
            raise IntegrityError("duplicate", "", "")
        original_commit(self)

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(SQLAlchemyUnitOfWork, "commit", racing_commit)
        result = commit_new_job_or_fetch(unit2, model2, "job-race")
        assert result.job_id == "job-race"
        assert result.receipt_id == "r1"
    unit2.close()

    # Cover the defensive re-raise when IntegrityError happens but no row is found
    unit3 = SQLAlchemyUnitOfWork(db_uri)
    model3 = build_new_job(envelope=_envelope("job-race-3"), receipt_id="r3")

    def fake_execute(_self, _stmt):
        class _Result:
            def scalar_one_or_none(self):
                return None

        return _Result()

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(
            SQLAlchemyUnitOfWork,
            "commit",
            lambda self: (_ for _ in ()).throw(IntegrityError("dup", "", "")),
        )
        mp.setattr(type(unit3.session), "execute", fake_execute)
        with pytest.raises(IntegrityError):
            commit_new_job_or_fetch(unit3, model3, "job-race-3")
    unit3.close()


def test_get_distributed_job_rejects_ambiguous_public_job_id(tmp_path: Path) -> None:
    first_source_db_uri = f"sqlite:///{tmp_path / 'distributed-history-first.sqlite'}"
    second_source_db_uri = f"sqlite:///{tmp_path / 'distributed-history-second.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'distributed-history-target.sqlite'}"

    for db_uri in (first_source_db_uri, second_source_db_uri):
        service = SQLAlchemyDistributedJobService(db_uri)
        service.create_or_get_job(envelope=_envelope("job-1"), receipt_id="r1")

    target_client = PersistenceClient(target_db_uri)
    target_client.import_history(PersistenceClient(first_source_db_uri).export_history())
    target_client.import_history(PersistenceClient(second_source_db_uri).export_history())

    jobs = list_distributed_jobs(db_uri=target_db_uri, limit=10)
    assert [job.job_id for job in jobs] == ["job-1", "job-1"]

    with pytest.raises(ValueError, match="ambiguous distributed job id"):
        get_distributed_job(db_uri=target_db_uri, job_id="job-1")


def test_get_distributed_job_prefers_exact_live_job_over_imported_history(tmp_path: Path) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'distributed-live-history-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'distributed-live-history-target.sqlite'}"

    source_service = SQLAlchemyDistributedJobService(source_db_uri)
    source_service.create_or_get_job(envelope=_envelope("job-1"), receipt_id="r1")

    target_client = PersistenceClient(target_db_uri)
    target_client.import_history(PersistenceClient(source_db_uri).export_history())

    live_service = SQLAlchemyDistributedJobService(target_db_uri)
    live = live_service.create_or_get_job(envelope=_envelope("job-1"), receipt_id="r2")

    loaded = get_distributed_job(db_uri=target_db_uri, job_id="job-1")
    assert loaded is not None
    assert loaded.receipt_id == "r2"
    assert loaded.submitted_at == live.submitted_at


def test_imported_history_does_not_satisfy_live_idempotency_lookup(tmp_path: Path) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'distributed-idem-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'distributed-idem-target.sqlite'}"

    source_service = SQLAlchemyDistributedJobService(source_db_uri)
    source_service.create_or_get_job(
        envelope=_envelope("job-1", idempotency_key="idem-1"), receipt_id="r1"
    )

    target_client = PersistenceClient(target_db_uri)
    target_client.import_history(PersistenceClient(source_db_uri).export_history())

    target_service = SQLAlchemyDistributedJobService(target_db_uri)
    created = target_service.create_or_get_job(
        envelope=_envelope("job-2", idempotency_key="idem-1"), receipt_id="r2"
    )

    assert created.job_id == "job-2"
    jobs = list_distributed_jobs(db_uri=target_db_uri, limit=10)
    assert sorted(job.job_id for job in jobs) == ["job-1", "job-2"]


def test_distributed_pipeline_client_lists_and_drains(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'client.sqlite'}"
    client = DistributedPipelineClient(db_uri=db_uri, queue_path=str(tmp_path / "queue"))
    job = client.submit(
        PipelineJobRequest(
            input_kind="text",
            source_value="client drain",
            persist=True,
            db_uri=db_uri,
            check_warnings=False,
        ),
        queue_name="ingest",
    )
    drained = client.drain(queue_name="ingest", limit=5)
    assert len(drained) == 1
    assert client.get_job(job_id=job.job_id).status == "completed"
    assert len(client.list_jobs(limit=10, statuses=("completed",))) == 1
    assert client.list_dead_letters(limit=10) == []


def test_queue_factory_and_optional_queue_adapters() -> None:
    class FakeRabbitChannel:
        def __init__(self) -> None:
            self.queues: dict[str, list[tuple[object, bytes]]] = {}
            self.acked: list[int] = []

        def queue_declare(self, *, queue: str, durable: bool) -> None:
            del durable
            self.queues.setdefault(queue, [])

        def basic_publish(
            self, *, exchange: str, routing_key: str, body: bytes, properties: object
        ) -> None:
            del exchange
            self.queues.setdefault(routing_key, []).append((properties, body))

        def basic_get(self, *, queue: str, auto_ack: bool):
            del auto_ack
            items = self.queues.get(queue, [])
            if not items:
                return None, None, None
            props, body = items.pop(0)
            return SimpleNamespace(delivery_tag=1), props, body

        def basic_ack(self, *, delivery_tag: int) -> None:
            self.acked.append(delivery_tag)

        def close(self) -> None:
            return None

    class FakeRabbitConnection:
        def __init__(self, params: object) -> None:
            self.params = params
            self.channel_obj = FakeRabbitChannel()

        def channel(self) -> FakeRabbitChannel:
            return self.channel_obj

        def close(self) -> None:
            return None

    class FakePika:
        class URLParameters:
            def __init__(self, url: str) -> None:
                self.url = url

        class BasicProperties:
            def __init__(self, *, delivery_mode: int, message_id: str) -> None:
                self.delivery_mode = delivery_mode
                self.message_id = message_id

        @staticmethod
        def BlockingConnection(params: object) -> FakeRabbitConnection:
            return FakeRabbitConnection(params)

    class FakeSQSClient:
        def __init__(self) -> None:
            self.queues: dict[str, list[dict[str, str]]] = {}

        def send_message(
            self,
            *,
            QueueUrl: str,
            MessageBody: str,
            MessageAttributes: dict[str, object] | None = None,
        ):
            receipt = f"rh-{len(self.queues.setdefault(QueueUrl, [])) + 1}"
            message = {"Body": MessageBody, "ReceiptHandle": receipt, "MessageId": f"msg-{receipt}"}
            self.queues[QueueUrl].append(message)
            return {"MessageId": message["MessageId"]}

        def receive_message(
            self,
            *,
            QueueUrl: str,
            MaxNumberOfMessages: int,
            WaitTimeSeconds: int,
            MessageAttributeNames: list[str],
        ):
            del MaxNumberOfMessages, WaitTimeSeconds, MessageAttributeNames
            items = self.queues.get(QueueUrl, [])
            return {"Messages": items[:1]} if items else {}

        def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
            self.queues[QueueUrl] = [
                item
                for item in self.queues.get(QueueUrl, [])
                if item["ReceiptHandle"] != ReceiptHandle
            ]

    class FakeBoto3:
        def __init__(self) -> None:
            self.client_obj = FakeSQSClient()

        def client(self, service_name: str) -> FakeSQSClient:
            assert service_name == "sqs"
            return self.client_obj

    class FakeAsyncResult:
        def __init__(self, task_id: str) -> None:
            self.id = task_id

    class FakeCeleryApp:
        def send_task(
            self, task_name: str, *, args: list[object], queue: str, task_id: str
        ) -> FakeAsyncResult:
            del task_name, args, queue
            return FakeAsyncResult(task_id)

    class FakeCeleryModule:
        class Celery:
            def __init__(self, name: str, broker: str) -> None:
                del name, broker
                self.app = FakeCeleryApp()

            def send_task(self, *args: object, **kwargs: object) -> FakeAsyncResult:
                return self.app.send_task(*args, **kwargs)

    envelope = _envelope("queue-job")
    with installed_module("pika", FakePika()):
        rabbit = create_queue_adapter("rabbitmq", queue_url="amqp://guest:guest@localhost")
        assert isinstance(rabbit, RabbitMQQueueAdapter)
        assert rabbit.dequeue(queue_name="jobs") is None
        receipt = rabbit.enqueue(queue_name="jobs", envelope=envelope)
        dequeued = rabbit.dequeue(queue_name="jobs")
        assert dequeued is not None
        rabbit.ack(dequeued[0])
        rabbit.requeue(dequeued[0], envelope=envelope)
        requeued_item = rabbit.dequeue(queue_name="jobs")
        assert requeued_item is not None
        rabbit.dead_letter(requeued_item[0], envelope=envelope)
        rabbit.close()

    with installed_module("boto3", FakeBoto3()):
        sqs = create_queue_adapter(
            "sqs",
            queue_url="https://sqs.example/jobs",
            dead_letter_queue_url="https://sqs.example/jobs-dead",
        )
        assert isinstance(sqs, SQSQueueAdapter)
        assert sqs.dequeue(queue_name="ignored") is None
        receipt = sqs.enqueue(queue_name="ignored", envelope=envelope)
        item = sqs.dequeue(queue_name="ignored")
        assert item is not None
        sqs.ack(item[0])
        sqs.requeue(receipt, envelope=envelope)
        sqs.dead_letter(receipt, envelope=envelope)

    with installed_module("celery", FakeCeleryModule()):
        celery = create_queue_adapter("celery", queue_url="redis://localhost/0")
        assert isinstance(celery, CeleryQueueAdapter)
        receipt = celery.enqueue(queue_name="jobs", envelope=envelope)
        assert receipt.queue_backend == "celery"
        assert celery.dequeue(queue_name="jobs") is None
        celery.ack(receipt)
        celery.requeue(receipt, envelope=envelope)
        celery.dead_letter(receipt, envelope=envelope)
        assert json.loads(build_celery_task_payload(envelope))["queue_name"] == "jobs"

    with pytest.raises(ValueError, match="requires queue_url"):
        create_queue_adapter("rabbitmq")
    with pytest.raises(ValueError, match="Unsupported queue backend"):
        create_queue_adapter("unsupported")
