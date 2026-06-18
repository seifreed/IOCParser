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
    QueueReceipt,
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


def test_queue_envelope_from_record_rejects_bool_integer_fields() -> None:
    payload = _envelope("job-int").to_record()
    payload["attempts"] = True

    with pytest.raises(TypeError, match="attempts"):
        QueueEnvelope.from_record(payload)


def test_queue_envelope_rejects_invalid_retry_counters() -> None:
    negative_attempts = _envelope("job-negative-attempts").to_record()
    negative_attempts["attempts"] = "-1"

    with pytest.raises(ValueError, match="attempts"):
        QueueEnvelope.from_record(negative_attempts)

    zero_max_attempts = _envelope("job-zero-max-attempts").to_record()
    zero_max_attempts["max_attempts"] = 0

    with pytest.raises(ValueError, match="max_attempts"):
        QueueEnvelope.from_record(zero_max_attempts)


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


def test_filesystem_queue_stages_records_invisibly_to_dequeue_glob(tmp_path: Path) -> None:
    # Records must be staged under a name the dequeue/count glob ("*.json") never
    # matches; otherwise a concurrent dequeue can grab a half-staged file mid-write,
    # crashing the rename and leaking the source record in processing/.
    adapter = FilesystemQueueAdapter(tmp_path / "queue")
    staged: list[tuple[str, str]] = []
    original_rename = Path.rename

    def recording_rename(path_obj: Path, target: Path) -> Path:
        target_path = Path(target)
        # Only renames that publish a new record into a glob-scanned directory matter;
        # the dequeue claim (pending -> processing) legitimately moves a real .json file.
        if target_path.parent.name in {"pending", "dead"}:
            staged.append((Path(path_obj).name, target_path.name))
        return original_rename(path_obj, target)

    receipt = adapter.enqueue(queue_name="jobs", envelope=_envelope("stage-job"))
    Path.rename = recording_rename  # type: ignore[assignment]
    try:
        dequeued = adapter.dequeue(queue_name="jobs")
        assert dequeued is not None
        processing_receipt, envelope = dequeued
        adapter.requeue(processing_receipt, envelope=envelope)
        again = adapter.dequeue(queue_name="jobs")
        assert again is not None
        adapter.dead_letter(again[0], envelope=again[1])
    finally:
        Path.rename = original_rename  # type: ignore[assignment]

    assert receipt.message_id == "stage-job"
    json_targets = [(src, dst) for src, dst in staged if dst.endswith(".json")]
    assert json_targets
    for src, dst in json_targets:
        assert not src.endswith(".json"), f"staging file {src} renamed to {dst} is glob-visible"


def test_filesystem_queue_rejects_path_traversal_components(tmp_path: Path) -> None:
    adapter = FilesystemQueueAdapter(tmp_path / "queue")
    envelope = _envelope("../escape-job")

    with pytest.raises(ValueError, match="queue name"):
        adapter.enqueue(queue_name="../escape", envelope=envelope)

    receipt = adapter.enqueue(queue_name="safe", envelope=envelope)
    receipt_path = Path(receipt.receipt_id).resolve()
    pending_dir = (tmp_path / "queue" / "safe" / "pending").resolve()
    assert receipt_path.parent == pending_dir
    assert ".." not in receipt_path.name
    assert adapter.pending_count(queue_name="safe") == 1


def test_filesystem_queue_rejects_external_receipt_paths(tmp_path: Path) -> None:
    adapter = FilesystemQueueAdapter(tmp_path / "queue")
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-delete", encoding="utf-8")
    external = QueueReceipt("filesystem", "safe", str(victim), "victim")

    with pytest.raises(ValueError, match="receipt"):
        adapter.ack(external)

    assert victim.read_text(encoding="utf-8") == "do-not-delete"


def test_filesystem_queue_rejects_pending_receipt_ack(tmp_path: Path) -> None:
    adapter = FilesystemQueueAdapter(tmp_path / "queue")
    pending_receipt = adapter.enqueue(queue_name="safe", envelope=_envelope("pending-job"))

    with pytest.raises(ValueError, match="receipt"):
        adapter.ack(pending_receipt)

    assert Path(pending_receipt.receipt_id).exists()


def test_filesystem_queue_quarantines_invalid_payload_and_continues(tmp_path: Path) -> None:
    adapter = FilesystemQueueAdapter(tmp_path / "queue")
    pending_dir = tmp_path / "queue" / "bad-payload" / "pending"
    pending_dir.mkdir(parents=True)
    invalid_path = pending_dir / "000-invalid.json"
    invalid_path.write_text('{"attempts": -1, "max_attempts": 3}', encoding="utf-8")
    adapter.enqueue(queue_name="bad-payload", envelope=_envelope("valid-job"))

    item = adapter.dequeue(queue_name="bad-payload")

    assert item is not None
    assert item[1].request.job_id == "valid-job"
    assert adapter.dead_count(queue_name="bad-payload") == 1
    adapter.ack(item[0])
    assert not list((tmp_path / "queue" / "bad-payload" / "processing").glob("*.json"))


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


def test_completed_job_clears_prior_attempt_error(tmp_path: Path) -> None:
    """A job that succeeds after a retried failure must not report the old error.

    Regression: apply_transition only ever wrote last_error and never cleared it,
    so mark_completed left the failed attempt's last_error in place and get_job
    reported a successful job as if it had errored.
    """
    db_uri = f"sqlite:///{tmp_path / 'clear-error.sqlite'}"
    service = SQLAlchemyDistributedJobService(db_uri)
    service.create_or_get_job(envelope=_envelope("job-clear"), receipt_id="r1")
    service.mark_running(job_id="job-clear", attempts=1, receipt_id="r1")
    service.mark_failed(
        job_id="job-clear",
        attempts=1,
        error=PipelineErrorInfo(
            code="INPUT_TIMEOUT",
            category="timeout",
            retryable=True,
            status="failed",
            message="timeout",
        ),
        will_retry=True,
        metrics={},
    )
    failed_record = service.get_job(job_id="job-clear")
    assert failed_record is not None
    assert failed_record.last_error is not None

    service.mark_completed(
        job_id="job-clear", attempts=2, run_id=None, result_json={"ok": True}, metrics={}
    )
    completed_record = service.get_job(job_id="job-clear")
    assert completed_record is not None
    assert completed_record.status == "completed"
    assert completed_record.last_error is None


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


def test_get_distributed_job_escapes_imported_history_job_id_wildcards(
    tmp_path: Path,
) -> None:
    source_db_uri = f"sqlite:///{tmp_path / 'distributed-wildcard-history-source.sqlite'}"
    target_db_uri = f"sqlite:///{tmp_path / 'distributed-wildcard-history-target.sqlite'}"

    source_service = SQLAlchemyDistributedJobService(source_db_uri)
    source_service.create_or_get_job(envelope=_envelope("jobA"), receipt_id="r1")

    target_client = PersistenceClient(target_db_uri)
    target_client.import_history(PersistenceClient(source_db_uri).export_history())

    assert get_distributed_job(db_uri=target_db_uri, job_id="job_") is None


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
        dead_receipt = sqs.dead_letter(receipt, envelope=envelope)
        assert dead_receipt.queue_name == "ignored.dead"
        assert sqs._resolve_queue_url(dead_receipt.queue_name) == "https://sqs.example/jobs-dead"
        assert len(sqs.client.queues["https://sqs.example/jobs-dead"]) == 1

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


def test_rabbitmq_adapter_serializes_concurrent_access() -> None:
    """The shared RabbitMQ channel must be accessed by one thread at a time.

    Regression: RabbitMQQueueAdapter shared a single non-thread-safe pika
    channel across worker threads (concurrency > 1) with no lock, so
    basic_get/basic_ack frames could interleave and ack the wrong delivery
    tag. The adapter must serialize channel access.
    """
    import threading
    import time

    class TrackingProperties:
        def __init__(self, *, message_id: str, delivery_mode: int = 2) -> None:
            del delivery_mode
            self.message_id = message_id

    class TrackingChannel:
        def __init__(self) -> None:
            self.active = 0
            self.violations = 0
            self.messages: list[tuple[int, str, bytes]] = []
            self.tag = 0

        def _enter(self) -> None:
            self.active += 1
            if self.active > 1:
                self.violations += 1
            time.sleep(0.001)
            self.active -= 1

        def queue_declare(self, *, queue: str, durable: bool) -> None:
            del queue, durable
            self._enter()

        def basic_publish(
            self, *, exchange: str, routing_key: str, body: bytes, properties: object
        ) -> None:
            del exchange, routing_key
            self._enter()
            self.tag += 1
            self.messages.append((self.tag, properties.message_id, body))

        def basic_get(self, *, queue: str, auto_ack: bool):
            del queue, auto_ack
            self._enter()
            if not self.messages:
                return None, None, None
            tag, message_id, body = self.messages.pop(0)
            return SimpleNamespace(delivery_tag=tag), TrackingProperties(message_id=message_id), body

        def basic_ack(self, *, delivery_tag: int) -> None:
            del delivery_tag
            self._enter()

        def close(self) -> None:
            return None

    channel = TrackingChannel()

    class TrackingConnection:
        def __init__(self, params: object) -> None:
            del params

        def channel(self) -> TrackingChannel:
            return channel

        def close(self) -> None:
            return None

    class TrackingPika:
        class URLParameters:
            def __init__(self, url: str) -> None:
                self.url = url

        BasicProperties = TrackingProperties

        @staticmethod
        def BlockingConnection(params: object) -> TrackingConnection:
            return TrackingConnection(params)

    envelope = _envelope("concurrent-job")
    with installed_module("pika", TrackingPika()):
        adapter = RabbitMQQueueAdapter("amqp://guest:guest@localhost")

        def hammer() -> None:
            for _ in range(20):
                adapter.enqueue(queue_name="jobs", envelope=envelope)
                dequeued = adapter.dequeue(queue_name="jobs")
                if dequeued is not None:
                    adapter.ack(dequeued[0])

        threads = [threading.Thread(target=hammer) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert channel.violations == 0


def test_optional_queue_adapters_quarantine_invalid_payloads() -> None:
    class FakeRabbitChannel:
        def __init__(self) -> None:
            self.queues: dict[str, list[tuple[object, bytes]]] = {
                "jobs": [(SimpleNamespace(message_id="bad-rabbit"), b"[]")]
            }
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
            return SimpleNamespace(delivery_tag=7), props, body

        def basic_ack(self, *, delivery_tag: int) -> None:
            self.acked.append(delivery_tag)

        def close(self) -> None:
            return None

    class FakeRabbitConnection:
        def __init__(self) -> None:
            self.channel_obj = FakeRabbitChannel()

        def channel(self) -> FakeRabbitChannel:
            return self.channel_obj

        def close(self) -> None:
            return None

    class FakePika:
        connection = FakeRabbitConnection()

        class URLParameters:
            def __init__(self, url: str) -> None:
                self.url = url

        class BasicProperties:
            def __init__(self, *, delivery_mode: int, message_id: str) -> None:
                self.delivery_mode = delivery_mode
                self.message_id = message_id

        @staticmethod
        def BlockingConnection(params: object) -> FakeRabbitConnection:
            del params
            return FakePika.connection

    class FakeSQSClient:
        def __init__(self) -> None:
            self.queues: dict[str, list[dict[str, str]]] = {
                "https://sqs.example/jobs": [
                    {"Body": "[]", "ReceiptHandle": "rh-bad", "MessageId": "bad-sqs"},
                    {"ReceiptHandle": "rh-missing-body", "MessageId": "missing-body-sqs"},
                ]
            }

        def send_message(
            self,
            *,
            QueueUrl: str,
            MessageBody: str,
            MessageAttributes: dict[str, object] | None = None,
        ):
            del MessageAttributes
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

    with installed_module("pika", FakePika()):
        rabbit = RabbitMQQueueAdapter("amqp://guest:guest@localhost")
        assert rabbit.dequeue(queue_name="jobs") is None
        channel = FakePika.connection.channel_obj
        assert channel.acked == [7]
        assert len(channel.queues["jobs.dead"]) == 1
        dead_body = json.loads(channel.queues["jobs.dead"][0][1].decode("utf-8"))
        assert dead_body["invalid_payload"] == "[]"

    with installed_module("boto3", FakeBoto3()):
        sqs = SQSQueueAdapter(
            "https://sqs.example/jobs",
            dead_letter_queue_url="https://sqs.example/jobs-dead",
        )
        assert sqs.dequeue(queue_name="ignored") is None
        assert sqs.dequeue(queue_name="ignored") is None
        assert sqs.client.queues["https://sqs.example/jobs"] == []
        assert len(sqs.client.queues["https://sqs.example/jobs-dead"]) == 2
        dead_body = json.loads(sqs.client.queues["https://sqs.example/jobs-dead"][0]["Body"])
        assert dead_body["invalid_payload"] == "[]"
        missing_body = json.loads(sqs.client.queues["https://sqs.example/jobs-dead"][1]["Body"])
        assert missing_body["invalid_payload"] == ""


def test_celery_queue_falls_back_to_task_id_and_dead_letters_receipt_queue() -> None:
    class FakeAsyncResult:
        id = None

    class FakeCeleryApp:
        def __init__(self) -> None:
            self.sent: list[dict[str, object]] = []

        def send_task(
            self, task_name: str, *, args: list[object], queue: str, task_id: str
        ) -> FakeAsyncResult:
            self.sent.append(
                {"task_name": task_name, "args": args, "queue": queue, "task_id": task_id}
            )
            return FakeAsyncResult()

    class FakeCeleryModule:
        class Celery(FakeCeleryApp):
            def __init__(self, name: str, broker: str) -> None:
                del name, broker
                super().__init__()

    envelope = _envelope("celery-job")
    with installed_module("celery", FakeCeleryModule()):
        celery = CeleryQueueAdapter("redis://localhost/0")
        receipt = celery.enqueue(queue_name="jobs", envelope=envelope)
        assert receipt.receipt_id == "celery-job"

        dead_receipt = celery.dead_letter(
            QueueReceipt("celery", "priority", "old-task", "old-task"), envelope=envelope
        )

        assert dead_receipt.queue_name == "priority.dead"
        assert celery.app.sent[-1]["queue"] == "priority.dead"


def test_import_optional_backend_module_reports_missing_dependency_cleanly() -> None:
    """Regression: a missing optional backend dependency (boto3/pika/celery) used to
    surface as a bare ModuleNotFoundError stack trace from the worker. The shared
    importer must translate it to a clean IOCParserError naming the install extra.
    """
    from iocparser.errors import IOCParserError
    from iocparser.infrastructure.queue_records import import_optional_backend_module

    with pytest.raises(IOCParserError, match=r"sqs backend requires.*iocparser-tool\[pipeline\]"):
        import_optional_backend_module("a_module_that_is_not_installed", backend="sqs")

    sentinel = SimpleNamespace(marker="present")
    with installed_module("a_present_backend_module", sentinel):
        resolved = import_optional_backend_module("a_present_backend_module", backend="sqs")
    assert resolved is sentinel


def test_mark_dead_lettered_retains_phase_metrics(tmp_path: Path) -> None:
    """Regression: a job that exhausts its retries and is dead-lettered used to lose
    its phase timings (mark_dead_lettered ignored metrics, unlike mark_failed). The
    metrics are now persisted and readable back from the job record.
    """
    service = SQLAlchemyDistributedJobService(f"sqlite:///{tmp_path / 'dl-metrics.sqlite'}")
    envelope = _envelope("dl-metrics-job")
    service.create_or_get_job(envelope=envelope, receipt_id="r1")

    service.mark_dead_lettered(
        job_id="dl-metrics-job",
        attempts=3,
        error=PipelineErrorInfo(
            code="INPUT_TIMEOUT",
            category="timeout",
            retryable=False,
            status="failed",
            message="timeout",
        ),
        metrics={"download_ms": 12, "extract_ms": 34},
    )

    record = service.get_job(job_id="dl-metrics-job")
    assert record is not None
    assert record.phase_timings_ms == {"download_ms": 12, "extract_ms": 34}
