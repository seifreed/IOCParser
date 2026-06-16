from __future__ import annotations

import json
from pathlib import Path

import pytest

from iocparser.api_pipeline import (
    JOB_STATUS_COMPLETED,
    JOB_STATUS_DEAD_LETTERED,
    JOB_STATUS_QUEUED,
    DistributedPipelineClient,
    PipelineJobRequest,
    PipelineJobResult,
    PipelineWorker,
    ResourceLimits,
    default_queue_backend,
)
from iocparser.application.distributed_use_cases import idempotency_key_for
from iocparser.client import IOCParserClient
from iocparser.distributed_pipeline import DistributedPipelineService
from iocparser.domain.distributed import QueueEnvelope
from iocparser.domain.models import ExtractionResult
from iocparser.errors import IOCTimeoutError
from iocparser.infrastructure.queue_factory import create_queue_adapter
from iocparser.infrastructure.queue_filesystem import FilesystemQueueAdapter
from iocparser.infrastructure.runtime.telemetry import InMemoryTelemetrySink


class TimeoutClient(IOCParserClient):
    def extract_result_from_text(self, text_content: str, **kwargs: object):  # type: ignore[override]
        del text_content, kwargs
        raise IOCTimeoutError("Extract", "retryable-input")


class RuntimeErrorClient(IOCParserClient):
    def extract_result_from_text(self, text_content: str, **kwargs: object):  # type: ignore[override]
        del text_content, kwargs
        raise RuntimeError("unexpected failure")


class FailedWithoutErrorProcessor:
    def __init__(self) -> None:
        self.limits = ResourceLimits()

    def process(self, request: PipelineJobRequest) -> PipelineJobResult:
        return PipelineJobResult(
            input_kind=request.input_kind,
            source_value=request.source_value,
            status="failed",
            result=ExtractionResult(),
            job_id=str(request.job_id),
            correlation_id=str(request.correlation_id or request.job_id),
        )


class RecordingDigester:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def digest_text(self, value: str) -> str:
        self.calls.append(("text", value))
        return f"text:{value}"

    def digest_file(self, file_path: str) -> str:
        self.calls.append(("file", file_path))
        return f"file:{file_path}"


def test_default_queue_backend_is_filesystem() -> None:
    assert default_queue_backend() == "filesystem"


def test_idempotency_key_for_uses_injected_digester() -> None:
    digester = RecordingDigester()
    request = PipelineJobRequest(input_kind="file", source_value="/tmp/sample.txt")

    key = idempotency_key_for(request, digester=digester)
    changed_options_key = idempotency_key_for(
        PipelineJobRequest(input_kind="file", source_value="/tmp/sample.txt", defang=False),
        digester=digester,
    )

    assert len(key) == 64
    assert changed_options_key != key
    assert digester.calls == [("file", "/tmp/sample.txt"), ("file", "/tmp/sample.txt")]


def test_distributed_pipeline_filesystem_queue_e2e(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'distributed.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    telemetry = InMemoryTelemetrySink()
    service = DistributedPipelineService(
        queue_adapter=queue,
        db_uri=db_uri,
        telemetry_sink=telemetry,
    )
    request = PipelineJobRequest(
        input_kind="text",
        source_value="See hxxp://evil.example and evil.example",
        persist=True,
        db_uri=db_uri,
        check_warnings=False,
    )

    queued = service.submit(request, queue_name="ingest")
    assert queued.status == JOB_STATUS_QUEUED
    assert queue.pending_count(queue_name="ingest") == 1

    completed = service.process_next(queue_name="ingest")
    assert completed is not None
    assert getattr(completed, "status", "") == JOB_STATUS_COMPLETED
    assert queue.pending_count(queue_name="ingest") == 0

    jobs = service.list_jobs(limit=10)
    assert len(jobs) == 1
    assert jobs[0].status == JOB_STATUS_COMPLETED
    assert jobs[0].run_id is not None
    assert [event["name"] for event in telemetry.events] == [
        "job_submitted",
        "job_started",
        "job_completed",
    ]


def test_process_next_skips_message_without_tracked_job(tmp_path: Path) -> None:
    """A queued message whose job_id has no DB row must be acked and skipped.

    When two concurrent submits share an idempotency key but carry different job
    ids, both enqueue a message yet only one job row is created (the other is
    deduplicated). The duplicate's job_id has no row, so mark_running returns
    None; processing it anyway re-ran the work and defeated idempotency. It must
    now be acked and skipped instead.
    """
    db_uri = f"sqlite:///{tmp_path / 'orphan.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    telemetry = InMemoryTelemetrySink()
    service = DistributedPipelineService(
        queue_adapter=queue,
        db_uri=db_uri,
        telemetry_sink=telemetry,
    )
    real_request = PipelineJobRequest(
        input_kind="text",
        source_value="evil.example",
        persist=False,
        check_warnings=False,
    )
    service.submit(real_request, queue_name="ingest")
    assert service.process_next(queue_name="ingest") is not None

    orphan_request = PipelineJobRequest(
        input_kind="text",
        source_value="evil.example",
        persist=False,
        check_warnings=False,
        job_id="never-tracked-job-id",
    )
    orphan = QueueEnvelope(
        request=orphan_request,
        queue_backend="filesystem",
        queue_name="ingest",
    )
    queue.enqueue(queue_name="ingest", envelope=orphan)

    telemetry.events.clear()
    result = service.process_next(queue_name="ingest")

    assert result is None
    assert queue.pending_count(queue_name="ingest") == 0
    assert [event["name"] for event in telemetry.events] == ["job_skipped"]


def test_filesystem_queue_dequeue_survives_race_condition(tmp_path: Path) -> None:
    """Regression: FileNotFoundError during rename must not crash dequeue."""
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    request = PipelineJobRequest(
        input_kind="text",
        source_value="race test",
        persist=False,
        check_warnings=False,
    )
    envelope = QueueEnvelope(
        request=request,
        queue_backend="filesystem",
        queue_name="race",
    )
    queue.enqueue(queue_name="race", envelope=envelope)
    queue.enqueue(queue_name="race", envelope=envelope)

    # Simulate another worker winning the race by removing the first pending file
    first = sorted((tmp_path / "queue" / "race" / "pending").glob("*.json"))[0]
    first.unlink()

    result = queue.dequeue(queue_name="race")
    assert result is not None
    assert queue.pending_count(queue_name="race") == 0


def test_process_next_drops_message_when_dead_letter_archival_fails(tmp_path: Path) -> None:
    """Regression: a backend that cannot archive (e.g. SQS with no DLQ) must not loop.

    The job is recorded dead-lettered, so the poison message is acked/removed instead
    of raising out of process_next and being redelivered forever.
    """

    class DeadLetterFailsAdapter(FilesystemQueueAdapter):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.acked: list[str] = []

        def dead_letter(self, receipt, *, envelope):  # type: ignore[no-untyped-def]
            raise RuntimeError("dead-letter queue not configured")

        def ack(self, receipt):  # type: ignore[no-untyped-def]
            self.acked.append(receipt.receipt_id)
            super().ack(receipt)

    queue = DeadLetterFailsAdapter(tmp_path / "queue")
    service = DistributedPipelineService(
        queue_adapter=queue,
        worker=PipelineWorker(client=TimeoutClient()),
    )
    request = PipelineJobRequest(
        input_kind="text",
        source_value="poison",
        persist=False,
        check_warnings=False,
    )
    service.submit(request, queue_name="poison", max_attempts=1)

    result = service.process_next(queue_name="poison")

    assert result is not None
    assert getattr(result, "status", "") == "failed"
    assert len(queue.acked) == 1
    assert queue.pending_count(queue_name="poison") == 0
    assert not list((tmp_path / "queue" / "poison" / "processing").glob("*.json"))


def test_submit_records_adapter_backend_not_requested_backend(tmp_path: Path) -> None:
    """Regression: the configured adapter is the source of truth for where a job lives.
    A requested queue_backend the adapter cannot honor must not be recorded, or the job
    becomes a phantom under list_jobs(queue_backend=...) and no worker drains it."""
    db_uri = f"sqlite:///{tmp_path / 'backend.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    service = DistributedPipelineService(queue_adapter=queue, db_uri=db_uri)
    request = PipelineJobRequest(
        input_kind="text", source_value="x", persist=False, check_warnings=False
    )

    record = service.submit(request, queue_name="q", queue_backend="sqs")

    assert getattr(record, "queue_backend", None) == "filesystem"
    assert service.list_jobs(queue_backend="sqs") == []
    assert len(service.list_jobs(queue_backend="filesystem")) == 1


def test_redelivered_completed_job_is_not_reprocessed(tmp_path: Path) -> None:
    """Regression: an at-least-once redelivery of an already-completed job (e.g. one
    whose post-completion ack failed) must be acked and skipped, not reset to running
    and reprocessed -- terminal states are not resurrected by mark_running."""
    from iocparser.infrastructure.queue_records import load_queue_record

    class CountingClient(IOCParserClient):
        def __init__(self) -> None:
            self.calls = 0

        def extract_result_from_text(self, text_content: str, **kwargs: object):  # type: ignore[override]
            del text_content, kwargs
            self.calls += 1
            return ExtractionResult()

    db_uri = f"sqlite:///{tmp_path / 'redeliver.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    client = CountingClient()
    service = DistributedPipelineService(
        queue_adapter=queue, db_uri=db_uri, worker=PipelineWorker(client=client)
    )
    request = PipelineJobRequest(
        input_kind="text", source_value="evil.example", persist=False, check_warnings=False
    )
    service.submit(request, queue_name="q")

    pending = next((tmp_path / "queue" / "q" / "pending").glob("*.json"))
    envelope = QueueEnvelope.from_record(load_queue_record(pending.read_text(encoding="utf-8")))

    first = service.process_next(queue_name="q")
    assert getattr(first, "status", "") == JOB_STATUS_COMPLETED
    assert client.calls == 1

    queue.enqueue(queue_name="q", envelope=envelope)
    second = service.process_next(queue_name="q")

    assert second is None
    assert client.calls == 1
    assert queue.pending_count(queue_name="q") == 0
    jobs = service.list_jobs(limit=10)
    assert len(jobs) == 1
    assert jobs[0].status == JOB_STATUS_COMPLETED


def test_completed_job_not_dead_lettered_when_ack_fails(tmp_path: Path) -> None:
    """Regression: an ack failure AFTER mark_completed (e.g. an SQS receipt handle
    expired past the visibility timeout) must leave the job COMPLETED, not let the
    failure fall through to the dead-letter handler and flip it to dead-lettered.
    """

    class AckFailsAdapter(FilesystemQueueAdapter):
        def ack(self, receipt):  # type: ignore[no-untyped-def]
            raise RuntimeError("ack failed: receipt handle expired")

    db_uri = f"sqlite:///{tmp_path / 'ack-fail.sqlite'}"
    queue = AckFailsAdapter(tmp_path / "queue")
    telemetry = InMemoryTelemetrySink()
    service = DistributedPipelineService(
        queue_adapter=queue, db_uri=db_uri, telemetry_sink=telemetry
    )
    request = PipelineJobRequest(
        input_kind="text", source_value="evil.example", persist=False, check_warnings=False
    )
    service.submit(request, queue_name="ack", max_attempts=1)

    result = service.process_next(queue_name="ack")

    assert result is not None
    assert getattr(result, "status", "") == JOB_STATUS_COMPLETED
    jobs = service.list_jobs(limit=10)
    assert jobs[0].status == JOB_STATUS_COMPLETED
    assert jobs[0].status != JOB_STATUS_DEAD_LETTERED
    event_names = [event["name"] for event in telemetry.events]
    assert "job_ack_failed" in event_names
    assert "job_dead_lettered" not in event_names
    assert "job_completed" not in event_names


def test_unexpected_exception_acks_when_dead_letter_archival_fails(tmp_path: Path) -> None:
    """Regression: the unexpected-exception path must ack a poison message when the
    backend cannot archive it, mirroring the failed-result path. Otherwise a backend
    like SQS without a DLQ redelivers and reprocesses it forever.
    """

    class DeadLetterFailsAdapter(FilesystemQueueAdapter):
        def __init__(self, root: Path) -> None:
            super().__init__(root)
            self.acked: list[str] = []

        def dead_letter(self, receipt, *, envelope):  # type: ignore[no-untyped-def]
            raise RuntimeError("dead-letter queue not configured")

        def ack(self, receipt):  # type: ignore[no-untyped-def]
            self.acked.append(receipt.receipt_id)
            super().ack(receipt)

    db_uri = f"sqlite:///{tmp_path / 'unexpected-ack.sqlite'}"
    queue = DeadLetterFailsAdapter(tmp_path / "queue")
    service = DistributedPipelineService(queue_adapter=queue, db_uri=db_uri)
    request = PipelineJobRequest(
        input_kind="text", source_value="boom", persist=False, check_warnings=False
    )
    service.submit(request, queue_name="unexpected", max_attempts=1)

    original_mark_running = service.job_service.mark_running

    def exploding_mark_running(**kwargs):
        original_mark_running(**kwargs)
        raise RuntimeError("db failure")

    service.job_service.mark_running = exploding_mark_running
    with pytest.raises(RuntimeError, match="db failure"):
        service.process_next(queue_name="unexpected")

    assert len(queue.acked) == 1
    assert queue.pending_count(queue_name="unexpected") == 0
    assert not list((tmp_path / "queue" / "unexpected" / "processing").glob("*.json"))


def test_filesystem_dead_letter_preserves_existing_dead_record(tmp_path: Path) -> None:
    """Regression: dead_letter must not overwrite a same-named existing dead record."""
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    request = PipelineJobRequest(
        input_kind="text",
        source_value="dead letter me",
        persist=False,
        check_warnings=False,
    )
    envelope = QueueEnvelope(request=request, queue_backend="filesystem", queue_name="dl")
    queue.enqueue(queue_name="dl", envelope=envelope)
    dequeued = queue.dequeue(queue_name="dl")
    assert dequeued is not None
    receipt, dequeued_envelope = dequeued

    dead_dir = tmp_path / "queue" / "dl" / "dead"
    dead_dir.mkdir(parents=True, exist_ok=True)
    existing = dead_dir / Path(receipt.receipt_id).name
    existing.write_text("existing-dead-record", encoding="utf-8")

    queue.dead_letter(receipt, envelope=dequeued_envelope)

    assert existing.read_text(encoding="utf-8") == "existing-dead-record"
    assert queue.dead_count(queue_name="dl") == 2


def test_distributed_pipeline_deduplicates_submit_before_enqueue(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'dedupe.sqlite'}"
    service = DistributedPipelineService(
        queue_adapter=FilesystemQueueAdapter(tmp_path / "queue"),
        db_uri=db_uri,
    )
    request = PipelineJobRequest(
        input_kind="text",
        source_value="same content",
        persist=True,
        db_uri=db_uri,
        check_warnings=False,
    )
    first = service.submit(request, queue_name="dedupe")
    second = service.submit(request, queue_name="dedupe")
    assert first.job_id == second.job_id
    assert service.queue_adapter.pending_count(queue_name="dedupe") == 1


def test_distributed_pipeline_idempotency_includes_processing_options(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'dedupe-options.sqlite'}"
    service = DistributedPipelineService(
        queue_adapter=FilesystemQueueAdapter(tmp_path / "queue"),
        db_uri=db_uri,
    )
    first = service.submit(
        PipelineJobRequest(
            input_kind="text",
            source_value="same source",
            persist=False,
            check_warnings=True,
        ),
        queue_name="dedupe-options",
    )
    second = service.submit(
        PipelineJobRequest(
            input_kind="text",
            source_value="same source",
            persist=False,
            check_warnings=False,
        ),
        queue_name="dedupe-options",
    )

    assert first.job_id != second.job_id
    assert service.queue_adapter.pending_count(queue_name="dedupe-options") == 2


def test_distributed_pipeline_retries_and_dead_letters(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'dead.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    service = DistributedPipelineService(
        queue_adapter=queue,
        worker=PipelineWorker(client=TimeoutClient()),
        db_uri=db_uri,
    )
    request = PipelineJobRequest(
        input_kind="text",
        source_value="retry me",
        persist=False,
        check_warnings=False,
    )
    service.submit(request, queue_name="retry", max_attempts=2)
    first = service.process_next(queue_name="retry")
    assert getattr(first, "status", "") == JOB_STATUS_QUEUED
    second = service.process_next(queue_name="retry")
    assert getattr(second, "status", "") == JOB_STATUS_DEAD_LETTERED
    dead_letters = service.list_dead_letters(limit=10)
    assert len(dead_letters) == 1
    assert dead_letters[0].error.code == "INPUT_TIMEOUT"
    assert queue.dead_count(queue_name="retry") == 1


def test_distributed_pipeline_dead_letters_on_unexpected_exception(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'unexpected.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    service = DistributedPipelineService(
        queue_adapter=queue,
        db_uri=db_uri,
    )
    request = PipelineJobRequest(
        input_kind="text",
        source_value="boom",
        persist=False,
        check_warnings=False,
    )
    service.submit(request, queue_name="unexpected", max_attempts=1)
    original_mark_running = service.job_service.mark_running

    def exploding_mark_running(**kwargs):
        original_mark_running(**kwargs)
        raise RuntimeError("db failure")

    service.job_service.mark_running = exploding_mark_running
    with pytest.raises(RuntimeError, match="db failure"):
        service.process_next(queue_name="unexpected")
    dead_letters = service.list_dead_letters(limit=10)
    assert len(dead_letters) == 1
    assert dead_letters[0].error.code == "UNEXPECTED_FAILURE"
    dead_queue_payloads = list((tmp_path / "queue" / "unexpected" / "dead").glob("*.json"))
    assert len(dead_queue_payloads) == 1
    dead_queue_record = json.loads(dead_queue_payloads[0].read_text(encoding="utf-8"))
    assert dead_queue_record["attempts"] == 1


def test_distributed_pipeline_dead_letters_failed_result_without_error(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'failed-without-error.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    service = DistributedPipelineService(
        queue_adapter=queue,
        worker=FailedWithoutErrorProcessor(),
        db_uri=db_uri,
    )
    queued = service.submit(
        PipelineJobRequest(input_kind="text", source_value="bad", check_warnings=False),
        queue_name="missing-error",
        max_attempts=1,
    )

    processed = service.process_next(queue_name="missing-error")

    assert getattr(processed, "status", "") == JOB_STATUS_DEAD_LETTERED
    assert service.get_job(job_id=queued.job_id).status == JOB_STATUS_DEAD_LETTERED
    dead_letters = service.list_dead_letters(limit=10)
    assert len(dead_letters) == 1
    assert dead_letters[0].error.code == "PIPELINE_FAILED"
    assert queue.dead_count(queue_name="missing-error") == 1


def test_queue_factory_and_client_wrapper(tmp_path: Path) -> None:
    adapter = create_queue_adapter("filesystem", queue_path=str(tmp_path / "factory-queue"))
    assert isinstance(adapter, FilesystemQueueAdapter)

    db_uri = f"sqlite:///{tmp_path / 'client.sqlite'}"
    client = DistributedPipelineClient(
        db_uri=db_uri,
        queue_path=str(tmp_path / "client-queue"),
    )
    job = client.submit(
        PipelineJobRequest(
            input_kind="text",
            source_value="client input",
            persist=True,
            db_uri=db_uri,
            check_warnings=False,
        ),
        queue_name="client",
    )
    assert client.process_next(queue_name="client") is not None
    assert client.get_job(job_id=job.job_id).status == JOB_STATUS_COMPLETED


def test_pipeline_json_schemas_are_published() -> None:
    schemas = {
        "pipeline-job-result-1.0.json",
        "batch-report-1.0.json",
        "distributed-job-1.0.json",
    }
    schema_dir = Path("iocparser/schemas")
    assert schemas == {path.name for path in schema_dir.glob("*.json")}
    for schema_name in schemas:
        payload = json.loads((schema_dir / schema_name).read_text(encoding="utf-8"))
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert payload["properties"]["schema_version"]["const"] == "1.0"
