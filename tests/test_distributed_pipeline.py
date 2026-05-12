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
    PipelineWorker,
    default_queue_backend,
)
from iocparser.application.distributed_use_cases import idempotency_key_for
from iocparser.client import IOCParserClient
from iocparser.distributed_pipeline import DistributedPipelineService
from iocparser.domain.distributed import QueueEnvelope
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

    assert key == "file:/tmp/sample.txt"
    assert digester.calls == [("file", "/tmp/sample.txt")]


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
    assert [event["name"] for event in telemetry.events] == ["job_submitted", "job_started", "job_completed"]


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
