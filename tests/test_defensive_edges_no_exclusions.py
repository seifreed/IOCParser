from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from iocparser.domain.distributed import QueueEnvelope, QueueReceipt
from iocparser.domain.models import ExtractionOptions, ExtractionResult, PersistOptions, Source
from iocparser.domain.pipeline import PipelineJobRequest


class _ScalarResult:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarResult:
        return self

    def all(self) -> list[object]:
        return self._rows

    def first(self) -> object | None:
        return self._rows[0] if self._rows else None

    def scalar_one_or_none(self) -> object | None:
        return self._rows[0] if self._rows else None


class _Savepoint:
    def __init__(self, rollback_error: Exception | None = None) -> None:
        self.rollback_error = rollback_error
        self.committed = False
        self.rolled_back = False

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True
        if self.rollback_error is not None:
            raise self.rollback_error


class _IntegritySession:
    def __init__(
        self,
        retry_rows: list[object],
        *,
        rollback_error: Exception | None = None,
    ) -> None:
        self.retry_rows = retry_rows
        self.rollback_error = rollback_error
        self.execute_calls = 0
        self.rollback_called = False

    def execute(self, _stmt: object) -> _ScalarResult:
        self.execute_calls += 1
        return _ScalarResult([] if self.execute_calls == 1 else self.retry_rows)

    def add(self, _model: object) -> None:
        return None

    def begin_nested(self) -> _Savepoint:
        return _Savepoint(self.rollback_error)

    def flush(self) -> None:
        raise IntegrityError("duplicate", {}, Exception("duplicate"))

    def rollback(self) -> None:
        self.rollback_called = True


def _raise(exc: BaseException) -> None:
    raise exc


def _fresh_db(tmp_path, name: str = "test.db") -> str:
    db_uri = f"sqlite:///{tmp_path / name}"
    engine = create_engine(db_uri, future=True)
    try:
        from iocparser.infrastructure.persistence_migration_runtime import migrate_engine

        migrate_engine(engine)
    finally:
        engine.dispose()
    return db_uri


def _job_model_kwargs(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "job_id": "job",
        "correlation_id": "corr",
        "queue_backend": "filesystem",
        "queue_name": "default",
        "input_kind": "text",
        "source_value": "payload",
        "idempotency_key": None,
        "status": "queued",
        "attempts": 0,
        "max_attempts": 3,
        "retryable": None,
        "receipt_id": "receipt",
        "payload_json": "{}",
        "result_json": "{}",
        "metrics_json": "{}",
        "last_error_code": None,
        "last_error_category": None,
        "last_error_message": None,
        "run_id": None,
        "submitted_at": now,
        "started_at": None,
        "completed_at": None,
        "dead_lettered_at": None,
    }
    values.update(overrides)
    return values


def _dead_letter_model_kwargs(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "job_id": "job",
        "correlation_id": "corr",
        "queue_backend": "filesystem",
        "queue_name": "default",
        "source_value": "payload",
        "attempts": 1,
        "max_attempts": 3,
        "error_code": "ERR",
        "error_category": "test",
        "error_message": "boom",
        "retryable": False,
        "payload_json": "{}",
        "dead_lettered_at": datetime.now(UTC),
    }
    values.update(overrides)
    return values


def test_json_object_returns_dict_with_string_keys() -> None:
    from iocparser.adapters.renderers_json import json_object

    assert json_object('{"1": "one", "two": 2}') == {"1": "one", "two": 2}


def test_validated_search_call_reraises_unknown_value_error() -> None:
    from iocparser.api_persistence_query import _validated_search_call

    original = ValueError("unexpected backend failure")

    def call() -> str:
        raise original

    with pytest.raises(ValueError, match="unexpected backend failure") as raised:
        _validated_search_call("needle", call)
    assert raised.value is original


def test_application_use_cases_propagate_process_interruptions() -> None:
    from iocparser.application.contracts import ExtractFileInput, PersistRunInput
    from iocparser.application.use_cases import extract_from_file, persist_run

    class InterruptingReader:
        def read(self, _file_path: str, _options: ExtractionOptions) -> str:
            raise KeyboardInterrupt

    class Extractor:
        def extract_all(self, _text: str, *, defang: bool = True) -> dict[str, list[str]]:
            return {}

    with pytest.raises(KeyboardInterrupt):
        extract_from_file(
            ExtractFileInput("sample.txt", ExtractionOptions()),
            reader=InterruptingReader(),
            extractor_engine=Extractor(),
        )

    class SourceRepository:
        def get_or_create(self, **_kwargs: object) -> int:
            raise KeyboardInterrupt

    unit = SimpleNamespace(
        source_repository=SourceRepository(),
        ioc_repository=SimpleNamespace(
            get_or_create_normal=lambda _r: [], get_or_create_warnings=lambda _r: []
        ),
        run_repository=SimpleNamespace(create_run=lambda **_k: 1, attach_iocs=lambda **_k: None),
        commit=lambda: None,
        rollback=lambda: None,
    )
    with pytest.raises(KeyboardInterrupt):
        persist_run(
            PersistRunInput(
                source=Source.from_raw("file", "sample.txt"),
                result=ExtractionResult(),
                tool_version="test",
                options=PersistOptions(
                    defang=True,
                    check_warnings=False,
                    force_update=False,
                    output_format="json",
                ),
            ),
            unit_of_work=unit,
        )


def test_distributed_process_next_propagates_interruptions() -> None:
    from iocparser.application.distributed_use_cases import DistributedPipelineCoordinator

    request = PipelineJobRequest(input_kind="text", source_value="payload", job_id="job")
    envelope = QueueEnvelope(request=request, queue_backend="memory", queue_name="default")
    receipt = QueueReceipt("memory", "default", "receipt", "message")

    class Queue:
        def dequeue(self, *, queue_name: str) -> tuple[QueueReceipt, QueueEnvelope]:
            assert queue_name == "default"
            return receipt, envelope

    class Processor:
        def process(self, _request: PipelineJobRequest) -> ExtractionResult:
            raise KeyboardInterrupt

    sink = SimpleNamespace(emit=lambda _event: None)
    coordinator = DistributedPipelineCoordinator(
        queue_adapter=Queue(),
        processor=Processor(),
        telemetry_sink=sink,
    )

    with pytest.raises(KeyboardInterrupt):
        coordinator.process_next(queue_name="default")


def test_cli_helpers_cover_url_source_and_retry_wrapper() -> None:
    from iocparser.cli_dispatch_workflow import _source_kind_for_args
    from iocparser.cli_processing_urls import _retry_attempt_for_url

    args = SimpleNamespace(stdin=False, url=None, url_direct="https://example.com")

    assert _source_kind_for_args(args) == "url"
    assert _retry_attempt_for_url("https://example.com", None) == 0


def test_future_based_executors_propagate_keyboard_interrupts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    from iocparser.cli_processing_support import BatchResultsCollection
    from iocparser.cli_url_batch_workflow import (
        URLBatchWorkflowRequest,
        URLBatchWorkflowState,
        _collect_url_results,
    )
    from iocparser.domain.options import ExtractionOptions as DomainExtractionOptions
    from iocparser.infrastructure.file_batch_executor import ThreadPoolFileBatchExecutor
    from iocparser.infrastructure.streaming_parallel import ParallelStreamingExtractor

    executor = ThreadPoolFileBatchExecutor(max_workers=1)
    with pytest.raises(KeyboardInterrupt):
        executor.execute(
            ["sample"],
            handler=lambda _request: _raise(KeyboardInterrupt()),
            key_for=str,
        )

    text_file = tmp_path / "sample.txt"
    text_file.write_text("hello", encoding="utf-8")
    parallel = ParallelStreamingExtractor(max_workers=1, chunk_size=4, defang=False)
    monkeypatch.setattr(
        "iocparser.infrastructure.streaming.StreamingIOCExtractor.extract_from_file",
        lambda *_args, **_kwargs: _raise(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        parallel.extract_from_files([text_file])

    class Future:
        def result(self) -> object:
            raise KeyboardInterrupt

    future = Future()

    class FakeExecutor:
        def __init__(self, *, max_workers: int) -> None:
            assert max_workers == 1

        def __enter__(self) -> FakeExecutor:
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def submit(self, *_args: object, **_kwargs: object) -> Future:
            return future

    monkeypatch.setattr("iocparser.cli_url_batch_workflow.ThreadPoolExecutor", FakeExecutor)
    monkeypatch.setattr("iocparser.cli_url_batch_workflow.as_completed", list)

    state = URLBatchWorkflowState(
        results=BatchResultsCollection(),
        source_metadata_map={},
        run_metadata_map={},
        failures={},
        item_reports=[],
    )
    request = URLBatchWorkflowRequest(
        args=SimpleNamespace(url_workers=1),
        reader=SimpleNamespace(),
        warning_service=None,
        downloader=SimpleNamespace(),
    )
    with pytest.raises(KeyboardInterrupt):
        _collect_url_results(
            request,
            url_items=[("u#1", "https://example.com")],
            options=DomainExtractionOptions(),
            retry_report=None,
            retry_batch_job=None,
            configured_plugin_client=None,
            state=state,
        )


def test_process_url_plugin_branch_isolates_downloader_per_call() -> None:
    """The plugin branch must read metadata from a per-call downloader clone.

    Regression: it reused the shared downloader, so concurrent batch URLs raced
    on last_download_metadata and cross-contaminated each source's metadata. The
    clone is also what the per-call plugin client must be bound to.
    """
    from iocparser import cli_processing_urls_execution as execution
    from iocparser.domain.options import ExtractionOptions as DomainExtractionOptions

    clones: list[object] = []
    bound: dict[str, object] = {}

    class FakeDownloader:
        def __init__(self, name: str) -> None:
            self.name = name

        def with_policy(self, **_overrides: object) -> FakeDownloader:
            clone = FakeDownloader(f"{self.name}-clone{len(clones) + 1}")
            clones.append(clone)
            return clone

        def download_metadata(self) -> dict[str, object]:
            return {"downloader": self.name}

    class FakeClient:
        def with_downloader(self, downloader: object) -> FakeClient:
            bound["downloader"] = downloader
            return self

        def extract_result_from_url(self, _url: str, **_kwargs: object) -> ExtractionResult:
            return ExtractionResult()

    shared = FakeDownloader("shared")
    _url, _result, metadata, _ms = execution.process_url(
        "http://example.com",
        options=DomainExtractionOptions(),
        reader=SimpleNamespace(),
        warning_service=None,
        downloader=shared,
        configured_plugin_client=FakeClient(),
    )

    assert len(clones) == 1
    assert metadata == {"downloader": clones[0].name}  # not "shared"
    assert bound["downloader"] is clones[0]


def test_network_policy_rejects_exact_prefix_and_suffix_fragments() -> None:
    from iocparser.infrastructure.extractor_network import DEFAULT_NETWORK_POLICY

    assert not DEFAULT_NETWORK_POLICY.is_valid_host_candidate("malware.addeventlistener")
    assert not DEFAULT_NETWORK_POLICY.is_valid_host_candidate("document.cookie")
    assert not DEFAULT_NETWORK_POLICY.is_valid_host_candidate("evil.view")


def test_persistence_query_count_none_is_zero() -> None:
    from iocparser.infrastructure.persistence.query.ops import _coerce_count

    assert _coerce_count(None) == 0


def test_ioc_repository_integrity_retry_and_reraise_paths() -> None:
    from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository

    existing = SimpleNamespace(id=7)
    retry_session = _IntegritySession([existing])

    assert (
        SQLAlchemyIOCRepository(retry_session)._get_or_create(
            ioc_type="md5",
            value="abc",
            is_warning=False,
            warning_list="",
            warning_description="",
        )
        == 7
    )

    rollback_error = RuntimeError("savepoint rollback failed")
    rollback_session = _IntegritySession([], rollback_error=rollback_error)
    with pytest.raises(IntegrityError) as raised:
        SQLAlchemyIOCRepository(rollback_session)._get_or_create(
            ioc_type="sha1",
            value="abc",
            is_warning=False,
            warning_list="",
            warning_description="",
        )
    assert "duplicate" in str(raised.value)
    assert raised.value.__cause__ is rollback_error
    assert rollback_session.rollback_called is True

    missing_session = _IntegritySession([])
    with pytest.raises(IntegrityError):
        SQLAlchemyIOCRepository(missing_session)._get_or_create(
            ioc_type="sha256",
            value="abc",
            is_warning=False,
            warning_list="",
            warning_description="",
        )


def test_source_repository_integrity_retry_and_reraise_paths() -> None:
    from iocparser.infrastructure.persistence_source_repository import SQLAlchemySourceRepository

    existing = SimpleNamespace(
        id=41,
        value="sample.txt",
        last_seen=datetime(2020, 1, 1, tzinfo=UTC),
        original_url=None,
        normalized_url=None,
        mime_type=None,
        input_size=None,
        content_hash=None,
        fingerprint=None,
        value_search="",
    )
    retry_session = _IntegritySession([existing])

    assert (
        SQLAlchemySourceRepository(retry_session).get_or_create(
            kind="file",
            value="sample.txt",
            original_url="https://origin.example",
            normalized_url="https://origin.example/",
            mime_type="text/plain",
            input_size=123,
            content_hash="hash",
            fingerprint="fp",
        )
        == 41
    )
    assert existing.mime_type == "text/plain"
    assert existing.input_size == 123
    assert existing.content_hash == "hash"

    rollback_error = RuntimeError("savepoint rollback failed")
    rollback_session = _IntegritySession([], rollback_error=rollback_error)
    with pytest.raises(IntegrityError) as raised:
        SQLAlchemySourceRepository(rollback_session).get_or_create(kind="file", value="rollback")
    assert raised.value.__cause__ is rollback_error
    assert rollback_session.rollback_called is True

    missing_session = _IntegritySession([])
    with pytest.raises(IntegrityError):
        SQLAlchemySourceRepository(missing_session).get_or_create(kind="file", value="missing")


def test_unit_of_work_race_branches_and_context_manager(tmp_path) -> None:
    from sqlalchemy import create_engine as sqlalchemy_create_engine
    from sqlalchemy.pool import NullPool, StaticPool

    from iocparser.infrastructure import persistence_uow
    from iocparser.infrastructure.persistence_uow import SQLAlchemyUnitOfWork

    assert persistence_uow._engine_kwargs(f"sqlite:///{tmp_path / 'pool.db'}") == {
        "poolclass": NullPool
    }
    assert persistence_uow._engine_kwargs("sqlite:///:memory:") == {
        "poolclass": StaticPool,
        "connect_args": {"check_same_thread": False},
    }
    # Non-sqlite backends use the driver's default pooling.
    assert persistence_uow._engine_kwargs("postgresql://user@host/db") == {}

    engine_uri = "sqlite:///:memory:?engine-race"
    sentinel_engine = sqlalchemy_create_engine("sqlite:///:memory:", future=True)
    persistence_uow._ENGINE_CACHE.pop(engine_uri, None)
    persistence_uow._ENGINE_LOCK.acquire()
    engine_results: list[object] = []

    def load_engine() -> None:
        engine_results.append(persistence_uow._get_or_create_engine(engine_uri))

    engine_thread = threading.Thread(target=load_engine)
    engine_thread.start()
    persistence_uow._ENGINE_CACHE[engine_uri] = sentinel_engine
    persistence_uow._ENGINE_LOCK.release()
    engine_thread.join(timeout=5)
    assert engine_results == [sentinel_engine]
    persistence_uow._ENGINE_CACHE.pop(engine_uri, None)
    sentinel_engine.dispose()

    migrate_uri = "sqlite:///:memory:?migrate-race"
    SQLAlchemyUnitOfWork._MIGRATED_URIS.discard(migrate_uri)
    SQLAlchemyUnitOfWork._MIGRATE_LOCK.acquire()

    migrate_thread = threading.Thread(target=lambda: SQLAlchemyUnitOfWork.migrate(migrate_uri))
    migrate_thread.start()
    SQLAlchemyUnitOfWork._MIGRATED_URIS.add(migrate_uri)
    SQLAlchemyUnitOfWork._MIGRATE_LOCK.release()
    migrate_thread.join(timeout=5)

    db_uri = _fresh_db(tmp_path, "context.db")
    with SQLAlchemyUnitOfWork(db_uri) as unit:
        assert unit.session is not None


def test_queue_adapters_close_and_preserve_interruptions(monkeypatch: pytest.MonkeyPatch) -> None:
    import iocparser.infrastructure.queue_rabbitmq as rabbitmq
    import iocparser.infrastructure.queue_sqs as sqs

    class Boto3:
        def client(self, service_name: str) -> object:
            assert service_name == "sqs"
            return SimpleNamespace()

    def boto3_module() -> Boto3:
        return Boto3()

    monkeypatch.setattr(sqs, "_boto3_module", boto3_module)
    sqs_adapter = sqs.SQSQueueAdapter("https://sqs.example/main")
    sqs_adapter.close()
    assert sqs_adapter.client is None

    monkeypatch.setattr(
        rabbitmq,
        "_pika_module",
        lambda: SimpleNamespace(
            URLParameters=lambda url: url,
            BlockingConnection=lambda _params: _raise(KeyboardInterrupt()),
        ),
    )
    with pytest.raises(KeyboardInterrupt):
        rabbitmq.RabbitMQQueueAdapter("amqp://localhost")._channel_for()

    monkeypatch.setattr(
        rabbitmq,
        "_pika_module",
        lambda: SimpleNamespace(
            URLParameters=lambda url: url,
            BlockingConnection=lambda _params: SimpleNamespace(
                channel=lambda: _raise(KeyboardInterrupt()),
            ),
        ),
    )
    with pytest.raises(KeyboardInterrupt):
        rabbitmq.RabbitMQQueueAdapter("amqp://localhost")._channel_for()

    closed: list[bool] = []
    monkeypatch.setattr(
        rabbitmq,
        "_pika_module",
        lambda: SimpleNamespace(
            URLParameters=lambda url: url,
            BlockingConnection=lambda _params: SimpleNamespace(
                channel=lambda: _raise(RuntimeError("channel failed")),
                close=lambda: closed.append(True),
            ),
        ),
    )
    with pytest.raises(RuntimeError):
        rabbitmq.RabbitMQQueueAdapter("amqp://localhost")._channel_for()
    assert closed == [True]


def test_rabbitmq_adapter_resets_cache_when_publish_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    import iocparser.infrastructure.queue_rabbitmq as rabbitmq

    connection_calls = [0]

    class _Channel:
        def queue_declare(self, *, queue: str, durable: bool) -> object:
            assert durable is True
            assert queue == "ingest"
            return None

        def basic_publish(self, **_kwargs: object) -> bool:
            raise RuntimeError("publish failed")

    class _Connection:
        def channel(self) -> _Channel:
            return _Channel()

        def close(self) -> object:
            return None

    def _blocking_connection(_params: object) -> _Connection:
        connection_calls[0] += 1
        return _Connection()

    monkeypatch.setattr(
        rabbitmq,
        "_pika_module",
        lambda: SimpleNamespace(
            URLParameters=lambda url: url,
            BlockingConnection=_blocking_connection,
            BasicProperties=lambda **kwargs: kwargs,
        ),
    )
    adapter = rabbitmq.RabbitMQQueueAdapter("amqp://localhost")
    request = PipelineJobRequest(input_kind="text", source_value="ioc", persist=False)
    envelope = QueueEnvelope(request=request, queue_backend="rabbitmq", queue_name="ingest")

    with pytest.raises(RuntimeError, match="publish failed"):
        adapter.enqueue(queue_name="ingest", envelope=envelope)
    assert adapter._channel is None
    assert adapter._connection is None

    with pytest.raises(RuntimeError, match="publish failed"):
        adapter.enqueue(queue_name="ingest", envelope=envelope)
    assert connection_calls == [2]
    assert adapter._channel is None
    assert adapter._connection is None


def test_streaming_mmap_boundary_and_interruptions(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from iocparser.infrastructure.streaming import StreamingIOCExtractor

    boundary_file = tmp_path / "utf8.txt"
    boundary_file.write_bytes("aé".encode())
    progress: list[int] = []
    extractor = StreamingIOCExtractor(
        chunk_size=2, overlap=0, defang=False, progress_callback=progress.append
    )
    assert extractor.extract_from_mmap(boundary_file) == {}
    assert progress

    text_file = tmp_path / "interrupt.txt"
    text_file.write_text("https://example.com", encoding="utf-8")
    interrupting = StreamingIOCExtractor(chunk_size=8, overlap=0, defang=False)
    monkeypatch.setattr(
        interrupting.extractor,
        "extract_all",
        lambda *_args, **_kwargs: _raise(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        interrupting.extract_from_file(text_file)
    with pytest.raises(KeyboardInterrupt):
        interrupting.extract_from_mmap(text_file)


def test_streaming_mmap_advances_when_chunk_starts_with_multibyte_utf8(tmp_path) -> None:
    from iocparser.infrastructure.streaming import StreamingIOCExtractor

    text_file = tmp_path / "multibyte-start.txt"
    text_file.write_text("é evil.example", encoding="utf-8")
    max_expected_progress_calls = len(text_file.read_bytes()) + 1
    progress_calls = 0

    def fail_if_stuck(_progress: int) -> None:
        nonlocal progress_calls
        progress_calls += 1
        if progress_calls > max_expected_progress_calls:
            raise RuntimeError("mmap chunk loop did not advance")

    extractor = StreamingIOCExtractor(
        chunk_size=1,
        overlap=0,
        defang=False,
        progress_callback=fail_if_stuck,
    )

    result = extractor.extract_from_mmap(text_file)

    assert isinstance(result, dict)
    assert progress_calls <= max_expected_progress_calls


def test_pipeline_worker_and_service_preserve_operational_interruptions() -> None:
    from iocparser.domain.pipeline import ResourceLimits
    from iocparser.pipeline_worker import PipelineWorker
    from iocparser.worker_service import DistributedWorkerService

    class InterruptingClient:
        downloader = SimpleNamespace()

        def extract_result_from_text(self, *_args: object, **_kwargs: object) -> ExtractionResult:
            raise KeyboardInterrupt

        def extract_result_from_file(self, *_args: object, **_kwargs: object) -> ExtractionResult:
            return ExtractionResult()

    class MemoryFailingClient:
        downloader = SimpleNamespace()

        def extract_result_from_text(self, *_args: object, **_kwargs: object) -> ExtractionResult:
            raise MemoryError

        def extract_result_from_file(self, *_args: object, **_kwargs: object) -> ExtractionResult:
            return ExtractionResult()

    request = PipelineJobRequest(input_kind="text", source_value="payload")
    with pytest.raises(KeyboardInterrupt):
        PipelineWorker(client=InterruptingClient()).process(request)
    with pytest.raises(MemoryError):
        PipelineWorker(client=MemoryFailingClient()).process(request)

    service = SimpleNamespace(
        limits=SimpleNamespace(max_workers="many"), process_next=lambda **_k: None
    )
    worker_service = DistributedWorkerService(
        service=service,
        queue_name="default",
        poll_interval_seconds=0.0,
        max_messages_per_cycle=1,
    )
    with pytest.raises(ValueError, match="invalid literal for int"):
        _ = worker_service.concurrency

    zero_limits = ResourceLimits(max_workers=0)
    zero_service = SimpleNamespace(limits=zero_limits, process_next=lambda **_k: None)
    zero_worker = DistributedWorkerService(
        service=zero_service,
        queue_name="default",
        poll_interval_seconds=0.0,
        max_messages_per_cycle=1,
    )
    assert zero_worker.concurrency == 1


def test_distributed_persistence_rolls_back_and_single_import_lookup(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import iocparser.infrastructure.persistence_distributed as distributed
    from iocparser.infrastructure.persistence_distributed import SQLAlchemyDistributedJobService
    from iocparser.infrastructure.persistence_schema import DistributedJobModel

    class Unit:
        def __init__(self, exc: BaseException) -> None:
            self.exc = exc
            self.session = SimpleNamespace(execute=lambda _stmt: _raise(exc))
            self.rollback_called = False
            self.close_called = False

        def rollback(self) -> None:
            self.rollback_called = True

        def close(self) -> None:
            self.close_called = True

    request = PipelineJobRequest(input_kind="text", source_value="payload", job_id="job")
    envelope = QueueEnvelope(request=request, queue_backend="memory", queue_name="default")

    create_unit = Unit(RuntimeError("create failed"))
    monkeypatch.setattr(distributed, "SQLAlchemyUnitOfWork", lambda _uri: create_unit)
    service = SQLAlchemyDistributedJobService("sqlite:///unused.db")
    monkeypatch.setattr(
        service,
        "_create_or_get_job_inner",
        lambda **_kwargs: _raise(RuntimeError("create failed")),
    )
    with pytest.raises(RuntimeError):
        service.create_or_get_job(envelope=envelope, receipt_id="receipt")
    assert create_unit.rollback_called is True
    assert create_unit.close_called is True

    create_interrupt_unit = Unit(KeyboardInterrupt())
    monkeypatch.setattr(distributed, "SQLAlchemyUnitOfWork", lambda _uri: create_interrupt_unit)
    monkeypatch.setattr(
        service,
        "_create_or_get_job_inner",
        lambda **_kwargs: _raise(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        service.create_or_get_job(envelope=envelope, receipt_id="receipt")
    assert create_interrupt_unit.rollback_called is False
    assert create_interrupt_unit.close_called is True

    interrupt_unit = Unit(KeyboardInterrupt())
    monkeypatch.setattr(distributed, "SQLAlchemyUnitOfWork", lambda _uri: interrupt_unit)
    with pytest.raises(KeyboardInterrupt):
        service._transition(job_id="job", status="running", attempts=1)
    assert interrupt_unit.rollback_called is False
    assert interrupt_unit.close_called is True

    transition_unit = Unit(RuntimeError("transition failed"))
    monkeypatch.setattr(distributed, "SQLAlchemyUnitOfWork", lambda _uri: transition_unit)
    with pytest.raises(RuntimeError):
        service._transition(job_id="job", status="running", attempts=1)
    assert transition_unit.rollback_called is True
    assert transition_unit.close_called is True

    from iocparser.infrastructure.persistence_schema import SQLAlchemyUnitOfWork as RealUnitOfWork

    monkeypatch.setattr(distributed, "SQLAlchemyUnitOfWork", RealUnitOfWork)
    db_uri = _fresh_db(tmp_path, "distributed-import.db")
    engine = create_engine(db_uri, future=True)
    try:
        with Session(engine) as session:
            session.add(
                DistributedJobModel(
                    **_job_model_kwargs(
                        job_id="public#history:archive",
                        payload_json=json.dumps({"request": {"job_id": "public"}}),
                    ),
                ),
            )
            session.commit()
        found = SQLAlchemyDistributedJobService(db_uri).get_job(job_id="public")
        assert found is not None
        assert found.job_id == "public"
    finally:
        engine.dispose()


def test_history_private_edges_with_real_models(tmp_path) -> None:
    from iocparser.infrastructure.persistence.history import ops
    from iocparser.infrastructure.persistence_batch import BatchJobModel, FailedBatchItemModel
    from iocparser.infrastructure.persistence_models import IOCModel
    from iocparser.infrastructure.persistence_schema import (
        DeadLetterJobModel,
        DistributedJobModel,
        RunModel,
        SourceModel,
    )

    db_uri = _fresh_db(tmp_path, "history-real.db")
    engine = create_engine(db_uri, future=True)
    now = datetime.now(UTC)
    try:
        with Session(engine) as session:
            session.add(
                DeadLetterJobModel(
                    **_dead_letter_model_kwargs(
                        job_id="dead-marker",
                        payload_json=json.dumps(
                            {ops.HISTORY_IMPORT_MARKER_KEY: {"archive_id": "legacy-archive"}},
                        ),
                    ),
                ),
            )
            session.commit()
            assert ops._has_legacy_archive_collision(session, archive_id="legacy-archive")

            batch = BatchJobModel(
                source_kind="url",
                started_at=now,
                finished_at=now,
                total_inputs=1,
                successful_inputs=0,
                failed_inputs=1,
                retry_attempt=2,
                status="partial",
                config_json="{}",
                error_summary_json='{"RuntimeError": 1}',
                metrics_json='{"duration_ms": 5}',
            )
            session.add(batch)
            session.flush()
            batch_row = {
                "source_kind": "url",
                "started_at": now,
                "finished_at": now,
                "total_inputs": 1,
                "successful_inputs": 0,
                "failed_inputs": 1,
                "retry_attempt": 2,
                "status": "partial",
                "config_json": "{}",
                "error_summary_json": '{"RuntimeError": 1}',
                "metrics_json": '{"duration_ms": 5}',
            }
            assert ops._existing_batch_job(session, batch_row) == batch
            assert ops._batch_job_signature(batch_row)[0] == "url"

            failed = FailedBatchItemModel(
                batch_job_id=batch.id,
                source_value="https://failed.example",
                error_type="RuntimeError",
                error_message="failed",
                retry_attempt=2,
                created_at=now,
            )
            session.add(failed)
            session.flush()
            assert (
                ops._existing_failed_batch_item(
                    session,
                    {
                        "source_value": "https://failed.example",
                        "error_type": "RuntimeError",
                        "error_message": "failed",
                        "retry_attempt": 2,
                        "created_at": now,
                    },
                    batch_job_id=batch.id,
                )
                == failed
            )

            source = SourceModel(
                kind="file",
                value="sample.txt",
                value_search="sample.txt",
                first_seen=now,
                last_seen=now,
            )
            session.add(source)
            session.flush()
            run = RunModel(
                source_id=source.id,
                batch_job_id=None,
                started_at=now,
                finished_at=now,
                tool_version="test",
                options_json='{"mode": "existing"}',
                normal_ioc_count=0,
                warning_ioc_count=0,
                processed_items=1,
                successful_items=1,
                failed_items=0,
                partial_error_count=0,
                duration_ms=0,
                status="success",
                error_message="",
            )
            session.add(run)
            session.flush()
            ioc = IOCModel(
                ioc_type="domains",
                value="history.example",
                value_search="history.example",
                is_warning=False,
                warning_list="",
                warning_description="",
            )
            session.add(ioc)
            session.flush()
            assert (
                ops._existing_ioc(
                    session,
                    {
                        "ioc_type": "domains",
                        "value": "history.example",
                        "is_warning": "false",
                        "warning_list": "",
                        "warning_description": "",
                    },
                )
                == ioc
            )
            assert (
                ops._existing_run(
                    session,
                    {
                        "started_at": now,
                        "finished_at": now,
                        "tool_version": "test",
                        "options_json": '{"mode": "incoming"}',
                        "normal_ioc_count": 0,
                        "warning_ioc_count": 0,
                        "processed_items": 1,
                        "successful_items": 1,
                        "failed_items": 0,
                        "partial_error_count": 0,
                        "duration_ms": 0,
                        "status": "success",
                        "error_message": "",
                    },
                    source_id=source.id,
                    batch_job_id=None,
                    ioc_signature=(),
                    archive_id="archive",
                    original_id=99,
                    same_origin=False,
                )
                is None
            )

            marker_payload = json.dumps(
                {
                    "request": {"job_id": "public-job"},
                    ops.HISTORY_IMPORT_MARKER_KEY: {"archive_id": "archive", "original_id": 1},
                },
            )
            distributed_model = DistributedJobModel(
                **_job_model_kwargs(job_id="internal-job", payload_json=marker_payload),
            )
            dead_model = DeadLetterJobModel(
                **_dead_letter_model_kwargs(job_id="internal-dead", payload_json=marker_payload),
            )
            session.add_all([distributed_model, dead_model])
            session.flush()
            assert ops._public_job_id(distributed_model) == "public-job"
            assert ops._public_job_id(dead_model) == "public-job"

            same_origin_distributed = DistributedJobModel(
                **_job_model_kwargs(job_id="same-origin-job", payload_json="{}"),
            )
            session.add(same_origin_distributed)
            session.flush()
            assert (
                ops._existing_distributed_job(
                    session,
                    {"id": 10, "job_id": "same-origin-job"},
                    archive_id="archive",
                    same_origin=True,
                )
                == same_origin_distributed
            )

            mismatched_dead = DeadLetterJobModel(
                **_dead_letter_model_kwargs(
                    job_id="payload-mismatch",
                    payload_json='{"payload": "stored"}',
                    dead_lettered_at=now,
                ),
            )
            session.add(mismatched_dead)
            session.flush()
            assert (
                ops._existing_dead_letter_job(
                    session,
                    {
                        "id": 11,
                        "job_id": "payload-mismatch",
                        "dead_lettered_at": now,
                        "correlation_id": "corr",
                        "queue_backend": "filesystem",
                        "queue_name": "default",
                        "source_value": "payload",
                        "attempts": 1,
                        "max_attempts": 3,
                        "error_code": "ERR",
                        "error_category": "test",
                        "error_message": "boom",
                        "retryable": "false",
                        "payload_json": '{"payload": "incoming"}',
                    },
                    archive_id="archive",
                    same_origin=True,
                )
                is None
            )
            matching_dead = DeadLetterJobModel(
                **_dead_letter_model_kwargs(
                    job_id="payload-mismatch",
                    payload_json='{"payload": "incoming"}',
                    dead_lettered_at=now,
                ),
            )
            session.add(matching_dead)
            session.flush()
            assert (
                ops._existing_dead_letter_job(
                    session,
                    {
                        "id": 12,
                        "job_id": "payload-mismatch",
                        "dead_lettered_at": now,
                        "correlation_id": "corr",
                        "queue_backend": "filesystem",
                        "queue_name": "default",
                        "source_value": "payload",
                        "attempts": 1,
                        "max_attempts": 3,
                        "error_code": "ERR",
                        "error_category": "test",
                        "error_message": "boom",
                        "retryable": False,
                        "payload_json": '{"payload": "incoming"}',
                    },
                    archive_id="archive",
                    same_origin=True,
                )
                == matching_dead
            )
    finally:
        engine.dispose()


def test_history_import_skip_and_same_origin_batch_paths() -> None:
    from iocparser.infrastructure.persistence.history import ops

    now = datetime.now(UTC)
    row = {
        "id": 5,
        "source_kind": "url",
        "started_at": now,
        "finished_at": now,
        "total_inputs": 1,
        "successful_inputs": 1,
        "failed_inputs": 0,
        "retry_attempt": 0,
        "status": "success",
        "config_json": '{"url_workers": 2}',
        "error_summary_json": "{}",
        "metrics_json": "{}",
    }
    matching_candidate = SimpleNamespace(id=103, config_json='{"url_workers": 2}')

    class BatchSession:
        def execute(self, _stmt: object) -> _ScalarResult:
            return _ScalarResult([101, 102, 103])

        def get(self, _model: object, model_id: int) -> object | None:
            if model_id == 101:
                return None
            if model_id == 102:
                return SimpleNamespace(id=102, config_json='{"url_workers": 4}')
            return matching_candidate

        def add(self, _model: object) -> None:
            raise AssertionError("existing same-origin batch should be reused")

        def flush(self) -> None:
            raise AssertionError("existing same-origin batch should be reused")

    inserted, batch_map = ops._import_batch_jobs(
        BatchSession(),
        [row],
        archive_id="archive",
        same_origin=True,
    )
    assert inserted == 0
    assert batch_map == {5: 103}

    inserted_runs, run_map = ops._import_runs(
        SimpleNamespace(),
        [{"id": 1, "source_id": 55}],
        archive_id="archive",
        same_origin=False,
        source_map={},
        batch_map={},
        run_ioc_rows=[
            {"run_id": "bad", "ioc_id": 1},
            {"run_id": 1, "ioc_id": 99},
        ],
        ioc_map={},
    )
    assert inserted_runs == 0
    assert run_map == {}

    assert (
        ops._import_run_iocs(
            SimpleNamespace(),
            [{"run_id": 1, "ioc_id": 2}],
            run_map={},
            ioc_map={},
        )
        == 0
    )
    assert (
        ops._import_failed_batch_items(SimpleNamespace(), [{"batch_job_id": 3}], batch_map={}) == 0
    )


def test_strict_coverage_option_and_metadata_edge_helpers() -> None:
    from iocparser.api_persistence_query import bool_option, validated_ioc_type_filter
    from iocparser.cli_output_rendering import (
        int_run_metadata_value,
        optional_int_run_metadata_value,
    )
    from iocparser.cli_processing_url_reports import bool_value
    from iocparser.cli_runtime_defaults import parse_http_mapping
    from iocparser.client_persistence import validated_severity_values
    from iocparser.domain.distributed import QueueEnvelope
    from iocparser.shared_utils import validated_severity_filters

    assert bool_option("ON") is True
    assert validated_ioc_type_filter("   ") is None
    assert int_run_metadata_value({"items": "   "}, "items", 3) == 3
    assert optional_int_run_metadata_value({"duration": True}, "duration") is None
    assert optional_int_run_metadata_value({"duration": "   "}, "duration") is None
    assert optional_int_run_metadata_value({"duration": "bad"}, "duration") is None
    assert validated_severity_filters("High,LOW") == ("high", "low")
    assert bool_value(None, default=True) is True
    assert bool_value(1) is True
    assert parse_http_mapping("X-Test: value", separator=":") == {"X-Test": "value"}
    assert validated_severity_values(("HIGH", "low")) == ("high", "low")

    with pytest.raises(TypeError, match="bool-compatible"):
        QueueEnvelope.from_record(
            {
                "request": {
                    "input_kind": "text",
                    "source_value": "payload",
                    "persist": "maybe",
                },
            },
        )


def test_strict_coverage_infrastructure_edge_helpers(tmp_path) -> None:
    from iocparser.infrastructure.http_download import RequestsURLDownloader
    from iocparser.infrastructure.persistence_batch import _int_report_value
    from iocparser.infrastructure.persistence_repository_support import (
        int_metadata_value,
        optional_int_metadata_value,
    )
    from iocparser.infrastructure.queue_filesystem import (
        FilesystemQueueAdapter,
        _validate_queue_name,
    )
    from iocparser.infrastructure.queue_rabbitmq import _payload_text

    downloader = RequestsURLDownloader(timeout=12.0)
    clone = downloader.with_policy(timeout=None)
    assert clone.timeout == downloader.timeout

    assert _int_report_value({"total": "   "}, "total", 9) == 9
    metadata = {"count": "   "}
    assert int_metadata_value(metadata, "count", 4) == 4
    assert optional_int_metadata_value(metadata, "count") is None

    with pytest.raises(ValueError, match="queue name"):
        _validate_queue_name("..")

    adapter = FilesystemQueueAdapter(tmp_path / "queues")
    pending_dir = adapter._queue_dir("default", "pending")
    dead_dir = adapter._queue_dir("default", "dead")
    invalid_payload = pending_dir / "bad.json"
    invalid_payload.write_text("{}", encoding="utf-8")
    (dead_dir / "bad.json").write_text("existing", encoding="utf-8")

    adapter._quarantine_invalid_payload("default", invalid_payload)

    assert not invalid_payload.exists()
    assert len(list(dead_dir.glob("bad*.json"))) == 2
    assert _payload_text(b"\xff") == repr(b"\xff")


def test_history_import_updates_stale_ioc_search_value(tmp_path) -> None:
    from iocparser.infrastructure.persistence.history import ops
    from iocparser.infrastructure.persistence_models import IOCModel
    from iocparser.infrastructure.persistence_repository_support import normalize_ioc_search

    db_uri = _fresh_db(tmp_path, "history-ioc-search.db")
    engine = create_engine(db_uri, future=True)
    try:
        with Session(engine) as session:
            ioc = IOCModel(
                ioc_type="domains",
                value="Example.COM",
                value_search="stale",
                is_warning=False,
                warning_list="",
                warning_description="",
            )
            session.add(ioc)
            session.flush()

            inserted, ioc_map = ops._import_iocs(
                session,
                [
                    {
                        "id": 42,
                        "ioc_type": "domains",
                        "value": "Example.COM",
                        "is_warning": False,
                        "warning_list": "",
                        "warning_description": "",
                    },
                ],
            )

            assert inserted == 0
            assert ioc_map == {42: ioc.id}
            assert ioc.value_search == normalize_ioc_search("Example.COM")
    finally:
        engine.dispose()


def test_streaming_mmap_general_exception_is_logged_and_reraised(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iocparser.infrastructure.streaming import StreamingIOCExtractor

    text_file = tmp_path / "mmap-error.txt"
    text_file.write_text("https://example.com/path", encoding="utf-8")
    extractor = StreamingIOCExtractor(chunk_size=8, overlap=0, defang=False)
    monkeypatch.setattr(
        extractor.extractor,
        "extract_all",
        lambda *_args, **_kwargs: _raise(RuntimeError("mmap failed")),
    )

    with pytest.raises(RuntimeError, match="mmap failed"):
        extractor.extract_from_mmap(text_file)


def test_warninglist_matching_empty_attribute_names_short_circuits() -> None:
    from iocparser.infrastructure.warninglists_matching import WarningListMatchingMixin

    class Matcher(WarningListMatchingMixin):
        IOC_TYPE_MAPPING = {}
        MISP_TYPE_MAPPING = {}

        def _clean_defanged_value(self, value: str) -> str:
            self.cleaned_value = value
            return value

    matcher = Matcher()

    assert (
        matcher._is_list_applicable(
            {"matching_attributes": [" ", {"name": ""}]},
            ["domain"],
            "domains",
        )
        is False
    )


def test_duplicate_file_processing_interrupts_and_generic_errors(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import iocparser.cli_processing_files as files

    sample = tmp_path / "sample.txt"
    sample.write_text("payload", encoding="utf-8")
    request = files.MultiFileProcessingRequest()
    options = request.to_processing_options()

    monkeypatch.setattr(
        files,
        "_streaming_result",
        lambda *_args, **_kwargs: _raise(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        files._process_duplicate_streaming_files(
            [sample],
            options=options,
            warning_service=None,
            request=request,
        )

    monkeypatch.setattr(
        files,
        "process_file",
        lambda *_args, **_kwargs: _raise(RuntimeError("batch failed")),
    )
    results = files._process_duplicate_files(
        [sample],
        reader=SimpleNamespace(),
        warning_service=None,
        request=request,
    )
    assert results.entries[0].normal_iocs == {}
    assert results.entries[0].warning_iocs == {}
    assert results.entries[0].error_message == "batch failed"

    monkeypatch.setattr(
        files,
        "process_file",
        lambda *_args, **_kwargs: _raise(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        files._process_duplicate_files(
            [sample],
            reader=SimpleNamespace(),
            warning_service=None,
            request=request,
        )


def test_duplicate_file_processing_propagates_validation_errors(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import iocparser.cli_processing_files as files
    from iocparser.errors import FileSizeError

    sample = tmp_path / "sample.txt"
    sample.write_text("payload", encoding="utf-8")
    request = files.MultiFileProcessingRequest()

    monkeypatch.setattr(
        files,
        "process_file",
        lambda *_args, **_kwargs: _raise(FileSizeError(1.0, 0.5)),
    )
    with pytest.raises(FileSizeError):
        files._process_duplicate_files(
            [sample],
            reader=SimpleNamespace(),
            warning_service=None,
            request=request,
        )


def test_pipeline_url_preparation_derives_missing_hash_metadata(tmp_path) -> None:
    import hashlib

    from iocparser.domain.pipeline import ResourceLimits
    from iocparser.pipeline_worker_support import _prepare_url_input

    payload_path = tmp_path / "download.txt"
    payload_path.write_bytes(b"url payload")
    expected_hash = hashlib.sha256(payload_path.read_bytes()).hexdigest()

    class Downloader:
        def __init__(self, metadata: dict[str, object]) -> None:
            self.last_download_metadata = metadata

        def download(self, _url: str) -> str:
            return str(payload_path)

    prepared_without_hash = _prepare_url_input(
        client=SimpleNamespace(
            downloader=Downloader({"input_size": payload_path.stat().st_size}),
        ),
        limits=ResourceLimits(max_input_size_bytes=100),
        url="https://example.com/report",
    )
    assert prepared_without_hash.content_hash == expected_hash
    assert prepared_without_hash.fingerprint == expected_hash[:16]

    prepared_without_fingerprint = _prepare_url_input(
        client=SimpleNamespace(
            downloader=Downloader(
                {
                    "input_size": payload_path.stat().st_size,
                    "content_hash": expected_hash,
                },
            ),
        ),
        limits=ResourceLimits(max_input_size_bytes=100),
        url="https://example.com/report",
    )
    assert prepared_without_fingerprint.fingerprint == expected_hash[:16]


def test_worker_config_bool_env_false_value(monkeypatch: pytest.MonkeyPatch) -> None:
    from iocparser.worker_config_support import bool_env

    monkeypatch.setenv("IOCPARSER_TEST_BOOL", "off")

    assert bool_env("IOCPARSER_TEST_BOOL", default=True) is False


def test_batch_listings_break_started_at_ties_deterministically(tmp_path) -> None:
    """Batch listings with a LIMIT must cut ties on started_at by id, not engine order.

    Regression: list_failed_batches/list_batch_jobs ordered only by started_at,
    so which rows survived a LIMIT (and their order) was engine-defined when
    timestamps collided. The id tiebreaker makes the cutoff deterministic.
    """
    from iocparser.infrastructure.persistence.history import ops
    from iocparser.infrastructure.persistence_batch import BatchJobModel

    db_uri = _fresh_db(tmp_path, "batch-ties.db")
    engine = create_engine(db_uri, future=True)
    shared = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    try:
        with Session(engine) as session:
            for _ in range(4):
                session.add(
                    BatchJobModel(
                        source_kind="url",
                        started_at=shared,
                        finished_at=shared,
                        total_inputs=1,
                        successful_inputs=0,
                        failed_inputs=1,
                        retry_attempt=0,
                        status="partial",
                        config_json="{}",
                        error_summary_json="{}",
                        metrics_json="{}",
                    )
                )
            session.commit()
            all_ids = sorted(row.id for row in session.execute(select(BatchJobModel)).scalars())
    finally:
        engine.dispose()

    expected = sorted(all_ids, reverse=True)[:2]
    failed_ids = [job.batch_job_id for job in ops.list_failed_batches(db_uri, limit=2)]
    listed_ids = [job.batch_job_id for job in ops.list_batch_jobs(db_uri, limit=2)]
    assert failed_ids == expected
    assert listed_ids == expected


def test_plugin_multi_file_batch_survives_single_file_failure(tmp_path, monkeypatch) -> None:
    """A configured-plugin -m batch must skip a failing file, not abort the run.

    Regression: the plugin branch of process_multiple_files_payload had no
    per-file try/except (unlike every other multi-file path), so one raising
    file lost the results of every other file in the batch. Interrupts must
    still propagate.
    """
    from iocparser import cli_processing_files
    from iocparser.domain.results import IOC
    from iocparser.errors import FileProcessingError

    good1 = tmp_path / "good1.txt"
    good1.write_text("1.2.3.4")
    bad = tmp_path / "bad.txt"
    bad.write_text("boom")
    good2 = tmp_path / "good2.txt"
    good2.write_text("5.6.7.8")
    args = SimpleNamespace(multiple=[str(good1), str(bad), str(good2)])

    def run_with(failure: BaseException):
        class FlakyPluginClient:
            def extract_result_from_file(
                self, source_value: str, **_kwargs: object
            ) -> ExtractionResult:
                if source_value == str(bad):
                    raise failure
                value = "1.2.3.4" if source_value == str(good1) else "5.6.7.8"
                return ExtractionResult(iocs=(IOC.from_raw("ip", value),))

        monkeypatch.setattr(
            cli_processing_files, "_plugin_client", lambda *_a, **_k: FlakyPluginClient()
        )
        return cli_processing_files.process_multiple_files_payload(
            args, reader=SimpleNamespace(), warning_service=None
        )

    # Both a domain file error and an unexpected error skip only the bad file.
    for failure in (FileProcessingError("bad.txt", "corrupt"), RuntimeError("plugin blew up")):
        payload = run_with(failure)
        extracted = {value for values in payload.normal_iocs.values() for value in values}
        assert "1.2.3.4" in extracted
        assert "5.6.7.8" in extracted

    # Interrupts must not be swallowed by the per-file guard.
    with pytest.raises(KeyboardInterrupt):
        run_with(KeyboardInterrupt())
