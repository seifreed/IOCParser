from __future__ import annotations

import os
import threading
from pathlib import Path
from types import SimpleNamespace as _SimpleNamespace

import pytest

from iocparser.distributed_pipeline import DistributedPipelineService
from iocparser.domain.pipeline import PipelineJobRequest
from iocparser.infrastructure.queue_filesystem import FilesystemQueueAdapter
from iocparser.pipeline_worker import PipelineWorker
from iocparser.worker_config import WorkerServiceConfig
from iocparser.worker_main import main
from iocparser.worker_service import DistributedWorkerService


class _Env:
    def __init__(self, **values: str) -> None:
        self.values = values
        self.previous = {key: os.environ.get(key) for key in values}

    def __enter__(self):
        for key, value in self.values.items():
            os.environ[key] = value

    def __exit__(self, exc_type, exc, tb):
        del exc_type, exc, tb
        for key, old in self.previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def test_worker_config_from_env_and_limits(tmp_path: Path) -> None:
    with _Env(
        IOCPARSER_WORKER_QUEUE_BACKEND="filesystem",
        IOCPARSER_WORKER_QUEUE_NAME="ingest",
        IOCPARSER_WORKER_QUEUE_PATH=str(tmp_path / "queue"),
        IOCPARSER_WORKER_DB_URI=f"sqlite:///{tmp_path / 'worker.sqlite'}",
        IOCPARSER_WORKER_POLL_INTERVAL_SECONDS="0.25",
        IOCPARSER_WORKER_MAX_MESSAGES_PER_CYCLE="3",
        IOCPARSER_WORKER_MAX_CYCLES="2",
        IOCPARSER_WORKER_CONCURRENCY="4",
        IOCPARSER_WORKER_TELEMETRY_MODE="none",
        IOCPARSER_WORKER_MAX_INPUT_SIZE_BYTES="1024",
        IOCPARSER_WORKER_MAX_INPUT_SECONDS="1.5",
        IOCPARSER_WORKER_MEMORY_LIMIT_BYTES="2048",
        IOCPARSER_WORKER_CPU_SECONDS="30",
        IOCPARSER_WORKER_HARD_TIMEOUT_SECONDS="10",
        IOCPARSER_WORKER_MAX_QUEUE_SIZE="9",
        IOCPARSER_WORKER_SKIP_PROCESSED="true",
    ):
        config = WorkerServiceConfig.from_sources()
    assert config.queue_name == "ingest"
    assert config.max_cycles == 2
    assert config.concurrency == 4
    limits = config.resource_limits()
    assert limits.max_workers == 4
    assert limits.max_input_size_bytes == 1024
    assert limits.skip_processed is True


def test_worker_config_blank_env_strings_use_defaults() -> None:
    with _Env(
        IOCPARSER_WORKER_QUEUE_BACKEND="",
        IOCPARSER_WORKER_QUEUE_NAME="",
        IOCPARSER_WORKER_QUEUE_URL="",
        IOCPARSER_WORKER_QUEUE_PATH="",
        IOCPARSER_WORKER_DEAD_LETTER_QUEUE_URL="",
        IOCPARSER_WORKER_DB_URI="",
        IOCPARSER_WORKER_TELEMETRY_MODE="",
    ):
        config = WorkerServiceConfig.from_sources()

    assert config.queue_backend == "filesystem"
    assert config.queue_name == "default"
    assert config.queue_url is None
    assert config.queue_path == ".iocparser-queue"
    assert config.dead_letter_queue_url is None
    assert config.db_uri is None
    assert config.telemetry_mode == "logging"


def test_worker_config_from_ini_file(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        """[database]
uri = sqlite:///from-ini.db
[worker]
queue_backend = rabbitmq
queue_name = ingest
queue_url = amqp://guest:guest@localhost:5672/
queue_path = /tmp/queue
dead_letter_queue_url = amqp://guest:guest@localhost:5672/dead
poll_interval_seconds = 0.25
max_messages_per_cycle = 5
max_cycles = 7
concurrency = 3
telemetry_mode = none
[runtime]
max_input_size_bytes = 4096
memory_limit_bytes = 8192
cpu_seconds = 60
hard_timeout_seconds = 15
max_queue_size = 11
skip_processed = true
[network]
max_input_seconds = 2.5
""",
        encoding="utf-8",
    )
    config = WorkerServiceConfig.from_sources(str(config_path))
    assert config.config_path == config_path
    assert config.queue_backend == "rabbitmq"
    assert config.queue_name == "ingest"
    assert config.queue_url == "amqp://guest:guest@localhost:5672/"
    assert config.max_messages_per_cycle == 5
    assert config.max_cycles == 7
    assert config.concurrency == 3
    assert config.db_uri == "sqlite:///from-ini.db"
    assert config.max_input_seconds == 2.5
    assert config.memory_limit_bytes == 8192
    assert config.max_queue_size == 11
    assert config.skip_processed is True


def test_worker_config_runtime_section_preserves_network_queue_limits(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        """[network]
max_queue_size = 17
skip_processed = true
[runtime]
max_input_size_bytes = 4096
""",
        encoding="utf-8",
    )

    config = WorkerServiceConfig.from_sources(str(config_path))

    assert config.max_input_size_bytes == 4096
    assert config.max_queue_size == 17
    assert config.skip_processed is True


def test_worker_config_preserves_zero_poll_interval(tmp_path: Path) -> None:
    with _Env(IOCPARSER_WORKER_POLL_INTERVAL_SECONDS="0"):
        env_config = WorkerServiceConfig.from_sources()
    assert env_config.poll_interval_seconds == 0.0

    config_path = tmp_path / "iocparser.ini"
    config_path.write_text("[worker]\npoll_interval_seconds = 0\n", encoding="utf-8")
    file_config = WorkerServiceConfig.from_sources(str(config_path))
    assert file_config.poll_interval_seconds == 0.0


def test_worker_config_sanitizes_negative_operational_limits() -> None:
    with _Env(
        IOCPARSER_WORKER_POLL_INTERVAL_SECONDS="-0.25",
        IOCPARSER_WORKER_MAX_MESSAGES_PER_CYCLE="-3",
        IOCPARSER_WORKER_CONCURRENCY="-4",
        IOCPARSER_WORKER_MAX_QUEUE_SIZE="-9",
    ):
        config = WorkerServiceConfig.from_sources()

    assert config.poll_interval_seconds == 1.0
    assert config.max_messages_per_cycle == 1
    assert config.concurrency == 1
    assert config.max_queue_size == 64


def test_worker_config_rejects_invalid_boolean_env() -> None:
    with _Env(IOCPARSER_WORKER_SKIP_PROCESSED="maybe"):
        with pytest.raises(ValueError, match="IOCPARSER_WORKER_SKIP_PROCESSED"):
            WorkerServiceConfig.from_sources()


def test_worker_config_whitespace_env_values_use_defaults() -> None:
    with _Env(
        IOCPARSER_WORKER_POLL_INTERVAL_SECONDS="   ",
        IOCPARSER_WORKER_MAX_MESSAGES_PER_CYCLE="   ",
        IOCPARSER_WORKER_SKIP_PROCESSED="   ",
    ):
        config = WorkerServiceConfig.from_sources()

    assert config.poll_interval_seconds == 1.0
    assert config.max_messages_per_cycle == 1
    assert config.skip_processed is False


def test_worker_config_uses_default_ini_path(tmp_path: Path) -> None:
    config_path = tmp_path / "iocparser.ini"
    config_path.write_text(
        """[worker]
queue_backend = filesystem
queue_name = default-path
""",
        encoding="utf-8",
    )
    original_cwd = Path.cwd()
    original_config = os.environ.pop("IOCPARSER_CONFIG", None)
    try:
        os.chdir(tmp_path)
        config = WorkerServiceConfig.from_sources()
    finally:
        os.chdir(original_cwd)
        if original_config is not None:
            os.environ["IOCPARSER_CONFIG"] = original_config
    assert config.config_path == config_path
    assert config.queue_name == "default-path"


def test_worker_service_run_once_and_forever(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'runtime.sqlite'}"
    queue = FilesystemQueueAdapter(tmp_path / "queue")
    service = DistributedPipelineService(queue_adapter=queue, db_uri=db_uri)
    request = PipelineJobRequest(
        input_kind="text",
        source_value="ioc test",
        persist=True,
        db_uri=db_uri,
        check_warnings=False,
    )
    service.submit(request, queue_name="ingest")
    worker_service = DistributedWorkerService(
        service=service,
        queue_name="ingest",
        poll_interval_seconds=0.0,
        max_messages_per_cycle=2,
    )
    assert worker_service.run_once() == 1
    stop_event = threading.Event()
    stop_event.set()
    assert worker_service.run_forever(stop_event=stop_event, max_cycles=1) == 0
    empty_service = DistributedWorkerService(
        service=DistributedPipelineService(
            queue_adapter=FilesystemQueueAdapter(tmp_path / "empty")
        ),
        queue_name="empty",
        poll_interval_seconds=0.0,
        max_messages_per_cycle=1,
    )
    assert empty_service.run_forever(max_cycles=2) == 0


def test_worker_service_from_config_and_main(tmp_path: Path) -> None:
    db_uri = f"sqlite:///{tmp_path / 'main.sqlite'}"
    queue_path = tmp_path / "worker-queue"
    queue = FilesystemQueueAdapter(queue_path)
    seed_service = DistributedPipelineService(queue_adapter=queue, db_uri=db_uri)
    seed_service.submit(
        PipelineJobRequest(
            input_kind="text",
            source_value="worker service input",
            persist=True,
            db_uri=db_uri,
            check_warnings=False,
        ),
        queue_name="worker",
    )
    config = WorkerServiceConfig(
        queue_backend="filesystem",
        queue_name="worker",
        queue_path=str(queue_path),
        db_uri=db_uri,
        poll_interval_seconds=0.0,
        max_messages_per_cycle=1,
        max_cycles=1,
        telemetry_mode="logging",
    )
    worker_service = DistributedWorkerService.from_config(config, worker=PipelineWorker())
    assert worker_service.run_forever(max_cycles=1) == 1

    with _Env(
        IOCPARSER_WORKER_QUEUE_BACKEND="filesystem",
        IOCPARSER_WORKER_QUEUE_NAME="worker-main",
        IOCPARSER_WORKER_QUEUE_PATH=str(tmp_path / "worker-main-queue"),
        IOCPARSER_WORKER_MAX_CYCLES="1",
        IOCPARSER_WORKER_POLL_INTERVAL_SECONDS="0",
        IOCPARSER_WORKER_TELEMETRY_MODE="none",
    ):
        assert main() == 0

    file_config = tmp_path / "worker.ini"
    file_config.write_text(
        "\n".join(
            [
                "[worker]",
                "queue_backend = filesystem",
                f"queue_path = {tmp_path / 'worker-main-config-queue'}",
                "queue_name = worker-main-config",
                "max_cycles = 1",
                "poll_interval_seconds = 0",
                "telemetry_mode = none",
            ]
        ),
        encoding="utf-8",
    )
    queue = FilesystemQueueAdapter(tmp_path / "worker-main-config-queue")
    DistributedPipelineService(queue_adapter=queue).submit(
        PipelineJobRequest(
            input_kind="text",
            source_value="config file worker",
            persist=False,
            check_warnings=False,
        ),
        queue_name="worker-main-config",
    )
    original_argv = os.sys.argv[:]
    try:
        os.sys.argv = ["iocparser-worker", "--config", str(file_config)]
        assert main() == 0
    finally:
        os.sys.argv = original_argv


def test_worker_main_reports_invalid_backend_without_traceback() -> None:
    # Regression: an unknown IOCPARSER_WORKER_QUEUE_BACKEND raised a bare ValueError
    # straight out of the daemon entrypoint as a stack trace. main() must catch the
    # startup/config error and return a non-zero exit code instead.
    with _Env(
        IOCPARSER_WORKER_QUEUE_BACKEND="bogus",
        IOCPARSER_WORKER_MAX_CYCLES="1",
        IOCPARSER_WORKER_POLL_INTERVAL_SECONDS="0",
    ):
        assert main() == 1


def test_worker_main_handles_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    def _interrupt(*_args: object, **_kwargs: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(DistributedWorkerService, "run_forever", _interrupt)
    with _Env(
        IOCPARSER_WORKER_QUEUE_BACKEND="filesystem",
        IOCPARSER_WORKER_MAX_CYCLES="1",
        IOCPARSER_WORKER_POLL_INTERVAL_SECONDS="0",
    ):
        assert main() == 0


def test_worker_service_survives_thread_exception():
    """Worker loop must not die when a thread raises an exception."""
    calls = [0]

    def fail_once(**_kwargs):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("boom")

    svc = _SimpleNamespace(process_next=fail_once, limits=_SimpleNamespace(max_workers=2))
    w = DistributedWorkerService(
        service=svc, queue_name="t", poll_interval_seconds=0.0, max_messages_per_cycle=1
    )
    assert w.run_forever(max_cycles=2) == 0


def test_worker_service_single_worker_sleep_on_empty():
    """Single-worker path must sleep when no messages are processed."""
    svc = _SimpleNamespace(process_next=lambda *_args, **_kwargs: None)
    w = DistributedWorkerService(
        service=svc, queue_name="s", poll_interval_seconds=0.0, max_messages_per_cycle=1
    )
    assert w.concurrency == 1
    assert w.run_forever(max_cycles=2) == 0


def test_worker_service_zero_max_cycles_does_not_process():
    calls = [0]

    def process_next(**_kwargs):
        calls[0] += 1
        return "processed"

    svc = _SimpleNamespace(process_next=process_next)
    w = DistributedWorkerService(
        service=svc, queue_name="zero", poll_interval_seconds=0.0, max_messages_per_cycle=1
    )

    assert w.run_forever(max_cycles=0) == 0
    assert calls == [0]


def test_worker_service_concurrent_positive_result():
    """Concurrent path must take short sleep when messages are processed."""
    svc = _SimpleNamespace(
        process_next=lambda *_args, **_kwargs: "ok", limits=_SimpleNamespace(max_workers=2)
    )
    w = DistributedWorkerService(
        service=svc, queue_name="c", poll_interval_seconds=0.0, max_messages_per_cycle=1
    )
    assert w.run_forever(max_cycles=2) == 4


def test_worker_service_survives_run_once_exception():
    """Concurrent loop must surface run_once worker exceptions."""
    svc = _SimpleNamespace(
        process_next=lambda *_args, **_kwargs: None, limits=_SimpleNamespace(max_workers=2)
    )
    w = DistributedWorkerService(
        service=svc, queue_name="r", poll_interval_seconds=0.0, max_messages_per_cycle=1
    )
    original_run_once = w.run_once

    def exploding_run_once(*args, **kwargs):
        del args, kwargs
        original_run_once()
        raise RuntimeError("boom")

    w.run_once = exploding_run_once
    with pytest.raises(RuntimeError, match="boom"):
        w.run_forever(max_cycles=1)


def test_worker_service_propagates_keyboard_interrupt_run_once():
    """run_once must propagate KeyboardInterrupt without silencing."""
    svc = _SimpleNamespace(
        process_next=lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    w = DistributedWorkerService(
        service=svc, queue_name="k", poll_interval_seconds=0.0, max_messages_per_cycle=1
    )
    with pytest.raises(KeyboardInterrupt):
        w.run_once()


def test_worker_service_propagates_keyboard_interrupt_forever():
    """run_forever must propagate KeyboardInterrupt from thread futures."""
    from concurrent.futures import Future
    from unittest.mock import patch

    future = Future()
    future.set_exception(KeyboardInterrupt())

    class _FakeExecutor:
        def __init__(self, max_workers=1):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def submit(self, *_args, **_kwargs):
            return future

    svc = _SimpleNamespace(
        process_next=lambda **_kwargs: None, limits=_SimpleNamespace(max_workers=2)
    )
    w = DistributedWorkerService(
        service=svc, queue_name="k", poll_interval_seconds=0.0, max_messages_per_cycle=1
    )
    with patch("iocparser.worker_service.ThreadPoolExecutor", _FakeExecutor):
        with pytest.raises(KeyboardInterrupt):
            w.run_forever(max_cycles=1)


def test_run_once_returns_count_processed_before_a_mid_cycle_exception():
    """Regression: when process_next raises mid-cycle, run_once must report the
    messages already processed this cycle, not 0 -- otherwise run_forever backs off
    as if the queue were empty and the throughput total under-counts."""
    calls = [0]

    def process(**_kwargs):
        calls[0] += 1
        if calls[0] == 2:
            raise RuntimeError("boom on second message")
        return _SimpleNamespace()

    svc = _SimpleNamespace(process_next=process, limits=_SimpleNamespace(max_workers=1))
    w = DistributedWorkerService(
        service=svc, queue_name="t", poll_interval_seconds=0.0, max_messages_per_cycle=5
    )
    assert w.run_once() == 1


def test_run_once_breaks_immediately_when_stop_event_is_set():
    """run_once must honor stop_event mid-cycle instead of draining the batch."""
    calls = [0]

    def process(**_kwargs):
        calls[0] += 1
        return _SimpleNamespace()

    svc = _SimpleNamespace(process_next=process, limits=_SimpleNamespace(max_workers=1))
    w = DistributedWorkerService(
        service=svc, queue_name="t", poll_interval_seconds=0.0, max_messages_per_cycle=5
    )
    stop = threading.Event()
    stop.set()
    assert w.run_once(stop_event=stop) == 0
    assert calls[0] == 0
