from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from iocparser.distributed_pipeline import DistributedPipelineService
from iocparser.errors import IntLiteralError
from iocparser.infrastructure.queueing import create_queue_adapter
from iocparser.infrastructure.runtime.service_builders import telemetry_sink_for_worker_mode
from iocparser.pipeline_worker import PipelineWorker
from iocparser.worker_config import WorkerServiceConfig

logger = logging.getLogger(__name__)
@dataclass(frozen=True)
class WorkerServiceRuntime:
    service: DistributedPipelineService
    queue_name: str
    poll_interval_seconds: float
    max_messages_per_cycle: int

def build_worker_service_runtime(
    config: WorkerServiceConfig,
    *,
    worker: PipelineWorker | None = None,
) -> WorkerServiceRuntime:
    adapter = create_queue_adapter(
        config.queue_backend,
        queue_url=config.queue_url,
        queue_path=config.queue_path,
        dead_letter_queue_url=config.dead_letter_queue_url,
    )
    service = DistributedPipelineService(
        queue_adapter=adapter,
        worker=worker,
        db_uri=config.db_uri,
        telemetry_sink=telemetry_sink_for_worker_mode(config.telemetry_mode),
        limits=config.resource_limits(),
    )
    return WorkerServiceRuntime(
        service=service,
        queue_name=config.queue_name,
        poll_interval_seconds=config.poll_interval_seconds,
        max_messages_per_cycle=config.max_messages_per_cycle,
    )


class DistributedWorkerService:
    def __init__(
        self,
        *,
        service: DistributedPipelineService,
        queue_name: str = "default",
        poll_interval_seconds: float = 1.0,
        max_messages_per_cycle: int = 1,
    ) -> None:
        self.service = service
        self.queue_name = queue_name
        self.poll_interval_seconds = poll_interval_seconds
        self.max_messages_per_cycle = max_messages_per_cycle

    @classmethod
    def from_config(
        cls,
        config: WorkerServiceConfig,
        *,
        worker: PipelineWorker | None = None,
    ) -> DistributedWorkerService:
        runtime = build_worker_service_runtime(config, worker=worker)
        return cls(
            service=runtime.service,
            queue_name=runtime.queue_name,
            poll_interval_seconds=runtime.poll_interval_seconds,
            max_messages_per_cycle=runtime.max_messages_per_cycle,
        )

    @property
    def concurrency(self) -> int:
        limits = getattr(self.service, "limits", None)
        raw_workers = getattr(limits, "max_workers", 1)
        if isinstance(raw_workers, bool):
            raise IntLiteralError(raw_workers)
        return max(1, int(raw_workers))

    def _inflight_capacity(self) -> int:
        """Processor backpressure threshold (max in-flight reservations = max_queue_size).

        Sizing the pool above this makes surplus workers trip the reservation guard, whose
        RuntimeError process_next dead-letters as an unprocessed job. Falls back to
        ``concurrency`` when no usable cap is exposed (e.g. a stub service).
        """
        processor = getattr(self.service, "processor", None)
        limits = getattr(processor, "limits", None)
        if limits is None:
            limits = getattr(self.service, "limits", None)
        raw_cap = getattr(limits, "max_queue_size", None)
        if isinstance(raw_cap, bool) or not isinstance(raw_cap, int) or raw_cap <= 0:
            return self.concurrency
        return raw_cap

    def _process_one(self) -> bool:
        return self.service.process_next(queue_name=self.queue_name) is not None

    def run_once(self, *, stop_event: threading.Event | None = None) -> int:
        processed = 0
        try:
            for _ in range(self.max_messages_per_cycle):
                if stop_event is not None and stop_event.is_set():
                    break
                if not self._process_one():
                    break
                processed += 1
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            logger.exception("Error during worker run_once")
            raise
        return processed

    def run_forever(  # noqa: C901
        self,
        *,
        stop_event: threading.Event | None = None,
        max_cycles: int | None = None,
    ) -> int:
        if max_cycles is not None and max_cycles <= 0:
            return 0
        requested_workers = self.concurrency
        workers = min(requested_workers, self._inflight_capacity())
        if workers < requested_workers:
            logger.info(
                "Capping worker pool at %s to honor the max_queue_size in-flight guard "
                "(requested max_workers=%s); surplus workers would otherwise dead-letter "
                "unprocessed jobs as backpressure errors",
                workers,
                requested_workers,
            )
        cycles = processed = 0
        if workers <= 1:
            while stop_event is None or not stop_event.is_set():
                current = self.run_once(stop_event=stop_event)
                processed += current
                cycles += 1
                if max_cycles is not None and cycles >= max_cycles:
                    break
                if current == 0:
                    time.sleep(self.poll_interval_seconds)
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                while stop_event is None or not stop_event.is_set():
                    cycle_error: Exception | None = None
                    futures = [
                        executor.submit(self.run_once, stop_event=stop_event)
                        for _ in range(workers)
                    ]
                    current = 0
                    for f in futures:
                        try:
                            current += f.result()
                        except (KeyboardInterrupt, SystemExit):
                            raise
                        except Exception as exc:
                            logger.exception("Worker thread raised an exception")
                            if cycle_error is None:
                                cycle_error = exc
                    processed += current
                    cycles += 1
                    if cycle_error is not None:
                        raise cycle_error
                    if max_cycles is not None and cycles >= max_cycles:
                        break
                    if current == 0:
                        time.sleep(self.poll_interval_seconds)
                    else:
                        time.sleep(min(0.05, self.poll_interval_seconds))
        return processed
