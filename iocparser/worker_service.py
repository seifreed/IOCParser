from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from iocparser.distributed_pipeline import DistributedPipelineService
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
        try:
            return max(1, int(getattr(limits, "max_workers", 1)))
        except (ValueError, TypeError):
            return 1

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
            # Return what was already processed this cycle, not 0. Discarding the count
            # made run_forever back off as if the queue were empty after a mid-cycle
            # failure and under-counted the aggregate throughput total.
            logger.exception("Error during worker run_once")
        return processed

    def run_forever(  # noqa: C901
        self,
        *,
        stop_event: threading.Event | None = None,
        max_cycles: int | None = None,
    ) -> int:
        if max_cycles is not None and max_cycles <= 0:
            return 0
        workers = self.concurrency
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
                        except Exception:
                            logger.exception("Worker thread raised an exception")
                    processed += current
                    cycles += 1
                    if max_cycles is not None and cycles >= max_cycles:
                        break
                    if current == 0:
                        time.sleep(self.poll_interval_seconds)
                    else:
                        time.sleep(min(0.05, self.poll_interval_seconds))
        return processed
