from __future__ import annotations

from dataclasses import dataclass, field

from iocparser.distributed_pipeline import DistributedPipelineService, default_queue_backend
from iocparser.domain.distributed import DeadLetterRecord, DistributedJobRecord
from iocparser.domain.pipeline import PipelineJobRequest, PipelineJobResult
from iocparser.infrastructure.queueing import create_queue_adapter
from iocparser.infrastructure.runtime import default_pipeline_telemetry_sink
from iocparser.pipeline_worker import PipelineWorker


def build_pipeline_service(
    *,
    queue_backend: str,
    queue_url: str | None,
    queue_path: str | None,
    dead_letter_queue_url: str | None,
    db_uri: str | None,
    worker: PipelineWorker,
) -> DistributedPipelineService:
    adapter = create_queue_adapter(
        queue_backend,
        queue_url=queue_url,
        queue_path=queue_path,
        dead_letter_queue_url=dead_letter_queue_url,
    )
    return DistributedPipelineService(
        queue_adapter=adapter,
        worker=worker,
        db_uri=db_uri,
        telemetry_sink=default_pipeline_telemetry_sink(),
    )


@dataclass
class DistributedPipelineClient:
    """High-level client for queue-backed distributed pipeline execution."""

    db_uri: str | None = None
    queue_backend: str = field(default_factory=default_queue_backend)
    queue_url: str | None = None
    queue_path: str | None = None
    dead_letter_queue_url: str | None = None
    worker: PipelineWorker = field(default_factory=PipelineWorker)
    _service: DistributedPipelineService = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_service",
            build_pipeline_service(
                queue_backend=self.queue_backend,
                queue_url=self.queue_url,
                queue_path=self.queue_path,
                dead_letter_queue_url=self.dead_letter_queue_url,
                db_uri=self.db_uri,
                worker=self.worker,
            ),
        )

    def submit(
        self,
        request: PipelineJobRequest,
        *,
        queue_name: str = "default",
        max_attempts: int = 3,
        idempotency_key: str | None = None,
    ) -> DistributedJobRecord | dict[str, str]:
        # No per-call queue_backend override: the adapter is fixed at construction, so a
        # per-call backend could not be honored and only mislabeled the recorded job.
        return self._service.submit(
            request,
            queue_name=queue_name,
            queue_backend=self.queue_backend,
            max_attempts=max_attempts,
            idempotency_key=idempotency_key,
        )

    def process_next(
        self, *, queue_name: str = "default"
    ) -> DistributedJobRecord | PipelineJobResult | None:
        return self._service.process_next(queue_name=queue_name)

    def drain(
        self, *, queue_name: str = "default", limit: int = 100
    ) -> list[DistributedJobRecord | PipelineJobResult]:
        return self._service.drain(queue_name=queue_name, limit=limit)

    def get_job(self, *, job_id: str) -> DistributedJobRecord | None:
        return self._service.get_job(job_id=job_id)

    def list_jobs(
        self,
        *,
        limit: int = 50,
        statuses: tuple[str, ...] = (),
        queue_backend: str | None = None,
    ) -> list[DistributedJobRecord]:
        return self._service.list_jobs(
            limit=limit,
            statuses=statuses,
            queue_backend=queue_backend,
        )

    def list_dead_letters(
        self, *, limit: int = 50, queue_backend: str | None = None
    ) -> list[DeadLetterRecord]:
        return self._service.list_dead_letters(limit=limit, queue_backend=queue_backend)
