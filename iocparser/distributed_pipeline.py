from __future__ import annotations

from dataclasses import dataclass

from iocparser.application.distributed_use_cases import (
    DistributedPipelineCoordinator,
    idempotency_key_for,
)
from iocparser.domain.distributed import DistributedJobRecord
from iocparser.domain.pipeline import PipelineJobRequest, PipelineJobResult, ResourceLimits
from iocparser.infrastructure.runtime import (
    bind_request_db_uri,
    distributed_service_dependencies,
    guarded_pipeline_runtime,
)
from iocparser.interfaces.ports import (
    ContentDigester,
    DistributedJobService,
    PipelineProcessor,
    QueueAdapter,
    TelemetrySink,
)
from iocparser.pipeline_worker import PipelineWorker

DEFAULT_QUEUE_BACKEND = "filesystem"


@dataclass(frozen=True)
class DistributedPipelineBoundaries:
    worker: PipelineProcessor
    db_uri: str | None
    telemetry_sink: TelemetrySink
    limits: ResourceLimits
    job_service: DistributedJobService | None
    content_digester: ContentDigester | None


def bind_pipeline_request(request: PipelineJobRequest, *, db_uri: str | None) -> PipelineJobRequest:
    return bind_request_db_uri(request, db_uri=db_uri)


def pipeline_boundaries(
    *,
    worker: PipelineWorker | None,
    db_uri: str | None,
    telemetry_sink: TelemetrySink | None,
    limits: ResourceLimits | None,
) -> DistributedPipelineBoundaries:
    dependencies = distributed_service_dependencies(
        worker=worker,
        db_uri=db_uri,
        telemetry_sink=telemetry_sink,
        limits=limits,
    )
    return DistributedPipelineBoundaries(
        worker=dependencies.worker,
        db_uri=db_uri,
        telemetry_sink=dependencies.telemetry_sink,
        limits=dependencies.limits,
        job_service=dependencies.job_service,
        content_digester=dependencies.content_digester,
    )


class DistributedPipelineService(DistributedPipelineCoordinator):
    """Queue-backed distributed pipeline service around PipelineWorker."""

    def __init__(
        self,
        *,
        queue_adapter: QueueAdapter,
        worker: PipelineWorker | None = None,
        db_uri: str | None = None,
        telemetry_sink: TelemetrySink | None = None,
        limits: ResourceLimits | None = None,
    ) -> None:
        self.queue_adapter = queue_adapter
        boundaries = pipeline_boundaries(
            worker=worker,
            db_uri=db_uri,
            telemetry_sink=telemetry_sink,
            limits=limits,
        )
        self.worker = boundaries.worker
        self.db_uri = db_uri
        self.telemetry_sink = boundaries.telemetry_sink
        self.limits = boundaries.limits
        self.job_service = boundaries.job_service
        self.content_digester = boundaries.content_digester
        super().__init__(
            queue_adapter=self.queue_adapter,
            processor=boundaries.worker,
            telemetry_sink=boundaries.telemetry_sink,
            job_service=boundaries.job_service,
            content_digester=boundaries.content_digester,
        )

    def submit(
        self,
        request: PipelineJobRequest,
        *,
        queue_name: str = "default",
        queue_backend: str = "filesystem",
        max_attempts: int = 3,
        idempotency_key: str | None = None,
    ) -> DistributedJobRecord | dict[str, str]:
        bound_request = bind_pipeline_request(request, db_uri=self.db_uri)
        return super().submit(
            bound_request,
            queue_name=queue_name,
            queue_backend=queue_backend,
            max_attempts=max_attempts,
            idempotency_key=idempotency_key,
        )

    def process_next(
        self, *, queue_name: str = "default"
    ) -> DistributedJobRecord | PipelineJobResult | None:
        with guarded_pipeline_runtime(self.limits):
            return super().process_next(queue_name=queue_name)

    def _idempotency_key(self, request: PipelineJobRequest) -> str:
        return idempotency_key_for(request, digester=self.content_digester)


def default_queue_backend() -> str:
    return DEFAULT_QUEUE_BACKEND
