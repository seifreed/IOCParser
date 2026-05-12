from __future__ import annotations

from dataclasses import dataclass

from iocparser.domain.pipeline import ResourceLimits
from iocparser.infrastructure.content_digests import SHA256ContentDigester
from iocparser.infrastructure.persistence import SQLAlchemyDistributedJobService
from iocparser.infrastructure.runtime.runtime_factories import (
    default_pipeline_telemetry_sink,
    pipeline_worker_for,
    telemetry_sink_for_mode,
)
from iocparser.interfaces.ports import TelemetrySink
from iocparser.pipeline_worker import PipelineWorker


@dataclass(frozen=True)
class DistributedServiceDependencies:
    worker: PipelineWorker
    telemetry_sink: TelemetrySink
    limits: ResourceLimits
    job_service: SQLAlchemyDistributedJobService | None
    content_digester: SHA256ContentDigester

def distributed_service_dependencies(*, worker: PipelineWorker | None, db_uri: str | None, telemetry_sink: TelemetrySink | None, limits: ResourceLimits | None) -> DistributedServiceDependencies:
    from iocparser.pipeline_worker_support import PipelineProcessedRunLookup
    lookup = PipelineProcessedRunLookup(db_uri) if db_uri else None
    effective_worker = pipeline_worker_for(worker, limits=limits, processed_run_lookup=lookup)
    return DistributedServiceDependencies(
        worker=effective_worker,
        telemetry_sink=default_pipeline_telemetry_sink(telemetry_sink),
        limits=limits or effective_worker.limits,
        job_service=SQLAlchemyDistributedJobService(db_uri) if db_uri else None,
        content_digester=SHA256ContentDigester(),
    )

def telemetry_sink_for_worker_mode(mode: str) -> TelemetrySink:
    return telemetry_sink_for_mode(mode)

__all__ = ["DistributedServiceDependencies", "distributed_service_dependencies", "telemetry_sink_for_worker_mode"]
