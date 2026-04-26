from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from iocparser.domain.pipeline import ResourceLimits
from iocparser.infrastructure.runtime.limits import runtime_limits_guard
from iocparser.infrastructure.runtime.telemetry import LoggingTelemetrySink, NoOpTelemetrySink
from iocparser.interfaces.ports import ProcessedRunLookup, TelemetrySink
from iocparser.pipeline_worker import PipelineWorker


def pipeline_worker_for(
    worker: PipelineWorker | None,
    *,
    limits: ResourceLimits | None,
    processed_run_lookup: ProcessedRunLookup | None = None,
) -> PipelineWorker:
    return worker or PipelineWorker(
        limits=limits,
        processed_run_lookup=processed_run_lookup,
    )
def default_pipeline_telemetry_sink(telemetry_sink: TelemetrySink | None = None) -> TelemetrySink:
    return telemetry_sink or LoggingTelemetrySink()
def telemetry_sink_for_mode(mode: str) -> TelemetrySink:
    normalized = mode.strip().lower()
    if normalized in {"none", "noop", "disabled"}:
        return NoOpTelemetrySink()
    return LoggingTelemetrySink()
@contextmanager
def guarded_pipeline_runtime(limits: ResourceLimits) -> Iterator[None]:
    with runtime_limits_guard(
        memory_limit_bytes=limits.memory_limit_bytes,
        cpu_seconds=limits.cpu_seconds,
        hard_timeout_seconds=limits.hard_timeout_seconds,
    ):
        yield

__all__ = ["default_pipeline_telemetry_sink", "guarded_pipeline_runtime", "pipeline_worker_for", "telemetry_sink_for_mode"]
