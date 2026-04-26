from __future__ import annotations

from pathlib import Path

from iocparser.infrastructure.logger import get_logger, setup_logger
from iocparser.infrastructure.runtime.limits import runtime_limits_guard
from iocparser.infrastructure.runtime.runtime_factories import (
    default_pipeline_telemetry_sink,
    guarded_pipeline_runtime,
    pipeline_worker_for,
    telemetry_sink_for_mode,
)
from iocparser.infrastructure.runtime.runtime_requests import bind_request_db_uri
from iocparser.infrastructure.runtime.service_builders import (
    distributed_service_dependencies,
    telemetry_sink_for_worker_mode,
)
from iocparser.infrastructure.runtime.telemetry import (
    InMemoryTelemetrySink,
    LoggingTelemetrySink,
    NoOpTelemetrySink,
)
from iocparser.interfaces.ports import FileWriter


class LocalFileWriter(FileWriter):
    def write(self, output_path: str, content: str) -> None:
        output_file = Path(output_path)
        output_file.resolve().parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(content, encoding="utf-8")

__all__ = ["InMemoryTelemetrySink", "LocalFileWriter", "LoggingTelemetrySink", "NoOpTelemetrySink", "bind_request_db_uri", "default_pipeline_telemetry_sink", "distributed_service_dependencies", "get_logger", "guarded_pipeline_runtime", "pipeline_worker_for", "runtime_limits_guard", "setup_logger", "telemetry_sink_for_mode", "telemetry_sink_for_worker_mode"]
