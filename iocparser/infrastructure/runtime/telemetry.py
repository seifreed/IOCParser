from __future__ import annotations

import json
from dataclasses import dataclass, field

from iocparser.domain.models import TelemetryEvent
from iocparser.infrastructure.logger import get_logger

logger = get_logger(__name__)


class NoOpTelemetrySink:
    """Telemetry sink that intentionally does nothing."""

    def emit(self, event: TelemetryEvent) -> None:
        del event


class LoggingTelemetrySink:
    """Structured JSON logger telemetry sink."""

    def emit(self, event: TelemetryEvent) -> None:
        logger.info(json.dumps(event.to_record(), sort_keys=True))


@dataclass
class InMemoryTelemetrySink:
    """Test-friendly telemetry sink that keeps emitted events in memory."""

    events: list[dict[str, object]] = field(default_factory=list)

    def emit(self, event: TelemetryEvent) -> None:
        self.events.append(event.to_record())


__all__ = ["InMemoryTelemetrySink", "LoggingTelemetrySink", "NoOpTelemetrySink"]
