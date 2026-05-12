from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from iocparser.domain.pipeline import ResourceLimits
from iocparser.worker_config_support import (
    bool_env,
    float_env,
    float_or,
    float_or_none,
    int_env,
    int_or,
    int_or_none,
    load_worker_file_values,
    resolve_config_path,
    str_or_none,
)


@dataclass(frozen=True)
class WorkerServiceConfig:
    """Environment-driven configuration for the standalone worker service."""

    queue_backend: str = "filesystem"
    queue_name: str = "default"
    queue_url: str | None = None
    queue_path: str | None = ".iocparser-queue"
    dead_letter_queue_url: str | None = None
    db_uri: str | None = None
    poll_interval_seconds: float = 1.0
    max_messages_per_cycle: int = 1
    max_cycles: int | None = None
    concurrency: int = 1
    telemetry_mode: str = "logging"
    max_input_size_bytes: int | None = None
    max_input_seconds: float | None = None
    memory_limit_bytes: int | None = None
    cpu_seconds: int | None = None
    hard_timeout_seconds: int | None = None
    max_queue_size: int = 64
    skip_processed: bool = False
    config_path: Path | None = None

    @classmethod
    def from_sources(cls, config_path: str | None = None) -> WorkerServiceConfig:
        """Load worker runtime settings from INI config plus environment overrides."""
        resolved_path = resolve_config_path(config_path)
        file_values = load_worker_file_values(resolved_path)
        poll_interval_default = float_or(file_values["poll_interval_seconds"], 1.0)
        poll_interval_seconds = float_env(
            "IOCPARSER_WORKER_POLL_INTERVAL_SECONDS", poll_interval_default
        )
        if poll_interval_seconds is None:
            poll_interval_seconds = poll_interval_default
        return cls(
            queue_backend=os.environ.get(
                "IOCPARSER_WORKER_QUEUE_BACKEND", str(file_values["queue_backend"])
            ),
            queue_name=os.environ.get(
                "IOCPARSER_WORKER_QUEUE_NAME", str(file_values["queue_name"])
            ),
            queue_url=os.environ.get("IOCPARSER_WORKER_QUEUE_URL")
            or str_or_none(file_values["queue_url"]),
            queue_path=os.environ.get(
                "IOCPARSER_WORKER_QUEUE_PATH", str(file_values["queue_path"])
            ),
            dead_letter_queue_url=os.environ.get("IOCPARSER_WORKER_DEAD_LETTER_QUEUE_URL")
            or str_or_none(file_values["dead_letter_queue_url"]),
            db_uri=os.environ.get("IOCPARSER_WORKER_DB_URI") or str_or_none(file_values["db_uri"]),
            poll_interval_seconds=poll_interval_seconds,
            max_messages_per_cycle=int_env(
                "IOCPARSER_WORKER_MAX_MESSAGES_PER_CYCLE",
                int_or(file_values["max_messages_per_cycle"], 1),
            )
            or 1,
            max_cycles=int_env(
                "IOCPARSER_WORKER_MAX_CYCLES", int_or_none(file_values["max_cycles"])
            ),
            concurrency=int_env(
                "IOCPARSER_WORKER_CONCURRENCY", int_or(file_values["concurrency"], 1)
            )
            or 1,
            telemetry_mode=os.environ.get(
                "IOCPARSER_WORKER_TELEMETRY_MODE", str(file_values["telemetry_mode"])
            ),
            max_input_size_bytes=int_env(
                "IOCPARSER_WORKER_MAX_INPUT_SIZE_BYTES",
                int_or_none(file_values["max_input_size_bytes"]),
            ),
            max_input_seconds=float_env(
                "IOCPARSER_WORKER_MAX_INPUT_SECONDS",
                float_or_none(file_values["max_input_seconds"]),
            ),
            memory_limit_bytes=int_env(
                "IOCPARSER_WORKER_MEMORY_LIMIT_BYTES",
                int_or_none(file_values["memory_limit_bytes"]),
            ),
            cpu_seconds=int_env(
                "IOCPARSER_WORKER_CPU_SECONDS", int_or_none(file_values["cpu_seconds"])
            ),
            hard_timeout_seconds=int_env(
                "IOCPARSER_WORKER_HARD_TIMEOUT_SECONDS",
                int_or_none(file_values["hard_timeout_seconds"]),
            ),
            max_queue_size=int_env(
                "IOCPARSER_WORKER_MAX_QUEUE_SIZE", int_or(file_values["max_queue_size"], 64)
            )
            or 64,
            skip_processed=bool_env(
                "IOCPARSER_WORKER_SKIP_PROCESSED", bool(file_values["skip_processed"])
            ),
            config_path=resolved_path,
        )

    def resource_limits(self) -> ResourceLimits:
        """Build runtime limits consumed by PipelineWorker and distributed service."""
        return ResourceLimits(
            max_input_size_bytes=self.max_input_size_bytes,
            max_input_seconds=self.max_input_seconds,
            memory_limit_bytes=self.memory_limit_bytes,
            cpu_seconds=self.cpu_seconds,
            hard_timeout_seconds=self.hard_timeout_seconds,
            max_workers=self.concurrency,
            max_queue_size=self.max_queue_size,
            skip_processed=self.skip_processed,
        )
