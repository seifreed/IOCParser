from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from iocparser.infrastructure.logger import get_logger

logger = get_logger(__name__)

# Per-job in-process enforcement of these is unreliable (RLIMIT_AS over-counts virtual
# memory, RLIMIT_CPU is cumulative-per-process not per-job, signal.alarm interrupts in-flight
# I/O), so they belong to the orchestrator. Warn once instead of silently ignoring a set limit.
_UNENFORCED_LIMITS_WARNING = (
    "Runtime resource limit(s) %s are configured but not enforced in-process; enforce them "
    "via the orchestrator (cgroups / Kubernetes / systemd / ulimit)."
)

_warn_state = {"warned": False}
_warn_lock = threading.Lock()


def _warn_unenforced_limits(names: list[str]) -> None:
    with _warn_lock:
        if _warn_state["warned"]:
            return
        _warn_state["warned"] = True
    logger.warning(_UNENFORCED_LIMITS_WARNING, ", ".join(names))


@contextmanager
def runtime_limits_guard(
    *,
    memory_limit_bytes: int | None = None,
    cpu_seconds: int | None = None,
    hard_timeout_seconds: int | None = None,
) -> Iterator[None]:
    """Warn once about configured orchestrator-level limits; nothing is enforced in-process."""
    configured = [
        name
        for name, value in (
            ("memory_limit_bytes", memory_limit_bytes),
            ("cpu_seconds", cpu_seconds),
            ("hard_timeout_seconds", hard_timeout_seconds),
        )
        if value is not None
    ]
    if configured:
        _warn_unenforced_limits(configured)
    yield


__all__ = ["runtime_limits_guard"]
