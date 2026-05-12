from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def runtime_limits_guard(
    *,
    memory_limit_bytes: int | None = None,
    cpu_seconds: int | None = None,
    hard_timeout_seconds: int | None = None,
) -> Iterator[None]:
    """Best-effort runtime guard; hard limits still belong to the orchestrator."""
    del memory_limit_bytes, cpu_seconds, hard_timeout_seconds
    yield


__all__ = ["runtime_limits_guard"]
