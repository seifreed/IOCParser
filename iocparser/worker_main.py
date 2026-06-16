from __future__ import annotations

import sys

from iocparser.errors import IOCParserError
from iocparser.infrastructure.logger import get_logger
from iocparser.worker_config import WorkerServiceConfig
from iocparser.worker_service import DistributedWorkerService

logger = get_logger("iocparser.worker")


def _config_path_from_argv(argv: list[str]) -> str | None:
    # Accept both '--config path' (any position) and the GNU '--config=path' form.
    for index, arg in enumerate(argv[1:], start=1):
        if arg == "--config" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--config="):
            return arg.split("=", 1)[1]
    return None


def _report_startup_failure(exc: Exception) -> int:
    # Logging lives here (not lexically in the except) so it stays a concise message
    # rather than a stack trace -- an expected config error is not a crash to debug.
    logger.error("Worker startup failed: %s", exc)
    return 1


def main() -> int:
    """Entrypoint for the standalone distributed worker service."""
    try:
        config = WorkerServiceConfig.from_sources(_config_path_from_argv(sys.argv))
        service = DistributedWorkerService.from_config(config)
    except (IOCParserError, ValueError) as exc:
        # Scope this to setup only: an unknown queue backend, a missing queue_url or a
        # bad numeric env var surface here. run_forever (below) is outside the catch so a
        # genuine ValueError during processing still propagates instead of being masked.
        return _report_startup_failure(exc)
    try:
        service.run_forever(max_cycles=config.max_cycles)
    except KeyboardInterrupt:
        logger.warning("Worker stopped by user")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
