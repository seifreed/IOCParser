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


def main() -> int:
    """Entrypoint for the standalone distributed worker service."""
    try:
        config = WorkerServiceConfig.from_sources(_config_path_from_argv(sys.argv))
        service = DistributedWorkerService.from_config(config)
        service.run_forever(max_cycles=config.max_cycles)
    except KeyboardInterrupt:
        logger.warning("Worker stopped by user")
        return 0
    except (IOCParserError, ValueError) as exc:
        # Startup/config problems -- unknown queue backend, missing queue_url, a bad
        # numeric env var -- reach here as ValueError/IOCParserError; report them as a
        # concise message instead of an unhandled stack trace from the daemon entrypoint.
        logger.error("Worker startup failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
