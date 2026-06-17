from __future__ import annotations

import sys

from iocparser.errors import IOCParserError
from iocparser.infrastructure.logger import get_logger
from iocparser.worker_config import WorkerServiceConfig
from iocparser.worker_service import DistributedWorkerService

logger = get_logger("iocparser.worker")


_USAGE = """\
usage: iocparser-worker [--config PATH] [-h|--help]

Standalone distributed worker that pulls jobs from a queue and runs them forever.

Options:
  --config PATH   INI file with a [worker] section (also accepts --config=PATH).

Configuration comes from that INI plus IOCPARSER_WORKER_* environment variables
(QUEUE_BACKEND, QUEUE_URL, QUEUE_PATH, DB_URI, POLL_INTERVAL_SECONDS,
MAX_MESSAGES_PER_CYCLE, MAX_CYCLES, ...). The default backend is the filesystem
queue. Stop the worker with Ctrl-C.\
"""


def _wants_help(argv: list[str]) -> bool:
    return "-h" in argv[1:] or "--help" in argv[1:]


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
    if _wants_help(sys.argv):
        sys.stdout.write(_USAGE + "\n")
        return 0
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
