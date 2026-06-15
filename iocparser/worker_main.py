from __future__ import annotations

import sys

from iocparser.worker_config import WorkerServiceConfig
from iocparser.worker_service import DistributedWorkerService


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
    config = WorkerServiceConfig.from_sources(_config_path_from_argv(sys.argv))
    service = DistributedWorkerService.from_config(config)
    service.run_forever(max_cycles=config.max_cycles)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
