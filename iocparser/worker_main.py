from __future__ import annotations

import sys

from iocparser.worker_config import WorkerServiceConfig
from iocparser.worker_service import DistributedWorkerService


def _config_path_from_argv(argv: list[str]) -> str | None:
    if len(argv) >= 3 and argv[1] == "--config":
        return argv[2]
    return None


def main() -> int:
    """Entrypoint for the standalone distributed worker service."""
    config = WorkerServiceConfig.from_sources(_config_path_from_argv(sys.argv))
    service = DistributedWorkerService.from_config(config)
    service.run_forever(max_cycles=config.max_cycles)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
