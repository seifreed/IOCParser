from __future__ import annotations

from pathlib import Path

from iocparser.interfaces.ports import TemporaryResourceCleaner


class TemporaryFileCleaner(TemporaryResourceCleaner):
    """Best-effort cleanup of temporary local files."""

    def cleanup(self, resource_path: str) -> None:
        path = Path(resource_path)
        try:
            path.unlink(missing_ok=True)
        except (OSError, PermissionError):
            return
