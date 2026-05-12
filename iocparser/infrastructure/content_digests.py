from __future__ import annotations

import hashlib
from pathlib import Path

from iocparser.interfaces.ports import ContentDigester


class SHA256ContentDigester(ContentDigester):
    """Infrastructure digester for idempotency and content-addressed workflows."""

    def digest_text(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def digest_file(self, file_path: str) -> str:
        hasher = hashlib.sha256()
        with Path(file_path).open("rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
