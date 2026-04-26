from __future__ import annotations

import concurrent.futures
from collections.abc import Callable, Sequence
from typing import TypeVar

from iocparser.domain.models import ExtractionResult
from iocparser.errors import SourceNotFoundError, SourceProcessingError
from iocparser.interfaces.ports import FileBatchExecutor

TBatchRequest = TypeVar("TBatchRequest")


class ThreadPoolFileBatchExecutor(FileBatchExecutor):
    """Infrastructure batch executor using a thread pool."""

    def __init__(self, *, max_workers: int = 4) -> None:
        self.max_workers = max_workers

    def execute(
        self,
        requests: Sequence[TBatchRequest],
        *,
        handler: Callable[[TBatchRequest], ExtractionResult],
        key_for: Callable[[TBatchRequest], str],
    ) -> dict[str, ExtractionResult]:
        results: dict[str, ExtractionResult] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(handler, request): key_for(request) for request in requests}
            for future in concurrent.futures.as_completed(future_map):
                source_key = future_map[future]
                try:
                    results[source_key] = future.result()
                except (SourceNotFoundError, SourceProcessingError):
                    results[source_key] = ExtractionResult()
        return results
