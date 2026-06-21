from __future__ import annotations

import concurrent.futures
from collections.abc import Callable, Sequence
from typing import TypeVar

from iocparser.domain.models import ExtractionResult
from iocparser.errors import SourceNotFoundError, SourceProcessingError
from iocparser.infrastructure.logger import get_logger
from iocparser.interfaces.ports import FileBatchExecutor

logger = get_logger(__name__)

TBatchRequest = TypeVar("TBatchRequest")


class ThreadPoolFileBatchExecutor(FileBatchExecutor):
    """Infrastructure batch executor using a thread pool."""

    def __init__(self, *, max_workers: int = 4) -> None:
        self.max_workers = max(1, max_workers)

    def execute(
        self,
        requests: Sequence[TBatchRequest],
        *,
        handler: Callable[[TBatchRequest], ExtractionResult],
        key_for: Callable[[TBatchRequest], str],
    ) -> dict[str, ExtractionResult]:
        results: dict[str, ExtractionResult] = {}
        request_items = [(request, key_for(request)) for request in requests]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(handler, request): key for request, key in request_items}
            for future in concurrent.futures.as_completed(future_map):
                source_key = future_map[future]
                try:
                    results[source_key] = future.result()
                except (SourceNotFoundError, SourceProcessingError):
                    results[source_key] = ExtractionResult()
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    logger.exception("Batch processing failed for %s", source_key)
                    raise
        # Return results in input order, not thread-completion order, so the downstream
        # merge dedup (which keeps the first-seen raw value for a shared canonical IOC)
        # is deterministic across runs rather than dependent on which worker finished first.
        return {key: results[key] for _, key in request_items if key in results}
