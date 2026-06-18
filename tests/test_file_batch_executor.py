#!/usr/bin/env python3
"""
Regression tests for file_batch_executor bug fixes
"""

import logging
import threading

import pytest

from iocparser.domain.models import ExtractionResult
from iocparser.errors import SourceNotFoundError, SourceProcessingError
from iocparser.infrastructure.file_batch_executor import ThreadPoolFileBatchExecutor


class TestFileBatchExecutorRegression:
    def test_zero_workers_falls_back_to_single_worker(self):
        """Regression: invalid zero parallelism must not crash ThreadPoolExecutor."""
        executor = ThreadPoolFileBatchExecutor(max_workers=0)

        results = executor.execute(
            requests=["item"],
            handler=lambda _: ExtractionResult.from_grouped_payload({"domains": ["ok.test"]}, {}),
            key_for=lambda _: "key1",
        )

        assert executor.max_workers == 1
        assert results["key1"].iocs[0].canonical_value() == "ok.test"

    def test_logs_exception_on_unexpected_failure(self, caplog):
        """Regression: except Exception must not silently swallow errors."""
        executor = ThreadPoolFileBatchExecutor(max_workers=1)

        def exploding_handler(_):
            raise RuntimeError("boom")

        with caplog.at_level(logging.ERROR, logger="iocparser.infrastructure.file_batch_executor"):
            with pytest.raises(RuntimeError, match="boom"):
                executor.execute(
                    requests=["item"],
                    handler=exploding_handler,
                    key_for=lambda _: "key1",
                )

        assert "Batch processing failed" in caplog.text
        assert "RuntimeError: boom" in caplog.text

    def test_known_file_errors_still_yield_empty_results(self):
        executor = ThreadPoolFileBatchExecutor(max_workers=1)

        def missing_handler(_):
            raise SourceNotFoundError("missing.txt")

        results = executor.execute(
            requests=["item"],
            handler=missing_handler,
            key_for=lambda _: "key1",
        )

        assert results["key1"] == ExtractionResult()

    def test_known_processing_errors_still_yield_empty_results(self):
        executor = ThreadPoolFileBatchExecutor(max_workers=1)

        def broken_handler(_):
            raise SourceProcessingError("broken.txt", "boom")

        results = executor.execute(
            requests=["item"],
            handler=broken_handler,
            key_for=lambda _: "key1",
        )

        assert results["key1"] == ExtractionResult()

    def test_results_returned_in_input_order_not_completion_order(self):
        """Regression: results must be keyed in input order, not thread-completion order,
        so the downstream merge dedup (first-seen raw value wins) is deterministic."""
        executor = ThreadPoolFileBatchExecutor(max_workers=3)
        c_done = threading.Event()

        def handler(request):
            # Force "a" (first input) to finish last and "c" (last input) first, so
            # completion order is the reverse of input order.
            if request == "a":
                c_done.wait(timeout=5)
            elif request == "c":
                c_done.set()
            return ExtractionResult()

        results = executor.execute(
            requests=["a", "b", "c"],
            handler=handler,
            key_for=lambda request: request,
        )

        assert list(results.keys()) == ["a", "b", "c"]
