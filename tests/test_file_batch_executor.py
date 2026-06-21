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
        assert results["key1"].result.iocs[0].canonical_value() == "ok.test"
        assert results["key1"].error is None

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

        assert results["key1"].result == ExtractionResult()
        assert results["key1"].error is not None
        assert "missing.txt" in results["key1"].error

    def test_known_processing_errors_still_yield_empty_results(self):
        executor = ThreadPoolFileBatchExecutor(max_workers=1)

        def broken_handler(_):
            raise SourceProcessingError("broken.txt", "boom")

        results = executor.execute(
            requests=["item"],
            handler=broken_handler,
            key_for=lambda _: "key1",
        )

        assert results["key1"].result == ExtractionResult()
        assert results["key1"].error is not None
        assert "broken.txt" in results["key1"].error

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

    def test_key_for_is_only_called_once_per_request(self):
        """Regression: the return path must not call key_for() a second time."""
        executor = ThreadPoolFileBatchExecutor(max_workers=1)
        calls = 0

        def handler(request):
            return ExtractionResult.from_grouped_payload({"domains": [str(request)]}, {})

        def key_for(request):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise RuntimeError("key_for called twice")
            return f"key:{request}"

        results = executor.execute(
            requests=["item"],
            handler=handler,
            key_for=key_for,
        )

        assert calls == 1
        assert list(results.keys()) == ["key:item"]
