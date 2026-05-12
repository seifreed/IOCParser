#!/usr/bin/env python3
"""
Regression tests for file_batch_executor bug fixes
"""

import logging

from iocparser.domain.models import ExtractionResult
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
            results = executor.execute(
                requests=["item"],
                handler=exploding_handler,
                key_for=lambda _: "key1",
            )

        assert results["key1"] == ExtractionResult()
        assert "Batch processing failed" in caplog.text
        assert "RuntimeError: boom" in caplog.text
