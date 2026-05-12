#!/usr/bin/env python3
"""
Regression tests for file_batch_executor bug fixes
"""

import logging

from iocparser.domain.models import ExtractionResult
from iocparser.infrastructure.file_batch_executor import ThreadPoolFileBatchExecutor


class TestFileBatchExecutorRegression:
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
