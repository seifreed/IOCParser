#!/usr/bin/env python3
"""Benchmark-only tests for IOCParser."""

import pytest

from iocparser.infrastructure.extraction import IOCExtractor
from tests.performance_helpers import generate_test_data


class TestBenchmarks:
    """Benchmark-only tests."""

    @pytest.mark.benchmark
    def test_extraction_small_text(self, benchmark):
        """Benchmark extraction on small text (1KB)."""
        extractor = IOCExtractor(defang=True)
        test_data = generate_test_data(1)

        def extract():
            return extractor.extract_all(test_data)

        result = benchmark(extract)
        assert isinstance(result, dict)

    @pytest.mark.benchmark
    def test_extraction_medium_text(self, benchmark):
        """Benchmark extraction on medium text (100KB)."""
        extractor = IOCExtractor(defang=True)
        test_data = generate_test_data(100)

        def extract():
            return extractor.extract_all(test_data)

        result = benchmark(extract)
        assert isinstance(result, dict)

    @pytest.mark.benchmark
    @pytest.mark.slow
    def test_extraction_large_text(self, benchmark):
        """Benchmark extraction on large text (1MB)."""
        extractor = IOCExtractor(defang=True)
        test_data = generate_test_data(1024)

        def extract():
            return extractor.extract_all(test_data)

        result = benchmark(extract)
        assert isinstance(result, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--benchmark-only"])
