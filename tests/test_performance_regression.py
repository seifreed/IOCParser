"""Functional performance regression tests kept outside the benchmark suite."""

import random
import tempfile
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from iocparser.infrastructure.extraction import IOCExtractor
from tests.performance_helpers import generate_test_data


class TestPerformanceRegression:
    """Fast functional checks for pathological performance regressions."""

    def test_extraction_speed_baseline(self):
        extractor = IOCExtractor(defang=True)
        test_data = generate_test_data(10)

        start_time = time.time()
        result = extractor.extract_all(test_data)
        elapsed_time = time.time() - start_time

        assert elapsed_time < 1.0
        assert isinstance(result, dict)

    def test_memory_efficiency(self):
        extractor = IOCExtractor(defang=True)
        test_data = generate_test_data(100)

        tracemalloc.start()
        result = extractor.extract_all(test_data)
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert peak / 1024 / 1024 < 50
        assert isinstance(result, dict)

    @pytest.mark.slow
    @pytest.mark.parametrize(
        ("size_kb", "max_time"),
        [(1, 0.1), (10, 0.5), (100, 2.0)],
    )
    def test_scaling_performance(self, size_kb, max_time):
        extractor = IOCExtractor(defang=True)
        test_data = generate_test_data(size_kb)

        start_time = time.time()
        result = extractor.extract_all(test_data)
        elapsed_time = time.time() - start_time

        assert elapsed_time < max_time
        assert isinstance(result, dict)

    @pytest.mark.slow
    def test_parallel_extraction_performance(self):
        test_files: list[Path] = []
        temp_dir = Path(tempfile.mkdtemp())

        try:
            for index in range(5):
                test_file = temp_dir / f"test_{index}.txt"
                test_file.write_text(generate_test_data(10))
                test_files.append(test_file)

            start_time = time.time()
            for file_path in test_files:
                extractor = IOCExtractor(defang=True)
                text = file_path.read_text()
                extractor.extract_all(text)
            sequential_time = time.time() - start_time

            start_time = time.time()
            with ThreadPoolExecutor(max_workers=3) as executor:

                def extract_from_file(file_path: Path):
                    extractor = IOCExtractor(defang=True)
                    text = file_path.read_text()
                    return extractor.extract_all(text)

                list(executor.map(extract_from_file, test_files))
            parallel_time = time.time() - start_time

            assert parallel_time <= sequential_time * 1.75
        finally:
            for file_path in test_files:
                if file_path.exists():
                    file_path.unlink()
            temp_dir.rmdir()


class TestSpecificExtractorPerformance:
    """Fast extractor-level regression checks."""

    def test_hash_extraction_performance(self):
        extractor = IOCExtractor(defang=False)
        hashes = ["".join(random.choices("0123456789abcdef", k=32)) for _ in range(1000)]

        start_time = time.time()
        result = extractor.extract_md5(" ".join(hashes))
        elapsed_time = time.time() - start_time

        assert elapsed_time < 0.5
        assert len(result) > 0

    def test_domain_extraction_performance(self):
        extractor = IOCExtractor(defang=True)
        domains = [f"subdomain{i}.example{i % 10}.com" for i in range(1000)]

        start_time = time.time()
        result = extractor.extract_domains(" ".join(domains))
        elapsed_time = time.time() - start_time

        assert elapsed_time < 1.0
        assert len(result) > 0

    def test_ip_extraction_performance(self):
        extractor = IOCExtractor(defang=True)
        ips = [
            f"{random.randint(1, 254)}.{random.randint(0, 255)}."
            f"{random.randint(0, 255)}.{random.randint(1, 254)}"
            for _ in range(1000)
        ]

        start_time = time.time()
        result = extractor.extract_ips(" ".join(ips))
        elapsed_time = time.time() - start_time

        assert elapsed_time < 0.5
        assert len(result) > 0
