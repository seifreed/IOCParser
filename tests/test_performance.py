#!/usr/bin/env python3
"""
Performance benchmarking tests for IOCParser

Author: Marc Rivero | @seifreed
"""

import random
import time
from pathlib import Path

import pytest

from iocparser.modules.extractor import IOCExtractor


class TestPerformance:
    """Performance benchmarking tests."""

    @staticmethod
    def generate_test_data(size_kb: int) -> str:
        """
        Generate test data with various IOCs embedded.

        Args:
            size_kb: Size of test data in kilobytes

        Returns:
            Generated test string
        """
        # Base text components
        words = [
            "the",
            "and",
            "for",
            "with",
            "from",
            "this",
            "that",
            "have",
            "will",
            "when",
            "there",
            "which",
            "their",
            "would",
            "could",
        ]

        # Sample IOCs to embed
        sample_iocs = {
            "md5": ["5f4dcc3b5aa765d61d8327deb882cf99", "e10adc3949ba59abbe56e057f20f883e"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "domains": ["example.com", "test.org", "malware.net", "evil.com"],
            "ips": ["192.168.1.1", "10.0.0.1", "8.8.8.8", "172.16.0.1"],
            "urls": ["https://example.com/path", "http://test.org/file.php"],
            "emails": ["user@example.com", "admin@test.org"],
            "cves": ["CVE-2021-44228", "CVE-2022-0001"],
        }

        # Generate text
        text_parts = []
        current_size = 0
        target_size = size_kb * 1024

        while current_size < target_size:
            # Add random words
            for _ in range(random.randint(5, 15)):
                text_parts.append(random.choice(words))

            # Randomly add IOCs
            if random.random() < 0.1:  # 10% chance to add an IOC
                ioc_type = random.choice(list(sample_iocs.keys()))
                ioc_value = random.choice(sample_iocs[ioc_type])
                text_parts.append(ioc_value)

            # Add newlines and punctuation
            if random.random() < 0.2:
                text_parts.append(".\n")
            else:
                text_parts.append(" ")

            current_size = len(" ".join(text_parts))

        return " ".join(text_parts)[:target_size]

    @pytest.mark.benchmark
    def test_extraction_small_text(self, benchmark):
        """Benchmark extraction on small text (1KB)."""
        extractor = IOCExtractor(defang=True)
        test_data = self.generate_test_data(1)

        def extract():
            return extractor.extract_all(test_data)

        result = benchmark(extract)
        assert isinstance(result, dict)

    @pytest.mark.benchmark
    def test_extraction_medium_text(self, benchmark):
        """Benchmark extraction on medium text (100KB)."""
        extractor = IOCExtractor(defang=True)
        test_data = self.generate_test_data(100)

        def extract():
            return extractor.extract_all(test_data)

        result = benchmark(extract)
        assert isinstance(result, dict)

    @pytest.mark.benchmark
    @pytest.mark.slow
    def test_extraction_large_text(self, benchmark):
        """Benchmark extraction on large text (1MB)."""
        extractor = IOCExtractor(defang=True)
        test_data = self.generate_test_data(1024)

        def extract():
            return extractor.extract_all(test_data)

        result = benchmark(extract)
        assert isinstance(result, dict)

    def test_extraction_speed_baseline(self):
        """Test that extraction completes within reasonable time."""
        extractor = IOCExtractor(defang=True)
        test_data = self.generate_test_data(10)  # 10KB

        start_time = time.time()
        result = extractor.extract_all(test_data)
        elapsed_time = time.time() - start_time

        # Should complete within 1 second for 10KB
        assert elapsed_time < 1.0
        assert isinstance(result, dict)

    def test_memory_efficiency(self):
        """Test memory efficiency with large inputs."""
        import tracemalloc

        extractor = IOCExtractor(defang=True)
        test_data = self.generate_test_data(100)  # 100KB

        # Start tracing
        tracemalloc.start()

        # Perform extraction
        result = extractor.extract_all(test_data)

        # Get memory usage
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Memory usage should be reasonable (less than 50MB for 100KB input)
        assert peak / 1024 / 1024 < 50  # MB
        assert isinstance(result, dict)

    @pytest.mark.parametrize(
        ("size_kb", "max_time"),
        [
            (1, 0.1),  # 1KB should complete in 0.1s
            (10, 0.5),  # 10KB should complete in 0.5s
            (100, 2.0),  # 100KB should complete in 2s
        ],
    )
    def test_scaling_performance(self, size_kb, max_time):
        """Test that performance scales reasonably with input size."""
        extractor = IOCExtractor(defang=True)
        test_data = self.generate_test_data(size_kb)

        start_time = time.time()
        result = extractor.extract_all(test_data)
        elapsed_time = time.time() - start_time

        assert elapsed_time < max_time
        assert isinstance(result, dict)

    def test_parallel_extraction_performance(self):
        """Test performance of parallel extraction for multiple files."""
        import tempfile
        from concurrent.futures import ThreadPoolExecutor

        # Create temporary test files
        test_files = []
        temp_dir = Path(tempfile.mkdtemp())

        try:
            for i in range(5):
                test_file = temp_dir / f"test_{i}.txt"
                test_file.write_text(self.generate_test_data(10))  # 10KB each
                test_files.append(test_file)

            # Sequential extraction
            start_time = time.time()
            sequential_results = []
            for file_path in test_files:
                extractor = IOCExtractor(defang=True)
                text = file_path.read_text()
                sequential_results.append(extractor.extract_all(text))
            sequential_time = time.time() - start_time

            # Parallel extraction
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=3) as executor:

                def extract_from_file(file_path):
                    extractor = IOCExtractor(defang=True)
                    text = file_path.read_text()
                    return extractor.extract_all(text)

                list(executor.map(extract_from_file, test_files))
            parallel_time = time.time() - start_time

            # Parallel should be faster or at least comparable
            assert parallel_time <= sequential_time * 1.2  # Allow 20% margin

        finally:
            # Cleanup
            for file_path in test_files:
                if file_path.exists():
                    file_path.unlink()
            temp_dir.rmdir()


class TestSpecificExtractorPerformance:
    """Test performance of specific extractors."""

    def test_hash_extraction_performance(self):
        """Test performance of hash extraction."""
        extractor = IOCExtractor(defang=False)

        # Generate text with many hashes
        hashes = []
        for _ in range(1000):
            # Generate random MD5-like strings
            hash_str = "".join(random.choices("0123456789abcdef", k=32))
            hashes.append(hash_str)

        test_text = " ".join(hashes)

        start_time = time.time()
        result = extractor.extract_md5(test_text)
        elapsed_time = time.time() - start_time

        # Should handle 1000 hashes in under 0.5 seconds
        assert elapsed_time < 0.5
        assert len(result) > 0

    def test_domain_extraction_performance(self):
        """Test performance of domain extraction."""
        extractor = IOCExtractor(defang=True)

        # Generate text with many domains
        domains = []
        for i in range(1000):
            domain = f"subdomain{i}.example{i % 10}.com"
            domains.append(domain)

        test_text = " ".join(domains)

        start_time = time.time()
        result = extractor.extract_domains(test_text)
        elapsed_time = time.time() - start_time

        # Should handle 1000 domains in under 1 second
        assert elapsed_time < 1.0
        assert len(result) > 0

    def test_ip_extraction_performance(self):
        """Test performance of IP extraction."""
        extractor = IOCExtractor(defang=True)

        # Generate text with many IPs
        ips = []
        for _ in range(1000):
            ip = f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ips.append(ip)

        test_text = " ".join(ips)

        start_time = time.time()
        result = extractor.extract_ips(test_text)
        elapsed_time = time.time() - start_time

        # Should handle 1000 IPs in under 0.5 seconds
        assert elapsed_time < 0.5
        assert len(result) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--benchmark-only"])
