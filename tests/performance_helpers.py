"""Shared helpers for performance-oriented tests."""

import random


def generate_test_data(size_kb: int) -> str:
    """Generate deterministic-enough text with embedded IOCs."""
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

    sample_iocs = {
        "md5": ["5f4dcc3b5aa765d61d8327deb882cf99", "e10adc3949ba59abbe56e057f20f883e"],
        "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "domains": ["example.com", "test.org", "malware.net", "evil.com"],
        "ips": ["192.168.1.1", "10.0.0.1", "8.8.8.8", "172.16.0.1"],
        "urls": ["https://example.com/path", "http://test.org/file.php"],
        "emails": ["user@example.com", "admin@test.org"],
        "cves": ["CVE-2021-44228", "CVE-2022-0001"],
    }

    text_parts: list[str] = []
    current_size = 0
    target_size = size_kb * 1024

    while current_size < target_size:
        for _ in range(random.randint(5, 15)):
            text_parts.append(random.choice(words))

        if random.random() < 0.1:
            ioc_type = random.choice(list(sample_iocs.keys()))
            text_parts.append(random.choice(sample_iocs[ioc_type]))

        text_parts.append(".\n" if random.random() < 0.2 else " ")
        current_size = len(" ".join(text_parts))

    return " ".join(text_parts)[:target_size]
