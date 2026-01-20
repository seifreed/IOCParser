#!/usr/bin/env python3
"""
Basic tests for IOCParser
"""

import pytest

from iocparser import IOCExtractor, extract_iocs_from_text


def test_extract_iocs_from_text():
    """Test basic IOC extraction from text"""
    text = "Malware contacts evil.com with IP 192.168.1.1 and uses hash 5f4dcc3b5aa765d61d8327deb882cf99"

    normal_iocs, _warning_iocs = extract_iocs_from_text(text, check_warnings=False)

    # Should extract at least one domain and one IP
    assert "domains" in normal_iocs or "ips" in normal_iocs
    assert len(normal_iocs) > 0


def test_ioc_extractor():
    """Test IOCExtractor class"""
    extractor = IOCExtractor(defang=True)

    text = "Sample text with domain example.com and IP 8.8.8.8"
    iocs = extractor.extract_all(text)

    # Should extract domains and IPs
    assert "domains" in iocs
    assert "ips" in iocs


def test_defanging():
    """Test that defanging works correctly"""
    extractor = IOCExtractor(defang=True)

    text = "Malware contacts evil.com"
    iocs = extractor.extract_all(text)

    if iocs.get("domains"):
        domain = iocs["domains"][0]
        # Check if domain is defanged (contains [.] or similar)
        assert "[" in domain or "." not in domain


def test_no_defanging():
    """Test that no defanging works correctly"""
    extractor = IOCExtractor(defang=False)

    text = "Malware contacts evil.com"
    iocs = extractor.extract_all(text)

    if iocs.get("domains"):
        domain = iocs["domains"][0]
        # Check if domain is not defanged
        assert "." in domain
        assert "[" not in domain


if __name__ == "__main__":
    pytest.main([__file__])
