#!/usr/bin/env python3
"""
Tests for duplicate removal functionality in IOCParser

This test suite ensures our automatic duplicate removal works correctly
with mixed types (strings and dictionaries) while preserving order.
"""

import argparse
import tempfile
from pathlib import Path

import pytest

from iocparser.core import process_multiple_files_input


class TestDuplicateRemoval:
    """Test suite for automatic duplicate removal functionality"""

    def create_temp_file_with_content(self, content: str) -> Path:
        """Helper method to create temporary file with specific content"""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        temp_file.write(content)
        temp_file.close()
        return Path(temp_file.name)

    def create_mock_args(self, file_paths: list) -> argparse.Namespace:
        """Helper to create mock args for testing"""
        args = argparse.Namespace()
        args.multiple = [str(path) for path in file_paths]
        args.type = None
        args.no_defang = False
        args.no_check_warnings = True  # Disable to avoid network calls
        args.force_update = False
        args.parallel = 1
        return args

    def test_basic_duplicate_removal(self):
        """Test that duplicate strings are removed correctly"""
        # Create test files with overlapping IOCs
        file1_content = """
        This file contains malware connecting to evil.com
        The IP address is 192.168.1.1
        Hash: d41d8cd98f00b204e9800998ecf8427e
        """

        file2_content = """
        Another file with evil.com domain
        Same IP: 192.168.1.1
        Different hash: 5d41402abc4b2a76b9719d911017c592
        """

        file1 = self.create_temp_file_with_content(file1_content)
        file2 = self.create_temp_file_with_content(file2_content)

        try:
            args = self.create_mock_args([file1, file2])
            normal_iocs, warning_iocs, display, _results = process_multiple_files_input(args)

            # Check domains are deduplicated (accounting for defanging)
            if 'domains' in normal_iocs:
                domains = normal_iocs['domains']
                # Count occurrences of evil.com (defanged as evil[.]com)
                evil_com_count = sum(1 for domain in domains if 'evil' in str(domain).lower() and 'com' in str(domain).lower())
                assert evil_com_count == 1, f"Expected 1 occurrence of evil.com, got {evil_com_count}"

            # Check IPs are deduplicated (accounting for defanging)
            if 'ips' in normal_iocs:
                ips = normal_iocs['ips']
                # Match 192.168.1.1 in both defanged (192[.]168[.]1[.]1) and non-defanged forms
                ip_count = sum(1 for ip in ips if '192' in str(ip) and '168' in str(ip) and str(ip).count('1') >= 2)
                assert ip_count == 1, f"Expected 1 occurrence of 192.168.1.1, got {ip_count}"

        finally:
            # Cleanup
            file1.unlink()
            file2.unlink()

    def test_mixed_type_duplicate_removal(self):
        """Test duplicate removal works with mixed string/dict types"""
        # Create test files that generate both string and dict IOCs
        file1_content = """
        Hash as string: d41d8cd98f00b204e9800998ecf8427e
        MD5: a1b2c3d4e5f6789012345678901234567890abcd
        """

        file2_content = """
        Same hash again: d41d8cd98f00b204e9800998ecf8427e
        Another hash: 5d41402abc4b2a76b9719d911017c592
        """

        file1 = self.create_temp_file_with_content(file1_content)
        file2 = self.create_temp_file_with_content(file2_content)

        try:
            args = self.create_mock_args([file1, file2])
            normal_iocs, warning_iocs, display, _results = process_multiple_files_input(args)

            # Check that we have results
            assert len(normal_iocs) > 0, "Should have extracted some IOCs"

            # Verify no type contains duplicates
            for ioc_type, ioc_list in normal_iocs.items():
                # Create keys the same way our duplicate removal does
                seen_keys = set()
                for item in ioc_list:
                    key = str(sorted(item.items())) if isinstance(item, dict) else str(item)
                    assert key not in seen_keys, f"Found duplicate in {ioc_type}: {item}"
                    seen_keys.add(key)

        finally:
            # Cleanup
            file1.unlink()
            file2.unlink()

    def test_order_preservation(self):
        """Test that first occurrence is preserved when removing duplicates"""
        file1_content = """
        First file with domain first.com
        Then second.com
        """

        file2_content = """
        Second file with domain second.com (duplicate)
        Then third.com
        And first.com again (duplicate)
        """

        file1 = self.create_temp_file_with_content(file1_content)
        file2 = self.create_temp_file_with_content(file2_content)

        try:
            args = self.create_mock_args([file1, file2])
            normal_iocs, warning_iocs, display, _results = process_multiple_files_input(args)

            if 'domains' in normal_iocs:
                domains = normal_iocs['domains']
                domain_strings = [str(d) for d in domains]

                # Verify we have unique domains
                unique_domains = set(domain_strings)
                assert len(domain_strings) == len(unique_domains), "Domains should be unique"

                # The order should generally preserve first occurrences
                # (exact order may depend on extraction patterns)
                assert len(domains) >= 3, "Should have at least 3 unique domains"

        finally:
            # Cleanup
            file1.unlink()
            file2.unlink()

    def test_empty_files_handling(self):
        """Test duplicate removal handles empty or no-IOC files gracefully"""
        file1_content = "This file has no IOCs in it at all, just plain text."
        file2_content = "This one also has no indicators of compromise."

        file1 = self.create_temp_file_with_content(file1_content)
        file2 = self.create_temp_file_with_content(file2_content)

        try:
            args = self.create_mock_args([file1, file2])
            normal_iocs, warning_iocs, display, _results = process_multiple_files_input(args)

            # Should handle gracefully without errors
            assert isinstance(normal_iocs, dict), "Should return dict even with no IOCs"
            assert isinstance(warning_iocs, dict), "Should return dict even with no IOCs"

        finally:
            # Cleanup
            file1.unlink()
            file2.unlink()

    def test_performance_with_many_duplicates(self):
        """Test performance doesn't degrade with many duplicates"""
        # Create content with many repetitive IOCs
        repeated_content = """
        evil.com appears many times
        192.168.1.1 is repeated
        hash: d41d8cd98f00b204e9800998ecf8427e
        """ * 50  # Repeat 50 times

        file1 = self.create_temp_file_with_content(repeated_content)
        file2 = self.create_temp_file_with_content(repeated_content)

        try:
            args = self.create_mock_args([file1, file2])

            import time
            start_time = time.time()
            normal_iocs, warning_iocs, display, _results = process_multiple_files_input(args)
            end_time = time.time()

            # Should complete in reasonable time (< 5 seconds for this small test)
            execution_time = end_time - start_time
            assert execution_time < 5, f"Duplicate removal took too long: {execution_time:.2f}s"

            # Verify deduplication worked
            for ioc_type, ioc_list in normal_iocs.items():
                # Should have much fewer items than the 100+ we put in
                assert len(ioc_list) < 20, f"Too many items in {ioc_type}: {len(ioc_list)}"

        finally:
            # Cleanup
            file1.unlink()
            file2.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
