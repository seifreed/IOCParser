#!/usr/bin/env python3
"""
Simple test for duplicate removal functionality

Tests the core duplicate removal logic directly without depending on
complex IOC extraction patterns.
"""

from typing import Dict, List, Set, Union

import pytest


def remove_duplicates_test_version(ioc_list: List[Union[str, Dict[str, str]]]) -> List[Union[str, Dict[str, str]]]:
    """
    Test version of our duplicate removal logic
    This mirrors the implementation in main.py
    """
    unique_items: List[Union[str, Dict[str, str]]] = []
    seen_keys: Set[str] = set()

    for item in ioc_list:
        # Create a unique key for each item (dicts use sorted items, strings use themselves)
        key = str(sorted(item.items())) if isinstance(item, dict) else str(item)

        # Only add if we haven't seen this key before
        if key not in seen_keys:
            seen_keys.add(key)
            unique_items.append(item)

    return unique_items


class TestDuplicateRemovalLogic:
    """Direct tests of duplicate removal logic"""

    def test_string_duplicates(self):
        """Test removing duplicate strings"""
        input_list = ["apple", "banana", "apple", "cherry", "banana"]
        result = remove_duplicates_test_version(input_list)

        assert len(result) == 3, f"Expected 3 unique items, got {len(result)}"
        assert result == ["apple", "banana", "cherry"], f"Order not preserved: {result}"

    def test_dict_duplicates(self):
        """Test removing duplicate dictionaries"""
        input_list = [
            {"type": "md5", "value": "abc123"},
            {"type": "sha1", "value": "def456"},
            {"type": "md5", "value": "abc123"},  # duplicate
            {"type": "sha256", "value": "ghi789"},
        ]
        result = remove_duplicates_test_version(input_list)

        assert len(result) == 3, f"Expected 3 unique items, got {len(result)}"
        # First occurrence should be preserved
        assert result[0] == {"type": "md5", "value": "abc123"}
        assert result[1] == {"type": "sha1", "value": "def456"}
        assert result[2] == {"type": "sha256", "value": "ghi789"}

    def test_mixed_duplicates(self):
        """Test removing duplicates from mixed string/dict list"""
        input_list = [
            "domain.com",
            {"type": "hash", "value": "abc123"},
            "domain.com",  # duplicate string
            {"type": "hash", "value": "abc123"},  # duplicate dict
            "another.com",
            {"type": "ip", "value": "1.2.3.4"},
        ]
        result = remove_duplicates_test_version(input_list)

        assert len(result) == 4, f"Expected 4 unique items, got {len(result)}"
        assert result[0] == "domain.com"
        assert result[1] == {"type": "hash", "value": "abc123"}
        assert result[2] == "another.com"
        assert result[3] == {"type": "ip", "value": "1.2.3.4"}

    def test_empty_list(self):
        """Test handling empty list"""
        input_list = []
        result = remove_duplicates_test_version(input_list)
        assert result == []

    def test_no_duplicates(self):
        """Test list with no duplicates"""
        input_list = ["unique1", "unique2", {"key": "unique3"}]
        result = remove_duplicates_test_version(input_list)
        assert len(result) == 3
        assert result == input_list

    def test_all_duplicates(self):
        """Test list where all items are duplicates"""
        input_list = ["same", "same", "same", "same"]
        result = remove_duplicates_test_version(input_list)
        assert len(result) == 1
        assert result == ["same"]

    def test_dict_same_values_different_order(self):
        """Test that dicts with same key-value pairs in different order are treated as duplicates"""
        input_list = [
            {"b": "2", "a": "1"},
            {"a": "1", "b": "2"},  # same dict, different key order
            {"c": "3", "a": "1"},
        ]
        result = remove_duplicates_test_version(input_list)

        # Should deduplicate the first two as they have the same key-value pairs
        assert len(result) == 2, f"Expected 2 unique items, got {len(result)}"

    def test_performance_many_duplicates(self):
        """Test performance with many duplicates"""
        # Create a list with many duplicates
        input_list = ["duplicate"] * 1000 + ["unique1", "unique2"]

        import time
        start_time = time.time()
        result = remove_duplicates_test_version(input_list)
        end_time = time.time()

        assert len(result) == 3, f"Expected 3 unique items, got {len(result)}"
        assert end_time - start_time < 1.0, "Deduplication should be fast"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
