#!/usr/bin/env python3
"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Tests for iocparser.modules.utils - deduplication utilities with stateful tracking.
"""

import pytest

from iocparser.modules.utils import deduplicate_iocs, deduplicate_iocs_with_state


class TestDeduplicateIocs:
    """Test basic IOC deduplication without external state."""

    def test_deduplicate_iocs_empty(self) -> None:
        """Test deduplication with empty input."""
        result = deduplicate_iocs({})
        assert result == {}

    def test_deduplicate_iocs_no_duplicates(self) -> None:
        """Test deduplication with unique IOCs."""
        iocs = {
            "domains": ["evil.com", "malware.net", "badsite.org"],
            "ips": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        }

        result = deduplicate_iocs(iocs)

        assert len(result["domains"]) == 3
        assert len(result["ips"]) == 3
        assert set(result["domains"]) == set(iocs["domains"])
        assert set(result["ips"]) == set(iocs["ips"])

    def test_deduplicate_iocs_with_duplicates(self) -> None:
        """Test deduplication removes duplicate IOCs."""
        iocs = {
            "domains": ["evil.com", "malware.net", "evil.com", "badsite.org", "evil.com"],
            "ips": ["192.168.1.1", "10.0.0.1", "192.168.1.1"],
        }

        result = deduplicate_iocs(iocs)

        assert len(result["domains"]) == 3
        assert len(result["ips"]) == 2
        assert set(result["domains"]) == {"evil.com", "malware.net", "badsite.org"}
        assert set(result["ips"]) == {"192.168.1.1", "10.0.0.1"}

    def test_deduplicate_iocs_preserves_order(self) -> None:
        """Test deduplication preserves first occurrence order."""
        iocs = {
            "domains": ["alpha.com", "beta.net", "alpha.com", "gamma.org", "beta.net"],
        }

        result = deduplicate_iocs(iocs)

        # Should preserve order of first occurrence
        assert result["domains"][0] == "alpha.com"
        assert result["domains"][1] == "beta.net"
        assert result["domains"][2] == "gamma.org"
        assert len(result["domains"]) == 3


class TestDeduplicateIocsWithState:
    """Test stateful IOC deduplication for streaming/incremental processing."""

    def test_deduplicate_iocs_with_state_empty_input(self) -> None:
        """Test deduplication with empty new IOCs."""
        seen_iocs: dict[str, set[str]] = {
            "domains": set(),
            "ips": set(),
        }
        new_iocs: dict[str, list[str]] = {}

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        assert result == {}
        assert seen_iocs == {"domains": set(), "ips": set()}

    def test_deduplicate_iocs_with_state_all_new(self) -> None:
        """Test deduplication when all IOCs are new."""
        seen_iocs: dict[str, set[str]] = {
            "domains": set(),
            "ips": set(),
            "hashes": set(),
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "malware.net"],
            "ips": ["192.168.1.1", "10.0.0.1"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # All IOCs should be returned as unique
        assert result == {
            "domains": ["evil.com", "malware.net"],
            "ips": ["192.168.1.1", "10.0.0.1"],
        }

        # State should be updated
        assert seen_iocs["domains"] == {"evil.com", "malware.net"}
        assert seen_iocs["ips"] == {"192.168.1.1", "10.0.0.1"}

    def test_deduplicate_iocs_with_state_all_seen(self) -> None:
        """Test deduplication when all IOCs have been seen before."""
        seen_iocs: dict[str, set[str]] = {
            "domains": {"evil.com", "malware.net"},
            "ips": {"192.168.1.1", "10.0.0.1"},
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "malware.net"],
            "ips": ["192.168.1.1"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # No new unique IOCs
        assert result == {}

        # State should remain unchanged (same items)
        assert seen_iocs["domains"] == {"evil.com", "malware.net"}
        assert seen_iocs["ips"] == {"192.168.1.1", "10.0.0.1"}

    def test_deduplicate_iocs_with_state_mixed(self) -> None:
        """Test deduplication with mix of new and seen IOCs."""
        seen_iocs: dict[str, set[str]] = {
            "domains": {"evil.com"},
            "ips": {"192.168.1.1"},
            "hashes": set(),
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "malware.net", "badsite.org"],
            "ips": ["192.168.1.1", "10.0.0.1"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # Only new IOCs should be returned
        assert result == {
            "domains": ["malware.net", "badsite.org"],
            "ips": ["10.0.0.1"],
        }

        # State should be updated with new IOCs
        assert seen_iocs["domains"] == {"evil.com", "malware.net", "badsite.org"}
        assert seen_iocs["ips"] == {"192.168.1.1", "10.0.0.1"}

    def test_deduplicate_iocs_with_state_preserves_order(self) -> None:
        """Test deduplication preserves order of unique IOCs."""
        seen_iocs: dict[str, set[str]] = {
            "domains": {"skip-this.com"},
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["alpha.com", "skip-this.com", "beta.net", "gamma.org"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # Should preserve order, excluding already-seen IOCs
        assert result["domains"] == ["alpha.com", "beta.net", "gamma.org"]

    def test_deduplicate_iocs_with_state_multiple_calls(self) -> None:
        """Test deduplication across multiple incremental calls."""
        seen_iocs: dict[str, set[str]] = {
            "domains": set(),
            "ips": set(),
        }

        # First batch
        batch1: dict[str, list[str]] = {
            "domains": ["evil.com", "malware.net"],
            "ips": ["192.168.1.1"],
        }
        result1 = deduplicate_iocs_with_state(batch1, seen_iocs)

        assert result1 == {
            "domains": ["evil.com", "malware.net"],
            "ips": ["192.168.1.1"],
        }
        assert seen_iocs["domains"] == {"evil.com", "malware.net"}
        assert seen_iocs["ips"] == {"192.168.1.1"}

        # Second batch with overlaps
        batch2: dict[str, list[str]] = {
            "domains": ["evil.com", "newsite.org"],
            "ips": ["192.168.1.1", "10.0.0.1"],
        }
        result2 = deduplicate_iocs_with_state(batch2, seen_iocs)

        assert result2 == {
            "domains": ["newsite.org"],
            "ips": ["10.0.0.1"],
        }
        assert seen_iocs["domains"] == {"evil.com", "malware.net", "newsite.org"}
        assert seen_iocs["ips"] == {"192.168.1.1", "10.0.0.1"}

        # Third batch, all duplicates
        batch3: dict[str, list[str]] = {
            "domains": ["evil.com", "malware.net"],
        }
        result3 = deduplicate_iocs_with_state(batch3, seen_iocs)

        assert result3 == {}
        assert seen_iocs["domains"] == {"evil.com", "malware.net", "newsite.org"}

    def test_deduplicate_iocs_with_state_requires_initialized_state(self) -> None:
        """Test that state must be pre-initialized with all expected IOC types."""
        seen_iocs: dict[str, set[str]] = {
            "domains": {"evil.com"},
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "newdomain.com"],
            "emails": ["bad@evil.com", "malware@test.net"],
        }

        # The function expects all IOC types to be pre-initialized in state
        # Attempting to use a new type raises KeyError
        with pytest.raises(KeyError):
            deduplicate_iocs_with_state(new_iocs, seen_iocs)

    def test_deduplicate_iocs_with_state_with_preinitialized_types(self) -> None:
        """Test that pre-initialized state handles all IOC types correctly."""
        # State must contain all IOC types that will be processed
        seen_iocs: dict[str, set[str]] = {
            "domains": {"evil.com"},
            "emails": set(),  # Pre-initialized empty
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "newdomain.com"],
            "emails": ["bad@evil.com", "malware@test.net"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # Should handle both IOC types correctly
        assert "domains" in result
        assert "emails" in result
        assert result["domains"] == ["newdomain.com"]
        assert result["emails"] == ["bad@evil.com", "malware@test.net"]

        # State should be updated
        assert seen_iocs["emails"] == {"bad@evil.com", "malware@test.net"}

    def test_deduplicate_iocs_with_state_duplicates_within_batch(self) -> None:
        """Test deduplication handles duplicates within same batch."""
        seen_iocs: dict[str, set[str]] = {
            "domains": set(),
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "malware.net", "evil.com", "badsite.org", "evil.com"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # First occurrence of each should be kept
        assert "evil.com" in result["domains"]
        assert "malware.net" in result["domains"]
        assert "badsite.org" in result["domains"]

        # State should only contain unique values
        assert seen_iocs["domains"] == {"evil.com", "malware.net", "badsite.org"}

    def test_deduplicate_iocs_with_state_empty_ioc_type(self) -> None:
        """Test deduplication with empty list for an IOC type."""
        seen_iocs: dict[str, set[str]] = {
            "domains": {"evil.com"},
            "ips": set(),
        }
        new_iocs: dict[str, list[str]] = {
            "domains": [],
            "ips": ["192.168.1.1"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # Empty domains should not appear in result
        assert "domains" not in result
        assert result == {"ips": ["192.168.1.1"]}

    def test_deduplicate_iocs_with_state_modifies_in_place(self) -> None:
        """Test that seen_iocs is modified in place (side effect)."""
        seen_iocs: dict[str, set[str]] = {
            "domains": set(),
        }
        original_seen_iocs = seen_iocs  # Same object reference

        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "malware.net"],
        }

        deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # Verify it's the same object that was modified
        assert seen_iocs is original_seen_iocs
        assert seen_iocs["domains"] == {"evil.com", "malware.net"}

    def test_deduplicate_iocs_with_state_case_sensitive(self) -> None:
        """Test deduplication is case-sensitive."""
        seen_iocs: dict[str, set[str]] = {
            "domains": {"evil.com"},
        }
        new_iocs: dict[str, list[str]] = {
            "domains": ["evil.com", "Evil.com", "EVIL.COM"],
        }

        result = deduplicate_iocs_with_state(new_iocs, seen_iocs)

        # Different cases should be treated as different values
        assert "Evil.com" in result["domains"]
        assert "EVIL.COM" in result["domains"]
        assert len(result["domains"]) == 2

    def test_deduplicate_iocs_with_state_streaming_scenario(self) -> None:
        """Test realistic streaming scenario with continuous processing."""
        # Initialize state for streaming processing
        seen_iocs: dict[str, set[str]] = {
            "domains": set(),
            "ips": set(),
            "hashes": set(),
        }

        # Simulate processing multiple documents in sequence
        document1: dict[str, list[str]] = {
            "domains": ["malware1.com", "c2-server.net"],
            "ips": ["192.168.1.100", "10.0.0.50"],
            "hashes": ["5f4dcc3b5aa765d61d8327deb882cf99"],
        }

        document2: dict[str, list[str]] = {
            "domains": ["malware1.com", "evil-new.org"],  # malware1.com is duplicate
            "ips": ["192.168.1.100", "172.16.0.1"],  # 192.168.1.100 is duplicate
            "hashes": ["098f6bcd4621d373cade4e832627b4f6"],
        }

        document3: dict[str, list[str]] = {
            "domains": ["final-domain.com"],
            "ips": ["8.8.8.8"],
            "hashes": ["5f4dcc3b5aa765d61d8327deb882cf99"],  # Duplicate from doc1
        }

        # Process documents sequentially
        result1 = deduplicate_iocs_with_state(document1, seen_iocs)
        assert len(result1["domains"]) == 2
        assert len(result1["ips"]) == 2
        assert len(result1["hashes"]) == 1

        result2 = deduplicate_iocs_with_state(document2, seen_iocs)
        assert len(result2["domains"]) == 1  # Only evil-new.org is new
        assert result2["domains"] == ["evil-new.org"]
        assert len(result2["ips"]) == 1  # Only 172.16.0.1 is new
        assert result2["ips"] == ["172.16.0.1"]

        result3 = deduplicate_iocs_with_state(document3, seen_iocs)
        assert result3["domains"] == ["final-domain.com"]
        assert result3["ips"] == ["8.8.8.8"]
        assert "hashes" not in result3  # Hash was seen in doc1

        # Verify final state
        assert len(seen_iocs["domains"]) == 4
        assert len(seen_iocs["ips"]) == 4
        assert len(seen_iocs["hashes"]) == 2


class TestDeduplicationComparison:
    """Test comparing behavior of both deduplication functions."""

    def test_both_functions_same_result_for_simple_case(self) -> None:
        """Test that both deduplication functions produce same result for simple input."""
        iocs = {
            "domains": ["evil.com", "malware.net", "evil.com"],
            "ips": ["192.168.1.1", "10.0.0.1", "192.168.1.1"],
        }

        # Test with basic deduplicate_iocs
        result1 = deduplicate_iocs(iocs)

        # Test with stateful version (fresh state)
        seen_iocs: dict[str, set[str]] = {
            "domains": set(),
            "ips": set(),
        }
        result2 = deduplicate_iocs_with_state(iocs, seen_iocs)

        # Results should be equivalent
        assert set(result1["domains"]) == set(result2["domains"])
        assert set(result1["ips"]) == set(result2["ips"])

    def test_stateful_function_enables_incremental_processing(self) -> None:
        """Test that stateful function enables true incremental processing."""
        # This is something deduplicate_iocs cannot do
        seen_iocs: dict[str, set[str]] = {"domains": set()}

        batch1 = {"domains": ["a.com", "b.com"]}
        batch2 = {"domains": ["b.com", "c.com"]}

        result1 = deduplicate_iocs_with_state(batch1, seen_iocs)
        result2 = deduplicate_iocs_with_state(batch2, seen_iocs)

        # Second call should only return c.com as b.com was seen in batch1
        assert result1["domains"] == ["a.com", "b.com"]
        assert result2["domains"] == ["c.com"]
        assert seen_iocs["domains"] == {"a.com", "b.com", "c.com"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
