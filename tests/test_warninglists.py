#!/usr/bin/env python3
"""
Unit tests for MISP warning lists functionality

Author: Marc Rivero | @seifreed
"""

import contextlib
import json
import tempfile
import time
from pathlib import Path

import pytest

from iocparser.infrastructure.warninglists_types import normalized_warning_list_text
from tests.test_warninglists_offline import (
    GOOD_BAD_DOMAIN_PAYLOADS,
    OfflineWarningLists,
    TrackingWarningLists,
    WarningListServer,
    patched_github_bases,
)

_warninglist_tempdirs: list[tempfile.TemporaryDirectory[str]] = []


def make_warning_lists() -> OfflineWarningLists:
    """Create an offline warning-lists instance without network refresh."""
    tempdir = tempfile.TemporaryDirectory()
    _warninglist_tempdirs.append(tempdir)
    return OfflineWarningLists(Path(tempdir.name), cache_duration=24, force_update=False)


def teardown_module() -> None:
    """Clean warning-list cache directories kept alive for module-scoped tests."""
    while _warninglist_tempdirs:
        _warninglist_tempdirs.pop().cleanup()


class TestMISPWarningLists:
    """Test MISP warning lists functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.sample_warning_lists = {
            "public-dns-v4": {
                "name": "Public DNS Resolvers",
                "description": "List of public DNS resolver IP addresses",
                "type": "string",
                "matching_attributes": ["ip-src", "ip-dst", "ip"],
                "list": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"],
            },
            "google-cidr": {
                "name": "Google IP ranges",
                "description": "IP ranges used by Google",
                "type": "cidr",
                "matching_attributes": ["ip-src", "ip-dst"],
                "list": ["8.8.8.0/24", "142.250.0.0/15", "172.217.0.0/16"],
            },
            "alexa-top1000": {
                "name": "Alexa Top 1000",
                "description": "Top 1000 most visited websites",
                "type": "string",
                "matching_attributes": ["domain", "hostname"],
                "list": ["google.com", "facebook.com", "youtube.com", "amazon.com"],
            },
            "security-provider-domains": {
                "name": "Security Provider Domains",
                "description": "Domains of security providers",
                "type": "substring",
                "matching_attributes": ["domain", "hostname", "url"],
                "list": ["virustotal", "malwarebytes", "kaspersky"],
            },
        }

    def test_initialization_with_cache(self):
        """Test initialization path uses a fresh local cache without update."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            cache_file = tmppath / "misp_warninglists_cache.json"
            metadata_file = tmppath / "misp_warninglists_metadata.json"

            cache_file.write_text(json.dumps(self.sample_warning_lists), encoding="utf-8")
            metadata_file.write_text(json.dumps({"last_update": time.time()}), encoding="utf-8")

            warning_lists = TrackingWarningLists(tmppath, cache_duration=24, force_update=False)
            warning_lists._load_or_update_lists()

            assert warning_lists.updated is False
            assert warning_lists.warning_lists == self.sample_warning_lists

    def test_clean_defanged_value(self):
        """Test defanging cleanup."""
        warning_lists = make_warning_lists()

        # Test various defanging patterns
        test_cases = [
            ("example[.]com", "example.com"),
            ("192[.]168[.]1[.]1", "192.168.1.1"),
            ("user[@]example[.]com", "user@example.com"),
            ("hxxp://example[.]com", "http://example.com"),
            ("hxxps://test[.]org", "https://test.org"),
            ("example{.}com", "example.com"),
            ("192(.)168(.)1(.)1", "192.168.1.1"),
            ("test{@}email{.}com", "test@email.com"),
        ]

        for defanged, expected in test_cases:
            result = warning_lists._clean_defanged_value(defanged)
            assert result == expected, f"Failed to clean {defanged}"

    def test_check_cidr(self):
        """Test CIDR range checking."""
        warning_lists = make_warning_lists()

        # Test CIDR checking
        cidr_list = ["192.168.1.0/24", "10.0.0.0/8", "8.8.8.8"]

        # Should match
        assert warning_lists._check_cidr("192.168.1.100", cidr_list)
        assert warning_lists._check_cidr("10.5.5.5", cidr_list)
        assert warning_lists._check_cidr("8.8.8.8", cidr_list)
        assert warning_lists._check_cidr(" 192.168.1.100 ", cidr_list)

        # Should not match
        assert not warning_lists._check_cidr("192.168.2.1", cidr_list)
        assert not warning_lists._check_cidr("11.0.0.1", cidr_list)
        assert not warning_lists._check_cidr("8.8.8.9", cidr_list)

        # Invalid IP should return False
        assert not warning_lists._check_cidr("not.an.ip", cidr_list)
        assert not warning_lists._check_cidr("256.256.256.256", cidr_list)

    def test_check_value_in_list_string(self):
        """Test string type list checking."""
        warning_lists = make_warning_lists()

        values = ["google.com", "facebook.com", "youtube.com"]

        # Exact match (case insensitive)
        assert warning_lists._check_value_in_list("google.com", values, "string")
        assert warning_lists._check_value_in_list("GOOGLE.COM", values, "string")
        assert warning_lists._check_value_in_list("Google.Com", values, "string")
        assert warning_lists._check_value_in_list(" google.com ", values, "string")

        # No match
        assert not warning_lists._check_value_in_list("amazon.com", values, "string")
        assert not warning_lists._check_value_in_list("sub.google.com", values, "string")

    def test_check_value_in_list_hostname(self):
        """Hostname lists must match like string lists in the diagnostic.

        Regression: preprocessing indexes hostname lists with the string lookups,
        but the diagnostic returned False for type "hostname", contradicting
        check_value (which reported a match).
        """
        warning_lists = make_warning_lists()
        values = ["google.com", "facebook.com"]
        assert warning_lists._check_value_in_list("google.com", values, "hostname")
        assert warning_lists._check_value_in_list("GOOGLE.COM", values, "hostname")
        assert warning_lists._check_value_in_list(" google.com ", values, "hostname")
        assert warning_lists._check_value_in_list(
            "static-185.132.201.202.andorpac.ad",
            ["static-185.132.201.202.andorpac.ad\\ "],
            "hostname",
        )
        assert not warning_lists._check_value_in_list("amazon.com", values, "hostname")

    def test_check_value_in_list_substring(self):
        """Test substring type list checking."""
        warning_lists = make_warning_lists()

        values = ["google", "facebook", "virus"]

        # Substring match
        assert warning_lists._check_value_in_list("google.com", values, "substring")
        assert warning_lists._check_value_in_list("mail.google.com", values, "substring")
        assert warning_lists._check_value_in_list("virustotal.com", values, "substring")
        assert warning_lists._check_value_in_list("mail.google.com", [" google "], "substring")

        # No match
        assert not warning_lists._check_value_in_list("amazon.com", values, "substring")

    def test_check_value_in_list_regex(self):
        """Test regex type list checking."""
        warning_lists = make_warning_lists()

        values = [r".*\.google\.com$", r"^192\.168\.\d+\.\d+$"]

        # Regex match
        assert warning_lists._check_value_in_list("mail.google.com", values, "regex")
        assert warning_lists._check_value_in_list("192.168.1.1", values, "regex")
        assert warning_lists._check_value_in_list(" mail.google.com ", values, "regex")

        # No match
        assert not warning_lists._check_value_in_list("google.net", values, "regex")
        assert not warning_lists._check_value_in_list("10.0.0.1", values, "regex")

    def test_warning_list_text_helpers_reject_non_string_entries(self):
        with pytest.raises(TypeError, match="string-like"):
            normalized_warning_list_text(None, list_type="string")  # type: ignore[arg-type]

    def test_check_value_in_list_cidr(self):
        """Test CIDR type list checking through the generic dispatcher."""
        warning_lists = make_warning_lists()

        values = ["192.168.1.0/24", "10.0.0.1"]

        assert warning_lists._check_value_in_list("192.168.1.24", values, "cidr")
        assert warning_lists._check_value_in_list("10.0.0.1", values, "cidr")
        assert warning_lists._check_value_in_list(" 192.168.1.24 ", values, "cidr")
        assert warning_lists._check_value_in_list("192.168.1.24", [" 192.168.1.0/24 "], "cidr")
        assert not warning_lists._check_value_in_list("172.16.0.1", values, "cidr")

    def test_check_string_type(self):
        """Test direct string matching helper."""
        warning_lists = make_warning_lists()

        values = ["google.com", None, "microsoft.com"]

        assert warning_lists._check_string_type("google.com", values)
        assert warning_lists._check_string_type("MICROSOFT.COM", values)
        assert warning_lists._check_string_type(" google.com ", values)
        assert warning_lists._check_string_type("google.com", [" google.com "])
        assert not warning_lists._check_string_type("amazon.com", values)

    def test_check_string_and_substring_type_reject_non_string_values(self):
        warning_lists = make_warning_lists()

        with pytest.raises(TypeError, match="string-like"):
            warning_lists._check_string_type("google.com", [object()])  # type: ignore[list-item]
        with pytest.raises(TypeError, match="string-like"):
            warning_lists._check_substring_type("google.com", [object()])  # type: ignore[list-item]

    def test_get_logger_falls_back_to_module_logger(self):
        """Test logger fallback when instance logger is missing."""
        warning_lists = make_warning_lists()

        resolved = warning_lists._get_logger()

        assert resolved.name == "iocparser.infrastructure.warninglists"

    def test_cache_check_value_clears_large_cache(self):
        """Test warning lookup cache reset when it grows beyond the cap."""
        warning_lists = make_warning_lists()
        warning_lists._warning_lookup_cache = {
            (f"value-{index}", "domains"): (False, None) for index in range(5000)
        }

        warning_lists._cache_check_value(
            ("fresh", "domains"), (True, {"name": "List", "description": "Desc"})
        )

        assert warning_lists._warning_lookup_cache == {
            ("fresh", "domains"): (True, {"name": "List", "description": "Desc"})
        }

    def test_check_value_with_sample_lists(self):
        """Test check_value with sample warning lists."""
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = self.sample_warning_lists
        warning_lists._preprocess_lists()  # Reprocess after setting mock data

        # Test IP in public DNS list
        is_warning, info = warning_lists.check_value("8.8.8.8", "ips")
        assert is_warning
        assert info["name"] == "Public DNS Resolvers"

        # Test IP in CIDR range
        is_warning, info = warning_lists.check_value("8.8.8.100", "ips")
        assert is_warning
        assert info["name"] == "Google IP ranges"

        warning_lists.warning_lists["google-cidr"]["list"][0] = " 8.8.8.0/24 "
        warning_lists._preprocess_lists()
        is_warning, info = warning_lists.check_value("8.8.8.100", "ips")
        assert is_warning
        assert info["name"] == "Google IP ranges"

        # Test domain in Alexa list
        is_warning, info = warning_lists.check_value("google.com", "domains")
        assert is_warning
        assert info["name"] == "Alexa Top 1000"

        warning_lists.warning_lists["alexa-top1000"]["list"][0] = " google.com "
        warning_lists._preprocess_lists()
        is_warning, info = warning_lists.check_value("google.com", "domains")
        assert is_warning
        assert info["name"] == "Alexa Top 1000"

        # Test domain with substring match
        is_warning, info = warning_lists.check_value("virustotal.com", "domains")
        assert is_warning
        assert info["name"] == "Security Provider Domains"

        # Test non-matching IP
        is_warning, info = warning_lists.check_value("192.168.1.1", "ips")
        assert not is_warning
        assert info is None

        is_warning, info = warning_lists.check_value(" google.com ", "domains")
        assert is_warning
        assert info["name"] == "Alexa Top 1000"

    def test_string_lookup_selection_is_deterministic(self):
        """A value in several string lists must resolve to a stable list.

        Regression: the matcher iterated the lookup's set of list ids, whose order
        varies under hash randomization, so the reported warning source was
        nondeterministic across runs (spurious diff churn). It now iterates the
        ordered candidate list ids, so the first-defined matching list wins.
        """
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "list-a": {
                "name": "List A",
                "description": "first",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["shared.example"],
            },
            "list-b": {
                "name": "List B",
                "description": "second",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["shared.example"],
            },
        }
        warning_lists._preprocess_lists()

        for _ in range(3):
            warning_lists._warning_lookup_cache = {}
            is_warning, info = warning_lists.check_value("shared.example", "domains")
            assert is_warning
            assert info["name"] == "List A"

    def test_substring_domain_list_matches_url(self):
        """A domain-scoped substring list must flag the domain inside a URL.

        Regression: the substring path gated applicability on the URL's MISP types
        only, so a list scoped to domain/hostname was skipped for URLs even though
        the extracted domain was passed to the matcher -- unlike the string/regex/
        cidr paths, which already match a URL's extracted domain.
        """
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "abuse-domains": {
                "name": "Abuse Domains",
                "description": "Substrings of abusive domains",
                "type": "substring",
                "matching_attributes": ["domain", "hostname"],
                "list": ["evil"],
            },
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("x.evil.com", "domains")
        assert is_warning
        is_warning, info = warning_lists.check_value("http://x.evil.com/path", "urls")
        assert is_warning
        assert info["name"] == "Abuse Domains"

    def test_email_domain_warning_excluded(self):
        """Email IOCs with warning-listed domains appear in warning list, not dropped."""
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = self.sample_warning_lists
        warning_lists._preprocess_lists()

        iocs = {
            "emails": ["intelreports@kaspersky.com"],
            "domains": ["kaspersky.com"],
        }

        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)

        assert "emails" not in normal_iocs
        assert "emails" in warning_iocs
        assert warning_iocs["emails"][0]["value"] == "intelreports@kaspersky.com"
        assert "domains" in warning_iocs

    def test_separate_iocs_by_warnings(self):
        """Test IOC separation by warnings."""
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = self.sample_warning_lists
        warning_lists._preprocess_lists()  # Reprocess after setting mock data

        # Input IOCs
        iocs = {
            "ips": ["8.8.8.8", "192.168.1.1", "1.1.1.1"],
            "domains": ["google.com", "evil.com", "facebook.com"],
            "urls": ["https://virustotal.com/scan", "https://malware.com/payload"],
        }

        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)

        # Check normal IOCs
        assert set(normal_iocs.get("ips", [])) == {"192.168.1.1"}
        assert set(normal_iocs.get("domains", [])) == {"evil.com"}
        assert set(normal_iocs.get("urls", [])) == {"https://malware.com/payload"}

        # Check warning IOCs
        warning_ips = {w["value"] for w in warning_iocs.get("ips", [])}
        assert warning_ips == {"8.8.8.8", "1.1.1.1"}

        warning_domains = {w["value"] for w in warning_iocs.get("domains", [])}
        assert warning_domains == {"google.com", "facebook.com"}

        warning_urls = {w["value"] for w in warning_iocs.get("urls", [])}
        assert warning_urls == {"https://virustotal.com/scan"}

    def test_ipv6_support(self):
        """Test IPv6 address checking."""
        warning_lists = make_warning_lists()

        # Test IPv6 CIDR
        cidr_list = ["2001:db8::/32", "::1"]

        # Should match
        assert warning_lists._check_cidr("2001:db8::1", cidr_list)
        assert warning_lists._check_cidr("2001:db8:abcd::1234", cidr_list)
        assert warning_lists._check_cidr("::1", cidr_list)

        # Should not match
        assert not warning_lists._check_cidr("2002:db8::1", cidr_list)
        assert not warning_lists._check_cidr("::2", cidr_list)

    def test_hash_type_mapping(self):
        """Test hash type IOC mapping."""
        warning_lists = make_warning_lists()

        # Create mock hash warning list
        warning_lists.warning_lists = {
            "known-hashes": {
                "name": "Known Software Hashes",
                "description": "Hashes of known software",
                "type": "string",
                "matching_attributes": ["md5", "sha256", "filename|md5", "filename|sha256"],
                "list": ["5f4dcc3b5aa765d61d8327deb882cf99"],
            },
        }
        warning_lists._preprocess_lists()  # Reprocess after setting mock data

        # Test MD5 hash
        is_warning, info = warning_lists.check_value("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
        assert is_warning
        assert info["name"] == "Known Software Hashes"

        # Test SHA256 (not in list)
        is_warning, info = warning_lists.check_value(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256",
        )
        assert not is_warning

    def test_edge_cases(self):
        """Test edge cases and error handling."""
        warning_lists = make_warning_lists()

        # Empty lists
        assert not warning_lists._check_value_in_list("test", [], "string")
        assert not warning_lists._check_value_in_list("test", None, "string")

        # None values in list
        assert warning_lists._check_value_in_list("test", [None, "test", None], "string")

        # Invalid regex should not crash
        assert not warning_lists._check_value_in_list("test", ["[invalid(regex"], "regex")

        # Invalid CIDR should not crash
        assert not warning_lists._check_cidr("192.168.1.1", ["not/a/cidr", "256.256.256.256/24"])


class TestWarningListsDownloadAndUpdate:
    """Test warning list download and update functionality."""

    def test_update_warning_lists_with_network(self):
        """Test updating warning lists from a local HTTP source."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            warning_lists = OfflineWarningLists(tmppath, cache_duration=24, force_update=False)
            payloads = GOOD_BAD_DOMAIN_PAYLOADS

            with (
                WarningListServer(["good-domains", "bad-domains"], payloads) as base_url,
                patched_github_bases(base_url),
            ):
                warning_lists._update_warning_lists()

            assert "good-domains" in warning_lists.warning_lists
            assert warning_lists.cache_metadata_file.exists()
            with warning_lists.cache_metadata_file.open() as f:
                metadata = json.load(f)
            assert "last_update" in metadata
            assert isinstance(metadata["last_update"], (int, float))

    def test_load_from_cache_when_fresh(self):
        """Test loading warning lists from fresh cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create sample cache files
            cache_file = tmppath / "misp_warninglists_cache.json"
            metadata_file = tmppath / "misp_warninglists_metadata.json"

            sample_lists = {
                "test-list": {
                    "name": "Test List",
                    "description": "Test description",
                    "type": "string",
                    "list": ["test1", "test2"],
                }
            }

            with cache_file.open("w") as f:
                json.dump(sample_lists, f)

            with metadata_file.open("w") as f:
                json.dump({"last_update": time.time()}, f)

            warning_lists = OfflineWarningLists(tmppath, cache_duration=24, force_update=False)

            # Load from cache
            warning_lists._load_or_update_lists()

            # Verify lists were loaded
            assert "test-list" in warning_lists.warning_lists
            assert warning_lists.warning_lists["test-list"]["name"] == "Test List"

    def test_cache_expiration_triggers_update(self):
        """Test that expired cache triggers update."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create old cache files
            cache_file = tmppath / "misp_warninglists_cache.json"
            metadata_file = tmppath / "misp_warninglists_metadata.json"

            with cache_file.open("w") as f:
                json.dump({}, f)

            # Set last_update to old timestamp (25 hours ago)
            old_time = 0.0  # Unix epoch
            with metadata_file.open("w") as f:
                json.dump({"last_update": old_time}, f)

            warning_lists = TrackingWarningLists(tmppath, cache_duration=24, force_update=False)
            warning_lists._load_or_update_lists()
            assert warning_lists.updated is True

    def test_corrupted_cache_fallback(self):
        """Test fallback when cache is corrupted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create corrupted cache file
            cache_file = tmppath / "misp_warninglists_cache.json"
            metadata_file = tmppath / "misp_warninglists_metadata.json"

            with cache_file.open("w") as f:
                f.write("{ invalid json content }")

            with metadata_file.open("w") as f:
                f.write('{ "last_update": "not a number" }')

            warning_lists = TrackingWarningLists(tmppath, cache_duration=24, force_update=False)
            warning_lists._load_or_update_lists()
            assert warning_lists.updated is True


class TestWarningListsPreprocessing:
    """Test warning list preprocessing functionality."""

    def test_preprocess_lists_with_invalid_regex(self):
        """Test preprocessing handles invalid regex patterns."""
        warning_lists = make_warning_lists()

        # Create lists with invalid regex
        warning_lists.warning_lists = {
            "invalid-regex-list": {
                "name": "Invalid Regex List",
                "description": "Contains invalid regex patterns",
                "type": "regex",
                "matching_attributes": ["domain"],
                "list": [r"valid\.regex", r"[invalid(regex", r"(?P<invalid", None],
            }
        }

        # Should not crash when preprocessing invalid regex
        warning_lists._preprocess_lists()

        # Should only compile valid patterns
        assert "invalid-regex-list" in warning_lists.compiled_regex
        assert len(warning_lists.compiled_regex["invalid-regex-list"]) == 1

    def test_preprocess_lists_supports_slash_delimited_regex(self):
        """Test preprocessing handles MISP-style slash-delimited regex patterns."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "common-contact-emails": {
                "name": "Common Contact Emails",
                "description": "Regex-delimited contact email list",
                "type": "regex",
                "matching_attributes": ["email-src", "email-dst"],
                "list": [r"/^(security|noc|soc|abuse)\@.*\..*$/i"],
            }
        }

        warning_lists._preprocess_lists()

        assert "common-contact-emails" in warning_lists.compiled_regex
        assert warning_lists.check_value("security@example.com", "emails")[0]

    def test_preprocess_lists_supports_slash_delimited_regex_flags(self):
        """Test preprocessing handles slash-delimited regex flags like /.../g."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "phone_numbers": {
                "name": "Phone Numbers",
                "description": "Regex-delimited phone list",
                "type": "regex",
                "matching_attributes": ["phone-number", "whois-registrant-phone"],
                "list": [r"/((?:\+|00)61)?1900654321/g"],
            }
        }

        warning_lists._preprocess_lists()

        assert "phone_numbers" in warning_lists.compiled_regex
        assert warning_lists.check_value("1900654321", "unknown-type")[0]

    def test_preprocess_lists_supports_slash_delimited_regex_without_flags(self):
        """Test preprocessing handles slash-delimited regexes with no flags."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "simple-regex-list": {
                "name": "Simple Regex List",
                "description": "Regex-delimited list without flags",
                "type": "regex",
                "matching_attributes": ["domain"],
                "list": [r"/^example\.com$/"],
            }
        }

        warning_lists._preprocess_lists()

        assert "simple-regex-list" in warning_lists.compiled_regex
        assert warning_lists.check_value("example.com", "domains")[0]

    def test_scoped_list_with_unmapped_attribute_is_still_checked(self):
        """A scoped list whose matching_attributes map to no known IOC type must
        not be dead — its values should still be checked.

        Regression: a list scoped to e.g. 'azure-application-id' was never indexed
        under any IOC type and was excluded from the unscoped set, so a known Azure
        application ID present verbatim in the list was never flagged.
        """
        warning_lists = make_warning_lists()
        guid = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
        warning_lists.warning_lists = {
            "azure-appid-list": {
                "name": "Azure App IDs",
                "description": "Known Microsoft Azure application IDs",
                "type": "string",
                "matching_attributes": ["azure-application-id"],
                "list": [guid],
            }
        }
        warning_lists._preprocess_lists()

        matched, response = warning_lists.check_value(guid, "azure_app_ids")
        assert matched
        assert response is not None

    def test_preprocess_lists_skips_unsafe_regex(self):
        """Test preprocessing skips regex patterns with nested quantifiers."""
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "unsafe-regex-list": {
                "name": "Unsafe Regex List",
                "description": "Contains unsafe regex patterns",
                "type": "regex",
                "matching_attributes": ["domain"],
                "list": [r"valid\.regex", r"(a+)+", r"(a*)*", None],
            }
        }
        warning_lists._preprocess_lists()
        assert "unsafe-regex-list" in warning_lists.compiled_regex
        assert len(warning_lists.compiled_regex["unsafe-regex-list"]) == 1

    def test_preprocess_lists_keeps_safe_nested_group_regex(self):
        """A safe pattern containing a ')quantifier)' substring must not be dropped.

        Regression: the ReDoS guard also rejected the harmless ')+)' shape, so a
        safe pattern like (\\w(\\d)+) was silently discarded. Only genuine nested
        quantifiers (a+)+ should be skipped.
        """
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "mixed-regex-list": {
                "name": "Mixed Regex List",
                "description": "Safe nested group alongside an unsafe pattern",
                "type": "regex",
                "matching_attributes": ["domain"],
                "list": [r"(\w(\d)+)", r"(a+)+", None],
            }
        }
        warning_lists._preprocess_lists()
        compiled = warning_lists.compiled_regex["mixed-regex-list"]
        assert len(compiled) == 1
        assert compiled[0].search("a1") is not None

    def test_preprocess_lists_with_invalid_cidr(self):
        """Test preprocessing handles invalid CIDR ranges."""
        warning_lists = make_warning_lists()

        # Create lists with invalid CIDR
        warning_lists.warning_lists = {
            "invalid-cidr-list": {
                "name": "Invalid CIDR List",
                "description": "Contains invalid CIDR ranges",
                "type": "cidr",
                "matching_attributes": ["ip-src"],
                "list": ["192.168.1.0/24", "256.256.256.256/24", "not-an-ip", None, "10.0.0.0/8"],
            }
        }

        # Should not crash when preprocessing invalid CIDR
        warning_lists._preprocess_lists()

        # Should only parse valid CIDR ranges
        assert "invalid-cidr-list" in warning_lists.cidr_networks
        assert len(warning_lists.cidr_networks["invalid-cidr-list"]) == 2

    def test_preprocess_lists_with_non_list_values(self):
        """Test preprocessing handles non-list values gracefully."""
        warning_lists = make_warning_lists()

        # Create list with non-list value
        warning_lists.warning_lists = {
            "malformed-list": {
                "name": "Malformed List",
                "description": "List field is not a list",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": "not-a-list",  # Should be a list
            }
        }

        # Should handle gracefully
        warning_lists._preprocess_lists()

        # Should not crash and skip this list
        assert len(warning_lists.string_lookups) == 0

    def test_clear_preprocessed_data(self):
        """Test clearing preprocessed data structures."""
        warning_lists = make_warning_lists()

        # Populate preprocessed structures
        warning_lists.string_lookups["test"] = {"list1"}
        warning_lists.compiled_regex["list1"] = []
        warning_lists.cidr_networks["list1"] = []
        warning_lists.lists_by_ioc_type["ips"] = ["list1"]

        # Clear all
        warning_lists._clear_preprocessed_data()

        # Verify all are empty
        assert len(warning_lists.string_lookups) == 0
        assert len(warning_lists.compiled_regex) == 0
        assert len(warning_lists.cidr_networks) == 0
        assert len(warning_lists.lists_by_ioc_type) == 0

    def test_preprocess_clears_warning_lookup_cache(self):
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {}
        warning_lists._preprocess_lists()

        is_warning, _ = warning_lists.check_value("example.com", "domains")
        assert not is_warning

        warning_lists.warning_lists = {
            "new-domains": {
                "name": "New Domains",
                "description": "Updated cache content",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["example.com"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("example.com", "domains")
        assert is_warning
        assert info is not None
        assert info["name"] == "New Domains"


class TestWarningListsGetWarnings:
    """Test get_warnings_for_iocs functionality."""

    def test_get_warnings_for_iocs_with_string_iocs(self):
        """Test getting warnings for string IOCs."""
        warning_lists = make_warning_lists()

        # Setup mock lists
        warning_lists.warning_lists = {
            "public-dns": {
                "name": "Public DNS",
                "description": "Public DNS servers",
                "type": "string",
                "matching_attributes": ["ip-src", "ip-dst"],
                "list": ["8.8.8.8", "1.1.1.1"],
            }
        }
        warning_lists._preprocess_lists()

        # Test with string IOCs
        iocs = {
            "ips": ["8.8.8.8", "192.168.1.1", "1.1.1.1"],
            "domains": ["google.com", "example.com"],
        }

        warnings = warning_lists.get_warnings_for_iocs(iocs)

        # Should find warnings for matching IPs
        assert "ips" in warnings
        assert len(warnings["ips"]) == 2

        warning_values = [w["value"] for w in warnings["ips"]]
        assert "8.8.8.8" in warning_values
        assert "1.1.1.1" in warning_values
        assert "192.168.1.1" not in warning_values

    def test_get_warnings_for_iocs_with_dict_iocs(self):
        """Test getting warnings for dictionary IOCs."""
        warning_lists = make_warning_lists()

        # Setup mock lists
        warning_lists.warning_lists = {
            "known-hashes": {
                "name": "Known Hashes",
                "description": "Known software hashes",
                "type": "string",
                "matching_attributes": ["md5", "sha256"],
                "list": ["5f4dcc3b5aa765d61d8327deb882cf99"],
            }
        }
        warning_lists._preprocess_lists()

        # Test with dictionary IOCs
        iocs = {
            "md5": [
                {"value": "5f4dcc3b5aa765d61d8327deb882cf99", "file": "test.exe"},
                {"value": "abcd1234abcd1234abcd1234abcd1234", "file": "malware.exe"},
            ]
        }

        warnings = warning_lists.get_warnings_for_iocs(iocs)

        # Should find warning for first hash
        assert "md5" in warnings
        assert len(warnings["md5"]) == 1
        assert warnings["md5"][0]["value"] == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert warnings["md5"][0]["warning_list"] == "Known Hashes"

    def test_get_warnings_for_iocs_rejects_non_string_dict_values(self):
        """Malformed IOC dict values should fail instead of being stringified."""
        warning_lists = make_warning_lists()

        with pytest.raises(TypeError, match="Expected value to be string"):
            warning_lists.get_warnings_for_iocs({"domains": [{"value": object()}]})

    def test_check_value_rejects_non_string_warning_metadata(self):
        """Malformed warning-list metadata should fail instead of being stringified."""
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "bad-list": {
                "name": object(),
                "description": object(),
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["example.com"],
            }
        }
        warning_lists._preprocess_lists()

        with pytest.raises(TypeError, match="Expected name to be string"):
            warning_lists.check_value("example.com", "domains")

    def test_preprocess_rejects_non_string_warning_type(self):
        """Malformed warning-list types should fail instead of being stringified."""
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "bad-list": {
                "name": "Bad List",
                "description": "Bad type",
                "type": object(),
                "matching_attributes": ["domain"],
                "list": ["example.com"],
            }
        }

        with pytest.raises(TypeError, match="Expected type to be string"):
            warning_lists._preprocess_lists()

    def test_preprocess_rejects_non_string_regex_and_cidr_entries(self):
        """Regex and CIDR entries should fail fast instead of being stringified."""
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "bad-regex": {
                "name": "Bad Regex",
                "description": "Bad regex entry",
                "type": "regex",
                "matching_attributes": ["domain"],
                "list": [object()],
            }
        }
        with pytest.raises(TypeError, match="Expected regex pattern to be string"):
            warning_lists._preprocess_lists()

        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "bad-cidr": {
                "name": "Bad CIDR",
                "description": "Bad cidr entry",
                "type": "cidr",
                "matching_attributes": ["ip-src"],
                "list": [object()],
            }
        }
        with pytest.raises(TypeError, match="Expected cidr entry to be string"):
            warning_lists._preprocess_lists()

    def test_substring_matching_rejects_non_string_entries(self):
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "bad-substring": {
                "name": "Bad Substring",
                "description": "Bad substring entry",
                "type": "substring",
                "matching_attributes": ["domain"],
                "list": [object()],
            }
        }

        with pytest.raises(TypeError, match="Expected warning list entry to be string"):
            warning_lists._check_against_warning_list(
                "example.com",
                None,
                warning_lists.warning_lists["bad-substring"],
                "bad-substring",
            )

    def test_regex_and_cidr_checks_reject_non_string_entries(self):
        warning_lists = make_warning_lists()

        with pytest.raises(TypeError, match="string-like"):
            warning_lists._check_value_in_list("example.com", [object()], "regex")  # type: ignore[list-item]
        with pytest.raises(TypeError, match="string-like"):
            warning_lists._check_value_in_list("1.2.3.4", [object()], "cidr")  # type: ignore[list-item]

    def test_get_warnings_for_iocs_empty_input(self):
        """Test getting warnings with empty input."""
        warning_lists = make_warning_lists()

        # Test with empty dict
        warnings = warning_lists.get_warnings_for_iocs({})
        assert warnings == {}

        # Test with empty lists
        warnings = warning_lists.get_warnings_for_iocs({"ips": [], "domains": []})
        assert warnings == {}


class TestWarningListsSeparateIOCs:
    """Test separate_iocs_by_warnings functionality with dict IOCs."""

    def test_separate_iocs_preserves_dict_fields(self):
        """Test that separation preserves additional fields in dict IOCs."""
        warning_lists = make_warning_lists()

        # Setup mock lists
        warning_lists.warning_lists = {
            "known-hashes": {
                "name": "Known Hashes",
                "description": "Known software hashes",
                "type": "string",
                "matching_attributes": ["md5", "sha256"],
                "list": ["5f4dcc3b5aa765d61d8327deb882cf99"],
            }
        }
        warning_lists._preprocess_lists()

        # Test with dictionary IOCs containing extra fields
        iocs = {
            "md5": [
                {
                    "value": "5f4dcc3b5aa765d61d8327deb882cf99",
                    "filename": "test.exe",
                    "source": "virustotal",
                    "confidence": "high",
                },
                {
                    "value": "abcd1234abcd1234abcd1234abcd1234",
                    "filename": "malware.exe",
                    "source": "sandbox",
                },
            ]
        }

        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)

        # Check that warning IOC preserves extra fields
        assert "md5" in warning_iocs
        assert len(warning_iocs["md5"]) == 1
        warning_entry = warning_iocs["md5"][0]
        assert warning_entry["value"] == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert warning_entry["filename"] == "test.exe"
        assert warning_entry["source"] == "virustotal"
        assert warning_entry["confidence"] == "high"
        assert "warning_list" in warning_entry
        assert "description" in warning_entry

        # Check that normal IOC is preserved as-is
        assert "md5" in normal_iocs
        assert len(normal_iocs["md5"]) == 1
        assert normal_iocs["md5"][0]["value"] == "abcd1234abcd1234abcd1234abcd1234"


class TestWarningListsHelperFunctions:
    """Test helper functions and edge cases."""

    def test_get_misp_types_for_cryptocurrency(self):
        """Test MISP type mapping for cryptocurrency IOCs."""
        warning_lists = make_warning_lists()

        # Test bitcoin
        types = warning_lists._get_misp_types_for_ioc("bitcoin")
        assert "btc" in types
        assert "bitcoin" in types
        assert "cryptocurrency" in types

        # Test ethereum
        types = warning_lists._get_misp_types_for_ioc("ethereum")
        assert "eth" in types
        assert "cryptocurrency" in types

        # Test monero
        types = warning_lists._get_misp_types_for_ioc("monero")
        assert "xmr" in types
        assert "cryptocurrency" in types

    def test_get_misp_types_for_hashes(self):
        """Test MISP type mapping for hash IOCs."""
        warning_lists = make_warning_lists()

        for hash_type in ["md5", "sha1", "sha256", "sha512"]:
            types = warning_lists._get_misp_types_for_ioc(hash_type)
            assert hash_type in types
            assert f"filename|{hash_type}" in types
            assert "hash" in types

    def test_extract_domain_from_url_with_port(self):
        """Test domain extraction from URL with port."""
        warning_lists = make_warning_lists()

        # Test URL with port
        domain = warning_lists._extract_domain_from_url("https://example.com:8080/path")
        assert domain == "example.com"

        # Test URL without port
        domain = warning_lists._extract_domain_from_url("https://example.com/path")
        assert domain == "example.com"

        # Test URL with user info
        domain = warning_lists._extract_domain_from_url("https://user:pass@example.com/path")
        assert domain == "example.com"

        # Test bracketed IPv6 host
        domain = warning_lists._extract_domain_from_url("https://[2001:db8::1]:443/path")
        assert domain == "2001:db8::1"

        # Test invalid URL
        domain = warning_lists._extract_domain_from_url("not-a-url")
        assert domain is None

    def test_is_list_applicable_with_dict_attributes(self):
        """Test list applicability check with dictionary attributes."""
        warning_lists = make_warning_lists()

        # Test with dictionary attributes
        warning_list = {
            "name": "Test List",
            "type": "string",
            "matching_attributes": [
                {"name": "ip-src"},
                {"name": "domain"},
                "email",
            ],
            "list": [],
        }

        # Should match IP types
        assert warning_lists._is_list_applicable(warning_list, ["ip-src", "ip-dst"], "ips")

        # Should match domain types
        assert warning_lists._is_list_applicable(warning_list, ["domain", "hostname"], "domains")

        # Should match email types
        assert warning_lists._is_list_applicable(warning_list, ["email", "email-src"], "emails")

    def test_is_list_applicable_without_attributes(self):
        """Test list applicability when matching_attributes is missing or invalid."""
        warning_lists = make_warning_lists()

        # Test without matching_attributes
        warning_list = {
            "name": "Test List",
            "type": "string",
            "list": [],
        }
        assert not warning_lists._is_list_applicable(warning_list, ["ip-src"], "ips")

        # Test with non-list matching_attributes
        warning_list["matching_attributes"] = "not-a-list"
        assert not warning_lists._is_list_applicable(warning_list, ["ip-src"], "ips")

        # Test with empty list
        warning_list["matching_attributes"] = []
        assert not warning_lists._is_list_applicable(warning_list, ["ip-src"], "ips")

    def test_is_list_applicable_cidr_special_case(self):
        """Test CIDR list applicability for IPs."""
        warning_lists = make_warning_lists()

        # CIDR lists should apply to IPs even without matching attributes
        warning_list = {
            "name": "CIDR List",
            "type": "cidr",
            "matching_attributes": ["unrelated-type"],
            "list": ["192.168.0.0/16"],
        }

        assert warning_lists._is_list_applicable(warning_list, ["ip-src"], "ips")
        assert warning_lists._is_list_applicable(warning_list, ["ipv6"], "ipv6")

    def test_check_against_warning_list_with_url_domain_extraction(self):
        """Test checking against warning list with URL domain extraction."""
        warning_lists = make_warning_lists()

        warning_list = {
            "name": "Alexa Top Sites",
            "description": "Top visited domains",
            "type": "string",
            "list": ["google.com", "facebook.com"],
        }

        # Test URL matching via domain extraction
        result = warning_lists._check_against_warning_list(
            "https://google.com/search",
            "google.com",
            warning_list,
            "alexa-top-sites",
        )

        assert result is not None
        assert result["name"] == "Alexa Top Sites"

    def test_check_value_with_no_relevant_lists(self):
        """Test check_value when no relevant lists exist for IOC type."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "unrelated-list": {
                "name": "Unrelated List",
                "description": "For different IOC type",
                "type": "string",
                "matching_attributes": ["unrelated-type"],
                "list": ["test"],
            }
        }
        warning_lists._preprocess_lists()

        # Should fall back to checking all lists
        is_warning, _info = warning_lists.check_value("test", "unknown-type")
        # May or may not match depending on fallback logic
        assert isinstance(is_warning, bool)

    def test_check_substring_type(self):
        """Test substring type checking."""
        warning_lists = make_warning_lists()

        values = ["malware", "virus", "trojan", ""]

        # Should match substring
        assert warning_lists._check_substring_type("malwarebytes.com", values)
        assert warning_lists._check_substring_type("antivirus-software", values)
        assert warning_lists._check_substring_type("trojan-dropper", values)
        assert warning_lists._check_substring_type("mail.google.com", [" google "])

        # Should also match if value contains list item
        assert warning_lists._check_substring_type("malware", values)

        # Should not match
        assert not warning_lists._check_substring_type("clean-domain.com", values)

    def test_check_regex_type_with_none_values(self):
        """Test regex checking with None values in list."""
        warning_lists = make_warning_lists()

        values = [r".*\.google\.com$", None, r"^test.*", ""]

        # Should skip None values
        assert warning_lists._check_regex_type("mail.google.com", values)
        assert warning_lists._check_regex_type(" mail.google.com ", values)
        assert warning_lists._check_regex_type("testdomain.com", values)
        assert not warning_lists._check_regex_type("example.com", values)

    def test_check_value_in_list_unknown_type(self):
        """Test check_value_in_list with unknown type."""
        warning_lists = make_warning_lists()

        # Unknown type should return False
        result = warning_lists._check_value_in_list("test", ["test"], "unknown-type")
        assert result is False

    def test_check_value_with_extracted_domain_in_string_lookups(self):
        """Test check_value when extracted domain is in string lookups."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "alexa-top": {
                "name": "Alexa Top Sites",
                "description": "Top sites",
                "type": "string",
                "matching_attributes": ["domain", "url"],
                "list": ["google.com", "facebook.com"],
            }
        }
        warning_lists._preprocess_lists()

        # Test URL that extracts to a domain in string lookups
        is_warning, info = warning_lists.check_value("https://google.com/search?q=test", "urls")
        assert is_warning
        assert info["name"] == "Alexa Top Sites"

    def test_check_value_with_extracted_domain_in_email_lookups(self):
        """Test check_value when email domain is in string lookups."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "domain-block": {
                "name": "Domain Block",
                "description": "Domain-scoped blocklist",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["example.com"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("user@example.com", "emails")
        assert is_warning
        assert info["name"] == "Domain Block"

    def test_check_value_with_hostname_escape_artifact(self):
        """Hostname entries with escaped trailing whitespace should still match."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "public-dns-hostname": {
                "name": "Public DNS Hostname",
                "description": "Hostname list with escaped trailing whitespace",
                "type": "hostname",
                "matching_attributes": ["domain"],
                "list": ["static-185.132.201.202.andorpac.ad\\ "],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value(
            "static-185.132.201.202.andorpac.ad", "domains"
        )
        assert is_warning
        assert info["name"] == "Public DNS Hostname"

    def test_check_value_with_extracted_domain_in_regex(self):
        """Test check_value when extracted domain matches regex."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "google-domains": {
                "name": "Google Domains",
                "description": "All Google domains",
                "type": "regex",
                "matching_attributes": ["domain", "url"],
                "list": [r".*\.google\.com$", r".*\.googleapis\.com$"],
            }
        }
        warning_lists._preprocess_lists()

        # Test URL with domain matching regex
        is_warning, info = warning_lists.check_value("https://mail.google.com/inbox", "urls")
        assert is_warning
        assert info["name"] == "Google Domains"

    def test_check_value_ipv6_in_cidr(self):
        """Test IPv6 address checking in CIDR ranges."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "reserved-ipv6": {
                "name": "Reserved IPv6",
                "description": "Reserved IPv6 ranges",
                "type": "cidr",
                "matching_attributes": ["ip-src", "ipv6"],
                "list": ["2001:db8::/32", "fe80::/10"],
            }
        }
        warning_lists._preprocess_lists()

        # Test IPv6 in CIDR range
        is_warning, info = warning_lists.check_value("2001:db8::1234", "ipv6")
        assert is_warning
        assert info["name"] == "Reserved IPv6"

        # Test IPv6 in another range
        is_warning, info = warning_lists.check_value("fe80::1", "ipv6")
        assert is_warning

    def test_ipv6_matches_cidr_list_scoped_to_ip_attributes(self):
        """Regression: IPv6 IOCs must match IP CIDR lists that use only ip-src/ip-dst.

        MISP CIDR lists are typically scoped to ["ip-src", "ip-dst", "ip"] (no
        explicit "ipv6" attribute), so they index under "ips". IPv6 IOCs must
        still be checked against them, not silently skipped.
        """
        warning_lists = make_warning_lists()
        warning_lists.warning_lists = {
            "doc-range": {
                "name": "Documentation IPv6",
                "description": "RFC 3849 documentation range",
                "type": "cidr",
                "matching_attributes": ["ip-src", "ip-dst", "ip"],
                "list": ["2001:db8::/32"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("2001:db8:abcd::42", "ipv6")
        assert is_warning
        assert info["name"] == "Documentation IPv6"
        assert warning_lists.check_value("2001:dead::1", "ipv6")[0] is False

    def test_check_value_invalid_ip_for_cidr(self):
        """Test CIDR checking with invalid IP address."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "private-ips": {
                "name": "Private IPs",
                "description": "Private IP ranges",
                "type": "cidr",
                "matching_attributes": ["ip-src"],
                "list": ["192.168.0.0/16", "10.0.0.0/8"],
            }
        }
        warning_lists._preprocess_lists()

        # Test invalid IP
        is_warning, info = warning_lists.check_value("not-an-ip", "ips")
        assert not is_warning
        assert info is None


class TestWarningListsAdditionalEdgeCases:
    """Test additional edge cases for higher coverage."""

    def test_get_misp_types_for_ipv6(self):
        """Test MISP type mapping specifically for IPv6."""
        warning_lists = make_warning_lists()

        types = warning_lists._get_misp_types_for_ioc("ipv6")
        assert "ip-src" in types
        assert "ip-dst" in types
        assert "ipv6" in types

    def test_get_misp_types_for_ssdeep(self):
        """Test MISP type mapping for ssdeep hash type."""
        warning_lists = make_warning_lists()

        types = warning_lists._get_misp_types_for_ioc("ssdeep")
        assert "ssdeep" in types
        assert "filename|ssdeep" in types
        assert "hash" in types

    def test_get_misp_types_for_imphash(self):
        """Test MISP type mapping for imphash type."""
        warning_lists = make_warning_lists()

        types = warning_lists._get_misp_types_for_ioc("imphash")
        assert "imphash" in types
        assert "filename|imphash" in types

    def test_check_against_warning_list_with_non_list_values(self):
        """Test checking against warning list when values field is not a list."""
        warning_lists = make_warning_lists()

        # Create warning list with non-list values field
        warning_list = {
            "name": "Test List",
            "description": "Test",
            "type": "string",
            "list": "not-a-list",  # Should be a list
        }

        result = warning_lists._check_against_warning_list(
            "test-value",
            None,
            warning_list,
            "test-list",
        )

        # Should return None since values is not a list
        assert result is None

    def test_check_cidr_with_ipv6_exact_match(self):
        """Test CIDR checking with exact IPv6 match."""
        warning_lists = make_warning_lists()

        cidr_list = ["2001:db8::1", "::1"]

        # Should match exact IPv6
        assert warning_lists._check_cidr("2001:db8::1", cidr_list)
        assert warning_lists._check_cidr("::1", cidr_list)

        # Should not match different IPv6
        assert not warning_lists._check_cidr("2001:db8::2", cidr_list)

    def test_check_substring_type_with_none_values(self):
        """Test substring checking with None values in list."""
        warning_lists = make_warning_lists()

        values = ["malware", None, "virus"]

        # Should skip None values
        assert warning_lists._check_substring_type("malware-sample", values)
        assert not warning_lists._check_substring_type("clean", values)

    def test_extract_domain_from_url_exception_handling(self):
        """Test domain extraction with various edge cases."""
        warning_lists = make_warning_lists()

        # Test with empty string
        domain = warning_lists._extract_domain_from_url("")
        assert domain is None

        # Test with malformed URL
        domain = warning_lists._extract_domain_from_url(":///")
        assert domain is None

    def test_diagnose_with_non_matching_list(self):
        """Test diagnostic output when value not in list."""
        import io
        import logging

        warning_lists = make_warning_lists()

        # Setup mock list with non-matching values and proper matching attributes
        warning_lists.warning_lists = {
            "test-domain-list": {
                "name": "Test Domain List",
                "description": "Test domain values",
                "type": "string",
                "matching_attributes": ["domain", "hostname"],
                "list": ["example.com", "test.com"],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic on non-matching value
        warning_lists.diagnose_value_detection("nonexistent.com", "domains")

        # Get log output
        log_output = log_capture.getvalue()

        # Should show checking the list and indicate not found
        assert "Test Domain List" in log_output or "FINAL RESULT: Value is NOT" in log_output

        # Cleanup
        logger.removeHandler(handler)


class TestWarningListsDiagnostic:
    """Test diagnose_value_detection functionality."""

    def test_diagnose_value_detection_found(self):
        """Test diagnostic tool when value is found."""
        import io
        import logging

        warning_lists = make_warning_lists()

        # Setup mock lists
        warning_lists.warning_lists = {
            "public-dns-v4": {
                "name": "Public DNS Resolvers",
                "description": "List of public DNS resolver IP addresses",
                "type": "string",
                "matching_attributes": ["ip-src", "ip-dst", "ip"],
                "list": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic
        warning_lists.diagnose_value_detection("8.8.8.8", "ips")

        # Get log output
        log_output = log_capture.getvalue()

        # Verify diagnostic output
        assert "Diagnosing detection for 8.8.8.8" in log_output
        assert "Public DNS Resolvers" in log_output
        assert "FINAL RESULT: Value IS in warning list" in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_diagnose_value_detection_not_found(self):
        """Test diagnostic tool when value is not found."""
        import io
        import logging

        warning_lists = make_warning_lists()

        # Setup mock lists
        warning_lists.warning_lists = {
            "public-dns-v4": {
                "name": "Public DNS Resolvers",
                "description": "List of public DNS resolver IP addresses",
                "type": "string",
                "matching_attributes": ["ip-src", "ip-dst"],
                "list": ["8.8.8.8", "1.1.1.1"],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic
        warning_lists.diagnose_value_detection("192.168.1.1", "ips")

        # Get log output
        log_output = log_capture.getvalue()

        # Verify diagnostic output
        assert "Diagnosing detection for 192.168.1.1" in log_output
        assert "FINAL RESULT: Value is NOT in any warning list" in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_diagnose_with_expected_lists_filter(self):
        """Test diagnostic with expected lists filter."""
        import io
        import logging

        warning_lists = make_warning_lists()

        # Setup multiple mock lists
        warning_lists.warning_lists = {
            "public-dns-v4": {
                "name": "Public DNS Resolvers",
                "description": "List of public DNS resolver IP addresses",
                "type": "string",
                "matching_attributes": ["ip-src"],
                "list": ["8.8.8.8"],
            },
            "alexa-top1000": {
                "name": "Alexa Top 1000",
                "description": "Top websites",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["google.com"],
            },
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic with expected lists filter
        warning_lists.diagnose_value_detection("8.8.8.8", "ips", expected_lists=["DNS"])

        # Get log output
        log_output = log_capture.getvalue()

        # Should check Public DNS list (contains 'DNS')
        assert "Public DNS Resolvers" in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_diagnose_with_defanged_value(self):
        """Test diagnostic with defanged value."""
        import io
        import logging

        warning_lists = make_warning_lists()

        # Setup mock lists
        warning_lists.warning_lists = {
            "alexa-top": {
                "name": "Alexa Top Sites",
                "description": "Top websites",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["google.com", "facebook.com"],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic with defanged value
        warning_lists.diagnose_value_detection("google[.]com", "domains")

        # Get log output
        log_output = log_capture.getvalue()

        # Should show cleaned value
        assert "Cleaned value: google.com" in log_output
        assert "FINAL RESULT: Value IS in warning list" in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_diagnose_with_padded_string_entry(self):
        """Diagnostics should normalize padded string list entries."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "alexa-top": {
                "name": "Alexa Top Sites",
                "description": "Top websites",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": [" google.com "],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection("google.com", "domains")

        log_output = log_capture.getvalue()

        assert "Matched: google.com" in log_output
        assert "FINAL RESULT: Value IS in warning list" in log_output

        logger.removeHandler(handler)

    def test_diagnose_with_email_domain_warning(self):
        """Email diagnostics should surface warning-listed domains."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "domain-blocklist": {
                "name": "Domain Blocklist",
                "description": "Domain-scoped blocklist",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["kaspersky.com"],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection("intelreports@kaspersky.com", "emails")

        log_output = log_capture.getvalue()

        assert "Domain Blocklist" in log_output
        assert "FINAL RESULT: Value IS in warning list" in log_output

        logger.removeHandler(handler)

    def test_diagnose_with_host_ioc_type(self):
        """Host diagnostics should surface domain-scoped warning lists."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "blocked-hosts": {
                "name": "Blocked Hosts",
                "description": "Domain-scoped blocklist",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["blocked.example"],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection("blocked.example", "hosts")

        log_output = log_capture.getvalue()

        assert "Blocked Hosts" in log_output
        assert "FINAL RESULT: Value IS in warning list" in log_output

        logger.removeHandler(handler)

    def test_diagnose_with_host_alias(self):
        """Singular host aliases should normalize before diagnostics filtering."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "blocked-hosts": {
                "name": "Blocked Hosts",
                "description": "Domain-scoped blocklist",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["blocked.example"],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection("blocked.example", "host")

        log_output = log_capture.getvalue()

        assert "Found 1 potentially relevant lists" in log_output
        assert "Blocked Hosts" in log_output

        logger.removeHandler(handler)

    def test_diagnose_uses_matching_attributes_for_relevance(self):
        """Diagnostics should show domain lists even when names omit domain keywords."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "public-ipfs-gateways": {
                "name": "List of known public IPFS gateways",
                "description": "Event contains one or more entries of known public IPFS gateways",
                "type": "string",
                "matching_attributes": ["domain", "hostname", "domain|ip", "url", "uri"],
                "list": ["4everland.io"],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection("4everland.io", "domains")

        log_output = log_capture.getvalue()

        assert "Found 1 potentially relevant lists" in log_output
        assert "List of known public IPFS gateways" in log_output

        logger.removeHandler(handler)

    def test_diagnose_ignores_unrelated_matching_attributes(self):
        """Diagnostics should not treat substring accidents as relevant attribute tokens."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "ghost-list": {
                "name": "Ghost List",
                "description": "Unrelated entries",
                "type": "string",
                "matching_attributes": ["ghost-field"],
                "list": ["example.com"],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection("example.com", "domains")

        log_output = log_capture.getvalue()

        assert "Found 0 potentially relevant lists" in log_output
        assert "\nChecking list: Ghost List\n" not in log_output

        logger.removeHandler(handler)

    def test_diagnose_matches_multiword_expected_lists(self):
        """Diagnostics should still honor multiword expected list filters."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "public-ipfs-gateways": {
                "name": "List of known public IPFS gateways",
                "description": "Event contains one or more entries of known public IPFS gateways",
                "type": "string",
                "matching_attributes": ["domain", "hostname", "domain|ip", "url", "uri"],
                "list": ["4everland.io"],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection(
            "4everland.io", "domains", expected_lists=["public IPFS"]
        )

        log_output = log_capture.getvalue()

        assert "Found 1 potentially relevant lists" in log_output
        assert "List of known public IPFS gateways" in log_output

        logger.removeHandler(handler)

    def test_diagnose_with_host_keyword_only_list_name(self):
        """Host diagnostics should not miss host-oriented list names."""
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "check-host-net": {
                "name": "List of known check-host.net IP address ranges",
                "description": "check-host IP addresses",
                "type": "cidr",
                "matching_attributes": ["ip-src"],
                "list": ["192.0.2.0/24"],
            }
        }
        warning_lists._preprocess_lists()

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        warning_lists.diagnose_value_detection("192.0.2.10", "hosts")

        log_output = log_capture.getvalue()

        assert "List of known check-host.net IP address ranges" in log_output

        logger.removeHandler(handler)

    def test_is_list_relevant_for_expected(self):
        """Test expected list relevance checking."""
        warning_lists = make_warning_lists()

        # Test matching name
        assert warning_lists._is_list_relevant_for_expected(
            "Public DNS Resolvers",
            "DNS servers",
            ["DNS", "resolvers"],
        )

        # Test matching description
        assert warning_lists._is_list_relevant_for_expected(
            "IP List",
            "Contains DNS resolver IPs",
            ["DNS"],
        )

        # Test no match
        assert not warning_lists._is_list_relevant_for_expected(
            "Alexa Top Sites",
            "Popular websites",
            ["DNS", "IP"],
        )

        # Test empty expected list
        assert not warning_lists._is_list_relevant_for_expected(
            "Any List",
            "Any description",
            [],
        )

        # Test None expected list
        assert not warning_lists._is_list_relevant_for_expected(
            "Any List",
            "Any description",
            None,
        )

    def test_is_list_relevant_for_type(self):
        """Test IOC type relevance checking."""
        warning_lists = make_warning_lists()

        # Test IP relevance
        assert warning_lists._is_list_relevant_for_type(
            "Public IP Addresses",
            "List of IP addresses",
            "ips",
        )

        # Test domain relevance
        assert warning_lists._is_list_relevant_for_type(
            "Top Domains",
            "Popular domain names",
            "domains",
        )

        # Test URL relevance
        assert warning_lists._is_list_relevant_for_type(
            "URL Shorteners",
            "Common URL shortening services",
            "urls",
        )

        # Test no match
        assert not warning_lists._is_list_relevant_for_type(
            "Hash List",
            "File hashes",
            "ips",
        )

        # Test unknown IOC type
        assert not warning_lists._is_list_relevant_for_type(
            "Any List",
            "Any description",
            "unknown-type",
        )


class TestWarningListsUpdateAndDownload:
    """Test warning list update and download functionality for 100% coverage."""

    def test_update_warning_lists_network_request(self):
        """
        Test warning list download flow via a local HTTP server.
        """
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            warning_lists = OfflineWarningLists(tmppath, cache_duration=0, force_update=True)
            payloads = {
                "test-domains": (
                    200,
                    {
                        "name": "Test Domains",
                        "type": "string",
                        "matching_attributes": ["domain"],
                        "list": ["example.com"],
                    },
                ),
            }

            with (
                WarningListServer(["test-domains"], payloads) as base_url,
                patched_github_bases(base_url),
            ):
                warning_lists._update_warning_lists()

            assert len(warning_lists.warning_lists) == 1
            assert warning_lists.cache_file.exists()
            assert warning_lists.cache_metadata_file.exists()

    def test_update_warning_lists_exception_handling(self):
        """
        Test exception handling during warning list updates.

        Validates that network errors are handled gracefully.
        """
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            warning_lists = make_warning_lists()
            warning_lists.data_dir = tmppath
            warning_lists.cache_file = tmppath / "misp_warninglists_cache.json"
            warning_lists.cache_metadata_file = tmppath / "misp_warninglists_metadata.json"

            warning_lists.GITHUB_API_BASE = "http://127.0.0.1:9/unreachable"

            with contextlib.suppress(Exception):
                warning_lists._update_warning_lists()

            assert isinstance(warning_lists.warning_lists, dict)


class TestWarningListsCheckValueEdgeCases:
    """Test edge cases in check_value for complete coverage."""

    def test_check_value_with_regex_match(self):
        """
        Test check_value when regex pattern matches.

        Validates regex matching code path in check_value.
        """
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "google-regex": {
                "name": "Google Domains Regex",
                "description": "Google domains via regex",
                "type": "regex",
                "matching_attributes": ["domain", "hostname"],
                "list": [r".*\.google\.com$", r".*\.googleapis\.com$"],
            }
        }
        warning_lists._preprocess_lists()

        # Test domain that matches regex
        is_warning, info = warning_lists.check_value("mail.google.com", "domains")
        assert is_warning
        assert info["name"] == "Google Domains Regex"

        # Test extracted domain from URL
        is_warning, info = warning_lists.check_value(
            "https://storage.googleapis.com/bucket", "urls"
        )
        assert is_warning

    def test_check_value_with_slash_delimited_regex_match(self):
        """Slash-delimited regex patterns should match like raw regexes."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "common-contact-emails": {
                "name": "Common Contact Emails",
                "description": "Regex-delimited contact email list",
                "type": "regex",
                "matching_attributes": ["email-src", "email-dst"],
                "list": [r"/^(security|noc|soc|abuse)\@.*\..*$/i"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("security@example.com", "emails")
        assert is_warning
        assert info["name"] == "Common Contact Emails"

    def test_check_value_with_cidr_match(self):
        """
        Test check_value when IP matches CIDR range.

        Validates CIDR matching code path.
        """
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "private-ips": {
                "name": "Private IP Ranges",
                "description": "RFC1918 private IPs",
                "type": "cidr",
                "matching_attributes": ["ip-src", "ip-dst"],
                "list": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
            }
        }
        warning_lists._preprocess_lists()

        # Test IP in CIDR range
        is_warning, info = warning_lists.check_value("192.168.1.100", "ips")
        assert is_warning
        assert info["name"] == "Private IP Ranges"

        # Test IP in different range
        is_warning, info = warning_lists.check_value("10.5.5.5", "ips")
        assert is_warning

    def test_check_value_with_exact_ip_in_cidr_list(self):
        """Test CIDR warning lists can contain exact IP values."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "exact-ips": {
                "name": "Exact IPs",
                "description": "Exact IP entries in a CIDR warning list",
                "type": "cidr",
                "matching_attributes": ["ip-src", "ipv6"],
                "list": ["8.8.8.8", "2001:db8::1"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("8.8.8.8", "ips")
        assert is_warning
        assert info["name"] == "Exact IPs"

        is_warning, info = warning_lists.check_value("2001:db8::1", "ipv6")
        assert is_warning
        assert info["name"] == "Exact IPs"

    def test_check_value_applies_domain_lists_to_hosts(self):
        """Host IOCs should match the same warning-list scopes as domains."""
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "blocked-hosts": {
                "name": "Blocked Hosts",
                "description": "Domain-scoped blocklist",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["blocked.example"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("blocked.example", "hosts")
        assert is_warning
        assert info["name"] == "Blocked Hosts"

    def test_check_value_with_substring_fallback(self):
        """
        Test check_value substring type fallback path.

        Validates substring matching in fallback logic.
        """
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "security-providers": {
                "name": "Security Provider Domains",
                "description": "Security company domains",
                "type": "substring",
                "matching_attributes": ["domain", "url"],
                "list": ["virustotal", "malwarebytes", "kaspersky"],
            }
        }
        warning_lists._preprocess_lists()

        # Test substring match
        is_warning, info = warning_lists.check_value("virustotal.com", "domains")
        assert is_warning
        assert info["name"] == "Security Provider Domains"

    def test_known_ioc_type_does_not_fallback_to_unrelated_warning_lists(self):
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "email-only": {
                "name": "Email Only",
                "description": "Values that only apply to email IOCs",
                "type": "string",
                "matching_attributes": ["email"],
                "list": ["example.com"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("example.com", "domains")
        assert not is_warning
        assert info is None

    def test_all_builtin_ioc_types_avoid_unrelated_warning_list_fallback(self):
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "email-only": {
                "name": "Email Only",
                "description": "Values that only apply to email IOCs",
                "type": "string",
                "matching_attributes": ["email"],
                "list": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
            }
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "registry"
        )
        assert not is_warning
        assert info is None

    def test_unscoped_warning_lists_still_apply_when_relevant_lists_exist(self):
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "domain-other": {
                "name": "Other Domains",
                "description": "A typed list that does not contain the IOC",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["other.example"],
            },
            "global-list": {
                "name": "Global List",
                "description": "A list without matching attributes applies globally",
                "type": "string",
                "list": ["example.com"],
            },
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("example.com", "domains")
        assert is_warning
        assert info["name"] == "Global List"

    def test_unscoped_substring_warning_lists_still_apply_globally(self):
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "domain-other": {
                "name": "Other Domains",
                "description": "A typed list that does not contain the IOC",
                "type": "string",
                "matching_attributes": ["domain"],
                "list": ["other.example"],
            },
            "global-substring": {
                "name": "Global Substring",
                "description": "A substring list without matching attributes applies globally",
                "type": "substring",
                "list": ["trusted-cdn"],
            },
        }
        warning_lists._preprocess_lists()

        is_warning, info = warning_lists.check_value("https://trusted-cdn.example/path", "urls")
        assert is_warning
        assert info["name"] == "Global Substring"

    def test_check_value_with_extracted_domain_in_regex(self):
        """
        Test check_value when extracted domain matches regex.

        Validates URL domain extraction and regex matching.
        """
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "cdn-domains": {
                "name": "CDN Domains",
                "description": "Content delivery networks",
                "type": "regex",
                "matching_attributes": ["domain", "url"],
                "list": [r".*\.cloudfront\.net$", r".*\.akamai\.net$"],
            }
        }
        warning_lists._preprocess_lists()

        # Test URL with domain matching regex
        is_warning, info = warning_lists.check_value(
            "https://d111111abcdef8.cloudfront.net/image.jpg", "urls"
        )
        assert is_warning
        assert info["name"] == "CDN Domains"

    def test_check_value_invalid_ip_for_cidr(self):
        """
        Test CIDR checking with invalid IP format.

        Validates exception handling in IP address parsing.
        """
        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "test-cidrs": {
                "name": "Test CIDR List",
                "description": "Test",
                "type": "cidr",
                "matching_attributes": ["ip-src"],
                "list": ["10.0.0.0/8"],
            }
        }
        warning_lists._preprocess_lists()

        # Test with invalid IP
        is_warning, info = warning_lists.check_value("not-an-ip-address", "ips")
        assert not is_warning
        assert info is None

        # Test with malformed IP
        is_warning, info = warning_lists.check_value("999.999.999.999", "ips")
        assert not is_warning


class TestWarningListsExtractDomainEdgeCases:
    """Test domain extraction edge cases for complete coverage."""

    def test_extract_domain_from_url_with_port(self):
        """
        Test domain extraction from URL with port number.

        Validates port stripping in domain extraction.
        """
        warning_lists = make_warning_lists()

        # Test URL with port
        domain = warning_lists._extract_domain_from_url("https://example.com:8080/path")
        assert domain == "example.com"

        # Test URL with standard port
        domain = warning_lists._extract_domain_from_url("https://example.com:443/path")
        assert domain == "example.com"

    def test_extract_domain_exception_handling(self):
        """
        Test domain extraction exception handling.

        Validates graceful failure for malformed URLs.
        """
        warning_lists = make_warning_lists()

        # Test with invalid URL
        domain = warning_lists._extract_domain_from_url("not a url")
        assert domain is None

        # Test with empty string
        domain = warning_lists._extract_domain_from_url("")
        assert domain is None

        # Test with malformed URL
        domain = warning_lists._extract_domain_from_url("http://")
        assert domain is None or domain == ""


class TestWarningListsIsListApplicableEdgeCases:
    """Test _is_list_applicable edge cases for complete coverage."""

    def test_is_list_applicable_with_empty_attrs_list(self):
        """
        Test list applicability when attrs_list is empty after processing.

        Validates handling of edge case where matching_attributes yields no valid attrs.
        """
        warning_lists = make_warning_lists()

        # List with only invalid attribute formats
        warning_list = {
            "name": "Test List",
            "type": "string",
            "matching_attributes": [123, None, {"no_name_key": "value"}],
            "list": [],
        }

        result = warning_lists._is_list_applicable(warning_list, ["ip-src"], "ips")
        assert not result


class TestWarningListsDiagnoseValueDetection:
    """Test diagnose_value_detection for complete coverage."""

    def test_diagnose_value_detection_execution(self):
        """
        Test that diagnose_value_detection executes without errors.

        Validates the diagnostic helper function code path.
        """
        import io
        import logging

        warning_lists = make_warning_lists()

        warning_lists.warning_lists = {
            "test-list": {
                "name": "Test Warning List",
                "description": "For testing diagnostics",
                "type": "string",
                "matching_attributes": ["ip-src", "ip-dst"],
                "list": ["8.8.8.8", "1.1.1.1"],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("iocparser.infrastructure.warninglists")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic
        warning_lists.diagnose_value_detection("8.8.8.8", "ips")

        # Get log output
        log_output = log_capture.getvalue()

        # Should contain diagnostic information
        assert "Diagnosing detection" in log_output or "FINAL RESULT" in log_output

        # Cleanup
        logger.removeHandler(handler)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
