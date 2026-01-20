#!/usr/bin/env python3

"""
Test suite for output_formatter.py module

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Author: Marc Rivero | @seifreed
"""

import json
import tempfile
from pathlib import Path
from typing import Union

import pytest

from iocparser.modules.output_formatter import JSONFormatter, STIXFormatter, TextFormatter


class TestJSONFormatter:
    """Test suite for JSONFormatter class"""

    def test_prepare_data_for_json_with_string_lists(self):
        """
        Test _prepare_data_for_json() with lists of strings.

        Validates that string lists are sorted and properly formatted.
        Covers lines 64-86.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example.com", "test.com", "abc.com"],
            "ips": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        }
        formatter = JSONFormatter(data)

        # Act
        result = formatter._prepare_data_for_json()

        # Assert
        assert "domains" in result
        assert "ips" in result
        # Verify strings are sorted
        assert result["domains"] == ["abc.com", "example.com", "test.com"]
        assert result["ips"] == ["10.0.0.1", "172.16.0.1", "192.168.1.1"]

    def test_prepare_data_for_json_with_dict_values(self):
        """
        Test _prepare_data_for_json() with dict values.

        Validates that dict values are preserved as-is without sorting.
        Covers lines 70-76.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "hashes": [
                {"type": "md5", "value": "5f4dcc3b5aa765d61d8327deb882cf99"},
                {"type": "sha1", "value": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
            ]
        }
        formatter = JSONFormatter(data)

        # Act
        result = formatter._prepare_data_for_json()

        # Assert
        assert "hashes" in result
        assert len(result["hashes"]) == 2
        # Verify dicts are preserved in original order
        assert result["hashes"][0]["type"] == "md5"
        assert result["hashes"][1]["type"] == "sha1"

    def test_prepare_data_for_json_with_hashes_key(self):
        """
        Test _prepare_data_for_json() with 'hashes' key.

        Validates that hashes are not sorted (special case handling).
        Covers lines 68, 78.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "hashes": [
                {"type": "sha256", "value": "zzzz"},
                {"type": "md5", "value": "aaaa"},
            ]
        }
        formatter = JSONFormatter(data)

        # Act
        result = formatter._prepare_data_for_json()

        # Assert
        assert "hashes" in result
        # Verify original order is preserved for hashes
        assert result["hashes"][0]["value"] == "zzzz"
        assert result["hashes"][1]["value"] == "aaaa"

    def test_prepare_data_for_json_with_mixed_str_and_dict(self):
        """
        Test _prepare_data_for_json() with mixed string and dict values.

        Validates handling when a list contains both strings and dicts.
        Covers lines 70-76 (else branch on line 75-76).
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "mixed_data": [
                "plain_string",
                {"key": "value"},
                "another_string",
            ]
        }
        formatter = JSONFormatter(data)

        # Act
        result = formatter._prepare_data_for_json()

        # Assert
        assert "mixed_data" in result
        # When mixed, should preserve original order (else branch at line 76)
        assert len(result["mixed_data"]) == 3
        assert result["mixed_data"][0] == "plain_string"
        assert result["mixed_data"][1] == {"key": "value"}
        assert result["mixed_data"][2] == "another_string"

    def test_prepare_data_for_json_with_warning_iocs(self):
        """
        Test _prepare_data_for_json() with warning_iocs.

        Validates that warning IOCs are included in output.
        Covers lines 81-85.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"domains": ["malware.com"]}
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "ips": [
                {
                    "value": "8.8.8.8",
                    "warning_list": "Google DNS",
                    "description": "Public DNS server",
                }
            ]
        }
        formatter = JSONFormatter(data, warning_iocs)

        # Act
        result = formatter._prepare_data_for_json()

        # Assert
        assert "warning_list_matches" in result
        assert "ips" in result["warning_list_matches"]
        assert result["warning_list_matches"]["ips"][0]["value"] == "8.8.8.8"

    def test_prepare_data_for_json_without_warning_iocs(self):
        """
        Test _prepare_data_for_json() without warning_iocs.

        Validates that warning_list_matches is not added when no warnings exist.
        Covers lines 81 (false branch).
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"domains": ["example.com"]}
        formatter = JSONFormatter(data)

        # Act
        result = formatter._prepare_data_for_json()

        # Assert
        assert "warning_list_matches" not in result
        assert "domains" in result

    def test_format_returns_valid_json(self):
        """
        Test format() returns valid JSON string.

        Validates JSON serialization with indentation and sorting.
        Covers lines 95-97.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["test.com", "example.com"],
            "ips": ["192.168.1.1"],
        }
        formatter = JSONFormatter(data)

        # Act
        result = formatter.format()

        # Assert
        # Verify it's valid JSON
        parsed = json.loads(result)
        assert "domains" in parsed
        assert "ips" in parsed
        # Verify indentation and sorting
        assert "    " in result  # 4-space indentation
        assert result.index("domains") < result.index("ips")  # sorted keys

    def test_format_with_complex_data(self):
        """
        Test format() with complex nested data structures.

        Validates JSON serialization with mixed string and dict values.
        Covers lines 95-97.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example.com"],
            "hashes": [{"type": "md5", "value": "5f4dcc3b5aa765d61d8327deb882cf99"}],
        }
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "urls": [{"value": "http://malware.com", "warning_list": "Test List"}]
        }
        formatter = JSONFormatter(data, warning_iocs)

        # Act
        result = formatter.format()

        # Assert
        parsed = json.loads(result)
        assert parsed["domains"] == ["example.com"]
        assert parsed["hashes"][0]["type"] == "md5"
        assert "warning_list_matches" in parsed

    def test_save_creates_json_file(self):
        """
        Test save() creates a valid JSON file.

        Validates file creation with proper JSON formatting.
        Covers lines 106-110.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example.com", "test.com"],
            "ips": ["10.0.0.1"],
        }
        formatter = JSONFormatter(data)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output.json"

            # Act
            formatter.save(str(output_file))

            # Assert
            assert output_file.exists()
            with output_file.open("r", encoding="utf-8") as f:
                content = json.load(f)
            assert "domains" in content
            assert content["domains"] == ["example.com", "test.com"]
            assert content["ips"] == ["10.0.0.1"]

    def test_save_creates_nested_directory(self):
        """
        Test save() creates parent directories if they don't exist.

        Validates _ensure_directory() functionality.
        Covers lines 38, 106.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"domains": ["example.com"]}
        formatter = JSONFormatter(data)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested path
            output_file = Path(tmpdir) / "sub1" / "sub2" / "output.json"

            # Act
            formatter.save(str(output_file))

            # Assert
            assert output_file.exists()
            assert output_file.parent.exists()
            with output_file.open("r", encoding="utf-8") as f:
                content = json.load(f)
            assert content["domains"] == ["example.com"]

    def test_save_with_warning_iocs(self):
        """
        Test save() includes warning_iocs in saved file.

        Validates complete data serialization including warnings.
        Covers lines 106-110.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"domains": ["malicious.com"]}
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "domains": [
                {
                    "value": "google.com",
                    "warning_list": "Alexa Top 1000",
                    "description": "Popular domain",
                }
            ]
        }
        formatter = JSONFormatter(data, warning_iocs)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output.json"

            # Act
            formatter.save(str(output_file))

            # Assert
            with output_file.open("r", encoding="utf-8") as f:
                content = json.load(f)
            assert "warning_list_matches" in content
            assert content["warning_list_matches"]["domains"][0]["value"] == "google.com"

    def test_constructor_with_warning_iocs(self):
        """
        Test JSONFormatter constructor with warning_iocs parameter.

        Validates proper initialization of both data and warning_iocs.
        Covers lines 33-34.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"ips": ["192.168.1.1"]}
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "ips": [{"value": "8.8.8.8", "warning_list": "Test"}]
        }

        # Act
        formatter = JSONFormatter(data, warning_iocs)

        # Assert
        assert formatter.data == data
        assert formatter.warning_iocs == warning_iocs

    def test_constructor_without_warning_iocs(self):
        """
        Test JSONFormatter constructor without warning_iocs parameter.

        Validates default initialization to empty dict.
        Covers lines 33-34.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"domains": ["example.com"]}

        # Act
        formatter = JSONFormatter(data)

        # Assert
        assert formatter.data == data
        assert formatter.warning_iocs == {}


class TestTextFormatter:
    """Test suite for TextFormatter class"""

    def test_format_hashes_section_with_dict_objects(self):
        """
        Test _format_hashes_section() with hash dict objects.

        Validates hash grouping by type and sorting.
        Covers lines 150-166.
        """
        # Arrange
        data: list[Union[str, dict[str, str]]] = [
            {"type": "md5", "value": "zzz123"},
            {"type": "sha1", "value": "aaa456"},
            {"type": "md5", "value": "aaa789"},
        ]
        formatter = TextFormatter({})

        # Act
        result = formatter._format_hashes_section(data)

        # Assert
        # Should group by type and sort within each type
        assert len(result) == 3
        # MD5 hashes should be sorted
        assert result[0] == "aaa789"
        assert result[1] == "zzz123"
        # SHA1 after MD5
        assert result[2] == "aaa456"

    def test_format_hashes_section_with_string_values(self):
        """
        Test _format_hashes_section() with string hash values.

        Validates handling of non-dict hash entries.
        Covers lines 157-161.
        """
        # Arrange
        data: list[Union[str, dict[str, str]]] = [
            "hash_string_2",
            "hash_string_1",
            "hash_string_3",
        ]
        formatter = TextFormatter({})

        # Act
        result = formatter._format_hashes_section(data)

        # Assert
        # Strings should be grouped as 'unknown' and sorted
        assert len(result) == 3
        assert result[0] == "hash_string_1"
        assert result[1] == "hash_string_2"
        assert result[2] == "hash_string_3"

    def test_format_hashes_section_mixed_types(self):
        """
        Test _format_hashes_section() with mixed dict and string entries.

        Validates handling of heterogeneous hash data.
        Covers lines 150-166.
        """
        # Arrange
        data: list[Union[str, dict[str, str]]] = [
            {"type": "sha256", "value": "zzz"},
            "unknown_hash_1",
            {"type": "sha256", "value": "aaa"},
        ]
        formatter = TextFormatter({})

        # Act
        result = formatter._format_hashes_section(data)

        # Assert
        assert len(result) == 3
        # SHA256 entries first (sorted)
        assert "aaa" in result
        assert "zzz" in result
        # Unknown string last
        assert "unknown_hash_1" in result

    def test_format_yara_section(self):
        """
        Test _format_yara_section() formats YARA rules.

        Validates YARA rule wrapping with code blocks.
        Covers line 170.
        """
        # Arrange
        data: list[str] = [
            "rule TestRule { condition: true }",
            'rule AnotherRule { strings: $a = "test" condition: $a }',
        ]
        formatter = TextFormatter({})

        # Act
        result = formatter._format_yara_section(data)

        # Assert
        assert len(result) == 2
        assert result[0] == "```\nrule TestRule { condition: true }\n```\n"
        assert result[1] == '```\nrule AnotherRule { strings: $a = "test" condition: $a }\n```\n'

    def test_format_section_with_hashes_key(self):
        """
        Test _format_section() delegates to _format_hashes_section().

        Validates special handling for 'hashes' key.
        Covers lines 176-177.
        """
        # Arrange
        data: list[Union[str, dict[str, str]]] = [
            {"type": "md5", "value": "abc123"},
        ]
        formatter = TextFormatter({})

        # Act
        result = formatter._format_section("hashes", data)

        # Assert
        assert len(result) == 1
        assert result[0] == "abc123"

    def test_format_section_with_yara_key(self):
        """
        Test _format_section() delegates to _format_yara_section().

        Validates special handling for 'yara' key.
        Covers lines 178-181.
        """
        # Arrange
        data: list[Union[str, dict[str, str]]] = [
            "rule Example { condition: true }",
        ]
        formatter = TextFormatter({})

        # Act
        result = formatter._format_section("yara", data)

        # Assert
        assert len(result) == 1
        assert "```" in result[0]
        assert "rule Example" in result[0]

    def test_format_section_with_regular_data(self):
        """
        Test _format_section() with regular IOC types.

        Validates default sorting for non-special sections.
        Covers lines 182-186.
        """
        # Arrange
        data: list[Union[str, dict[str, str]]] = [
            "zzz.com",
            "aaa.com",
            "mmm.com",
        ]
        formatter = TextFormatter({})

        # Act
        result = formatter._format_section("domains", data)

        # Assert
        assert len(result) == 3
        assert result == ["aaa.com", "mmm.com", "zzz.com"]

    def test_format_warning_ioc_with_dict(self):
        """
        Test _format_warning_ioc() with dict entry.

        Validates warning IOC formatting with description.
        Covers lines 190-197.
        """
        # Arrange
        ioc: dict[str, str] = {
            "value": "8.8.8.8",
            "warning_list": "Google Public DNS",
            "description": "Known public DNS resolver",
        }
        formatter = TextFormatter({})

        # Act
        result = formatter._format_warning_ioc(ioc)

        # Assert
        assert len(result) == 2
        assert result[0] == "8.8.8.8 - *Google Public DNS*"
        assert result[1] == "  Description: Known public DNS resolver"

    def test_format_warning_ioc_without_description(self):
        """
        Test _format_warning_ioc() with dict missing description.

        Validates warning IOC formatting without description field.
        Covers lines 190-195, 196 (false branch).
        """
        # Arrange
        ioc: dict[str, str] = {
            "value": "1.1.1.1",
            "warning_list": "Cloudflare DNS",
        }
        formatter = TextFormatter({})

        # Act
        result = formatter._format_warning_ioc(ioc)

        # Assert
        assert len(result) == 1
        assert result[0] == "1.1.1.1 - *Cloudflare DNS*"

    def test_format_warning_ioc_with_string(self):
        """
        Test _format_warning_ioc() with string entry.

        Validates fallback handling for non-dict warnings.
        Covers lines 198-200.
        """
        # Arrange
        ioc: str = "simple_string_ioc"
        formatter = TextFormatter({})

        # Act
        result = formatter._format_warning_ioc(ioc)

        # Assert
        assert len(result) == 1
        assert result[0] == "simple_string_ioc"

    def test_format_basic_output(self):
        """
        Test format() generates basic text output.

        Validates text formatting structure and section ordering.
        Covers lines 209-240.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["malware.com", "evil.net"],
            "ips": ["192.168.1.100"],
        }
        formatter = TextFormatter(data)

        # Act
        result = formatter.format()

        # Assert
        assert "# Indicators of Compromise (IOCs) Extracted" in result
        assert "## Domains" in result
        assert "## IP Addresses" in result
        assert "evil.net" in result
        assert "malware.com" in result
        assert "192.168.1.100" in result

    def test_format_with_hashes(self):
        """
        Test format() with hash IOCs.

        Validates hash section formatting.
        Covers lines 209-223.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "md5": ["5f4dcc3b5aa765d61d8327deb882cf99"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        }
        formatter = TextFormatter(data)

        # Act
        result = formatter.format()

        # Assert
        assert "## MD5 Hashes" in result
        assert "## SHA256 Hashes" in result
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in result
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in result

    def test_format_with_yara_rules(self):
        """
        Test format() with YARA rules.

        Validates YARA section formatting with code blocks.
        Covers lines 209-223.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "yara": ["rule MalwareDetect { condition: true }"],
        }
        formatter = TextFormatter(data)

        # Act
        result = formatter.format()

        # Assert
        assert "## YARA Rules" in result
        assert "```" in result
        assert "rule MalwareDetect" in result

    def test_format_with_warning_iocs(self):
        """
        Test format() includes warning list matches.

        Validates warning section rendering.
        Covers lines 226-238.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["malicious.com"],
        }
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "ips": [
                {
                    "value": "8.8.8.8",
                    "warning_list": "Google DNS",
                    "description": "Public DNS server",
                }
            ],
        }
        formatter = TextFormatter(data, warning_iocs)

        # Act
        result = formatter.format()

        # Assert
        assert "# Warning List Matches" in result
        assert "might be false positives" in result
        assert "## IP Addresses in Warning Lists" in result
        assert "8.8.8.8 - *Google DNS*" in result
        assert "Description: Public DNS server" in result

    def test_format_without_warning_iocs(self):
        """
        Test format() without warning IOCs.

        Validates warning section is omitted when no warnings exist.
        Covers line 226 (false branch).
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example.com"],
        }
        formatter = TextFormatter(data)

        # Act
        result = formatter.format()

        # Assert
        assert "# Warning List Matches" not in result
        assert "## Domains" in result
        assert "example.com" in result

    def test_format_section_ordering(self):
        """
        Test format() follows SECTION_ORDER.

        Validates sections appear in predefined order.
        Covers lines 212-223.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "urls": ["http://evil.com"],
            "domains": ["evil.com"],
            "md5": ["abc123"],
        }
        formatter = TextFormatter(data)

        # Act
        result = formatter.format()

        # Assert
        # MD5 should appear before domains, domains before urls
        md5_pos = result.index("## MD5 Hashes")
        domains_pos = result.index("## Domains")
        urls_pos = result.index("## URLs")
        assert md5_pos < domains_pos < urls_pos

    def test_format_with_dict_section_data(self):
        """
        Test format() with section data containing dict items.

        Validates union_data conversion when items are dicts.
        Covers line 220 (dict branch in union_data conversion).
        """
        # Arrange
        # Use mitre_attack which is in SECTION_ORDER and can have dict values
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "mitre_attack": [
                {"id": "T1055", "name": "Process Injection"},
                {"id": "T1003", "name": "Credential Dumping"},
            ]
        }
        formatter = TextFormatter(data)

        # Act
        result = formatter.format()

        # Assert
        # The dict items will be converted to strings for sorting
        assert "# Indicators of Compromise" in result
        assert "## MITRE ATT&CK Techniques" in result
        # The dict objects will be stringified and appear in output
        assert "T1055" in result or "Process Injection" in result

    def test_save_creates_text_file(self):
        """
        Test save() creates a text file.

        Validates file creation and content writing.
        Covers lines 249-254.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example.com"],
            "ips": ["10.0.0.1"],
        }
        formatter = TextFormatter(data)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output.txt"

            # Act
            formatter.save(str(output_file))

            # Assert
            assert output_file.exists()
            content = output_file.read_text(encoding="utf-8")
            assert "# Indicators of Compromise" in content
            assert "example.com" in content
            assert "10.0.0.1" in content

    def test_save_creates_nested_directory(self):
        """
        Test save() creates parent directories.

        Validates _ensure_directory() functionality for text output.
        Covers lines 250.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["test.com"],
        }
        formatter = TextFormatter(data)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "deep" / "nested" / "path" / "output.txt"

            # Act
            formatter.save(str(output_file))

            # Assert
            assert output_file.exists()
            assert output_file.parent.exists()
            content = output_file.read_text(encoding="utf-8")
            assert "test.com" in content

    def test_save_handles_exception_gracefully(self):
        """
        Test save() handles exceptions by printing error.

        Validates error handling in save method.
        Covers lines 253-254.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example.com"],
        }
        formatter = TextFormatter(data)

        # Use an invalid path that will cause an error
        # (trying to create a file where a directory would be needed)
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file, then try to use it as a directory
            block_file = Path(tmpdir) / "blocker"
            block_file.write_text("block")
            invalid_path = str(block_file / "subdir" / "file.txt")

            # Act - should not raise, but print error
            # We can't easily test the print, but we verify no exception is raised
            formatter.save(invalid_path)

            # Assert - the invalid file should not exist
            assert not Path(invalid_path).exists()

    def test_constructor_with_warning_iocs(self):
        """
        Test TextFormatter constructor with warning_iocs.

        Validates proper initialization.
        Covers lines 33-34.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"domains": ["example.com"]}
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "ips": [{"value": "1.1.1.1", "warning_list": "Test"}]
        }

        # Act
        formatter = TextFormatter(data, warning_iocs)

        # Assert
        assert formatter.data == data
        assert formatter.warning_iocs == warning_iocs

    def test_constructor_without_warning_iocs(self):
        """
        Test TextFormatter constructor without warning_iocs.

        Validates default initialization.
        Covers lines 33-34.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {"domains": ["example.com"]}

        # Act
        formatter = TextFormatter(data)

        # Assert
        assert formatter.data == data
        assert formatter.warning_iocs == {}


class TestFormatterIntegration:
    """Integration tests for formatter classes"""

    def test_json_and_text_formatters_produce_consistent_data(self):
        """
        Test that JSON and Text formatters handle the same data correctly.

        Validates consistency between formatters.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["evil.com", "malware.net"],
            "ips": ["192.168.1.1", "10.0.0.1"],
            "md5": ["5f4dcc3b5aa765d61d8327deb882cf99"],
        }
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "domains": [
                {
                    "value": "google.com",
                    "warning_list": "Alexa Top 1000",
                    "description": "Popular site",
                }
            ],
        }

        json_formatter = JSONFormatter(data, warning_iocs)
        text_formatter = TextFormatter(data, warning_iocs)

        # Act
        json_output = json_formatter.format()
        text_output = text_formatter.format()

        # Assert
        # Verify JSON contains all domains
        json_parsed = json.loads(json_output)
        assert "evil.com" in json_parsed["domains"]
        assert "malware.net" in json_parsed["domains"]

        # Verify text contains all domains
        assert "evil.com" in text_output
        assert "malware.net" in text_output

        # Both should include warnings
        assert "google.com" in json_output
        assert "google.com" in text_output

    def test_round_trip_save_and_load_json(self):
        """
        Test saving and loading JSON preserves data integrity.

        Validates complete save/load cycle.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["test.com"],
            "hashes": [{"type": "md5", "value": "abc123"}],
        }
        formatter = JSONFormatter(data)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "test.json"

            # Act
            formatter.save(str(output_file))

            # Reload the file
            with output_file.open("r", encoding="utf-8") as f:
                loaded_data = json.load(f)

            # Assert
            assert loaded_data["domains"] == ["test.com"]
            assert loaded_data["hashes"][0]["type"] == "md5"
            assert loaded_data["hashes"][0]["value"] == "abc123"

    def test_round_trip_save_and_load_text(self):
        """
        Test saving and loading text preserves content.

        Validates complete save/load cycle for text format.
        """
        # Arrange
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example.com"],
            "cves": ["CVE-2021-1234"],
        }
        formatter = TextFormatter(data)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "test.txt"

            # Act
            formatter.save(str(output_file))

            # Reload the file
            loaded_content = output_file.read_text(encoding="utf-8")

            # Assert
        assert "# Indicators of Compromise" in loaded_content
        assert "## Domains" in loaded_content
        assert "example.com" in loaded_content
        assert "## Vulnerabilities (CVEs)" in loaded_content
        assert "CVE-2021-1234" in loaded_content


class TestSTIXFormatter:
    """Tests for STIXFormatter output."""

    def test_stix_bundle_contains_indicators(self) -> None:
        """STIX formatter should produce a bundle with refanged indicators."""
        data: dict[str, list[Union[str, dict[str, str]]]] = {
            "domains": ["example[.]com"],
            "md5": [{"type": "md5", "value": "5f4dcc3b5aa765d61d8327deb882cf99"}],
            "urls": ["hxxp://malicious.example[.]com/path"],
        }
        warning_iocs: dict[str, list[dict[str, str]]] = {
            "domains": [
                {"value": "benign[.]com", "warning_list": "majestic", "description": "top sites"},
            ],
        }

        formatter = STIXFormatter(data, warning_iocs=warning_iocs, source="unit-test")

        result = formatter.format()
        parsed = json.loads(result)

        assert parsed["type"] == "bundle"
        indicators = [obj for obj in parsed.get("objects", []) if obj.get("type") == "indicator"]
        assert indicators

        patterns = {obj["pattern"] for obj in indicators}
        labels_sets = {tuple(obj.get("labels", [])) for obj in indicators}
        indicator_types_sets = {tuple(obj.get("indicator_types", [])) for obj in indicators}

        assert "[domain-name:value = 'example.com']" in patterns
        assert "[url:value = 'http://malicious.example.com/path']" in patterns
        assert labels_sets == {()}  # labels omitted for strictness
        assert indicator_types_sets == {("unknown",)}

        warning_indicator = next(
            (
                obj
                for obj in indicators
                if obj.get("pattern") == "[domain-name:value = 'benign.com']"
            ),
            None,
        )
        if warning_indicator:
            assert warning_indicator.get("x_warning_list") == "majestic"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
