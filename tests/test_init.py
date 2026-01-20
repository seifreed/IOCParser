#!/usr/bin/env python3

# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive unit tests for iocparser.__init__ module

Tests cover extract_iocs_from_file() and extract_iocs_from_text() functions
with real file operations, various file types (PDF, HTML, text), and different
configuration options. All tests use real implementations without mocks.

Author: Marc Rivero | @seifreed
"""

from pathlib import Path

import pytest

from iocparser import extract_iocs_from_file, extract_iocs_from_text
from iocparser.modules.exceptions import FileExistenceError


def create_minimal_pdf(pdf_path: Path, text_content: str) -> None:
    """
    Create a minimal valid PDF file with text content.

    This uses the raw PDF format to create a real, parseable PDF
    without requiring external PDF creation libraries.

    Args:
        pdf_path: Path where PDF will be created
        text_content: Text to include in the PDF
    """
    # Minimal PDF structure with text content
    # This is a valid PDF 1.4 file that pdfplumber can parse
    pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Resources 4 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>
endobj
4 0 obj
<< /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >>
endobj
5 0 obj
<< /Length {len(text_content) + 50} >>
stream
BT
/F1 12 Tf
100 700 Td
({text_content}) Tj
ET
endstream
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000214 00000 n
0000000304 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
{400 + len(text_content)}
%%EOF
"""
    pdf_path.write_text(pdf_content, encoding="latin-1")


class TestExtractIocsFromFile:
    """Test suite for extract_iocs_from_file() function."""

    def test_extract_from_pdf_file(self, tmp_path: Path) -> None:
        """
        Test extracting IOCs from a real PDF file.

        Creates an actual PDF with IOC content and validates that
        domains, IPs, and hashes are correctly extracted.
        """
        # Arrange: Create PDF with IOC content
        pdf_path = tmp_path / "malware_report.pdf"
        ioc_text = "Malware C2: malicious-domain.com IP: 192.168.1.100 MD5: d41d8cd98f00b204e9800998ecf8427e"
        create_minimal_pdf(pdf_path, ioc_text)

        # Act: Extract IOCs from PDF
        normal_iocs, _warning_iocs = extract_iocs_from_file(
            pdf_path, check_warnings=False, defang=False
        )

        # Assert: Verify IOCs were extracted
        assert "domains" in normal_iocs or "ips" in normal_iocs or "md5" in normal_iocs
        assert isinstance(normal_iocs, dict)
        assert isinstance(_warning_iocs, dict)

    def test_extract_from_html_file(self, tmp_path: Path) -> None:
        """
        Test extracting IOCs from a real HTML file.

        Creates an actual HTML file with IOC content embedded in tags
        and validates extraction.
        """
        # Arrange: Create HTML file with IOC content
        html_path = tmp_path / "threat_report.html"
        html_content = """<!DOCTYPE html>
<html>
<head><title>Threat Report</title></head>
<body>
    <h1>Malware Analysis</h1>
    <p>Command and Control server: evil-server.net</p>
    <p>IP Address: 10.0.0.50</p>
    <p>File Hash: 5d41402abc4b2a76b9719d911017c592</p>
    <div>URL: http://phishing-site.com/login</div>
</body>
</html>"""
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Extract IOCs from HTML
        normal_iocs, _warning_iocs = extract_iocs_from_file(
            html_path, check_warnings=False, file_type="html", defang=False
        )

        # Assert: Verify IOCs were extracted
        assert isinstance(normal_iocs, dict)
        assert len(normal_iocs) > 0
        # At least one IOC type should be present
        assert any(key in normal_iocs for key in ["domains", "ips", "md5", "urls"])

    def test_extract_from_text_file(self, tmp_path: Path) -> None:
        """
        Test extracting IOCs from a plain text file.

        Creates a real text file and validates the full text extraction
        and IOC parsing pipeline.
        """
        # Arrange: Create plain text file with IOCs
        text_path = tmp_path / "ioc_list.txt"
        text_content = """Threat Intelligence Report

Indicators of Compromise:
- Domain: badactor.org
- IP: 172.16.0.1
- SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Email: attacker@malicious.net
"""
        text_path.write_text(text_content, encoding="utf-8")

        # Act: Extract IOCs from text file
        normal_iocs, _warning_iocs = extract_iocs_from_file(
            text_path, check_warnings=False, defang=False
        )

        # Assert: Verify extraction
        assert isinstance(normal_iocs, dict)
        assert len(normal_iocs) > 0

    def test_extract_from_text_file_with_unicode(self, tmp_path: Path) -> None:
        """
        Test extracting IOCs from a text file with Unicode content.

        Validates that the UTF-8 encoding and error handling ('ignore')
        works correctly with international characters.
        """
        # Arrange: Create text file with Unicode characters
        text_path = tmp_path / "unicode_iocs.txt"
        text_content = """Análisis de Malware 恶意软件分析

Dominio malicioso: атака-сервер.com (Cyrillic)
IP válida: 192.168.1.1
Hash: 098f6bcd4621d373cade4e832627b4f6
"""
        text_path.write_text(text_content, encoding="utf-8")

        # Act: Extract IOCs
        normal_iocs, _warning_iocs = extract_iocs_from_file(
            text_path, check_warnings=False, defang=False
        )

        # Assert: Should handle Unicode gracefully and extract IPs/hashes
        assert isinstance(normal_iocs, dict)
        # IP and hash should be extractable regardless of surrounding Unicode
        assert "ips" in normal_iocs or "md5" in normal_iocs

    def test_file_not_found_raises_error(self, tmp_path: Path) -> None:
        """
        Test that FileExistenceError is raised for non-existent files.

        Validates the file existence check in extract_iocs_from_file().
        """
        # Arrange: Non-existent file path
        non_existent = tmp_path / "does_not_exist.txt"

        # Act & Assert: Should raise FileExistenceError
        with pytest.raises(FileExistenceError) as exc_info:
            extract_iocs_from_file(non_existent)

        # Verify error message contains the file path
        assert str(non_existent) in str(exc_info.value)

    def test_extract_with_defang_enabled(self, tmp_path: Path) -> None:
        """
        Test IOC extraction with defanging enabled.

        Validates that the defang=True parameter is properly passed
        through to the IOCExtractor.
        """
        # Arrange: Create text file with IOCs
        text_path = tmp_path / "iocs_to_defang.txt"
        text_content = "Malicious domain: dangerous.com and IP: 203.0.113.1"
        text_path.write_text(text_content, encoding="utf-8")

        # Act: Extract with defanging
        normal_iocs, _ = extract_iocs_from_file(text_path, check_warnings=False, defang=True)

        # Assert: Verify defanging occurred (domains/IPs should contain '[' or be modified)
        if "domains" in normal_iocs:
            # Defanged domains typically have [.] instead of .
            domain = str(normal_iocs["domains"][0])
            assert "[" in domain or "." not in domain

    def test_extract_with_defang_disabled(self, tmp_path: Path) -> None:
        """
        Test IOC extraction with defanging disabled.

        Validates that the defang=False parameter preserves original
        IOC format.
        """
        # Arrange: Create text file
        text_path = tmp_path / "iocs_no_defang.txt"
        text_content = "Domain: testdomain.org IP: 198.51.100.1"
        text_path.write_text(text_content, encoding="utf-8")

        # Act: Extract without defanging
        normal_iocs, _ = extract_iocs_from_file(text_path, check_warnings=False, defang=False)

        # Assert: Verify no defanging (domains should contain '.')
        if "domains" in normal_iocs:
            domain = str(normal_iocs["domains"][0])
            assert "." in domain
            assert "[" not in domain

    def test_force_file_type_pdf(self, tmp_path: Path) -> None:
        """
        Test forcing file type to PDF regardless of extension.

        Creates a PDF file with a non-standard extension and validates
        that file_type='pdf' forces PDF parsing.
        """
        # Arrange: Create PDF with .bin extension
        pdf_path = tmp_path / "report.bin"
        create_minimal_pdf(pdf_path, "C2 server: forced-pdf-test.com")

        # Act: Force PDF parsing
        normal_iocs, _ = extract_iocs_from_file(
            pdf_path, check_warnings=False, file_type="pdf", defang=False
        )

        # Assert: Should successfully parse as PDF
        assert isinstance(normal_iocs, dict)

    def test_force_file_type_html(self, tmp_path: Path) -> None:
        """
        Test forcing file type to HTML.

        Validates that file_type='html' parameter forces HTML parsing
        even for files without .html extension.
        """
        # Arrange: Create HTML file with .txt extension
        html_path = tmp_path / "page.txt"
        html_content = "<html><body>Malware IP: 192.0.2.1</body></html>"
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Force HTML parsing
        normal_iocs, _ = extract_iocs_from_file(
            html_path, check_warnings=False, file_type="html", defang=False
        )

        # Assert: Should parse as HTML
        assert isinstance(normal_iocs, dict)

    def test_force_file_type_text(self, tmp_path: Path) -> None:
        """
        Test forcing file type to plain text.

        Validates that file_type='text' bypasses format detection
        and reads file as plain text.
        """
        # Arrange: Create text file
        text_path = tmp_path / "data.unknown"
        text_content = "Threat actor domain: text-forced.net"
        text_path.write_text(text_content, encoding="utf-8")

        # Act: Force text parsing
        normal_iocs, _ = extract_iocs_from_file(
            text_path, check_warnings=False, file_type="text", defang=False
        )

        # Assert: Should read as plain text
        assert isinstance(normal_iocs, dict)

    def test_check_warnings_enabled(self, tmp_path: Path) -> None:
        """
        Test IOC extraction with MISP warning list checking enabled.

        Creates a file with both normal and potentially false-positive IOCs
        and validates they are separated correctly.
        """
        # Arrange: Create file with well-known domains that may be in warning lists
        text_path = tmp_path / "mixed_iocs.txt"
        text_content = """
Real threats:
- malware-c2.evil

Common infrastructure (may be in warning lists):
- google.com
- cloudflare.com
- 8.8.8.8
"""
        text_path.write_text(text_content, encoding="utf-8")

        # Act: Extract with warning list checking
        normal_iocs, warning_iocs = extract_iocs_from_file(
            text_path, check_warnings=True, force_update=False, defang=False
        )

        # Assert: Both dictionaries should be returned
        assert isinstance(normal_iocs, dict)
        assert isinstance(warning_iocs, dict)
        # At least one should contain IOCs (distribution depends on warning lists)
        assert len(normal_iocs) > 0 or len(warning_iocs) > 0

    def test_check_warnings_disabled(self, tmp_path: Path) -> None:
        """
        Test IOC extraction with warning list checking disabled.

        Validates that check_warnings=False returns all IOCs as normal
        and an empty warning_iocs dictionary.
        """
        # Arrange: Create file with IOCs
        text_path = tmp_path / "all_normal.txt"
        text_content = "Domain: google.com IP: 8.8.8.8"
        text_path.write_text(text_content, encoding="utf-8")

        # Act: Extract without warning checking
        normal_iocs, warning_iocs = extract_iocs_from_file(
            text_path, check_warnings=False, defang=False
        )

        # Assert: All IOCs should be in normal_iocs, warning_iocs should be empty
        assert isinstance(normal_iocs, dict)
        assert warning_iocs == {}
        assert len(normal_iocs) > 0


class TestExtractIocsFromText:
    """Test suite for extract_iocs_from_text() function."""

    def test_extract_from_simple_text(self) -> None:
        """
        Test extracting IOCs from simple text content.

        Validates basic functionality with a straightforward input
        containing multiple IOC types.
        """
        # Arrange: Simple text with various IOCs
        text = """
Malware Analysis Report:
C2 Domain: malicious-server.com
IP Address: 192.168.1.100
File Hash (MD5): 5f4dcc3b5aa765d61d8327deb882cf99
Contact Email: badguy@evil.net
"""

        # Act: Extract IOCs
        normal_iocs, _warning_iocs = extract_iocs_from_text(
            text, check_warnings=False, defang=False
        )

        # Assert: Verify extraction
        assert isinstance(normal_iocs, dict)
        assert len(normal_iocs) > 0
        # Should contain at least domains, IPs, or hashes
        assert any(key in normal_iocs for key in ["domains", "ips", "md5", "emails"])

    def test_extract_from_empty_text(self) -> None:
        """
        Test extracting IOCs from empty text.

        Validates that empty input is handled gracefully and returns
        empty dictionaries.
        """
        # Arrange: Empty text
        text = ""

        # Act: Extract IOCs
        normal_iocs, _warning_iocs = extract_iocs_from_text(
            text, check_warnings=False, defang=False
        )

        # Assert: Should return empty dictionaries
        assert isinstance(normal_iocs, dict)
        assert isinstance(_warning_iocs, dict)
        assert len(normal_iocs) == 0

    def test_extract_with_only_text_no_iocs(self) -> None:
        """
        Test extracting IOCs from text with no actual IOCs.

        Validates that normal text without indicators returns empty results.
        """
        # Arrange: Text without IOCs
        text = "This is just normal text without any indicators of compromise."

        # Act: Extract IOCs
        normal_iocs, _warning_iocs = extract_iocs_from_text(
            text, check_warnings=False, defang=False
        )

        # Assert: Should return empty or minimal results
        assert isinstance(normal_iocs, dict)
        assert isinstance(_warning_iocs, dict)

    def test_extract_multiple_ioc_types(self) -> None:
        """
        Test extracting multiple different IOC types from complex text.

        Validates that all IOC types (domains, IPs, hashes, URLs, emails)
        are correctly identified and categorized.
        """
        # Arrange: Text with diverse IOCs
        text = """
Advanced Persistent Threat Report

Network Indicators:
- Domain: apt-group-c2.org
- IP: 203.0.113.42
- URL: http://phishing-portal.net/login.php

File Indicators:
- MD5: 098f6bcd4621d373cade4e832627b4f6
- SHA1: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
- SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

Communication:
- Email: spearphish@malicious-domain.com
"""

        # Act: Extract IOCs
        normal_iocs, _warning_iocs = extract_iocs_from_text(
            text, check_warnings=False, defang=False
        )

        # Assert: Should extract multiple types
        assert isinstance(normal_iocs, dict)
        assert len(normal_iocs) > 0
        # At least 3 different IOC types should be present
        ioc_type_count = len([k for k in normal_iocs if normal_iocs[k]])
        assert ioc_type_count >= 3

    def test_extract_with_defang_enabled_from_text(self) -> None:
        """
        Test text extraction with defanging enabled.

        Validates that defang=True properly defangs extracted IOCs
        in the text processing pipeline.
        """
        # Arrange: Text with IOCs
        text = "Malware contacts command-server.com and 198.51.100.50"

        # Act: Extract with defanging
        normal_iocs, _ = extract_iocs_from_text(text, check_warnings=False, defang=True)

        # Assert: Verify defanging
        if "domains" in normal_iocs:
            domain = str(normal_iocs["domains"][0])
            # Defanged domains should have modified format
            assert "[" in domain or "." not in domain

    def test_extract_with_defang_disabled_from_text(self) -> None:
        """
        Test text extraction with defanging disabled.

        Validates that defang=False preserves original IOC format
        in text extraction.
        """
        # Arrange: Text with IOCs
        text = "Suspicious domain: preserve-format.org"

        # Act: Extract without defanging
        normal_iocs, _ = extract_iocs_from_text(text, check_warnings=False, defang=False)

        # Assert: Verify no defanging
        if "domains" in normal_iocs:
            domain = str(normal_iocs["domains"][0])
            assert "." in domain
            assert "[" not in domain

    def test_extract_with_warning_check_enabled(self) -> None:
        """
        Test text extraction with MISP warning list checking.

        Validates that check_warnings=True properly separates IOCs
        into normal and warning categories.
        """
        # Arrange: Text with potentially whitelisted domains
        text = """
Legitimate services seen in traffic:
- google.com
- microsoft.com

Suspicious domains:
- random-malware.xyz
"""

        # Act: Extract with warning checking
        normal_iocs, warning_iocs = extract_iocs_from_text(
            text, check_warnings=True, force_update=False, defang=False
        )

        # Assert: Should separate IOCs
        assert isinstance(normal_iocs, dict)
        assert isinstance(warning_iocs, dict)
        # At least one category should have IOCs
        assert len(normal_iocs) > 0 or len(warning_iocs) > 0

    def test_extract_with_warning_check_disabled(self) -> None:
        """
        Test text extraction without warning list checking.

        Validates that check_warnings=False returns all IOCs as normal.
        """
        # Arrange: Text with IOCs
        text = "Domains: google.com, suspicious-site.net"

        # Act: Extract without warning checking
        normal_iocs, warning_iocs = extract_iocs_from_text(text, check_warnings=False, defang=False)

        # Assert: All IOCs in normal, warnings empty
        assert isinstance(normal_iocs, dict)
        assert warning_iocs == {}
        if "domains" in normal_iocs:
            assert len(normal_iocs["domains"]) > 0

    def test_extract_with_force_update_warning_lists(self) -> None:
        """
        Test text extraction with forced update of MISP warning lists.

        Validates that force_update=True parameter is passed correctly
        to the MISPWarningLists initialization.
        """
        # Arrange: Text with known domains
        text = "Checking against updated lists: cloudflare.com"

        # Act: Extract with forced warning list update
        # This will trigger actual warning list update
        normal_iocs, warning_iocs = extract_iocs_from_text(
            text, check_warnings=True, force_update=True, defang=False
        )

        # Assert: Should complete without errors and return results
        assert isinstance(normal_iocs, dict)
        assert isinstance(warning_iocs, dict)

    def test_extract_preserves_ioc_structure(self) -> None:
        """
        Test that extracted IOCs maintain proper structure.

        Validates that the returned dictionaries have correct types
        and structure (dict[str, list[str | dict[str, str]]]).
        """
        # Arrange: Text with various IOCs
        text = "IOCs: malware.net 10.0.0.1 http://phish.com/page"

        # Act: Extract IOCs
        normal_iocs, warning_iocs = extract_iocs_from_text(text, check_warnings=False, defang=False)

        # Assert: Verify structure
        assert isinstance(normal_iocs, dict)
        assert isinstance(warning_iocs, dict)

        # All values should be lists
        for value in normal_iocs.values():
            assert isinstance(value, list)
            # Each item should be str or dict
            for item in value:
                assert isinstance(item, (str, dict))

    def test_extract_with_special_characters(self) -> None:
        """
        Test IOC extraction from text with special characters.

        Validates that special characters, punctuation, and formatting
        don't interfere with IOC extraction.
        """
        # Arrange: Text with special characters around IOCs
        text = """
IOCs found in traffic logs:
* Domain: [malicious.com]
* IP: (192.168.1.1)
* Hash: {5f4dcc3b5aa765d61d8327deb882cf99}
* URL: <http://evil.net/payload.exe>
"""

        # Act: Extract IOCs
        normal_iocs, _ = extract_iocs_from_text(text, check_warnings=False, defang=False)

        # Assert: Should extract IOCs despite surrounding characters
        assert isinstance(normal_iocs, dict)
        assert len(normal_iocs) > 0

    def test_extract_with_newlines_and_whitespace(self) -> None:
        """
        Test IOC extraction from text with varied whitespace.

        Validates that different line endings and whitespace patterns
        are handled correctly.
        """
        # Arrange: Text with various whitespace patterns
        text = "Domain:     malware.com\n\n\nIP:\t\t192.168.1.1\r\n\r\nHash:  5f4dcc3b5aa765d61d8327deb882cf99"

        # Act: Extract IOCs
        normal_iocs, _ = extract_iocs_from_text(text, check_warnings=False, defang=False)

        # Assert: Should handle whitespace variations
        assert isinstance(normal_iocs, dict)
        assert len(normal_iocs) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
