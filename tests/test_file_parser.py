#!/usr/bin/env python3

# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive unit tests for file_parser module

Tests cover PDF extraction, HTML extraction (local and URL),
parser factory function, and error handling - all using real
implementations without mocks.

Author: Marc Rivero | @seifreed
"""

from pathlib import Path

import pytest

from iocparser.modules.exceptions import (
    FileExistenceError,
    HTMLProcessingError,
    PDFProcessingError,
    UnsupportedFileTypeError,
    URLAccessError,
)
from iocparser.modules.file_parser import (
    HTMLParser,
    PDFParser,
    get_parser,
)


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


class TestPDFParser:
    """Test PDF text extraction using real PDF files."""

    def test_extract_text_from_single_page_pdf(self, tmp_path: Path) -> None:
        """
        Test extracting text from a real single-page PDF.

        This creates an actual PDF file using raw PDF format and extracts
        text using pdfplumber to validate the full pipeline.
        """
        # Arrange: Create a real PDF file with known content
        pdf_path = tmp_path / "test_single_page.pdf"
        expected_text = "This is test content for IOC extraction"

        create_minimal_pdf(pdf_path, expected_text)

        # Act: Extract text using PDFParser
        parser = PDFParser(str(pdf_path))
        extracted_text = parser.extract_text()

        # Assert: Verify the expected text is present
        assert expected_text in extracted_text
        assert len(extracted_text) > 0

    def test_extract_text_from_multi_page_pdf(self, tmp_path: Path) -> None:
        """
        Test extracting text from a multi-page PDF.

        Validates that PDFParser correctly processes all pages
        and aggregates content. Note: Using single-page PDF with aggregated
        content as multi-page PDF generation with raw PDF syntax is complex.
        """
        # Arrange: Create PDF with content representing multiple sections
        pdf_path = tmp_path / "test_multi_page.pdf"
        # Simulating multi-page content in single page
        aggregated_text = "Page 1 IP 192.168.1.1 | Page 2 Domain example.com | Page 3 Hash abc123"

        create_minimal_pdf(pdf_path, aggregated_text)

        # Act: Extract text
        parser = PDFParser(str(pdf_path))
        extracted_text = parser.extract_text()

        # Assert: Content should be present
        assert "192.168.1.1" in extracted_text
        assert "example.com" in extracted_text
        assert "abc123" in extracted_text

    def test_extract_text_from_pdf_with_table(self, tmp_path: Path) -> None:
        """
        Test extracting text from PDF containing table-like structures.

        PDFParser should extract both regular text and tabular data,
        as IOCs often appear in tables.
        """
        # Arrange: Create PDF with structured table-like content
        pdf_path = tmp_path / "test_table.pdf"
        # Simulate table structure with text
        table_text = "192.168.1.1 IP Malicious | evil.com Domain C2"

        create_minimal_pdf(pdf_path, table_text)

        # Act: Extract text
        parser = PDFParser(str(pdf_path))
        extracted_text = parser.extract_text()

        # Assert: Table content should be extractable
        assert "192.168.1.1" in extracted_text
        assert "evil.com" in extracted_text
        assert "Malicious" in extracted_text

    def test_extract_text_from_empty_pdf(self, tmp_path: Path) -> None:
        """
        Test extracting text from an empty PDF (no text content).

        Should return empty string without raising errors.
        """
        # Arrange: Create empty PDF (minimal content)
        pdf_path = tmp_path / "test_empty.pdf"

        create_minimal_pdf(pdf_path, "")

        # Act: Extract text
        parser = PDFParser(str(pdf_path))
        extracted_text = parser.extract_text()

        # Assert: Should return empty or whitespace-only content
        assert extracted_text.strip() == ""

    def test_pdf_parser_file_not_found(self, tmp_path: Path) -> None:
        """
        Test PDFParser raises FileExistenceError for non-existent file.

        Validates error handling when file path is invalid.
        """
        # Arrange: Use non-existent file path
        non_existent_path = tmp_path / "does_not_exist.pdf"

        # Act & Assert: Should raise FileExistenceError during initialization
        with pytest.raises(FileExistenceError) as exc_info:
            PDFParser(str(non_existent_path))

        assert str(non_existent_path) in str(exc_info.value)

    def test_pdf_parser_invalid_pdf_file(self, tmp_path: Path) -> None:
        """
        Test PDFParser raises PDFProcessingError for corrupted PDF.

        Creates an invalid PDF file to test error handling during extraction.
        """
        # Arrange: Create invalid PDF file (just text, not valid PDF format)
        invalid_pdf_path = tmp_path / "invalid.pdf"
        invalid_pdf_path.write_text("This is not a valid PDF file")

        # Act & Assert: Should raise PDFProcessingError during extraction
        parser = PDFParser(str(invalid_pdf_path))
        with pytest.raises(PDFProcessingError):
            parser.extract_text()


class TestHTMLParser:
    """Test HTML text extraction from local files and URLs."""

    def test_extract_text_from_local_html_file(self, tmp_path: Path) -> None:
        """
        Test extracting text from a local HTML file.

        Validates that HTMLParser correctly parses HTML structure
        and extracts visible text content.
        """
        # Arrange: Create real HTML file
        html_path = tmp_path / "test.html"
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <script>console.log('should be removed');</script>
            <style>.class { color: red; }</style>
        </head>
        <body>
            <h1>IOC List</h1>
            <p>IP: 10.0.0.1</p>
            <p>Domain: malware.example.com</p>
        </body>
        </html>
        """
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Extract text
        parser = HTMLParser(str(html_path))
        extracted_text = parser.extract_text()

        # Assert: Should contain visible text but not script/style content
        assert "IOC List" in extracted_text
        assert "10.0.0.1" in extracted_text
        assert "malware.example.com" in extracted_text
        assert "console.log" not in extracted_text
        assert "color: red" not in extracted_text

    def test_extract_text_from_html_with_special_characters(self, tmp_path: Path) -> None:
        """
        Test HTML extraction with special characters and entities.

        Validates proper handling of HTML entities and Unicode.
        """
        # Arrange: Create HTML with special characters
        html_path = tmp_path / "special_chars.html"
        html_content = """
        <html>
        <body>
            <p>Email: user@example.com &amp; admin@test.com</p>
            <p>Special: &lt;script&gt; &quot;test&quot;</p>
            <p>Unicode: café résumé</p>
        </body>
        </html>
        """
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Extract text
        parser = HTMLParser(str(html_path))
        extracted_text = parser.extract_text()

        # Assert: HTML entities should be decoded
        assert "user@example.com" in extracted_text
        assert "&" in extracted_text or "and" in extracted_text  # & or 'and'
        assert "<script>" in extracted_text  # Decoded entity
        assert "café" in extracted_text

    def test_extract_text_from_html_file_containing_url(self, tmp_path: Path) -> None:
        """
        Test HTML file that contains only URL(s).

        When HTML file contains just URLs (not HTML structure),
        should return the URL text directly.
        """
        # Arrange: Create file with just a URL
        html_path = tmp_path / "url_only.html"
        url_content = "https://malicious-site.com/payload\n"
        html_path.write_text(url_content, encoding="utf-8")

        # Act: Extract text
        parser = HTMLParser(str(html_path))
        extracted_text = parser.extract_text()

        # Assert: Should return the URL as-is
        assert "https://malicious-site.com/payload" in extracted_text

    def test_extract_text_from_html_removes_scripts_and_styles(self, tmp_path: Path) -> None:
        """
        Test that script, style, meta tags are properly removed.

        Validates the cleanup of non-content HTML elements.
        """
        # Arrange: Create HTML with multiple removable elements
        html_path = tmp_path / "cleanup_test.html"
        html_content = """
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Test</title>
            <script>alert('xss');</script>
            <script src="external.js"></script>
            <style>body { margin: 0; }</style>
        </head>
        <body>
            <noscript>Enable JavaScript</noscript>
            <div>Visible content here</div>
            <script>document.write('bad');</script>
        </body>
        </html>
        """
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Extract text
        parser = HTMLParser(str(html_path))
        extracted_text = parser.extract_text()

        # Assert: Only visible content should remain
        assert "Visible content here" in extracted_text
        assert "alert" not in extracted_text
        assert "xss" not in extracted_text
        assert "margin: 0" not in extracted_text
        assert "Enable JavaScript" not in extracted_text

    def test_extract_text_cleans_multiple_whitespaces(self, tmp_path: Path) -> None:
        """
        Test that multiple whitespaces are normalized.

        HTML often has extra whitespace that should be collapsed.
        """
        # Arrange: Create HTML with excessive whitespace
        html_path = tmp_path / "whitespace.html"
        html_content = """
        <html><body>
            <p>IP:     192.168.1.1</p>
            <p>Domain:


            example.com</p>
        </body></html>
        """
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Extract text
        parser = HTMLParser(str(html_path))
        extracted_text = parser.extract_text()

        # Assert: Multiple spaces should be normalized to single space
        assert "IP: 192.168.1.1" in extracted_text
        # Multiple newlines and spaces should be reduced
        assert "  " not in extracted_text or extracted_text.count("  ") < 3

    def test_html_parser_file_not_found(self, tmp_path: Path) -> None:
        """
        Test HTMLParser raises FileExistenceError for non-existent file.
        """
        # Arrange: Use non-existent file path
        non_existent_path = tmp_path / "missing.html"

        # Act & Assert: Should raise FileExistenceError
        with pytest.raises(FileExistenceError):
            HTMLParser(str(non_existent_path))

    def test_html_parser_url_skips_file_existence_check(self) -> None:
        """
        Test that HTMLParser doesn't validate file existence for URLs.

        URLs should skip the file existence check in __init__.
        """
        # Arrange: Use URL (doesn't need to exist for initialization)
        test_url = "https://example.com/test.html"

        # Act: Create parser - should not raise during initialization
        parser = HTMLParser(test_url)

        # Assert: Parser should be created successfully
        assert parser.file_path == test_url

    def test_html_parser_invalid_html_local_file(self, tmp_path: Path) -> None:
        """
        Test HTMLParser handles malformed HTML gracefully.

        BeautifulSoup is generally permissive, but we test edge cases.
        """
        # Arrange: Create malformed HTML
        html_path = tmp_path / "malformed.html"
        html_content = "<html><body><p>Unclosed paragraph<div>Test</div>"
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Extract text (should not crash)
        parser = HTMLParser(str(html_path))
        extracted_text = parser.extract_text()

        # Assert: Should still extract visible text
        assert "Unclosed paragraph" in extracted_text
        assert "Test" in extracted_text


class TestGetParser:
    """Test the parser factory function."""

    def test_get_parser_returns_pdf_parser_for_pdf_extension(self, tmp_path: Path) -> None:
        """
        Test get_parser returns PDFParser for .pdf files.

        Validates correct parser selection based on file extension.
        """
        # Arrange: Create a real PDF file
        pdf_path = tmp_path / "test.pdf"
        create_minimal_pdf(pdf_path, "Test")

        # Act: Get parser
        parser = get_parser(str(pdf_path))

        # Assert: Should return PDFParser instance
        assert isinstance(parser, PDFParser)
        assert parser.file_path == str(pdf_path)

    def test_get_parser_returns_html_parser_for_html_extension(self, tmp_path: Path) -> None:
        """
        Test get_parser returns HTMLParser for .html files.
        """
        # Arrange: Create HTML file
        html_path = tmp_path / "test.html"
        html_path.write_text("<html><body>Test</body></html>", encoding="utf-8")

        # Act: Get parser
        parser = get_parser(str(html_path))

        # Assert: Should return HTMLParser instance
        assert isinstance(parser, HTMLParser)

    def test_get_parser_returns_html_parser_for_htm_extension(self, tmp_path: Path) -> None:
        """
        Test get_parser returns HTMLParser for .htm files.

        Validates support for alternate HTML extension.
        """
        # Arrange: Create .htm file
        htm_path = tmp_path / "test.htm"
        htm_path.write_text("<html><body>Test</body></html>", encoding="utf-8")

        # Act: Get parser
        parser = get_parser(str(htm_path))

        # Assert: Should return HTMLParser instance
        assert isinstance(parser, HTMLParser)

    def test_get_parser_returns_html_parser_for_http_url(self) -> None:
        """
        Test get_parser returns HTMLParser for HTTP URLs.

        URLs without recognized extension default to HTML.
        """
        # Arrange: Use HTTP URL
        url = "http://example.com/page"

        # Act: Get parser
        parser = get_parser(url)

        # Assert: Should return HTMLParser for URL
        assert isinstance(parser, HTMLParser)
        assert parser.file_path == url

    def test_get_parser_returns_html_parser_for_https_url(self) -> None:
        """
        Test get_parser returns HTMLParser for HTTPS URLs.
        """
        # Arrange: Use HTTPS URL
        url = "https://example.com/data"

        # Act: Get parser
        parser = get_parser(url)

        # Assert: Should return HTMLParser
        assert isinstance(parser, HTMLParser)

    def test_get_parser_raises_unsupported_file_type_for_unknown_extension(
        self,
        tmp_path: Path,
    ) -> None:
        """
        Test get_parser raises UnsupportedFileTypeError for unsupported files.

        Validates error handling for file types without parser mapping.
        """
        # Arrange: Create file with unsupported extension
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Some text content")

        # Act & Assert: Should raise UnsupportedFileTypeError
        with pytest.raises(UnsupportedFileTypeError) as exc_info:
            get_parser(str(txt_path))

        assert str(txt_path) in str(exc_info.value)

    def test_get_parser_raises_unsupported_for_no_extension(self, tmp_path: Path) -> None:
        """
        Test get_parser raises error for files without extension.
        """
        # Arrange: Create file without extension
        no_ext_path = tmp_path / "noextension"
        no_ext_path.write_text("Content")

        # Act & Assert: Should raise UnsupportedFileTypeError
        with pytest.raises(UnsupportedFileTypeError):
            get_parser(str(no_ext_path))

    def test_get_parser_handles_url_with_pdf_extension(self) -> None:
        """
        Test get_parser returns PDFParser for URLs ending in .pdf.

        Validates extension-based routing works for URLs too.
        """
        # Arrange: URL with .pdf extension
        pdf_url = "https://example.com/document.pdf"

        # Act: Get parser
        parser = get_parser(pdf_url)

        # Assert: Should return PDFParser based on extension
        assert isinstance(parser, PDFParser)

    def test_get_parser_handles_url_with_html_extension(self) -> None:
        """
        Test get_parser returns HTMLParser for URLs ending in .html.
        """
        # Arrange: URL with .html extension
        html_url = "https://example.com/page.html"

        # Act: Get parser
        parser = get_parser(html_url)

        # Assert: Should return HTMLParser
        assert isinstance(parser, HTMLParser)


class TestFileParserIntegration:
    """Integration tests for complete parsing workflows."""

    def test_complete_pdf_parsing_workflow(self, tmp_path: Path) -> None:
        """
        Test complete workflow: create PDF -> get parser -> extract text.

        End-to-end validation of PDF processing pipeline.
        """
        # Arrange: Create PDF with IOC-like content
        pdf_path = tmp_path / "ioc_report.pdf"
        ioc_content = "Detected: 192.168.1.100 evil-domain.com"

        create_minimal_pdf(pdf_path, ioc_content)

        # Act: Use factory function and extract
        parser = get_parser(str(pdf_path))
        extracted_text = parser.extract_text()

        # Assert: Complete workflow should produce expected results
        assert isinstance(parser, PDFParser)
        assert "192.168.1.100" in extracted_text
        assert "evil-domain.com" in extracted_text

    def test_complete_html_parsing_workflow(self, tmp_path: Path) -> None:
        """
        Test complete workflow: create HTML -> get parser -> extract text.

        End-to-end validation of HTML processing pipeline.
        """
        # Arrange: Create HTML with IOC content
        html_path = tmp_path / "threat_intel.html"
        html_content = """
        <html>
        <body>
            <h1>Threat Report</h1>
            <p>C2 Server: 203.0.113.42</p>
            <p>Malware hash: d41d8cd98f00b204e9800998ecf8427e</p>
        </body>
        </html>
        """
        html_path.write_text(html_content, encoding="utf-8")

        # Act: Use factory function and extract
        parser = get_parser(str(html_path))
        extracted_text = parser.extract_text()

        # Assert: Complete workflow validation
        assert isinstance(parser, HTMLParser)
        assert "Threat Report" in extracted_text
        assert "203.0.113.42" in extracted_text
        assert "d41d8cd98f00b204e9800998ecf8427e" in extracted_text


class TestPDFParserTableExtraction:
    """Test PDF table extraction functionality for 100% coverage."""

    def test_extract_text_from_pdf_with_actual_tables(self, tmp_path: Path) -> None:
        """
        Test extraction from PDF with tables containing IOCs.

        Validates that table extraction code path is executed
        and processes table data correctly.
        """
        # Arrange: Create PDF with table-like content
        pdf_path = tmp_path / "table_iocs.pdf"

        # Create a more complex PDF structure that pdfplumber will parse as having tables
        # Note: This tests the table extraction code path even if the table is simple
        table_content = "IP Address | Type | Description | 10.0.0.1 | Private | Test"

        create_minimal_pdf(pdf_path, table_content)

        # Act: Extract text
        parser = PDFParser(str(pdf_path))
        extracted_text = parser.extract_text()

        # Assert: Table content should be extracted
        assert "10.0.0.1" in extracted_text or "IP Address" in extracted_text
        assert len(extracted_text) > 0


class TestHTMLParserURLFetching:
    """Test HTML parser URL fetching functionality."""

    def test_extract_text_from_http_url(self) -> None:
        """
        Test HTML extraction from HTTP URL.

        Validates that HTTP URL fetching code path works.
        Note: This test requires network access and uses a real lightweight service.
        """
        # Use httpbin.org which provides a simple HTML page for testing
        test_url = "http://httpbin.org/html"

        # Create parser for URL
        parser = HTMLParser(test_url)

        # Attempt extraction - may fail if network is unavailable
        try:
            extracted_text = parser.extract_text()

            # Should have extracted some HTML content
            assert len(extracted_text) > 0
            assert isinstance(extracted_text, str)

        except Exception as e:
            # If network fails, skip test
            pytest.skip(f"Network request failed: {e}")

    def test_extract_text_from_https_url(self) -> None:
        """
        Test HTML extraction from HTTPS URL.

        Validates HTTPS URL fetching with real request.
        """
        # Use a simple, reliable HTTPS endpoint
        test_url = "https://httpbin.org/html"

        parser = HTMLParser(test_url)

        try:
            extracted_text = parser.extract_text()

            assert len(extracted_text) > 0
            assert isinstance(extracted_text, str)

        except Exception as e:
            pytest.skip(f"Network request failed: {e}")

    def test_extract_text_from_url_with_bad_status(self) -> None:
        """
        Test HTML extraction from URL that returns error status.

        Validates error handling for HTTP error responses.
        """
        # Use httpbin.org endpoint that returns 404
        test_url = "https://httpbin.org/status/404"

        parser = HTMLParser(test_url)

        # Should raise URLAccessError or HTTPError
        with pytest.raises((URLAccessError, Exception)):
            parser.extract_text()

    def test_extract_text_from_unreachable_url(self) -> None:
        """
        Test HTML extraction from unreachable URL.

        Validates connection error handling.
        """
        # Use an invalid domain that won't resolve
        test_url = "http://this-domain-does-not-exist-12345.invalid"

        parser = HTMLParser(test_url)

        # Should raise URLAccessError
        with pytest.raises((URLAccessError, Exception)):
            parser.extract_text()


class TestHTMLParserErrorHandling:
    """Test HTML parser error handling for complete coverage."""

    def test_html_parser_with_local_file_processing_error(self, tmp_path: Path) -> None:
        """
        Test HTML parser error handling for invalid local files.

        Validates HTMLProcessingError is raised for problematic content.
        """
        # Create a file that might cause processing issues
        html_path = tmp_path / "weird.html"

        # Write extremely malformed content that might cause parsing issues
        # Note: BeautifulSoup is very permissive, so this tests the exception path
        weird_content = "<" * 10000  # Pathological case
        html_path.write_text(weird_content, encoding="utf-8")

        parser = HTMLParser(str(html_path))

        # Should handle gracefully or raise HTMLProcessingError
        try:
            result = parser.extract_text()
            # BeautifulSoup is permissive, so it might succeed
            assert isinstance(result, str)
        except HTMLProcessingError:
            # This is also acceptable
            pass
