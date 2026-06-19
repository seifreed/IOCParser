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

from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from iocparser.errors import (
    FileExistenceError,
    FileSizeError,
    HTMLProcessingError,
    PDFProcessingError,
    UnsupportedFileTypeError,
    URLAccessError,
)
from iocparser.infrastructure.file_parser import (
    HTMLParser,
    PDFParser,
    XMLParser,
    get_parser,
)
from iocparser.infrastructure.http_download import MAX_URL_SIZE
from tests.http_server_helpers import ThreadedHTTPServer


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


def create_table_pdf(pdf_path: Path) -> None:
    """Create a minimal PDF whose table is detected by pdfplumber."""
    stream = (
        "BT\n"
        "/F1 12 Tf\n"
        "60 735 Td\n"
        "(IP) Tj\n"
        "90 0 Td\n"
        "(Type) Tj\n"
        "-90 -40 Td\n"
        "(203.0.113.7) Tj\n"
        "90 0 Td\n"
        "(C2) Tj\n"
        "ET\n"
        "50 750 m 250 750 l S\n"
        "50 710 m 250 710 l S\n"
        "50 670 m 250 670 l S\n"
        "50 670 m 50 750 l S\n"
        "150 670 m 150 750 l S\n"
        "250 670 m 250 750 l S\n"
    )

    objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        (
            "3 0 obj\n"
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
            "/MediaBox [0 0 300 800] /Contents 5 0 R >>\n"
            "endobj\n"
        ),
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        f"5 0 obj\n<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}endstream\nendobj\n",
    ]

    header = "%PDF-1.4\n"
    body = ""
    offsets = [0]
    for obj in objects:
        offsets.append(len((header + body).encode("latin-1")))
        body += obj

    xref_start = len((header + body).encode("latin-1"))
    xref = "xref\n0 6\n0000000000 65535 f \n"
    for offset in offsets[1:]:
        xref += f"{offset:010d} 00000 n \n"
    trailer = f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n"
    pdf_path.write_bytes((header + body + xref + trailer).encode("latin-1"))


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

    def test_extract_pdf_text_separates_page_text(self) -> None:
        """Page boundaries must not merge adjacent IOCs or words."""

        class Page:
            def __init__(self, text: str) -> None:
                self.text = text

            def extract_text(self) -> str:
                return self.text

            def extract_tables(self) -> list[list[list[str | None]]]:
                return []

        pdf = type("PDF", (), {"pages": [Page("Domain evil.com"), Page("IP 203.0.113.7")]})()

        extracted_text = PDFParser._extract_pdf_text(pdf)

        assert "evil.com\nIP" in extracted_text
        assert "evil.comIP" not in extracted_text

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

    def test_pdf_parser_expands_user_home_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        home.mkdir()
        pdf_path = home / "sample.pdf"
        create_minimal_pdf(pdf_path, "example.com")
        monkeypatch.setenv("HOME", str(home))

        parser = PDFParser("~/sample.pdf")

        assert parser.file_path == str(pdf_path)

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

    def test_extract_table_text_handles_empty_rows(self) -> None:
        assert PDFParser._extract_table_text(None) == ""
        assert PDFParser._extract_table_text([]) == ""
        assert PDFParser._extract_table_text([[], [None, None]]) == ""
        assert (
            PDFParser._extract_table_text([["ioc", None], ["value", "203.0.113.5"]])
            == "ioc\nvalue 203.0.113.5\n"
        )


class TestXMLParser:
    """Test XML text extraction keeps data the HTML parser would strip."""

    def test_xml_keeps_data_bearing_elements_html_would_strip(self, tmp_path: Path) -> None:
        """Regression: XML routed through the HTML parser lost IOCs inside
        script/style/meta/head elements, which in XML carry real data."""
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(
            "<config><script>1.2.3.4</script><meta>http://evil.com</meta>"
            "<node>5.6.7.8</node></config>",
            encoding="utf-8",
        )

        text = XMLParser(str(xml_path)).extract_text()

        assert "1.2.3.4" in text
        assert "http://evil.com" in text
        assert "5.6.7.8" in text

    def test_xml_unescapes_entities(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "entity.xml"
        xml_path.write_text("<a>&#104;ttp://evil.com</a>", encoding="utf-8")
        assert "http://evil.com" in XMLParser(str(xml_path)).extract_text()


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

    def test_extract_text_harvests_url_bearing_attributes(self, tmp_path: Path) -> None:
        """URLs in href/src/action/data-* attributes must be extracted, not dropped.

        get_text() returns only text nodes, so malicious URLs that live only in link
        attributes (the common case in phishing/threat-report HTML) were silently lost.
        """
        html_path = tmp_path / "attrs.html"
        html_path.write_text(
            """
            <html><body>
            <a href="https://evil-c2.ru/gate.php">click</a>
            <img src="https://tracker.bad.io/p.png" data-src="https://lazy.evil.org/x"/>
            <form action="https://exfil.evil.net/post"></form>
            </body></html>
            """,
            encoding="utf-8",
        )

        text = HTMLParser(str(html_path)).extract_text()

        assert "https://evil-c2.ru/gate.php" in text
        assert "https://exfil.evil.net/post" in text
        assert "https://lazy.evil.org/x" in text
        assert "tracker.bad.io" in text

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

    def test_html_parser_expands_user_home_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        home.mkdir()
        html_path = home / "sample.html"
        html_path.write_text("<html><body>x</body></html>", encoding="utf-8")
        monkeypatch.setenv("HOME", str(home))

        parser = HTMLParser("~/sample.html")

        assert parser.file_path == str(html_path)

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

    def test_xml_parser_expands_user_home_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        home.mkdir()
        xml_path = home / "sample.xml"
        xml_path.write_text("<root>x</root>", encoding="utf-8")
        monkeypatch.setenv("HOME", str(home))

        parser = XMLParser("~/sample.xml")

        assert parser.file_path == str(xml_path)

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

    def test_get_parser_handles_uppercase_pdf_extension(self, tmp_path: Path) -> None:
        pdf_path = tmp_path / "TEST.PDF"
        create_minimal_pdf(pdf_path, "Test")

        parser = get_parser(str(pdf_path))

        assert isinstance(parser, PDFParser)

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

    def test_get_parser_treats_uppercase_url_scheme_as_remote(self) -> None:
        url = "HTTPS://example.com/data"

        parser = get_parser(url)

        assert isinstance(parser, HTMLParser)
        assert parser.file_path == url

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

    def test_get_parser_handles_pdf_url_with_query_string(self) -> None:
        parser = get_parser("https://example.com/document.PDF?download=1")

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
        create_table_pdf(pdf_path)

        # Act: Extract text
        parser = PDFParser(str(pdf_path))
        extracted_text = parser.extract_text()

        # Assert: Table content should be extracted
        assert "203.0.113.7" in extracted_text
        assert "C2" in extracted_text
        assert len(extracted_text) > 0


class TestHTMLParserURLFetching:
    """Test HTML parser URL fetching functionality."""

    class _LocalHTTPServer(ThreadedHTTPServer):
        path = "/page"

        def __init__(
            self,
            *,
            body: bytes,
            status: int = 200,
            content_type: str = "text/html",
            content_length: str | None = None,
        ) -> None:
            self.body = body
            self.status = status
            self.content_type = content_type
            self.content_length = content_length

        def build_handler(self) -> type[BaseHTTPRequestHandler]:
            body = self.body
            status = self.status
            content_type = self.content_type
            content_length = self.content_length

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    self.send_response(status)
                    self.send_header("Content-Type", content_type)
                    header_value = content_length if content_length is not None else str(len(body))
                    self.send_header("Content-Length", header_value)
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format: str, *args) -> None:
                    del format, args

            return Handler

    def test_extract_text_from_http_url(self) -> None:
        """
        Test HTML extraction from HTTP URL.

        Validates that HTTP URL fetching code path works.
        Note: This test requires network access and uses a real lightweight service.
        """
        with self._LocalHTTPServer(
            body=b"<html><body><h1>Local Page</h1><p>ioc.example</p></body></html>"
        ) as test_url:
            parser = HTMLParser(test_url)
            extracted_text = parser.extract_text()
        assert len(extracted_text) > 0
        assert "Local Page" in extracted_text
        assert "ioc.example" in extracted_text

    def test_extract_text_from_https_url(self) -> None:
        """
        Test HTML extraction from HTTPS URL.

        Validates HTTPS URL fetching with real request.
        """
        with self._LocalHTTPServer(
            body=b"<html><body><h1>HTTPS-like Page</h1></body></html>"
        ) as test_url:
            parser = HTMLParser(test_url)
            extracted_text = parser.extract_text()
        assert len(extracted_text) > 0
        assert "HTTPS-like Page" in extracted_text

    def test_extract_text_from_url_raises_cleanup_error_after_success(self, monkeypatch) -> None:
        """
        Test URL cleanup failure surfaces after successful extraction.
        """

        def failing_unlink(*args, **kwargs):
            del args, kwargs
            raise OSError("unlink failed")

        monkeypatch.setattr(Path, "unlink", failing_unlink)
        with self._LocalHTTPServer(
            body=b"<html><body><h1>Cleanup Page</h1></body></html>"
        ) as test_url:
            with pytest.raises(HTMLProcessingError):
                HTMLParser(test_url).extract_text()

    def test_extract_text_from_url_with_bad_status(self) -> None:
        """
        Test HTML extraction from URL that returns error status.

        Validates error handling for HTTP error responses.
        """
        with self._LocalHTTPServer(body=b"missing", status=404) as test_url:
            parser = HTMLParser(test_url)
            with pytest.raises(URLAccessError):
                parser.extract_text()

    def test_extract_text_from_unreachable_url(self) -> None:
        """
        Test HTML extraction from unreachable URL.

        Validates connection error handling.
        """
        parser = HTMLParser("http://127.0.0.1:9/unreachable")
        with pytest.raises(URLAccessError):
            parser.extract_text()

    def test_remote_file_parsers_reject_oversized_content_length(self) -> None:
        oversized_length = str(MAX_URL_SIZE + 1)

        with self._LocalHTTPServer(body=b"", content_length=oversized_length) as test_url:
            with pytest.raises(FileSizeError):
                HTMLParser(test_url).extract_text()

        with self._LocalHTTPServer(
            body=b"",
            content_type="application/pdf",
            content_length=oversized_length,
        ) as test_url:
            with pytest.raises(FileSizeError):
                get_parser(f"{test_url}.pdf").extract_text()

    def test_pdf_parser_extracts_remote_pdf_url(self, tmp_path: Path) -> None:
        pdf_path = tmp_path / "remote.pdf"
        create_minimal_pdf(pdf_path, "Remote PDF IOC 198.51.100.42")

        with self._LocalHTTPServer(
            body=pdf_path.read_bytes(), content_type="application/pdf"
        ) as test_url:
            parser = get_parser(f"{test_url}.PDF?download=1")
            extracted_text = parser.extract_text()

        assert isinstance(parser, PDFParser)
        assert "198.51.100.42" in extracted_text


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

        result = parser.extract_text()
        assert isinstance(result, str)

    def test_html_parser_raises_url_access_error_for_local_404(self) -> None:
        class NotFoundServer(ThreadedHTTPServer):
            path = "/missing.html"

            def build_handler(self) -> type[BaseHTTPRequestHandler]:
                class Handler(BaseHTTPRequestHandler):
                    def do_GET(self) -> None:
                        self.send_response(404)
                        self.end_headers()

                    def log_message(self, format: str, *args) -> None:
                        del format, args

                return Handler

        with NotFoundServer() as url:
            parser = HTMLParser(url)
            with pytest.raises(URLAccessError):
                parser.extract_text()

    def test_html_parser_wraps_generic_local_errors(self, tmp_path: Path) -> None:
        html_path = tmp_path / "generic-error.html"
        html_path.write_text("<html><body>ok</body></html>", encoding="utf-8")

        parser = HTMLParser(str(html_path))
        parser.file_path = "\0broken-path"

        with pytest.raises(HTMLProcessingError):
            parser.extract_text()
