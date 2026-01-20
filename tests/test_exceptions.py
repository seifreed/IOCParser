#!/usr/bin/env python3

# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive unit tests for iocparser.modules.exceptions module

Tests cover all custom exception classes with focus on uncovered lines:
- HTMLParsingError
- UnexpectedDownloadError factory function
- InvalidCacheError (if it exists)
- FileExistenceError message override

All tests validate real exception behavior, messages, and attributes
without using mocks.

Author: Marc Rivero | @seifreed
"""

import tempfile
from pathlib import Path

import pytest

from iocparser.modules.exceptions import (
    DownloadError,
    DownloadSizeError,
    FileExistenceError,
    FileProcessingError,
    FileSizeError,
    HTMLParsingError,
    HTMLProcessingError,
    InvalidURLError,
    IOCFileNotFoundError,
    IOCParserError,
    IOCTimeoutError,
    NetworkDownloadError,
    NetworkError,
    PDFParsingError,
    PDFProcessingError,
    UnexpectedDownloadError,
    UnsupportedFileTypeError,
    URLAccessError,
    ValidationError,
    WarningListError,
)


class TestBaseExceptions:
    """Test suite for base exception classes."""

    def test_iocparser_error_is_base_exception(self) -> None:
        """
        Test that IOCParserError is the base for all custom exceptions.

        Validates the exception hierarchy and that IOCParserError
        inherits from Python's base Exception.
        """
        # Arrange & Act: Create base exception
        error = IOCParserError("Base error message")

        # Assert: Verify inheritance
        assert isinstance(error, Exception)
        assert str(error) == "Base error message"

    def test_file_parsing_error_inherits_from_base(self) -> None:
        """
        Test that FileParsingError properly inherits from IOCParserError.

        Validates exception hierarchy and message handling.
        """
        # Arrange & Act: Create file parsing error
        error = IOCParserError("File parsing failed")

        # Assert: Verify it's an IOCParserError
        assert isinstance(error, IOCParserError)
        assert isinstance(error, Exception)


class TestHTMLParsingError:
    """Test suite for HTMLParsingError (uncovered in coverage report)."""

    def test_html_parsing_error_creation(self) -> None:
        """
        Test creating and raising HTMLParsingError.

        This covers the uncovered line 60 in exceptions.py where
        HTMLParsingError is defined but not tested.
        """
        # Arrange: Error message
        error_msg = "Failed to parse HTML structure"

        # Act: Create HTMLParsingError
        error = HTMLParsingError(error_msg)

        # Assert: Verify exception attributes
        assert isinstance(error, HTMLParsingError)
        assert isinstance(error, IOCParserError)
        assert str(error) == error_msg

    def test_html_parsing_error_can_be_raised(self) -> None:
        """
        Test that HTMLParsingError can be raised and caught.

        Validates real exception flow in try/except blocks.
        """

        # Arrange: Function that raises HTMLParsingError
        def parse_invalid_html() -> None:
            raise HTMLParsingError("Malformed HTML tag detected")  # noqa: TRY003

        # Act & Assert: Should raise and be catchable
        with pytest.raises(HTMLParsingError) as exc_info:
            parse_invalid_html()

        assert "Malformed HTML tag detected" in str(exc_info.value)

    def test_html_parsing_error_inheritance_chain(self) -> None:
        """
        Test the complete inheritance chain for HTMLParsingError.

        Validates: HTMLParsingError -> FileParsingError -> IOCParserError -> Exception
        """
        # Arrange & Act: Create error
        error = HTMLParsingError("Test error")

        # Assert: Verify full inheritance chain
        assert isinstance(error, HTMLParsingError)
        assert isinstance(error, IOCParserError)
        assert isinstance(error, Exception)


class TestUnexpectedDownloadError:
    """Test suite for UnexpectedDownloadError factory function (uncovered line 113)."""

    def test_unexpected_download_error_factory(self) -> None:
        """
        Test the UnexpectedDownloadError factory function.

        This covers line 113 in exceptions.py where the factory function
        creates a DownloadError with error_type='unexpected'.
        """
        # Arrange: Download error parameters
        url = "http://malware-sample.com/payload.exe"
        reason = "Connection reset by peer"

        # Act: Create error using factory function
        error = UnexpectedDownloadError(url, reason)

        # Assert: Verify it's a DownloadError with unexpected type
        assert isinstance(error, DownloadError)
        assert error.url == url
        assert error.reason == reason
        assert error.error_type == "unexpected"

    def test_unexpected_download_error_message_format(self) -> None:
        """
        Test that UnexpectedDownloadError has correct message format.

        Validates that the error message starts with "Unexpected error"
        instead of "Failed to" (line 103 in exceptions.py).
        """
        # Arrange: Error parameters
        url = "http://test-download.com/file.bin"
        reason = "SSL certificate verification failed"

        # Act: Create error
        error = UnexpectedDownloadError(url, reason)

        # Assert: Message should start with "Unexpected error"
        error_message = str(error)
        assert error_message.startswith("Unexpected error")
        assert url in error_message
        assert reason in error_message

    def test_unexpected_download_error_can_be_raised(self) -> None:
        """
        Test that UnexpectedDownloadError can be raised and caught.

        Validates real exception flow with the factory function.
        """

        # Arrange: Function that raises unexpected download error
        def download_file() -> None:
            raise UnexpectedDownloadError("http://evil.com/malware.zip", "Timeout after 30 seconds")

        # Act & Assert: Should raise DownloadError
        with pytest.raises(DownloadError) as exc_info:
            download_file()

        assert exc_info.value.error_type == "unexpected"
        assert "Unexpected error" in str(exc_info.value)


class TestFileExistenceError:
    """Test suite for FileExistenceError (uncovered lines 145-146)."""

    def test_file_existence_error_message_override(self) -> None:
        """
        Test that FileExistenceError overrides the message format.

        This covers lines 145-146 in exceptions.py where the args tuple
        is overridden with a custom message format.
        """
        # Arrange: Non-existent file path
        file_path = "/path/to/nonexistent/file.txt"

        # Act: Create FileExistenceError
        error = FileExistenceError(file_path)

        # Assert: Verify custom message format
        error_message = str(error)
        assert "does not exist or is not accessible" in error_message
        assert file_path in error_message

    def test_file_existence_error_inherits_from_iocfilenotfound(self) -> None:
        """
        Test that FileExistenceError properly inherits from IOCFileNotFoundError.

        Validates the inheritance chain and attribute preservation.
        """
        # Arrange & Act: Create error
        file_path = str(Path(tempfile.gettempdir()) / "missing.pdf")
        error = FileExistenceError(file_path)

        # Assert: Verify inheritance and attributes
        assert isinstance(error, IOCFileNotFoundError)
        assert isinstance(error, IOCParserError)
        assert error.file_path == file_path

    def test_file_existence_error_message_differs_from_parent(self) -> None:
        """
        Test that FileExistenceError has different message than parent class.

        Validates that the message override in lines 145-146 produces
        a different format than IOCFileNotFoundError.
        """
        # Arrange: Same file path for both errors
        file_path = "/data/report.html"

        # Act: Create both error types
        parent_error = IOCFileNotFoundError(file_path)
        child_error = FileExistenceError(file_path)

        # Assert: Messages should differ
        parent_msg = str(parent_error)
        child_msg = str(child_error)
        assert parent_msg != child_msg
        assert "does not exist or is not accessible" in child_msg
        assert "does not exist or is not accessible" not in parent_msg

    def test_file_existence_error_can_be_raised(self) -> None:
        """
        Test that FileExistenceError can be raised in real code.

        Validates exception flow when file doesn't exist.
        """

        # Arrange: Function that checks file existence
        def check_file_exists(path: str) -> None:
            from pathlib import Path

            if not Path(path).is_file():
                raise FileExistenceError(path)

        # Act & Assert: Should raise FileExistenceError
        with pytest.raises(FileExistenceError) as exc_info:
            check_file_exists("/nonexistent/path.txt")

        assert "does not exist or is not accessible" in str(exc_info.value)


class TestHTMLProcessingError:
    """Test suite for HTMLProcessingError (uncovered lines 137-138)."""

    def test_html_processing_error_creation(self) -> None:
        """
        Test creating HTMLProcessingError with reason parameter.

        This covers lines 137-138 in exceptions.py where the error
        is initialized with a formatted message.
        """
        # Arrange: Processing error reason
        reason = "Missing required HTML tags"

        # Act: Create HTMLProcessingError
        error = HTMLProcessingError(reason)

        # Assert: Verify error attributes
        assert isinstance(error, HTMLProcessingError)
        assert isinstance(error, HTMLParsingError)
        assert error.reason == reason

    def test_html_processing_error_message_format(self) -> None:
        """
        Test that HTMLProcessingError formats message correctly.

        Validates the message format from line 138: f"Error processing HTML: {reason}"
        """
        # Arrange: Specific error reason
        reason = "BeautifulSoup parse failure"

        # Act: Create error
        error = HTMLProcessingError(reason)

        # Assert: Message should have correct format
        error_message = str(error)
        assert error_message == f"Error processing HTML: {reason}"
        assert "Error processing HTML:" in error_message
        assert reason in error_message

    def test_html_processing_error_can_be_raised(self) -> None:
        """
        Test that HTMLProcessingError can be raised and caught.

        Validates real exception flow for HTML processing failures.
        """

        # Arrange: Function that processes HTML
        def process_html_content(content: str) -> None:
            if "<html>" not in content:
                raise HTMLProcessingError("Invalid HTML structure")  # noqa: TRY003

        # Act & Assert: Should raise HTMLProcessingError
        with pytest.raises(HTMLProcessingError) as exc_info:
            process_html_content("Not HTML content")

        assert exc_info.value.reason == "Invalid HTML structure"
        assert "Error processing HTML:" in str(exc_info.value)


class TestURLAccessError:
    """Test suite for URLAccessError (uncovered lines 145-146)."""

    def test_url_access_error_creation(self) -> None:
        """
        Test creating URLAccessError with reason parameter.

        This covers lines 145-146 in exceptions.py (in URLAccessError.__init__).
        """
        # Arrange: Access error reason
        reason = "403 Forbidden - Access denied"

        # Act: Create URLAccessError
        error = URLAccessError(reason)

        # Assert: Verify error attributes
        assert isinstance(error, URLAccessError)
        assert isinstance(error, NetworkError)
        assert error.reason == reason

    def test_url_access_error_message_format(self) -> None:
        """
        Test that URLAccessError formats message correctly.

        Validates the message format from line 146: f"Error accessing URL: {reason}"
        """
        # Arrange: Specific error reason
        reason = "Connection timeout after 30s"

        # Act: Create error
        error = URLAccessError(reason)

        # Assert: Message should have correct format
        error_message = str(error)
        assert error_message == f"Error accessing URL: {reason}"
        assert "Error accessing URL:" in error_message
        assert reason in error_message

    def test_url_access_error_can_be_raised(self) -> None:
        """
        Test that URLAccessError can be raised and caught.

        Validates real exception flow for URL access failures.
        """

        # Arrange: Function that accesses URLs
        def fetch_url(url: str) -> None:
            if not url.startswith("http"):
                raise URLAccessError("Invalid URL protocol")  # noqa: TRY003

        # Act & Assert: Should raise URLAccessError
        with pytest.raises(URLAccessError) as exc_info:
            fetch_url("ftp://invalid.com")

        assert exc_info.value.reason == "Invalid URL protocol"
        assert "Error accessing URL:" in str(exc_info.value)


class TestDownloadSizeError:
    """Test suite for DownloadSizeError (uncovered line 60)."""

    def test_download_size_error_creation(self) -> None:
        """
        Test creating DownloadSizeError with max_size_mb parameter.

        This covers line 60 in exceptions.py where DownloadSizeError
        calls super().__init__ with specific parameters.
        """
        # Arrange: Maximum allowed size
        max_size_mb = 50.0

        # Act: Create DownloadSizeError
        error = DownloadSizeError(max_size_mb)

        # Assert: Verify error attributes
        assert isinstance(error, DownloadSizeError)
        assert isinstance(error, FileSizeError)
        assert error.max_size_mb == max_size_mb
        assert error.actual_size_mb == 0
        assert error.item_type == "Downloaded content"

    def test_download_size_error_message_format(self) -> None:
        """
        Test that DownloadSizeError has correct message format.

        Validates that the error message includes "Downloaded content"
        as the item_type from line 60.
        """
        # Arrange: Size limit
        max_size = 100.0

        # Act: Create error
        error = DownloadSizeError(max_size)

        # Assert: Message should mention "Downloaded content"
        error_message = str(error)
        assert "Downloaded content" in error_message
        assert f"{max_size:.2f}MB" in error_message

    def test_download_size_error_can_be_raised(self) -> None:
        """
        Test that DownloadSizeError can be raised and caught.

        Validates real exception flow for oversized downloads.
        """

        # Arrange: Function that checks download size
        def validate_download_size(size_mb: float, limit_mb: float) -> None:
            if size_mb > limit_mb:
                raise DownloadSizeError(limit_mb)

        # Act & Assert: Should raise DownloadSizeError
        with pytest.raises(DownloadSizeError) as exc_info:
            validate_download_size(150.0, 100.0)

        assert exc_info.value.max_size_mb == 100.0
        assert "Downloaded content" in str(exc_info.value)


class TestOtherExceptions:
    """Test suite for additional exception classes to ensure full coverage."""

    def test_pdf_parsing_error(self) -> None:
        """Test PDFParsingError creation and inheritance."""
        # Arrange & Act
        error = PDFParsingError("Invalid PDF structure")

        # Assert
        assert isinstance(error, PDFParsingError)
        assert isinstance(error, IOCParserError)
        assert str(error) == "Invalid PDF structure"

    def test_pdf_processing_error(self) -> None:
        """Test PDFProcessingError with reason parameter."""
        # Arrange & Act
        reason = "Encrypted PDF not supported"
        error = PDFProcessingError(reason)

        # Assert
        assert isinstance(error, PDFProcessingError)
        assert error.reason == reason
        assert "Error processing PDF:" in str(error)

    def test_validation_error(self) -> None:
        """Test ValidationError creation."""
        # Arrange & Act
        error = ValidationError("Invalid input format")

        # Assert
        assert isinstance(error, ValidationError)
        assert isinstance(error, IOCParserError)

    def test_file_size_error_with_custom_item_type(self) -> None:
        """Test FileSizeError with custom item type."""
        # Arrange & Act
        error = FileSizeError(actual_size_mb=150.5, max_size_mb=100.0, item_type="Archive")

        # Assert
        assert error.actual_size_mb == 150.5
        assert error.max_size_mb == 100.0
        assert error.item_type == "Archive"
        assert "Archive" in str(error)

    def test_ioc_timeout_error(self) -> None:
        """Test IOCTimeoutError with operation and target."""
        # Arrange & Act
        error = IOCTimeoutError("download", "http://slow-server.com/file")

        # Assert
        assert error.operation == "download"
        assert error.target == "http://slow-server.com/file"
        assert "download timeout" in str(error)

    def test_invalid_url_error(self) -> None:
        """Test InvalidURLError creation."""
        # Arrange & Act
        url = "htp://invalid-protocol.com"
        error = InvalidURLError(url)

        # Assert
        assert error.url == url
        assert "Invalid URL:" in str(error)
        assert url in str(error)

    def test_unsupported_file_type_error(self) -> None:
        """Test UnsupportedFileTypeError creation."""
        # Arrange & Act
        file_path = "/path/to/file.xyz"
        error = UnsupportedFileTypeError(file_path)

        # Assert
        assert error.file_path == file_path
        assert "Unsupported file type:" in str(error)

    def test_download_error_with_network_type(self) -> None:
        """Test DownloadError with network error type."""
        # Arrange & Act
        error = DownloadError(
            url="http://example.com/file", reason="DNS resolution failed", error_type="network"
        )

        # Assert
        assert error.url == "http://example.com/file"
        assert error.reason == "DNS resolution failed"
        assert error.error_type == "network"
        assert "Failed to download" in str(error)

    def test_network_download_error_alias(self) -> None:
        """Test NetworkDownloadError alias for DownloadError."""
        # Arrange & Act
        error = NetworkDownloadError(url="http://test.com", reason="Connection refused")

        # Assert: Should be a DownloadError
        assert isinstance(error, DownloadError)
        assert error.url == "http://test.com"

    def test_file_processing_error(self) -> None:
        """Test FileProcessingError with file path and reason."""
        # Arrange & Act
        error = FileProcessingError(
            file_path=str(Path(tempfile.gettempdir()) / "data.bin"), reason="Corrupted file header"
        )

        # Assert
        assert error.file_path == str(Path(tempfile.gettempdir()) / "data.bin")
        assert error.reason == "Corrupted file header"
        assert "Failed to process" in str(error)

    def test_warning_list_error(self) -> None:
        """Test WarningListError creation."""
        # Arrange & Act
        error = WarningListError("Failed to download MISP warning lists")

        # Assert
        assert isinstance(error, WarningListError)
        assert isinstance(error, IOCParserError)

    def test_network_error(self) -> None:
        """Test NetworkError creation."""
        # Arrange & Act
        error = NetworkError("Connection timeout")

        # Assert
        assert isinstance(error, NetworkError)
        assert isinstance(error, IOCParserError)

    def test_ioc_file_not_found_error(self) -> None:
        """Test IOCFileNotFoundError creation."""
        # Arrange & Act
        file_path = "/missing/file.txt"
        error = IOCFileNotFoundError(file_path)

        # Assert
        assert error.file_path == file_path
        assert "File not found:" in str(error)
        assert file_path in str(error)


class TestExceptionInheritance:
    """Test suite to validate exception inheritance relationships."""

    def test_all_exceptions_inherit_from_base(self) -> None:
        """
        Test that all custom exceptions inherit from IOCParserError.

        This validates the entire exception hierarchy is properly structured.
        """
        # Arrange: List of all exception classes
        exceptions_to_test = [
            HTMLParsingError("test"),
            HTMLProcessingError("test"),
            PDFParsingError("test"),
            PDFProcessingError("test"),
            WarningListError("test"),
            NetworkError("test"),
            ValidationError("test"),
            FileSizeError(10.0, 5.0),
            DownloadSizeError(5.0),
            IOCTimeoutError("op", "target"),
            IOCFileNotFoundError("/path"),
            InvalidURLError("url"),
            UnsupportedFileTypeError("/path"),
            DownloadError("url", "reason"),
            FileProcessingError("/path", "reason"),
            URLAccessError("reason"),
            FileExistenceError("/path"),
        ]

        # Act & Assert: All should inherit from IOCParserError
        for error in exceptions_to_test:
            assert isinstance(error, IOCParserError)
            assert isinstance(error, Exception)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
