#!/usr/bin/env python3

"""
Custom exceptions for IOCParser

Author: Marc Rivero | @seifreed
"""


class IOCParserError(Exception):
    """Base exception for IOCParser."""


class FileParsingError(IOCParserError):
    """Exception raised when file parsing fails."""


class PDFParsingError(FileParsingError):
    """Exception raised when PDF parsing fails."""


class HTMLParsingError(FileParsingError):
    """Exception raised when HTML parsing fails."""


class ExtractionError(IOCParserError):
    """Exception raised when IOC extraction fails."""


class WarningListError(IOCParserError):
    """Exception raised when warning list operations fail."""


class NetworkError(IOCParserError):
    """Exception raised for network-related errors."""


class ValidationError(IOCParserError):
    """Exception raised for input validation errors."""


class FileSizeError(ValidationError):
    """Exception raised when file size exceeds limits."""

    def __init__(self, actual_size_mb: float, max_size_mb: float, item_type: str = "File") -> None:
        self.actual_size_mb = actual_size_mb
        self.max_size_mb = max_size_mb
        self.item_type = item_type
        message = (
            f"{item_type} size ({actual_size_mb:.2f}MB) exceeds "
            f"maximum allowed size ({max_size_mb:.2f}MB)"
        )
        super().__init__(message)


class DownloadSizeError(FileSizeError):
    """Exception raised when downloaded content exceeds limits."""

    def __init__(self, max_size_mb: float) -> None:
        super().__init__(0, max_size_mb, "Downloaded content")


class IOCTimeoutError(IOCParserError):
    """Exception raised when operation times out."""

    def __init__(self, operation: str, target: str) -> None:
        self.operation = operation
        self.target = target
        super().__init__(f"{operation} timeout for {target}")


class IOCFileNotFoundError(IOCParserError):
    """Exception raised when file is not found."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        super().__init__(f"File not found: {file_path}")


class InvalidURLError(ValidationError):
    """Exception raised for invalid URLs."""

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(f"Invalid URL: {url}")


class UnsupportedFileTypeError(ValidationError):
    """Exception raised for unsupported file types."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        super().__init__(f"Unsupported file type: {file_path}")


class NetworkDownloadError(NetworkError):
    """Exception raised for network download failures."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Failed to download {url}: {reason}")


class UnexpectedDownloadError(NetworkError):
    """Exception raised for unexpected download errors."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Unexpected error downloading {url}: {reason}")


class FileProcessingError(FileParsingError):
    """Exception raised when file processing fails."""

    def __init__(self, file_path: str, reason: str) -> None:
        self.file_path = file_path
        self.reason = reason
        super().__init__(f"Failed to process {file_path}: {reason}")


class PDFProcessingError(PDFParsingError):
    """Exception raised when PDF processing fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Error processing PDF: {reason}")


class HTMLProcessingError(HTMLParsingError):
    """Exception raised when HTML processing fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Error processing HTML: {reason}")


class URLAccessError(NetworkError):
    """Exception raised when URL access fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Error accessing URL: {reason}")


class FileExistenceError(IOCFileNotFoundError):
    """Exception raised when file does not exist or is not accessible."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        super().__init__(file_path)
        # Override the message for this specific case
        self.args = (f"The file {file_path} does not exist or is not accessible",)
