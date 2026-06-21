#!/usr/bin/env python3

"""
Custom exceptions for IOCParser

Author: Marc Rivero | @seifreed
"""


class IOCParserError(Exception):
    """Base exception for IOCParser."""


class SourceNotFoundError(IOCParserError, FileNotFoundError):
    """Raised when a requested input source cannot be read because it does not exist."""

    def __init__(self, source_path: str) -> None:
        self.source_path = source_path
        super().__init__(f"Source not found: {source_path}")


class SourceProcessingError(IOCParserError):
    """Raised when a source cannot be processed into text or extracted results."""

    def __init__(self, source_path: str, reason: str) -> None:
        self.source_path = source_path
        self.reason = reason
        super().__init__(f"Failed to process {source_path}: {reason}")


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


_OMIT_GOT = object()
_MISSING_VALUE = object()
#: Sentinel passed as the ``value`` argument of :class:`TypeValidationError` to
#: render a "got missing" suffix (the guarded key/attribute was absent entirely).
MISSING_VALUE = _MISSING_VALUE


class TypeValidationError(TypeError):
    """Raised at a trust boundary when a value fails an isinstance/shape guard.

    The message is assembled here so call sites pass structured arguments instead
    of inline f-strings. Pass ``subject`` for an "Expected {subject} to be …" lead
    (or None for "Expected {expected} …"); omit ``value`` for no "got" suffix, or
    pass :data:`MISSING_VALUE` for "got missing", otherwise the runtime type name
    of ``value`` is appended.
    """

    def __init__(
        self, subject: str | None, expected: str, value: object = _OMIT_GOT
    ) -> None:
        head = f"Expected {subject} to be {expected}" if subject else f"Expected {expected}"
        if value is _OMIT_GOT:
            message = head
        elif value is _MISSING_VALUE:
            message = f"{head}, got missing"
        else:
            message = f"{head}, got {type(value).__name__}"
        super().__init__(message)


class NonNegativeValueError(ValueError):
    """Raised when a numeric field that must be non-negative is negative."""

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"Expected {field} to be non-negative")


class RetryCounterError(ValueError):
    """Raised when ``max_attempts`` is not a usable retry counter."""

    def __init__(self) -> None:
        super().__init__("max_attempts must be a valid retry counter")


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


class BlockedURLError(ValidationError):
    """Raised when a URL resolves to a blocked (private/loopback/metadata) address."""

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(
            f"Refusing to fetch URL resolving to a private or reserved address: {url} "
            f"(set --allow-private-urls or IOCPARSER_ALLOW_PRIVATE_URLS=1 to override)"
        )


class UnsupportedFileTypeError(ValidationError):
    """Exception raised for unsupported file types."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        super().__init__(f"Unsupported file type: {file_path}")


class DownloadError(NetworkError):
    """Exception raised for download failures."""

    def __init__(self, url: str, reason: str, error_type: str = "network") -> None:
        self.url = url
        self.reason = reason
        self.error_type = error_type
        prefix = "Unexpected error" if error_type == "unexpected" else "Failed to"
        super().__init__(f"{prefix} download {url}: {reason}")


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
