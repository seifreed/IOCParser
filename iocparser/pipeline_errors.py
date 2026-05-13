from __future__ import annotations

from iocparser.domain.pipeline import PipelineErrorInfo, PipelineJobResult
from iocparser.errors import (
    DownloadError,
    FileExistenceError,
    FileProcessingError,
    FileSizeError,
    InvalidURLError,
    IOCTimeoutError,
    SourceNotFoundError,
    SourceProcessingError,
    UnsupportedFileTypeError,
    ValidationError,
)

_PIPELINE_ERROR_MAPPINGS: tuple[tuple[type[Exception], tuple[str, str, bool, str]], ...] = (
    (SourceNotFoundError, ("INPUT_NOT_FOUND", "malformed_input", False, "failed")),
    (FileExistenceError, ("INPUT_NOT_FOUND", "malformed_input", False, "failed")),
    (InvalidURLError, ("INVALID_URL", "malformed_input", False, "failed")),
    (UnsupportedFileTypeError, ("UNSUPPORTED_INPUT_TYPE", "parser_failure", False, "failed")),
    (FileSizeError, ("INPUT_TOO_LARGE", "resource_limit", False, "failed")),
    (IOCTimeoutError, ("INPUT_TIMEOUT", "transport_failure", True, "failed")),
    (DownloadError, ("DOWNLOAD_FAILED", "transport_failure", True, "failed")),
    (SourceProcessingError, ("PARSER_FAILED", "parser_failure", False, "failed")),
    (FileProcessingError, ("PARSER_FAILED", "parser_failure", False, "failed")),
    (ValidationError, ("VALIDATION_FAILED", "malformed_input", False, "failed")),
)


def classify_pipeline_exception(exc: Exception) -> PipelineErrorInfo:
    """Map internal exceptions to stable machine-readable pipeline errors."""
    for error_type, (code, category, retryable, status) in _PIPELINE_ERROR_MAPPINGS:
        if isinstance(exc, error_type):
            return PipelineErrorInfo(code, category, retryable, status, str(exc))
    return PipelineErrorInfo("UNEXPECTED_FAILURE", "non_retryable", False, "failed", str(exc))


def error_for_failed_result(result: PipelineJobResult) -> PipelineErrorInfo:
    if result.error is not None:
        return result.error
    return PipelineErrorInfo(
        code="PIPELINE_FAILED",
        category="non_retryable",
        retryable=False,
        status="failed",
        message="Pipeline processor returned failed status without error details",
    )
