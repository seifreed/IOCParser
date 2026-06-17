from __future__ import annotations

import argparse
import sys

from iocparser.application.contracts import ExtractTextInput
from iocparser.cli_args import ProcessingOptions
from iocparser.cli_processing_files import (
    FileProcessingRequest,
    MultiFileProcessingRequest,
    _directory_files,
    _streaming_result,
    merge_results,
    process_directory_input,
    process_file,
    process_file_result,
    process_multiple_files,
    process_multiple_files_input,
)
from iocparser.cli_processing_single import ProcessFileFunc
from iocparser.cli_processing_single import process_single_input as _process_single_input
from iocparser.cli_processing_support import plugin_client as _plugin_client
from iocparser.cli_processing_urls import (
    _failed_urls_from_batch,
    _failed_urls_from_report,
    _group_failures,
    _retry_attempt_for_url,
    process_url_file_input,
    process_url_file_input_with_report,
)
from iocparser.domain.models import ExtractionResult
from iocparser.interfaces.ports import TextSourceReader, URLDownloader, WarningListService

__all__ = [
    "ExtractTextInput",
    "FileProcessingRequest",
    "MultiFileProcessingRequest",
    "ProcessingOptions",
    "_directory_files",
    "_failed_urls_from_batch",
    "_failed_urls_from_report",
    "_group_failures",
    "_plugin_client",
    "_retry_attempt_for_url",
    "_streaming_result",
    "merge_results",
    "process_directory_input",
    "process_file",
    "process_file_result",
    "process_multiple_files",
    "process_multiple_files_input",
    "process_single_input",
    "process_url_file_input",
    "process_url_file_input_with_report",
    "sys",
]


def process_single_input(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    downloader: URLDownloader,
    process_file_func: ProcessFileFunc,
) -> tuple[
    dict[str, list[str | dict[str, str]]],
    dict[str, list[dict[str, str]]],
    str,
    ExtractionResult | None,
]:
    return _process_single_input(
        args,
        reader=reader,
        warning_service=warning_service,
        downloader=downloader,
        process_file_func=process_file_func,
    )
