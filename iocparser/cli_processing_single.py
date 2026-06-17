from __future__ import annotations

import argparse
import sys

from iocparser.cli_args import get_bool_arg, get_optional_str_arg
from iocparser.cli_processing_single_support import (
    ProcessFileFunc,
    SingleInputContext,
    UrlProcessingRequest,
    build_single_input_context,
    joined_type_filters,
    missing_url_error,
    plugin_client,
    process_file_input,
    process_stdin_input,
    process_url_input,
    stdin_stream_error,
)
from iocparser.cli_processing_support import (
    GroupedIocs,
    GroupedWarnings,
    extractor_engine,
    temporary_resource_cleaner,
)
from iocparser.domain.models import ExtractionResult
from iocparser.interfaces.ports import TextSourceReader, URLDownloader, WarningListService

_stdin_stream_error = stdin_stream_error
_joined_type_filters = joined_type_filters
_plugin_client = plugin_client
__all__ = ["ProcessFileFunc", "process_single_input"]


def process_single_input(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    downloader: URLDownloader,
    process_file_func: ProcessFileFunc,
) -> tuple[GroupedIocs, GroupedWarnings, str, ExtractionResult | None]:
    file_arg = get_optional_str_arg(args, "file")
    url = get_optional_str_arg(args, "url") or get_optional_str_arg(args, "url_direct")
    context: SingleInputContext = build_single_input_context(
        args,
        reader=reader,
        downloader=downloader,
        warning_service=warning_service,
    )

    if get_bool_arg(args, "stdin") or file_arg == "-":
        return process_stdin_input(
            stdin_stream=sys.stdin,
            context=context,
            extractor_engine=extractor_engine,
            warning_service=warning_service,
        )

    if file_arg:
        return process_file_input(
            file_arg=file_arg,
            context=context,
            process_file_func=process_file_func,
        )

    if not url:
        raise missing_url_error()

    return process_url_input(
        UrlProcessingRequest(
            context=context,
            url=url,
            downloader=downloader,
            reader=reader,
            extractor_engine=extractor_engine,
            temporary_resource_cleaner=temporary_resource_cleaner,
            warning_service=warning_service,
        )
    )
