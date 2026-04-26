from __future__ import annotations

import argparse
from dataclasses import dataclass
from io import TextIOBase
from pathlib import Path
from typing import Protocol

from iocparser.application.contracts import ExtractTextInput, ExtractURLInput
from iocparser.application.use_cases import extract_from_text as app_extract_from_text
from iocparser.application.use_cases import extract_from_url as app_extract_from_url
from iocparser.cli_args import (
    ProcessingOptions,
    get_bool_arg,
    get_int_arg,
)
from iocparser.cli_processing_files import FileProcessingRequest
from iocparser.cli_processing_support import GroupedIocs, GroupedWarnings, SingleInputPayload
from iocparser.cli_processing_support import joined_type_filters as shared_joined_type_filters
from iocparser.cli_processing_support import plugin_client as shared_plugin_client
from iocparser.client import IOCParserClient
from iocparser.domain.options import ExtractionOptions
from iocparser.domain.results import ExtractionResult
from iocparser.errors import ValidationError
from iocparser.interfaces.ports import (
    IOCExtractionEngine,
    TemporaryResourceCleaner,
    TextSourceReader,
    URLDownloader,
    WarningListService,
)


class ProcessFileFunc(Protocol):
    def __call__(
        self,
        file_path: Path,
        *,
        request: FileProcessingRequest | None = None,
    ) -> tuple[GroupedIocs, GroupedWarnings]: ...


class PluginClient(Protocol):
    def extract_result_from_text(
        self,
        text_content: str,
        *,
        check_warnings: bool,
        force_update: bool,
        defang: bool,
        only: str | None,
        exclude: str | None,
    ) -> ExtractionResult: ...

    def extract_result_from_file(
        self,
        file_path: str,
        *,
        file_type: str | None,
        check_warnings: bool,
        force_update: bool,
        defang: bool,
        only: str | None,
        exclude: str | None,
    ) -> ExtractionResult: ...

    def extract_result_from_url(
        self,
        url: str,
        *,
        check_warnings: bool,
        force_update: bool,
        defang: bool,
        only: str | None,
        exclude: str | None,
    ) -> ExtractionResult: ...


@dataclass(frozen=True)
class SingleInputContext:
    args: argparse.Namespace
    processing_options: ProcessingOptions
    options: ExtractionOptions
    configured_plugin_client: PluginClient | None


@dataclass(frozen=True)
class UrlProcessingRequest:
    context: SingleInputContext
    url: str
    downloader: URLDownloader
    reader: TextSourceReader
    extractor_engine: IOCExtractionEngine
    temporary_resource_cleaner: TemporaryResourceCleaner
    warning_service: WarningListService | None


def stdin_stream_error() -> ValidationError:
    return ValidationError("stdin is not a text stream")


def missing_url_error() -> ValidationError:
    return ValidationError("No URL provided")


def joined_type_filters(options: ProcessingOptions) -> tuple[str | None, str | None]:
    return shared_joined_type_filters(options.to_domain())


def build_single_input_context(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    downloader: URLDownloader,
    warning_service: WarningListService | None,
) -> SingleInputContext:
    processing_options = ProcessingOptions.from_args(args)
    return SingleInputContext(
        args=args,
        processing_options=processing_options,
        options=processing_options.to_domain(),
        configured_plugin_client=plugin_client(
            args,
            reader=reader,
            downloader=downloader,
            warning_service=warning_service,
        ),
    )


def plugin_client(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    downloader: URLDownloader,
    warning_service: WarningListService | None,
) -> PluginClient | None:
    client = shared_plugin_client(
        args,
        reader=reader,
        downloader=downloader,
        warning_service=warning_service,
    )
    return client if isinstance(client, IOCParserClient) else None


def process_stdin_input(
    *,
    stdin_stream: object,
    context: SingleInputContext,
    extractor_engine: IOCExtractionEngine,
    warning_service: WarningListService | None,
) -> tuple[GroupedIocs, GroupedWarnings, str]:
    payload = process_stdin_payload(
        stdin_stream=stdin_stream,
        context=context,
        extractor_engine=extractor_engine,
        warning_service=warning_service,
    )
    return payload.normal_iocs, payload.warning_iocs, payload.input_display


def process_stdin_payload(
    *,
    stdin_stream: object,
    context: SingleInputContext,
    extractor_engine: IOCExtractionEngine,
    warning_service: WarningListService | None,
) -> SingleInputPayload:
    if not isinstance(stdin_stream, TextIOBase):
        raise stdin_stream_error()
    text_content = stdin_stream.read()
    if context.configured_plugin_client is not None:
        only, exclude = joined_type_filters(context.processing_options)
        result = context.configured_plugin_client.extract_result_from_text(
            text_content,
            check_warnings=context.options.check_warnings,
            force_update=context.options.force_update,
            defang=context.options.defang,
            only=only,
            exclude=exclude,
        )
    else:
        result = app_extract_from_text(
            ExtractTextInput(text_content=text_content, options=context.options),
            extractor_engine=extractor_engine,
            warning_service=warning_service if context.options.check_warnings else None,
        )
    return SingleInputPayload(
        normal_iocs=result.grouped_iocs(),
        warning_iocs=result.grouped_warnings(),
        input_display="stdin",
    )


def process_file_input(
    *,
    file_arg: str,
    context: SingleInputContext,
    process_file_func: ProcessFileFunc,
) -> tuple[GroupedIocs, GroupedWarnings, str]:
    payload = process_file_payload(
        file_arg=file_arg,
        context=context,
        process_file_func=process_file_func,
    )
    return payload.normal_iocs, payload.warning_iocs, payload.input_display


def process_file_payload(
    *,
    file_arg: str,
    context: SingleInputContext,
    process_file_func: ProcessFileFunc,
) -> SingleInputPayload:
    if context.configured_plugin_client is not None and not get_bool_arg(context.args, "streaming"):
        only, exclude = joined_type_filters(context.processing_options)
        result = context.configured_plugin_client.extract_result_from_file(
            file_arg,
            file_type=context.options.file_type,
            check_warnings=context.options.check_warnings,
            force_update=context.options.force_update,
            defang=context.options.defang,
            only=only,
            exclude=exclude,
        )
        return SingleInputPayload(
            normal_iocs=result.grouped_iocs(),
            warning_iocs=result.grouped_warnings(),
            input_display=file_arg,
        )
    normal_iocs, warning_iocs = process_file_func(
        Path(file_arg),
        request=FileProcessingRequest(
            file_type=context.options.file_type,
            defang=context.options.defang,
            check_warnings=context.options.check_warnings,
            force_update=context.options.force_update,
            include_types=context.options.include_types,
            exclude_types=context.options.exclude_types,
            streaming=get_bool_arg(context.args, "streaming"),
            chunk_size=get_int_arg(context.args, "chunk_size", 1024 * 1024),
            overlap=get_int_arg(context.args, "overlap", 1024),
        ),
    )
    return SingleInputPayload(
        normal_iocs=normal_iocs,
        warning_iocs=warning_iocs,
        input_display=file_arg,
    )


def process_url_input(request: UrlProcessingRequest) -> tuple[GroupedIocs, GroupedWarnings, str]:
    payload = process_url_payload(request)
    return payload.normal_iocs, payload.warning_iocs, payload.input_display


def process_url_payload(request: UrlProcessingRequest) -> SingleInputPayload:
    if request.context.configured_plugin_client is not None:
        only, exclude = joined_type_filters(request.context.processing_options)
        result = request.context.configured_plugin_client.extract_result_from_url(
            request.url,
            check_warnings=request.context.options.check_warnings,
            force_update=request.context.options.force_update,
            defang=request.context.options.defang,
            only=only,
            exclude=exclude,
        )
    else:
        result = app_extract_from_url(
            ExtractURLInput(url=request.url, options=request.context.options),
            downloader=request.downloader,
            reader=request.reader,
            extractor_engine=request.extractor_engine,
            temporary_resource_cleaner=request.temporary_resource_cleaner,
            warning_service=request.warning_service if request.context.options.check_warnings else None,
        )
    return SingleInputPayload(
        normal_iocs=result.grouped_iocs(),
        warning_iocs=result.grouped_warnings(),
        input_display=request.url,
    )
