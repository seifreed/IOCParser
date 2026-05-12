from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

from iocparser.application.contracts import ExtractFileInput
from iocparser.application.use_cases import extract_from_file as app_extract_from_file
from iocparser.application.use_cases import extract_from_files as app_extract_from_files
from iocparser.cli_args import (
    MAX_WORKERS,
    ProcessingOptions,
    get_bool_arg,
    get_int_arg,
    get_list_arg,
    get_optional_str_arg,
)
from iocparser.cli_processing_support import (
    BatchInputPayload,
    BatchResultsCollection,
    GroupedIocs,
    GroupedWarnings,
    batch_item_keys,
    extractor_engine,
)
from iocparser.cli_processing_support import joined_type_filters as shared_joined_type_filters
from iocparser.cli_processing_support import plugin_client as shared_plugin_client
from iocparser.client import IOCParserClient
from iocparser.domain.enums import IOCType, IOCTypeName
from iocparser.domain.models import IOC, ExtractionResult, WarningMatch
from iocparser.errors import (
    FileExistenceError,
    FileProcessingError,
    SourceNotFoundError,
    SourceProcessingError,
    ValidationError,
)
from iocparser.infrastructure.file_batch_executor import ThreadPoolFileBatchExecutor
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.interfaces.ports import TextSourceReader, WarningListService
from iocparser.shared_utils import deduplicate_iocs

BatchResults = BatchResultsCollection
GroupedRawIocs = dict[str, list[str | dict[str, str]]]


@dataclass(frozen=True)
class FileProcessingRequest:
    file_type: str | None = None
    defang: bool = True
    check_warnings: bool = True
    force_update: bool = False
    include_types: tuple[IOCType | IOCTypeName, ...] = ()
    exclude_types: tuple[IOCType | IOCTypeName, ...] = ()
    streaming: bool = False
    chunk_size: int = 1024 * 1024
    overlap: int = 1024

    def to_processing_options(self) -> ProcessingOptions:
        return ProcessingOptions(
            file_type=self.file_type,
            defang=self.defang,
            check_warnings=self.check_warnings,
            force_update=self.force_update,
            include_types=self.include_types,
            exclude_types=self.exclude_types,
        )


@dataclass(frozen=True)
class MultiFileProcessingRequest(FileProcessingRequest):
    max_workers: int = MAX_WORKERS


class ExtractFromFileFunc(Protocol):
    def __call__(
        self,
        input_data: ExtractFileInput,
        *,
        reader: TextSourceReader,
        extractor_engine: object,
        warning_service: WarningListService | None,
    ) -> ExtractionResult: ...


class ExtractFromFilesFunc(Protocol):
    def __call__(
        self,
        inputs: list[ExtractFileInput],
        *,
        reader: TextSourceReader,
        extractor_engine: object,
        batch_executor: object,
        warning_service: WarningListService | None,
    ) -> dict[str, ExtractionResult]: ...


class StreamingExtractorProto(Protocol):
    def extract_from_file(self, file_path: Path) -> GroupedRawIocs: ...


class ParallelStreamingExtractorProto(Protocol):
    def extract_from_files(self, file_paths: Sequence[str | Path]) -> dict[str, GroupedRawIocs]: ...


class StreamingExtractorCtor(Protocol):
    def __call__(self, *, chunk_size: int, overlap: int, defang: bool) -> StreamingExtractorProto: ...


class ParallelStreamingExtractorCtor(Protocol):
    def __call__(
        self,
        *,
        max_workers: int,
        chunk_size: int,
        overlap: int,
        defang: bool,
    ) -> ParallelStreamingExtractorProto: ...


class PluginClient(Protocol):
    def __init__(
        self,
        *,
        reader: TextSourceReader,
        downloader: RequestsURLDownloader,
        enrichers: tuple[str, ...],
        extractors: tuple[str, ...],
        postprocessors: tuple[str, ...],
    ) -> None: ...

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
def _joined_type_filters(options: ProcessingOptions) -> tuple[str | None, str | None]:
    return shared_joined_type_filters(options.to_domain())


def _plugin_client(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
) -> PluginClient | None:
    client = shared_plugin_client(
        args,
        reader=reader,
        downloader=RequestsURLDownloader(),
        warning_service=warning_service,
    )
    return client if isinstance(client, IOCParserClient) else None


def _extract_from_file() -> ExtractFromFileFunc:
    return cast("ExtractFromFileFunc", app_extract_from_file)


def _extract_from_files() -> ExtractFromFilesFunc:
    return cast("ExtractFromFilesFunc", app_extract_from_files)


def _streaming_extractor(*, chunk_size: int, overlap: int, defang: bool) -> StreamingExtractorProto:
    module = import_module("iocparser.infrastructure.streaming")
    extractor_type = cast("StreamingExtractorCtor", module.StreamingIOCExtractor)
    return extractor_type(chunk_size=chunk_size, overlap=overlap, defang=defang)


def _parallel_streaming_extractor(
    *,
    max_workers: int,
    chunk_size: int,
    overlap: int,
    defang: bool,
) -> ParallelStreamingExtractorProto:
    module = import_module("iocparser.infrastructure.streaming")
    extractor_type = cast("ParallelStreamingExtractorCtor", module.ParallelStreamingExtractor)
    return extractor_type(max_workers=max_workers, chunk_size=chunk_size, overlap=overlap, defang=defang)


def _thread_pool_batch_executor(*, max_workers: int) -> ThreadPoolFileBatchExecutor:
    return ThreadPoolFileBatchExecutor(max_workers=max_workers)


def merge_results(results: dict[str, ExtractionResult]) -> ExtractionResult:
    all_iocs = [ioc for result in results.values() for ioc in result.iocs]
    all_warnings = [warning for result in results.values() for warning in result.warnings]
    return ExtractionResult(iocs=tuple(all_iocs), warnings=tuple(all_warnings))


def merge_batch_results(results: BatchResultsCollection) -> ExtractionResult:
    all_iocs: list[IOC] = []
    all_warnings: list[WarningMatch] = []
    for entry in results.entries:
        result = ExtractionResult.from_grouped_payload(entry.normal_iocs, entry.warning_iocs)
        all_iocs.extend(result.iocs)
        all_warnings.extend(result.warnings)
    return ExtractionResult(iocs=tuple(all_iocs), warnings=tuple(all_warnings))


def _directory_files(directory: Path, pattern: str, recursive: bool) -> list[Path]:
    iterator = directory.rglob(pattern) if recursive else directory.glob(pattern)
    return sorted(path for path in iterator if path.is_file())


def _streaming_result(
    file_path: Path,
    *,
    options: ProcessingOptions,
    warning_service: WarningListService | None,
    chunk_size: int,
    overlap: int,
) -> ExtractionResult:
    extractor = _streaming_extractor(chunk_size=chunk_size, overlap=overlap, defang=options.defang)
    raw_iocs = extractor.extract_from_file(file_path)
    result = ExtractionResult.from_grouped_payload(raw_iocs, {}).filter_types(options.include_types, options.exclude_types)
    if options.check_warnings and warning_service is not None:
        return warning_service.separate(result.iocs, force_update=options.force_update)
    return result


def _directory_multiple_namespace(args: argparse.Namespace, files: Sequence[Path]) -> argparse.Namespace:
    values = {str(key): value for key, value in vars(args).items()} | {"multiple": [str(path) for path in files]}
    return argparse.Namespace(**cast("Mapping[str, object]", values))


def process_file(
    file_path: Path,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    request: FileProcessingRequest,
) -> tuple[GroupedIocs, GroupedWarnings]:
    options = request.to_processing_options()
    if request.streaming:
        result = _streaming_result(
            file_path,
            options=options,
            warning_service=warning_service if request.check_warnings else None,
            chunk_size=request.chunk_size,
            overlap=request.overlap,
        )
    else:
        try:
            result = _extract_from_file()(
                ExtractFileInput(file_path=str(file_path), options=options.to_domain()),
                reader=reader,
                extractor_engine=extractor_engine,
                warning_service=warning_service if request.check_warnings else None,
            )
        except SourceNotFoundError as exc:
            raise FileExistenceError(exc.source_path) from exc
        except SourceProcessingError as exc:
            raise FileProcessingError(exc.source_path, exc.reason) from exc
    return result.grouped_iocs(), result.grouped_warnings()


def process_multiple_files(
    file_paths: list[Path],
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    request: MultiFileProcessingRequest,
) -> BatchResults:
    options = request.to_processing_options()
    duplicate_paths = len({str(path) for path in file_paths}) != len(file_paths)
    if request.streaming:
        results = BatchResultsCollection()
        if duplicate_paths:
            for item_key, source_value in batch_item_keys(str(path) for path in file_paths):
                result = _streaming_result(
                    Path(source_value),
                    options=options,
                    warning_service=warning_service if request.check_warnings else None,
                    chunk_size=request.chunk_size,
                    overlap=request.overlap,
                )
                results.add(
                    item_key=item_key,
                    source_value=source_value,
                    normal_iocs=result.grouped_iocs(),
                    warning_iocs=result.grouped_warnings(),
                )
        else:
            extractor = _parallel_streaming_extractor(
                max_workers=request.max_workers,
                chunk_size=request.chunk_size,
                overlap=request.overlap,
                defang=request.defang,
            )
            raw_results = extractor.extract_from_files(file_paths)
            for path, raw_iocs in raw_results.items():
                result = ExtractionResult.from_grouped_payload(raw_iocs, {}).filter_types(
                    options.include_types,
                    options.exclude_types,
                )
                if request.check_warnings and warning_service is not None:
                    result = warning_service.separate(result.iocs, force_update=request.force_update)
                results.add(
                    item_key=path,
                    source_value=path,
                    normal_iocs=result.grouped_iocs(),
                    warning_iocs=result.grouped_warnings(),
                )
    else:
        results = BatchResultsCollection()
        if duplicate_paths:
            for item_key, source_value in batch_item_keys(str(path) for path in file_paths):
                normal_iocs, warning_iocs = process_file(
                    Path(source_value),
                    reader=reader,
                    warning_service=warning_service,
                    request=FileProcessingRequest(
                        file_type=request.file_type,
                        defang=request.defang,
                        check_warnings=request.check_warnings,
                        force_update=request.force_update,
                        include_types=request.include_types,
                        exclude_types=request.exclude_types,
                        streaming=False,
                        chunk_size=request.chunk_size,
                        overlap=request.overlap,
                    ),
                )
                results.add(
                    item_key=item_key,
                    source_value=source_value,
                    normal_iocs=normal_iocs,
                    warning_iocs=warning_iocs,
                )
        else:
            extracted_results = _extract_from_files()(
                [ExtractFileInput(file_path=str(file_path), options=options.to_domain()) for file_path in file_paths],
                reader=reader,
                extractor_engine=extractor_engine,
                batch_executor=_thread_pool_batch_executor(max_workers=request.max_workers),
                warning_service=warning_service if request.check_warnings else None,
            )
            for path, result in extracted_results.items():
                results.add(
                    item_key=path,
                    source_value=path,
                    normal_iocs=result.grouped_iocs(),
                    warning_iocs=result.grouped_warnings(),
                )
    return results


def process_multiple_files_input(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
) -> tuple[
    dict[str, list[str | dict[str, str]]],
    dict[str, list[dict[str, str]]],
    str,
    BatchResults,
]:
    payload = process_multiple_files_payload(
        args,
        reader=reader,
        warning_service=warning_service,
    )
    return payload.normal_iocs, payload.warning_iocs, payload.input_display, payload.results


def process_multiple_files_payload(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
) -> BatchInputPayload:
    files = [Path(file_name) for file_name in get_list_arg(args, "multiple")]
    for file_path in files:
        if not file_path.exists():
            raise FileExistenceError(str(file_path))
    options = ProcessingOptions.from_args(args)
    configured_plugin_client = _plugin_client(args, reader=reader, warning_service=warning_service)
    if configured_plugin_client is not None and not get_bool_arg(args, "streaming"):
        results = BatchResultsCollection()
        only, exclude = _joined_type_filters(options)
        for item_key, source_value in batch_item_keys(str(file_path) for file_path in files):
            result = configured_plugin_client.extract_result_from_file(
                source_value,
                file_type=options.file_type,
                check_warnings=options.check_warnings,
                force_update=options.force_update,
                defang=options.defang,
                only=only,
                exclude=exclude,
            )
            results.add(
                item_key=item_key,
                source_value=source_value,
                normal_iocs=result.grouped_iocs(),
                warning_iocs=result.grouped_warnings(),
            )
    else:
        results = process_multiple_files(
            files,
            reader=reader,
            warning_service=warning_service,
            request=MultiFileProcessingRequest(
                file_type=options.file_type,
                defang=options.defang,
                check_warnings=options.check_warnings,
                force_update=options.force_update,
                include_types=options.include_types,
                exclude_types=options.exclude_types,
                streaming=get_bool_arg(args, "streaming"),
                chunk_size=get_int_arg(args, "chunk_size", 1024 * 1024),
                overlap=get_int_arg(args, "overlap", 1024),
                max_workers=get_int_arg(args, "parallel", default=1),
            ),
        )
    merged = merge_batch_results(results)
    normal_iocs, warning_iocs = merged.grouped_iocs(), merged.grouped_warnings()
    return BatchInputPayload(
        normal_iocs=deduplicate_iocs(normal_iocs),
        warning_iocs=warning_iocs,
        input_display=f"{len(files)} files",
        results=results,
    )


def process_directory_input(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
) -> tuple[
    dict[str, list[str | dict[str, str]]],
    dict[str, list[dict[str, str]]],
    str,
    BatchResults,
]:
    payload = process_directory_payload(
        args,
        reader=reader,
        warning_service=warning_service,
    )
    return payload.normal_iocs, payload.warning_iocs, payload.input_display, payload.results


def process_directory_payload(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
) -> BatchInputPayload:
    directory = Path(get_optional_str_arg(args, "directory") or "")
    if not directory.is_dir():
        raise FileExistenceError(str(directory))
    files = _directory_files(directory, get_optional_str_arg(args, "glob") or "*", get_bool_arg(args, "recursive"))
    if not files:
        message = f"No files matched in directory: {directory}"
        raise ValidationError(message)
    multiple_args = _directory_multiple_namespace(args, files)
    return process_multiple_files_payload(multiple_args, reader=reader, warning_service=warning_service)
