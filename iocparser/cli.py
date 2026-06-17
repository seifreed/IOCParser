from __future__ import annotations

import argparse
from pathlib import Path

import iocparser.cli_args as _cli_args
import iocparser.cli_dispatch as _cli_dispatch
import iocparser.cli_output as _cli_output
import iocparser.cli_processing as _cli_processing
import iocparser.cli_runtime as _cli_runtime
from iocparser.cli_processing_support import BatchResultsCollection, GroupedIocs, GroupedWarnings
from iocparser.cli_runtime import logger
from iocparser.domain.enums import IOCType, IOCTypeName
from iocparser.domain.models import ExtractionResult
from iocparser.infrastructure.warninglists import MISPWarningLists
from iocparser.interfaces.ports import WarningListService

create_argument_parser = _cli_args.create_argument_parser
FileProcessingRequest = _cli_processing.FileProcessingRequest
MultiFileProcessingRequest = _cli_processing.MultiFileProcessingRequest
BatchResults = BatchResultsCollection


def handle_misp_init() -> None:
    _cli_runtime.handle_misp_init_with(MISPWarningLists)


def _active_warning_service(args: argparse.Namespace) -> WarningListService:
    return _cli_runtime.warning_service_for_args(args)


def process_file_with_result(
    file_path: Path,
    *,
    request: FileProcessingRequest | None = None,
    file_type: str | None = None,
    defang: bool = True,
    check_warnings: bool = True,
    force_update: bool = False,
    include_types: tuple[IOCType | IOCTypeName, ...] = (),
    exclude_types: tuple[IOCType | IOCTypeName, ...] = (),
    streaming: bool = False,
    chunk_size: int = 1024 * 1024,
    overlap: int = 1024,
    warning_service: WarningListService | None = None,
) -> tuple[GroupedIocs, GroupedWarnings, ExtractionResult]:
    effective_request = request or FileProcessingRequest(
        file_type=file_type,
        defang=defang,
        check_warnings=check_warnings,
        force_update=force_update,
        include_types=include_types,
        exclude_types=exclude_types,
        streaming=streaming,
        chunk_size=chunk_size,
        overlap=overlap,
    )
    result = _cli_processing.process_file_result(
        file_path,
        reader=_cli_runtime.reader,
        warning_service=warning_service if effective_request.check_warnings else None,
        request=effective_request,
    )
    return result.grouped_iocs(), result.grouped_warnings(), result


def process_file(
    file_path: Path,
    *,
    request: FileProcessingRequest | None = None,
    file_type: str | None = None,
    defang: bool = True,
    check_warnings: bool = True,
    force_update: bool = False,
    include_types: tuple[IOCType | IOCTypeName, ...] = (),
    exclude_types: tuple[IOCType | IOCTypeName, ...] = (),
    streaming: bool = False,
    chunk_size: int = 1024 * 1024,
    overlap: int = 1024,
    warning_service: WarningListService | None = None,
) -> tuple[GroupedIocs, GroupedWarnings]:
    normal_iocs, warning_iocs, _result = process_file_with_result(
        file_path,
        request=request,
        file_type=file_type,
        defang=defang,
        check_warnings=check_warnings,
        force_update=force_update,
        include_types=include_types,
        exclude_types=exclude_types,
        streaming=streaming,
        chunk_size=chunk_size,
        overlap=overlap,
        warning_service=warning_service,
    )
    return normal_iocs, warning_iocs


def process_multiple_files(
    file_paths: list[Path],
    *,
    request: MultiFileProcessingRequest | None = None,
    file_type: str | None = None,
    defang: bool = True,
    check_warnings: bool = True,
    force_update: bool = False,
    include_types: tuple[IOCType | IOCTypeName, ...] = (),
    exclude_types: tuple[IOCType | IOCTypeName, ...] = (),
    streaming: bool = False,
    chunk_size: int = 1024 * 1024,
    overlap: int = 1024,
    max_workers: int = 32,
    warning_service: WarningListService | None = None,
) -> BatchResults:
    effective_request = request or MultiFileProcessingRequest(
        file_type=file_type,
        defang=defang,
        check_warnings=check_warnings,
        force_update=force_update,
        include_types=include_types,
        exclude_types=exclude_types,
        streaming=streaming,
        chunk_size=chunk_size,
        overlap=overlap,
        max_workers=max_workers,
    )
    return _cli_processing.process_multiple_files(
        file_paths,
        reader=_cli_runtime.reader,
        warning_service=warning_service if effective_request.check_warnings else None,
        request=effective_request,
    )


def process_multiple_files_input(
    args: argparse.Namespace,
) -> tuple[GroupedIocs, GroupedWarnings, str, BatchResults]:
    return _cli_processing.process_multiple_files_input(
        args,
        reader=_cli_runtime.reader,
        warning_service=_active_warning_service(args),
    )


def process_single_input(
    args: argparse.Namespace,
) -> tuple[GroupedIocs, GroupedWarnings, str, ExtractionResult | None]:
    active_warning_service = _active_warning_service(args)
    return _cli_processing.process_single_input(
        args,
        reader=_cli_runtime.reader,
        warning_service=active_warning_service,
        downloader=_cli_runtime.downloader_for_args(args),
        process_file_func=lambda file_path, *, request=None: process_file_with_result(
            file_path,
            request=request,
            warning_service=active_warning_service,
        ),
    )


def save_output(
    args: argparse.Namespace,
    normal_iocs: GroupedIocs,
    warning_iocs: GroupedWarnings,
    input_display: str,
    result: ExtractionResult | None = None,
) -> None:
    _cli_output.save_output(
        args,
        normal_iocs,
        warning_iocs,
        input_display,
        result=result,
        file_writer=_cli_runtime.file_writer,
    )


def run_cli(args: argparse.Namespace) -> None:
    _cli_dispatch.run_cli(
        args,
        handle_misp_init=handle_misp_init,
        process_multiple_files_input=process_multiple_files_input,
        process_single_input=process_single_input,
        save_output=save_output,
    )


def execute(argv: list[str] | None = None) -> None:
    _cli_dispatch.execute(
        argv,
        create_argument_parser=create_argument_parser,
        run_cli=run_cli,
    )


__all__ = [
    "BatchResults",
    "FileProcessingRequest",
    "GroupedIocs",
    "GroupedWarnings",
    "MISPWarningLists",
    "MultiFileProcessingRequest",
    "create_argument_parser",
    "execute",
    "handle_misp_init",
    "logger",
    "process_file",
    "process_multiple_files",
    "process_multiple_files_input",
    "process_single_input",
    "run_cli",
    "save_output",
]
