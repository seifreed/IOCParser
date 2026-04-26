from __future__ import annotations

import argparse
import time
from typing import Protocol

from iocparser.application.contracts import ExtractURLInput
from iocparser.application.use_cases import extract_from_url as app_extract_from_url
from iocparser.cli_processing_support import (
    batch_downloader as shared_batch_downloader,
)
from iocparser.cli_processing_support import (
    download_metadata as shared_download_metadata,
)
from iocparser.cli_processing_support import joined_type_filters as shared_joined_type_filters
from iocparser.cli_processing_support import plugin_client as shared_plugin_client
from iocparser.domain.models import ExtractionOptions, ExtractionResult
from iocparser.infrastructure.extraction import DefaultIOCExtractionEngine
from iocparser.infrastructure.temp_files import TemporaryFileCleaner
from iocparser.interfaces.ports import TextSourceReader, URLDownloader, WarningListService


class PluginClient(Protocol):
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


_extractor_engine = DefaultIOCExtractionEngine()
_temporary_resource_cleaner = TemporaryFileCleaner()


def extractor_engine() -> DefaultIOCExtractionEngine:
    return _extractor_engine


def temporary_resource_cleaner() -> TemporaryFileCleaner:
    return _temporary_resource_cleaner


def joined_type_filters(options: ExtractionOptions) -> tuple[str | None, str | None]:
    return shared_joined_type_filters(options)


def plugin_client(
    args: argparse.Namespace,
    *,
    reader: TextSourceReader,
    downloader: URLDownloader,
    warning_service: WarningListService | None,
) -> PluginClient | None:
    return shared_plugin_client(
        args,
        reader=reader,
        downloader=downloader,
        warning_service=warning_service,
    )


def process_url(
    url: str,
    *,
    options: ExtractionOptions,
    reader: TextSourceReader,
    warning_service: WarningListService | None,
    downloader: URLDownloader,
    configured_plugin_client: PluginClient | None,
) -> tuple[str, ExtractionResult, dict[str, object], int]:
    batch_downloader = shared_batch_downloader(downloader)
    started_at = time.perf_counter()
    if configured_plugin_client is not None:
        only, exclude = joined_type_filters(options)
        result = configured_plugin_client.extract_result_from_url(
            url,
            check_warnings=options.check_warnings,
            force_update=options.force_update,
            defang=options.defang,
            only=only,
            exclude=exclude,
        )
    else:
        result = app_extract_from_url(
            ExtractURLInput(url=url, options=options),
            downloader=batch_downloader,
            reader=reader,
            extractor_engine=extractor_engine(),
            temporary_resource_cleaner=temporary_resource_cleaner(),
            warning_service=warning_service if options.check_warnings else None,
        )
    metadata = shared_download_metadata(batch_downloader)
    duration_ms = int((time.perf_counter() - started_at) * 1000)
    return url, result, metadata, duration_ms


__all__ = [
    "PluginClient",
    "extractor_engine",
    "joined_type_filters",
    "plugin_client",
    "process_url",
    "temporary_resource_cleaner",
]
