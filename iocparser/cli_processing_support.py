from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import cast

from iocparser.client import IOCParserClient
from iocparser.domain.models import ExtractionResult
from iocparser.domain.options import ExtractionOptions
from iocparser.domain.type_filters import joined_type_filters as _joined_type_filters
from iocparser.infrastructure.extraction import DefaultIOCExtractionEngine
from iocparser.infrastructure.http_download import RequestsURLDownloader
from iocparser.infrastructure.temp_files import TemporaryFileCleaner
from iocparser.interfaces.ports import (
    DownloadMetadataProvider,
    TextSourceReader,
    URLDownloader,
    WarningListService,
)

extractor_engine = DefaultIOCExtractionEngine()
temporary_resource_cleaner = TemporaryFileCleaner()

GroupedIocs = dict[str, list[str | dict[str, str]]]
GroupedWarnings = dict[str, list[dict[str, str]]]


@dataclass(frozen=True)
class BatchResultItem:
    item_key: str
    source_value: str
    normal_iocs: GroupedIocs
    warning_iocs: GroupedWarnings
    # Rich per-item result, retained so batch --with-context can merge per-IOC evidence.
    # None for items added from grouped dicts only (e.g. failed/empty entries).
    result: ExtractionResult | None = None


@dataclass
class BatchResultsCollection:
    entries: list[BatchResultItem] = field(default_factory=list)

    def add(
        self,
        *,
        item_key: str,
        source_value: str,
        normal_iocs: GroupedIocs,
        warning_iocs: GroupedWarnings,
        result: ExtractionResult | None = None,
    ) -> None:
        self.entries.append(
            BatchResultItem(
                item_key=item_key,
                source_value=source_value,
                normal_iocs=normal_iocs,
                warning_iocs=warning_iocs,
                result=result,
            )
        )

    def items(self) -> list[tuple[str, tuple[GroupedIocs, GroupedWarnings]]]:
        return [(entry.item_key, (entry.normal_iocs, entry.warning_iocs)) for entry in self.entries]

    def values(self) -> list[tuple[GroupedIocs, GroupedWarnings]]:
        return [(entry.normal_iocs, entry.warning_iocs) for entry in self.entries]

    def keys(self) -> list[str]:
        return [entry.item_key for entry in self.entries]

    def source_value_for(self, item_key: str) -> str:
        for entry in self.entries:
            if entry.item_key == item_key:
                return entry.source_value
        return item_key

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def __getitem__(self, key: str) -> tuple[GroupedIocs, GroupedWarnings]:
        for entry in self.entries:
            if entry.item_key == key:
                source_matches = [
                    candidate for candidate in self.entries if candidate.source_value == key
                ]
                if len(source_matches) == 1 and source_matches[0] is not entry:
                    raise KeyError(key)
                return entry.normal_iocs, entry.warning_iocs
        source_matches = [entry for entry in self.entries if entry.source_value == key]
        if len(source_matches) == 1:
            entry = source_matches[0]
            return entry.normal_iocs, entry.warning_iocs
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        item_key_matches = [entry for entry in self.entries if entry.item_key == key]
        source_matches = [entry for entry in self.entries if entry.source_value == key]
        if (
            len(item_key_matches) == 1
            and len(source_matches) == 1
            and item_key_matches[0] is not source_matches[0]
        ):
            return False
        if item_key_matches:
            return True
        return len(source_matches) == 1

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            return dict(self.items()) == other
        if isinstance(other, BatchResultsCollection):
            return self.entries == other.entries
        return False


BatchResults = BatchResultsCollection


@dataclass(frozen=True)
class SingleInputPayload:
    normal_iocs: GroupedIocs
    warning_iocs: GroupedWarnings
    input_display: str
    # The rich extraction result is retained so the CLI can render per-IOC evidence
    # under --with-context; grouped dicts alone drop it. None on paths that have no
    # single result to render from (e.g. multi-file batches).
    result: ExtractionResult | None = None


@dataclass(frozen=True)
class BatchInputPayload(SingleInputPayload):
    results: BatchResults = field(default_factory=BatchResultsCollection)


@dataclass(frozen=True)
class URLBatchInputPayload(BatchInputPayload):
    batch_report: Mapping[str, object] = field(default_factory=dict)


def batch_item_keys(source_values: Iterable[str]) -> list[tuple[str, str]]:
    source_list = list(source_values)
    reserved_keys = set(source_list)
    totals: dict[str, int] = defaultdict(int)
    for source_value in source_list:
        totals[source_value] += 1
    counts: dict[str, int] = defaultdict(int)
    assigned_keys: set[str] = set()
    keys: list[tuple[str, str]] = []
    for index, source_value in enumerate(source_list, start=1):
        counts[source_value] += 1
        if totals[source_value] == 1:
            item_key = source_value
        else:
            suffix = 0
            candidate = f"batch-item:{index}"
            while candidate in reserved_keys or candidate in assigned_keys:
                suffix += 1
                candidate = f"batch-item:{index}:{suffix}"
            item_key = candidate
        assigned_keys.add(item_key)
        keys.append((item_key, source_value))
    return keys


def joined_type_filters(options: ExtractionOptions) -> tuple[str | None, str | None]:
    return _joined_type_filters(options.include_types, options.exclude_types)


def plugin_client(
    args: argparse.Namespace | None,
    *,
    reader: TextSourceReader,
    downloader: URLDownloader | None,
    warning_service: WarningListService | None,
) -> IOCParserClient | None:
    values: Mapping[str, object] = {} if args is None else cast("Mapping[str, object]", vars(args))
    raw_extractors = values.get("extractor", [])
    raw_postprocessors = values.get("postprocessor", [])
    raw_enrichers = values.get("enricher", [])
    extractor_values = raw_extractors if isinstance(raw_extractors, list | tuple) else ()
    postprocessor_values = (
        raw_postprocessors if isinstance(raw_postprocessors, list | tuple) else ()
    )
    enricher_values = raw_enrichers if isinstance(raw_enrichers, list | tuple) else ()
    extractor_names = tuple(str(name) for name in extractor_values if isinstance(name, str))
    postprocessor_names = tuple(str(name) for name in postprocessor_values if isinstance(name, str))
    enricher_names = tuple(str(name) for name in enricher_values if isinstance(name, str))
    if not extractor_names and not postprocessor_names and not enricher_names:
        return None
    return IOCParserClient(
        reader=reader,
        downloader=downloader if downloader is not None else RequestsURLDownloader(),
        enrichers=enricher_names or (("misp",) if warning_service is not None else ()),
        extractors=extractor_names,
        postprocessors=postprocessor_names,
    )


def batch_downloader(downloader: URLDownloader) -> URLDownloader:
    with_policy = getattr(downloader, "with_policy", None)
    if callable(with_policy):
        cloned = with_policy()
        if cloned is not None:
            return cast("URLDownloader", cloned)
    return downloader


def download_metadata(downloader: URLDownloader) -> dict[str, object]:
    if hasattr(downloader, "download_metadata"):
        return cast("DownloadMetadataProvider", downloader).download_metadata()
    return {}
