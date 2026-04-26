from __future__ import annotations

from iocparser.infrastructure.extractor_artifacts import ArtifactExtractionMixin
from iocparser.infrastructure.extractor_base import ExtractionAggregateMixin, ExtractorBase
from iocparser.infrastructure.extractor_network import NetworkExtractionMixin
from iocparser.infrastructure.file_batch_executor import ThreadPoolFileBatchExecutor
from iocparser.infrastructure.file_parser import HTMLParser, PDFParser, get_parser
from iocparser.infrastructure.file_readers import MagicTextSourceReader, detect_file_type
from iocparser.infrastructure.http_download import RequestsURLDownloader, download_url_to_temp
from iocparser.infrastructure.streaming import (
    ParallelStreamingExtractor,
    StreamingIOCExtractor,
    extract_iocs_from_large_file,
    stream_iocs_from_file,
)
from iocparser.infrastructure.temp_files import TemporaryFileCleaner
from iocparser.interfaces.ports import IOCExtractionEngine


class IOCExtractor(
    NetworkExtractionMixin,
    ArtifactExtractionMixin,
    ExtractionAggregateMixin,
):
    """Enhanced class for extracting different types of IOCs from text."""


class DefaultIOCExtractionEngine(IOCExtractionEngine):
    """Infrastructure adapter around the canonical IOC extractor implementation."""

    def extract_all(self, text_content: str, *, defang: bool = True) -> dict[str, list[str]]:
        return IOCExtractor(defang=defang).extract_all(text_content)

__all__ = [
    "ArtifactExtractionMixin",
    "DefaultIOCExtractionEngine",
    "ExtractionAggregateMixin",
    "ExtractorBase",
    "HTMLParser",
    "IOCExtractor",
    "MagicTextSourceReader",
    "NetworkExtractionMixin",
    "PDFParser",
    "ParallelStreamingExtractor",
    "RequestsURLDownloader",
    "StreamingIOCExtractor",
    "TemporaryFileCleaner",
    "ThreadPoolFileBatchExecutor",
    "detect_file_type",
    "download_url_to_temp",
    "extract_iocs_from_large_file",
    "get_parser",
    "stream_iocs_from_file",
]
