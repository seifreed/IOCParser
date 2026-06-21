from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, TypeVar

from iocparser.domain.models import IOC, ExtractionOptions, ExtractionResult

TBatchRequest = TypeVar("TBatchRequest")


@dataclass(frozen=True)
class BatchItemOutcome:
    """Per-item result of a batch execution.

    ``error`` is None on success and carries the failure message when the item
    failed, so a file that errored (e.g. a corrupt PDF) is distinguishable from
    one that legitimately produced zero IOCs.
    """

    result: ExtractionResult
    error: str | None = None


class TextSourceReader(Protocol):
    """Port for loading text from files or other stored sources."""

    def read(self, source_path: str, options: ExtractionOptions) -> str:
        """Read text from a source path."""


class WarningListService(Protocol):
    """Port for warning-list enrichment."""

    def separate(
        self,
        iocs: tuple[IOC, ...],
        *,
        force_update: bool = False,
    ) -> ExtractionResult:
        """Split normal IOCs from warning list matches."""


class IOCExtractionEngine(Protocol):
    """Port for raw IOC extraction from plain text."""

    def extract_all(self, text_content: str, *, defang: bool = True) -> dict[str, list[str]]:
        """Extract all supported IOC families from raw text."""


class TemporaryResourceCleaner(Protocol):
    """Port for temporary-file cleanup after infrastructure downloads."""

    def cleanup(self, resource_path: str) -> None:
        """Best-effort cleanup for a temporary local path."""


class FileBatchExecutor(Protocol):
    """Port for executing multiple file requests without coupling application to concurrency details."""

    def execute(
        self,
        requests: Sequence[TBatchRequest],
        *,
        handler: Callable[[TBatchRequest], ExtractionResult],
        key_for: Callable[[TBatchRequest], str],
    ) -> dict[str, BatchItemOutcome]:
        """Execute a batch of file requests and map them to per-item outcomes."""


class OutputRenderer(Protocol):
    """Port for rendering an extraction result."""

    def render(self, result: ExtractionResult) -> str:
        """Render an extraction result into a string output."""


class URLDownloader(Protocol):
    """Port for downloading URL content into a temporary file."""

    def download(self, url: str) -> str:
        """Download a URL and return a local path."""


class PolicyConfiguredURLDownloader(Protocol):
    """Optional policy-expansion port used by batch URL execution."""

    def with_policy(self) -> URLDownloader:
        """Return a downloader copy bound to the current policy."""


class DownloadMetadataProvider(Protocol):
    """Optional port for exposing metadata of the most recent download."""

    def download_metadata(self) -> dict[str, object]:
        """Return normalized metadata captured during the last download."""


class FileWriter(Protocol):
    """Port for writing rendered output to storage."""

    def write(self, output_path: str, content: str) -> None:
        """Write output content to a path."""
