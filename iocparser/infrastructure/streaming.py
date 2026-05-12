#!/usr/bin/env python3

"""
Streaming processor for handling large files efficiently.

Author: Marc Rivero | @seifreed
"""

import mmap
from collections import defaultdict
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO, TextIO

from iocparser.errors import IOCFileNotFoundError
from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.streaming_chunks import decode_chunk, read_chunks_with_prefix
from iocparser.infrastructure.streaming_matching import should_keep_ioc
from iocparser.infrastructure.streaming_parallel import (
    ParallelStreamingExtractor,
    extract_iocs_from_large_file,
    stream_iocs_from_file,
)
from iocparser.infrastructure.utils import deduplicate_iocs_with_state

logger = get_logger(__name__)


class StreamingIOCExtractor:
    """
    Streaming IOC extractor for processing large files efficiently.

    This class processes files in chunks to minimize memory usage
    and allows for real-time extraction of IOCs from large files.
    """

    def __init__(
        self,
        chunk_size: int = 1024 * 1024,  # 1MB chunks by default
        overlap: int = 1024,  # 1KB overlap to catch IOCs on boundaries
        defang: bool = True,
        progress_callback: Callable[[int], None] | None = None,
    ):
        """
        Initialize the streaming extractor.

        Args:
            chunk_size: Size of each chunk to process in bytes
            overlap: Overlap between chunks to catch IOCs on boundaries
            defang: Whether to defang extracted IOCs
            progress_callback: Optional callback for progress updates
        """
        self.chunk_size = max(1, chunk_size)
        self.overlap = overlap
        from iocparser.infrastructure.extraction import IOCExtractor

        self.extractor = IOCExtractor(defang=defang)
        self.progress_callback = progress_callback

        # Track IOCs to avoid duplicates
        self.seen_iocs: dict[str, set[str]] = defaultdict(set)

    def _decode_chunk(self, data: bytes | str) -> str:
        return decode_chunk(data)

    def _read_chunks(
        self,
        file_obj: BinaryIO | TextIO,
        is_text: bool = True,
    ) -> Iterator[str]:
        for chunk, _prefix_length in read_chunks_with_prefix(
            file_obj=file_obj,
            chunk_size=self.chunk_size,
            overlap=self.overlap,
            progress_callback=self.progress_callback,
            is_text=is_text,
        ):
            yield chunk

    def _read_chunks_with_prefix(
        self,
        file_obj: BinaryIO | TextIO,
        is_text: bool = True,
    ) -> Iterator[tuple[str, int]]:
        yield from read_chunks_with_prefix(
            file_obj=file_obj,
            chunk_size=self.chunk_size,
            overlap=self.overlap,
            progress_callback=self.progress_callback,
            is_text=is_text,
        )

    def _is_valid_match_boundary(
        self,
        ioc_type: str,
        haystack: str,
        start: int,
        end: int,
    ) -> bool:
        from iocparser.infrastructure.streaming_matching import is_valid_match_boundary

        return is_valid_match_boundary(ioc_type, haystack, start, end)

    def _should_keep_ioc(
        self,
        ioc_type: str,
        chunk: str,
        ioc: str,
        prefix_length: int,
    ) -> bool:
        return should_keep_ioc(
            ioc_type=ioc_type,
            chunk=chunk,
            ioc=ioc,
            prefix_length=prefix_length,
            chunk_size=self.chunk_size,
        )

    def _accumulate_iocs(
        self,
        target: dict[str, list[str]],
        source: dict[str, list[str]],
    ) -> None:
        """
        Accumulate IOCs from source into target dictionary.

        Args:
            target: Target dictionary to accumulate into
            source: Source dictionary with IOCs to add
        """
        for ioc_type, ioc_list in source.items():
            target[ioc_type].extend(ioc_list)

    def _deduplicate_iocs(
        self,
        new_iocs: dict[str, list[str]],
    ) -> dict[str, list[str]]:
        """
        Remove duplicate IOCs that have been seen before.

        Args:
            new_iocs: Newly extracted IOCs

        Returns:
            Deduplicated IOCs
        """
        result: dict[str, list[str]] = deduplicate_iocs_with_state(new_iocs, self.seen_iocs)
        return result

    def _filter_overlap_artifacts(
        self,
        chunk: str,
        chunk_iocs: dict[str, list[str]],
        prefix_length: int,
    ) -> dict[str, list[str]]:
        """Remove IOCs that exist only in the overlap prefix of a chunk."""
        if prefix_length <= 0:
            return chunk_iocs

        filtered: dict[str, list[str]] = {}
        for ioc_type, values in chunk_iocs.items():
            kept = [
                value
                for value in values
                if should_keep_ioc(
                    ioc_type=ioc_type,
                    chunk=chunk,
                    ioc=value,
                    prefix_length=prefix_length,
                    chunk_size=self.chunk_size,
                )
            ]
            if kept:
                filtered[ioc_type] = kept
        return filtered

    def extract_from_file(
        self,
        file_path: str | Path,
        yield_chunks: bool = False,
    ) -> dict[str, list[str]] | Iterator[dict[str, list[str]]]:
        """
        Extract IOCs from a file using streaming.

        Args:
            file_path: Path to the file to process
            yield_chunks: If True, yield IOCs as they're found;
                         if False, return all at the end

        Returns:
            Either a dictionary of all IOCs or an iterator of IOC chunks
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise IOCFileNotFoundError(str(file_path))

        logger.info("Starting streaming extraction from %s", file_path)

        # Reset seen IOCs for new file
        self.seen_iocs.clear()

        all_iocs: dict[str, list[str]] = defaultdict(list)

        def _iter_chunks() -> Iterator[dict[str, list[str]]]:
            try:
                with file_path.open(encoding="utf-8", errors="ignore") as f:
                    for chunk, prefix_length in read_chunks_with_prefix(
                        file_obj=f,
                        chunk_size=self.chunk_size,
                        overlap=self.overlap,
                        progress_callback=self.progress_callback,
                        is_text=True,
                    ):
                        chunk_iocs = self.extractor.extract_all(chunk)
                        chunk_iocs = self._filter_overlap_artifacts(
                            chunk, chunk_iocs, prefix_length
                        )
                        unique_iocs = self._deduplicate_iocs(chunk_iocs)
                        if unique_iocs:
                            if yield_chunks:
                                yield unique_iocs
                            else:
                                self._accumulate_iocs(all_iocs, unique_iocs)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                logger.exception("Error processing file %s", file_path)
                raise

        if yield_chunks:
            return _iter_chunks()

        list(_iter_chunks())
        return dict(all_iocs)

    def extract_from_stream(
        self,
        stream: BinaryIO | TextIO,
        is_text: bool = True,
    ) -> Iterator[dict[str, list[str]]]:
        """
        Extract IOCs from a stream in real-time.

        Args:
            stream: Input stream to process
            is_text: Whether the stream contains text

        Yields:
            Dictionaries of extracted IOCs as they're found
        """
        logger.info("Starting streaming extraction from stream")

        # Reset seen IOCs for new stream
        self.seen_iocs.clear()

        for chunk, prefix_length in read_chunks_with_prefix(
            file_obj=stream,
            chunk_size=self.chunk_size,
            overlap=self.overlap,
            progress_callback=self.progress_callback,
            is_text=is_text,
        ):
            # Extract IOCs from chunk
            chunk_iocs = self.extractor.extract_all(chunk)
            chunk_iocs = self._filter_overlap_artifacts(chunk, chunk_iocs, prefix_length)

            # Deduplicate
            unique_iocs = self._deduplicate_iocs(chunk_iocs)

            if unique_iocs:
                yield unique_iocs

    def extract_from_mmap(
        self,
        file_path: str | Path,
    ) -> dict[str, list[str]]:
        """
        Extract IOCs using memory-mapped file for very large files.

        This is more efficient for very large files as it doesn't
        load the entire file into memory.

        Args:
            file_path: Path to the file to process

        Returns:
            Dictionary of extracted IOCs
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise IOCFileNotFoundError(str(file_path))

        logger.info("Starting memory-mapped extraction from %s", file_path)

        # Reset seen IOCs
        self.seen_iocs.clear()
        all_iocs: dict[str, list[str]] = defaultdict(list)

        try:
            with (
                file_path.open("rb") as f,
                mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file,
            ):
                file_size = len(mmapped_file)
                offset = 0

                while offset < file_size:
                    # Calculate chunk boundaries
                    chunk_end = min(offset + self.chunk_size, file_size)

                    # Align chunk_end to a valid UTF-8 boundary to avoid
                    # splitting multi-byte characters across chunks.
                    if chunk_end < file_size:
                        while chunk_end > offset and mmapped_file[chunk_end] & 0xC0 == 0x80:
                            chunk_end -= 1

                    # Read chunk
                    chunk = decode_chunk(mmapped_file[offset:chunk_end])

                    # Prepend overlap from previous chunk (mirrors extract_from_file)
                    previous_tail = b""
                    if offset > 0:
                        overlap_start = max(0, offset - self.overlap)
                        previous_tail = mmapped_file[overlap_start:offset]
                    prefix_text = decode_chunk(previous_tail) if previous_tail else ""
                    prefix_length = len(prefix_text)
                    chunk = prefix_text + chunk

                    # Extract and accumulate IOCs
                    chunk_iocs = self.extractor.extract_all(chunk)
                    chunk_iocs = self._filter_overlap_artifacts(chunk, chunk_iocs, prefix_length)
                    unique_iocs = self._deduplicate_iocs(chunk_iocs)
                    self._accumulate_iocs(all_iocs, unique_iocs)

                    # Progress callback
                    if self.progress_callback:
                        progress = int((chunk_end / file_size) * 100)
                        self.progress_callback(progress)

                    # Move to next chunk
                    offset = chunk_end

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            logger.exception("Error in memory-mapped extraction")
            raise

        return dict(all_iocs)


__all__ = [
    "ParallelStreamingExtractor",
    "StreamingIOCExtractor",
    "extract_iocs_from_large_file",
    "stream_iocs_from_file",
]
