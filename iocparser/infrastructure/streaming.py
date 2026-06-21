#!/usr/bin/env python3

"""
Streaming processor for handling large files efficiently.

Author: Marc Rivero | @seifreed
"""

import mmap
from collections import defaultdict
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO, TextIO, cast

from iocparser.errors import IOCFileNotFoundError
from iocparser.infrastructure.file_parser import detect_bom_encoding
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

# Floor for the effective chunk overlap. A value straddling a chunk boundary is
# deferred to the next chunk and recovered only if the carried overlap is at least
# as long as the value; a shorter overlap silently drops it. The longest extractable
# IOC is a URL, whose path the extractor caps at 2048 chars, so this floor (path cap
# plus scheme/host/port/userinfo headroom) guarantees boundary recovery for every
# realistic IOC. The default 1 KB overlap was below this and dropped long boundary URLs.
_BOUNDARY_IOC_LENGTH_CAP = 4096


def _aligned_utf8_chunk_end(
    mmapped_file: mmap.mmap,
    *,
    offset: int,
    chunk_end: int,
    file_size: int,
) -> int:
    if chunk_end >= file_size:
        return chunk_end

    adjusted_end = chunk_end
    while adjusted_end > offset and mmapped_file[adjusted_end] & 0xC0 == 0x80:
        adjusted_end -= 1
    if adjusted_end != offset:
        return adjusted_end

    adjusted_end = chunk_end
    while adjusted_end < file_size and mmapped_file[adjusted_end] & 0xC0 == 0x80:
        adjusted_end += 1
    return adjusted_end


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
        # The chunk/dedup design assumes overlap < chunk_size; a larger overlap re-scans
        # whole chunk bodies and double-counts IOCs. Clamp to keep the invariant.
        # Also floor a non-zero overlap at the boundary-IOC cap so a long value (e.g. a
        # 1-2 KB URL) straddling a chunk boundary is re-presented in full and not dropped.
        # Only when the chunk is large enough to hold the cap with room to spare -- for a
        # small chunk a long IOC cannot fit anyway, and flooring would force a near-total
        # re-scan. overlap=0 keeps the explicit no-overlap opt-out.
        if overlap > 0 and self.chunk_size - 1 >= _BOUNDARY_IOC_LENGTH_CAP:
            overlap = max(overlap, _BOUNDARY_IOC_LENGTH_CAP)
        self.overlap = max(0, min(overlap, self.chunk_size - 1))
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
        for chunk, _prefix_length, _is_final in read_chunks_with_prefix(
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
    ) -> Iterator[tuple[str, int, bool]]:
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
        is_final: bool = False,
    ) -> bool:
        return should_keep_ioc(
            ioc_type=ioc_type,
            chunk=chunk,
            ioc=ioc,
            prefix_length=prefix_length,
            chunk_size=self.chunk_size,
            is_final=is_final,
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
        *,
        seen_iocs: dict[str, set[str]] | None = None,
    ) -> dict[str, list[str]]:
        """
        Remove duplicate IOCs that have been seen before.

        Args:
            new_iocs: Newly extracted IOCs

        Returns:
            Deduplicated IOCs
        """
        result: dict[str, list[str]] = deduplicate_iocs_with_state(
            new_iocs, seen_iocs if seen_iocs is not None else self.seen_iocs
        )
        return result

    def _filter_overlap_artifacts(
        self,
        chunk: str,
        chunk_iocs: dict[str, list[str]],
        prefix_length: int,
        is_final: bool = False,
    ) -> dict[str, list[str]]:
        """Remove IOCs that exist only in the overlap prefix of a chunk.

        The first chunk (prefix_length == 0) has no overlap prefix but can still
        emit a truncated match at its trailing boundary, so it is filtered too —
        should_keep_ioc defers that trailing-edge match to the next chunk, which
        re-presents the value in full via its overlap. Without an overlap there is
        no next chunk to recover a deferred value, so filtering is skipped.
        """
        if self.overlap <= 0:
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
                    is_final=is_final,
                )
            ]
            if kept:
                filtered[ioc_type] = kept
        return filtered

    def _extract_unique_from_chunk(
        self,
        chunk: str,
        prefix_length: int,
        is_final: bool = False,
        *,
        seen_iocs: dict[str, set[str]] | None = None,
    ) -> dict[str, list[str]]:
        """Extract, drop overlap artifacts, and deduplicate IOCs from one chunk."""
        chunk_iocs = self.extractor.extract_all(chunk)
        chunk_iocs = self._filter_overlap_artifacts(chunk, chunk_iocs, prefix_length, is_final)
        return self._deduplicate_iocs(chunk_iocs, seen_iocs=seen_iocs)

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
        seen_iocs: dict[str, set[str]] = defaultdict(set)

        all_iocs: dict[str, list[str]] = defaultdict(list)

        def _iter_chunks() -> Iterator[dict[str, list[str]]]:
            try:
                # Honour a UTF-16/UTF-8-BOM/UTF-32 BOM like the non-streaming reader;
                # opening with the right codec yields correctly decoded text chunks
                # instead of NUL-interleaved garbage that matches no IOC regex.
                with file_path.open("rb") as probe:
                    encoding = detect_bom_encoding(probe.read(4))
                with file_path.open(encoding=encoding, errors="ignore") as f:
                    for chunk, prefix_length, is_final in read_chunks_with_prefix(
                        file_obj=f,
                        chunk_size=self.chunk_size,
                        overlap=self.overlap,
                        progress_callback=self.progress_callback,
                        is_text=True,
                    ):
                        unique_iocs = self._extract_unique_from_chunk(
                            chunk, prefix_length, is_final, seen_iocs=seen_iocs
                        )
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
            finally:
                self.seen_iocs.clear()

        if yield_chunks:
            return _iter_chunks()

        list(_iter_chunks())
        return dict(all_iocs)

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

        # The mmap chunker decodes UTF-8 and aligns on UTF-8 boundaries; a UTF-16/
        # UTF-32 file must go through the encoding-aware reader instead, or it would
        # decode to garbage and yield no IOCs.
        with file_path.open("rb") as probe:
            if detect_bom_encoding(probe.read(4)) != "utf-8":
                result = self.extract_from_file(file_path, yield_chunks=False)
                return cast("dict[str, list[str]]", result)

        # Reset seen IOCs
        self.seen_iocs.clear()
        seen_iocs: dict[str, set[str]] = defaultdict(set)
        all_iocs: dict[str, list[str]] = defaultdict(list)

        if file_path.stat().st_size == 0:
            return {}

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

                    chunk_end = _aligned_utf8_chunk_end(
                        mmapped_file,
                        offset=offset,
                        chunk_end=chunk_end,
                        file_size=file_size,
                    )

                    # Read chunk
                    chunk = decode_chunk(mmapped_file[offset:chunk_end])

                    # Prepend overlap from previous chunk (mirrors extract_from_file)
                    previous_tail = b""
                    overlap_start = 0
                    if offset > 0:
                        overlap_start = max(0, offset - self.overlap - 1)
                        previous_tail = mmapped_file[overlap_start:offset]
                    prefix_text = decode_chunk(previous_tail) if previous_tail else ""
                    if prefix_text and overlap_start == 0:
                        # Preserve a known left boundary when the overlap starts at file origin.
                        prefix_text = f" {prefix_text}"
                    prefix_length = len(prefix_text)
                    chunk = prefix_text + chunk

                    # Extract and accumulate IOCs
                    unique_iocs = self._extract_unique_from_chunk(
                        chunk,
                        prefix_length,
                        chunk_end >= file_size,
                        seen_iocs=seen_iocs,
                    )
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
        finally:
            self.seen_iocs.clear()

        return dict(all_iocs)


__all__ = [
    "ParallelStreamingExtractor",
    "StreamingIOCExtractor",
    "extract_iocs_from_large_file",
    "stream_iocs_from_file",
]
