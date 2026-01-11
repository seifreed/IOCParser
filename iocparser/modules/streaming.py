#!/usr/bin/env python3

"""
Streaming processor for handling large files efficiently.

Author: Marc Rivero | @seifreed
"""

import io
import mmap
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import (
    BinaryIO,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    TextIO,
    Tuple,
    Union,
    cast,
)

from iocparser.modules.exceptions import IOCFileNotFoundError
from iocparser.modules.extractor import IOCExtractor
from iocparser.modules.logger import get_logger
from iocparser.modules.utils import deduplicate_iocs_with_state

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
        progress_callback: Optional[Callable[[int], None]] = None,
    ):
        """
        Initialize the streaming extractor.

        Args:
            chunk_size: Size of each chunk to process in bytes
            overlap: Overlap between chunks to catch IOCs on boundaries
            defang: Whether to defang extracted IOCs
            progress_callback: Optional callback for progress updates
        """
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.extractor = IOCExtractor(defang=defang)
        self.progress_callback = progress_callback

        # Track IOCs to avoid duplicates
        self.seen_iocs: Dict[str, Set[str]] = defaultdict(set)

    def _decode_chunk(self, data: Union[bytes, str]) -> str:
        """
        Decode bytes to string if needed.

        Args:
            data: Raw data that may be bytes or string

        Returns:
            Decoded string
        """
        if isinstance(data, bytes):
            return data.decode('utf-8', errors='ignore')
        return data

    def _accumulate_iocs(
        self,
        target: Dict[str, List[str]],
        source: Dict[str, List[str]],
    ) -> None:
        """
        Accumulate IOCs from source into target dictionary.

        Args:
            target: Target dictionary to accumulate into
            source: Source dictionary with IOCs to add
        """
        for ioc_type, ioc_list in source.items():
            target[ioc_type].extend(ioc_list)

    def _read_chunks(
        self,
        file_obj: Union[BinaryIO, TextIO],
        is_text: bool = True,
    ) -> Iterator[str]:
        """
        Read file in overlapping chunks.

        Args:
            file_obj: File object to read from
            is_text: Whether the file is text or binary

        Yields:
            Text chunks from the file
        """
        previous_chunk_tail = ""
        bytes_read = 0
        total_size = 0

        # Get total file size if possible
        try:
            file_obj.seek(0, 2)  # Seek to end
            total_size = file_obj.tell()
            file_obj.seek(0)  # Seek back to start
        except (OSError, io.UnsupportedOperation):
            pass

        while True:
            raw_chunk = file_obj.read(self.chunk_size)
            if not raw_chunk:
                break
            chunk = self._decode_chunk(raw_chunk)

            # Combine with overlap from previous chunk
            if previous_chunk_tail:
                chunk = previous_chunk_tail + chunk

            bytes_read += len(chunk.encode('utf-8', errors='ignore'))

            # Report progress if callback provided
            if self.progress_callback and total_size:
                progress = min(100, int((bytes_read / total_size) * 100))
                self.progress_callback(progress)

            yield chunk

            # Save tail for overlap with next chunk
            previous_chunk_tail = chunk[-self.overlap:] if len(chunk) > self.overlap else chunk

    def _deduplicate_iocs(
        self,
        new_iocs: Dict[str, List[str]],
    ) -> Dict[str, List[str]]:
        """
        Remove duplicate IOCs that have been seen before.

        Args:
            new_iocs: Newly extracted IOCs

        Returns:
            Deduplicated IOCs
        """
        result: Dict[str, List[str]] = deduplicate_iocs_with_state(new_iocs, self.seen_iocs)
        return result

    def extract_from_file(
        self,
        file_path: Union[str, Path],
        yield_chunks: bool = False,
    ) -> Union[Dict[str, List[str]], Iterator[Dict[str, List[str]]]]:
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

        logger.info(f"Starting streaming extraction from {file_path}")

        # Reset seen IOCs for new file
        self.seen_iocs.clear()

        all_iocs: Dict[str, List[str]] = defaultdict(list)

        try:
            with file_path.open(encoding='utf-8', errors='ignore') as f:
                for chunk in self._read_chunks(f, is_text=True):
                    # Extract IOCs from chunk
                    chunk_iocs = self.extractor.extract_all(chunk)

                    # Deduplicate
                    unique_iocs = self._deduplicate_iocs(chunk_iocs)

                    if unique_iocs:
                        if yield_chunks:
                            yield unique_iocs
                        else:
                            self._accumulate_iocs(all_iocs, unique_iocs)

        except Exception:
            logger.exception(f"Error processing file {file_path}")
            raise

        if not yield_chunks:
            return dict(all_iocs)

        # Generator exhausted - return empty dict to satisfy type checker
        return {}

    def extract_from_stream(
        self,
        stream: Union[BinaryIO, TextIO],
        is_text: bool = True,
    ) -> Iterator[Dict[str, List[str]]]:
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

        for chunk in self._read_chunks(stream, is_text=is_text):
            # Extract IOCs from chunk
            chunk_iocs = self.extractor.extract_all(chunk)

            # Deduplicate
            unique_iocs = self._deduplicate_iocs(chunk_iocs)

            if unique_iocs:
                yield unique_iocs

    def extract_from_mmap(
        self,
        file_path: Union[str, Path],
    ) -> Dict[str, List[str]]:
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

        logger.info(f"Starting memory-mapped extraction from {file_path}")

        # Reset seen IOCs
        self.seen_iocs.clear()
        all_iocs: Dict[str, List[str]] = defaultdict(list)

        try:
            with file_path.open('rb') as f, \
                 mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    file_size = len(mmapped_file)
                    offset = 0

                    while offset < file_size:
                        # Calculate chunk boundaries
                        chunk_end = min(offset + self.chunk_size, file_size)

                        # Read chunk
                        chunk = self._decode_chunk(mmapped_file[offset:chunk_end])

                        # Add overlap from next chunk if not at end
                        if chunk_end < file_size:
                            overlap_end = min(chunk_end + self.overlap, file_size)
                            chunk += self._decode_chunk(mmapped_file[chunk_end:overlap_end])

                        # Extract and accumulate IOCs
                        chunk_iocs = self.extractor.extract_all(chunk)
                        unique_iocs = self._deduplicate_iocs(chunk_iocs)
                        self._accumulate_iocs(all_iocs, unique_iocs)

                        # Progress callback
                        if self.progress_callback:
                            progress = int((chunk_end / file_size) * 100)
                            self.progress_callback(progress)

                        # Move to next chunk
                        offset = chunk_end

        except Exception:
            logger.exception("Error in memory-mapped extraction")
            raise

        return dict(all_iocs)


class ParallelStreamingExtractor:
    """
    Parallel streaming extractor for processing multiple large files concurrently.
    """

    def __init__(
        self,
        max_workers: int = 4,
        chunk_size: int = 1024 * 1024,
        defang: bool = True,
    ):
        """
        Initialize parallel streaming extractor.

        Args:
            max_workers: Maximum number of parallel workers
            chunk_size: Size of chunks for streaming
            defang: Whether to defang extracted IOCs
        """
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.defang = defang

    def extract_from_files(
        self,
        file_paths: List[Union[str, Path]],
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Extract IOCs from multiple files in parallel using streaming.

        Args:
            file_paths: List of file paths to process
            progress_callback: Optional callback for overall progress

        Returns:
            Dictionary mapping file paths to their extracted IOCs
        """
        results: Dict[str, Dict[str, List[str]]] = {}
        total_files = len(file_paths)
        completed_files = 0

        def process_file(
            file_path: Union[str, Path],
        ) -> Tuple[str, Union[Dict[str, List[str]], Iterator[Dict[str, List[str]]]]]:
            """Process a single file."""
            extractor = StreamingIOCExtractor(
                chunk_size=self.chunk_size,
                defang=self.defang,
            )
            return str(file_path), extractor.extract_from_file(file_path)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(process_file, file_path): file_path
                for file_path in file_paths
            }

            # Process completed tasks
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]

                try:
                    path_str, iocs_result = future.result()
                    if isinstance(iocs_result, dict):
                        results[path_str] = iocs_result
                    else:
                        results[path_str] = {}
                    completed_files += 1

                    # Report progress
                    if progress_callback:
                        progress = int((completed_files / total_files) * 100)
                        progress_callback(progress)

                    logger.info(f"Completed extraction from {path_str}")

                except Exception:
                    logger.exception(f"Error processing {file_path}")
                    results[str(file_path)] = {}

        return results


# Example usage and utility functions
def extract_iocs_from_large_file(
    file_path: Union[str, Path],
    chunk_size: int = 1024 * 1024,
    defang: bool = True,
    use_mmap: bool = False,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> Dict[str, List[str]]:
    """
    Convenience function to extract IOCs from a large file.

    Args:
        file_path: Path to the file
        chunk_size: Size of chunks for streaming
        defang: Whether to defang IOCs
        use_mmap: Use memory-mapped file for very large files
        progress_callback: Optional progress callback

    Returns:
        Dictionary of extracted IOCs
    """
    extractor = StreamingIOCExtractor(
        chunk_size=chunk_size,
        defang=defang,
        progress_callback=progress_callback,
    )

    if use_mmap:
        return extractor.extract_from_mmap(file_path)
    result = extractor.extract_from_file(file_path, yield_chunks=False)
    return cast("Dict[str, List[str]]", result)


def stream_iocs_from_file(
    file_path: Union[str, Path],
    chunk_size: int = 1024 * 1024,
    defang: bool = True,
) -> Iterator[Dict[str, List[str]]]:
    """
    Stream IOCs from a file as they're found.

    Args:
        file_path: Path to the file
        chunk_size: Size of chunks for streaming
        defang: Whether to defang IOCs

    Yields:
        Dictionaries of IOCs as they're extracted
    """
    extractor = StreamingIOCExtractor(
        chunk_size=chunk_size,
        defang=defang,
    )

    result = extractor.extract_from_file(file_path, yield_chunks=True)
    yield from cast("Iterator[Dict[str, List[str]]]", result)
