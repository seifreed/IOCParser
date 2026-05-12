from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import cast

from iocparser.infrastructure.logger import get_logger

logger = get_logger(__name__)


class ParallelStreamingExtractor:
    def __init__(
        self,
        max_workers: int = 4,
        chunk_size: int = 1024 * 1024,
        overlap: int = 1024,
        defang: bool = True,
    ):
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.defang = defang

    def extract_from_files(
        self,
        file_paths: list[str | Path],
        progress_callback: Callable[[int], None] | None = None,
    ) -> dict[str, dict[str, list[str]]]:
        from iocparser.infrastructure.streaming import StreamingIOCExtractor

        results: dict[str, dict[str, list[str]]] = {}
        total_files = len(file_paths)
        completed_files = 0

        def process_file(file_path: str | Path) -> tuple[str, dict[str, list[str]]]:
            extractor = StreamingIOCExtractor(
                chunk_size=self.chunk_size,
                overlap=self.overlap,
                defang=self.defang,
            )
            result = cast("dict[str, list[str]]", extractor.extract_from_file(file_path))
            return str(file_path), result

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(process_file, file_path): file_path for file_path in file_paths
            }
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    path_str, iocs_result = future.result()
                    results[path_str] = iocs_result
                    completed_files += 1
                    if progress_callback:
                        progress_callback(int((completed_files / total_files) * 100))
                    logger.info("Completed extraction from %s", path_str)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    logger.exception("Error processing %s", file_path)
                    results[str(file_path)] = {"_errors": [str(file_path)]}

        return results


def extract_iocs_from_large_file(
    file_path: str | Path,
    chunk_size: int = 1024 * 1024,
    defang: bool = True,
    use_mmap: bool = False,
    progress_callback: Callable[[int], None] | None = None,
) -> dict[str, list[str]]:
    from iocparser.infrastructure.streaming import StreamingIOCExtractor

    extractor = StreamingIOCExtractor(
        chunk_size=chunk_size,
        defang=defang,
        progress_callback=progress_callback,
    )
    if use_mmap:
        return extractor.extract_from_mmap(file_path)
    result = extractor.extract_from_file(file_path, yield_chunks=False)
    return cast("dict[str, list[str]]", result)


def stream_iocs_from_file(
    file_path: str | Path,
    chunk_size: int = 1024 * 1024,
    defang: bool = True,
) -> Iterator[dict[str, list[str]]]:
    from iocparser.infrastructure.streaming import StreamingIOCExtractor

    extractor = StreamingIOCExtractor(
        chunk_size=chunk_size,
        defang=defang,
    )
    result = extractor.extract_from_file(file_path, yield_chunks=True)
    yield from cast("Iterator[dict[str, list[str]]]", result)


__all__ = [
    "ParallelStreamingExtractor",
    "extract_iocs_from_large_file",
    "stream_iocs_from_file",
]
