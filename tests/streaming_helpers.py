from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from typing import BinaryIO, TextIO

from iocparser.infrastructure.file_parser import wrap_binary_stream_for_bom
from iocparser.infrastructure.streaming import StreamingIOCExtractor
from iocparser.infrastructure.streaming_chunks import read_chunks_with_prefix


def extract_from_stream(
    extractor: StreamingIOCExtractor,
    stream: BinaryIO | TextIO,
    is_text: bool = True,
) -> Iterator[dict[str, list[str]]]:
    """Extract IOCs from an open stream in real-time, yielding new IOCs per chunk.

    Formerly a production method on StreamingIOCExtractor; relocated here because the
    CLI streams files via extract_from_file/extract_from_mmap and nothing consumed the
    stream variant outside tests. The body is unchanged apart from the dropped start
    log line.
    """
    stream_obj, is_text = wrap_binary_stream_for_bom(stream, is_text=is_text)
    extractor.seen_iocs.clear()
    seen_iocs: dict[str, set[str]] = defaultdict(set)
    try:
        for chunk, prefix_length, is_final in read_chunks_with_prefix(
            file_obj=stream_obj,
            chunk_size=extractor.chunk_size,
            overlap=extractor.overlap,
            progress_callback=extractor.progress_callback,
            is_text=is_text,
        ):
            unique_iocs = extractor._extract_unique_from_chunk(
                chunk, prefix_length, is_final, seen_iocs=seen_iocs
            )
            if unique_iocs:
                yield unique_iocs
    finally:
        extractor.seen_iocs.clear()
