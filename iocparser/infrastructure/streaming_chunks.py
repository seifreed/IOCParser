from __future__ import annotations

import io
from collections.abc import Callable, Iterator
from typing import BinaryIO, TextIO


def decode_chunk(data: bytes | str) -> str:
    return data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data


def read_chunks_with_prefix(
    *,
    file_obj: BinaryIO | TextIO,
    chunk_size: int,
    overlap: int,
    progress_callback: Callable[[int], None] | None,
    is_text: bool = True,
) -> Iterator[tuple[str, int]]:
    chunk_size = max(1, chunk_size)
    if not is_text and isinstance(file_obj, io.TextIOBase) and hasattr(file_obj, "buffer"):
        file_obj = file_obj.buffer

    previous_chunk_tail = ""
    previous_tail_has_leading_context = True
    bytes_read = 0
    total_size = 0
    try:
        file_obj.seek(0, 2)
        total_size = file_obj.tell()
        file_obj.seek(0)
    except (OSError, io.UnsupportedOperation):
        pass

    while True:
        raw_chunk = file_obj.read(chunk_size)
        if not raw_chunk:
            break
        chunk = decode_chunk(raw_chunk)
        prefix = previous_chunk_tail
        if prefix and not previous_tail_has_leading_context:
            # Preserve a known left boundary when the overlap starts at the stream origin.
            prefix = f" {prefix}"
        prefix_length = len(prefix)
        if prefix:
            chunk = prefix + chunk

        bytes_read += (
            len(raw_chunk)
            if isinstance(raw_chunk, bytes)
            else len(raw_chunk.encode("utf-8", errors="ignore"))
        )
        if progress_callback and total_size:
            progress_callback(min(100, int((bytes_read / total_size) * 100)))

        yield chunk, prefix_length
        if overlap > 0:
            # Keep one extra character so boundary validation can reject truncated suffixes.
            tail_length = overlap + 1
            previous_tail_has_leading_context = len(chunk) > tail_length
            previous_chunk_tail = chunk[-tail_length:]
        else:
            previous_tail_has_leading_context = True
            previous_chunk_tail = ""
