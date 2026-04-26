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
    if not is_text and isinstance(file_obj, io.TextIOBase) and hasattr(file_obj, "buffer"):
        file_obj = file_obj.buffer

    previous_chunk_tail = ""
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
        prefix_length = len(previous_chunk_tail)
        if previous_chunk_tail:
            chunk = previous_chunk_tail + chunk

        bytes_read += len(decode_chunk(raw_chunk).encode("utf-8", errors="ignore"))
        if progress_callback and total_size:
            progress_callback(min(100, int((bytes_read / total_size) * 100)))

        yield chunk, prefix_length
        previous_chunk_tail = chunk[-overlap:] if len(chunk) > overlap else chunk
