from __future__ import annotations

import codecs
import io
from collections.abc import Callable, Iterator
from typing import BinaryIO, TextIO


def decode_chunk(data: bytes | str) -> str:
    return data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data


def decoded_stream_chunk(
    data: bytes | str,
    decoder: codecs.IncrementalDecoder,
    *,
    final: bool,
) -> str:
    return decoder.decode(data, final=final) if isinstance(data, bytes) else data


def chunk_size_bytes(data: bytes | str) -> int:
    return len(data) if isinstance(data, bytes) else len(data.encode("utf-8", errors="ignore"))


def chunk_with_prefix(
    chunk: str,
    previous_chunk_tail: str,
    previous_tail_has_leading_context: bool,
) -> tuple[str, int]:
    prefix = previous_chunk_tail
    if prefix and not previous_tail_has_leading_context:
        # Preserve a known left boundary when the overlap starts at the stream origin.
        prefix = f" {prefix}"
    return (prefix + chunk, len(prefix)) if prefix else (chunk, 0)


def read_chunks_with_prefix(
    *,
    file_obj: BinaryIO | TextIO,
    chunk_size: int,
    overlap: int,
    progress_callback: Callable[[int], None] | None,
    is_text: bool = True,
) -> Iterator[tuple[str, int, bool]]:
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

    utf8_decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")

    # Read one chunk ahead so the final chunk can be flagged on any stream -- seekable
    # or not. A chunk whose body fills chunk_size normally defers an IOC ending at its
    # boundary to the next chunk; on the final chunk there is no next chunk, so that
    # deferral would drop the IOC. An empty look-ahead read is the only reliable EOF
    # signal (short reads do not imply EOF), and it works without a seekable total_size.
    raw_chunk = file_obj.read(chunk_size)
    while raw_chunk:
        # Defer a look-ahead read error until after the current chunk is yielded, so a
        # stream that fails partway still emits everything read before the failure (and
        # the unreadable tail makes the current chunk the final one).
        deferred_error: Exception | None = None
        try:
            next_raw_chunk = file_obj.read(chunk_size)
        except Exception as exc:
            next_raw_chunk = b"" if isinstance(raw_chunk, bytes) else ""
            deferred_error = exc
        bytes_read += chunk_size_bytes(raw_chunk)
        if progress_callback and total_size:
            progress_callback(min(100, int((bytes_read / total_size) * 100)))

        chunk = decoded_stream_chunk(raw_chunk, utf8_decoder, final=not next_raw_chunk)
        if not chunk:
            if deferred_error is not None:
                raise deferred_error
            raw_chunk = next_raw_chunk
            continue
        chunk, prefix_length = chunk_with_prefix(
            chunk,
            previous_chunk_tail,
            previous_tail_has_leading_context,
        )

        is_final = not next_raw_chunk
        yield chunk, prefix_length, is_final
        if deferred_error is not None:
            raise deferred_error
        raw_chunk = next_raw_chunk
        if overlap > 0:
            # Keep one extra character so boundary validation can reject truncated suffixes.
            tail_length = overlap + 1
            previous_tail_has_leading_context = len(chunk) > tail_length
            previous_chunk_tail = chunk[-tail_length:]
        else:
            previous_tail_has_leading_context = True
            previous_chunk_tail = ""
