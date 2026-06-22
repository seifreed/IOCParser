"""Coverage for file_parser stream-BOM wrapping and remote parse-path cleanup."""

from __future__ import annotations

import codecs
import io
from pathlib import Path

import pytest

from iocparser.infrastructure import file_parser
from iocparser.infrastructure.file_parser import (
    _local_parse_path,
    wrap_binary_stream_for_bom,
)


def test_wrap_binary_stream_preserves_non_zero_position() -> None:
    """A binary stream already positioned past the start is returned untouched."""
    stream = io.BytesIO(b"some-data")
    stream.read(3)  # advance position to 3
    wrapped, is_text = wrap_binary_stream_for_bom(stream, is_text=False)
    assert wrapped is stream
    assert is_text is False
    assert stream.tell() == 3


def test_wrap_binary_stream_falls_back_to_buffered_reader() -> None:
    """When tell() and peek() both fail, a BufferedReader still detects the BOM."""

    class _AwkwardStream(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._data = data
            self._pos = 0

        def readable(self) -> bool:
            return True

        def tell(self) -> int:
            raise OSError("no tell")

        def peek(self, size: int = 0) -> bytes:
            del size
            raise OSError("no peek")

        def readinto(self, buffer: object) -> int:
            view = memoryview(buffer)  # type: ignore[arg-type]
            chunk = self._data[self._pos : self._pos + len(view)]
            view[: len(chunk)] = chunk
            self._pos += len(chunk)
            return len(chunk)

    stream = _AwkwardStream(codecs.BOM_UTF16_LE + "hi".encode("utf-16-le"))
    wrapped, is_text = wrap_binary_stream_for_bom(stream, is_text=False)
    assert isinstance(wrapped, io.TextIOWrapper)
    assert is_text is True


def test_wrap_binary_stream_gives_up_when_every_probe_fails() -> None:
    """If tell(), peek(), and the BufferedReader probe all fail, return as-is."""

    class _HostileStream(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def tell(self) -> int:
            raise OSError("no tell")

        def peek(self, size: int = 0) -> bytes:
            del size
            raise OSError("no peek")

        def readinto(self, buffer: object) -> int:
            del buffer
            raise OSError("no read")

    stream = _HostileStream()
    wrapped, is_text = wrap_binary_stream_for_bom(stream, is_text=False)
    assert wrapped is stream
    assert is_text is False


def test_local_parse_path_cleans_up_temp_on_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    temp = tmp_path / "downloaded.html"
    temp.write_text("<html>evil.example</html>", encoding="utf-8")
    monkeypatch.setattr(file_parser, "_download_remote_source", lambda _url: temp)

    with pytest.raises(RuntimeError, match="boom"), _local_parse_path("https://host/x.html"):
        raise RuntimeError("boom")
    # The temp file is removed even though the body raised.
    assert not temp.exists()


def test_local_parse_path_logs_cleanup_failure_after_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    temp = tmp_path / "downloaded.html"
    temp.write_text("<html>evil.example</html>", encoding="utf-8")
    monkeypatch.setattr(file_parser, "_download_remote_source", lambda _url: temp)

    def _failing_unlink(self: Path, *args: object, **kwargs: object) -> None:
        del args, kwargs
        if self == temp:
            raise OSError("unlink failed")

    monkeypatch.setattr(Path, "unlink", _failing_unlink)

    # The original error must propagate; the cleanup failure is only logged.
    with pytest.raises(RuntimeError, match="boom"), _local_parse_path("https://host/x.html"):
        raise RuntimeError("boom")
