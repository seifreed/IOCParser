from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from iocparser.domain.models import ExtractionOptions
from iocparser.infrastructure import file_readers as file_readers_module
from iocparser.infrastructure.file_readers import (
    MagicTextSourceReader,
    detect_file_type,
    read_text_content,
)


def test_detect_file_type_falls_back_to_extension_for_missing_file(tmp_path: Path) -> None:
    missing_html = tmp_path / "missing.html"

    assert detect_file_type(missing_html) == "html"


def test_read_text_content_reads_plain_text(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("IOC domain: example.com", encoding="utf-8")

    assert (
        read_text_content(str(sample), ExtractionOptions(file_type="text"))
        == "IOC domain: example.com"
    )


def test_load_magic_module_skips_windows() -> None:
    assert file_readers_module._load_magic_module("win32", lambda _name: object()) is None


def test_load_magic_module_handles_import_failure() -> None:
    def raise_import_error(_name: str) -> object:
        raise OSError("missing native library")

    assert file_readers_module._load_magic_module("linux", raise_import_error) is None


def test_load_magic_module_returns_imported_module() -> None:
    module = object()

    assert file_readers_module._load_magic_module("linux", lambda _name: module) is module


def test_magic_exception_type_falls_back_for_missing_or_invalid_type() -> None:
    class CustomMagicError(Exception):
        pass

    assert file_readers_module._magic_exception_type(None) is Exception
    assert (
        file_readers_module._magic_exception_type(SimpleNamespace(MagicException=CustomMagicError))
        is CustomMagicError
    )
    assert (
        file_readers_module._magic_exception_type(SimpleNamespace(MagicException=object()))
        is Exception
    )


def test_detect_file_type_falls_back_when_magic_module_unavailable(
    monkeypatch, tmp_path: Path
) -> None:
    sample = tmp_path / "sample.html"
    sample.write_text("<html></html>", encoding="utf-8")
    monkeypatch.setattr(file_readers_module, "_MAGIC_MODULE", None)

    assert MagicTextSourceReader().detect_file_type(sample) == "html"


def test_detect_file_type_uses_magic_instance_and_mime(monkeypatch, tmp_path: Path) -> None:
    class FakeMagic:
        def __init__(self, *, mime: bool) -> None:
            self.mime = mime

        def from_file(self, path: str) -> str:
            assert path == str(sample)
            return "application/pdf"

    sample = tmp_path / "sample.bin"
    sample.write_text("not a pdf, just exercising magic", encoding="utf-8")
    monkeypatch.setattr(file_readers_module, "_MAGIC_MODULE", SimpleNamespace(Magic=FakeMagic))
    reader = MagicTextSourceReader()
    reader._magic_local = SimpleNamespace()

    assert reader.detect_file_type(sample) == "pdf"
    assert reader._magic_local.instance.mime is True
    assert reader._magic() is reader._magic_local.instance


def test_detect_file_type_prefers_html_extension_for_text_plain_magic(
    monkeypatch, tmp_path: Path
) -> None:
    class FakeMagic:
        def __init__(self, *, mime: bool) -> None:
            assert mime is True

        def from_file(self, path: str) -> str:
            assert path == str(sample)
            return "text/plain"

    sample = tmp_path / "sample.html"
    sample.write_text("plain text saved as html", encoding="utf-8")
    monkeypatch.setattr(file_readers_module, "_MAGIC_MODULE", SimpleNamespace(Magic=FakeMagic))
    reader = MagicTextSourceReader()
    reader._magic_local = SimpleNamespace()

    assert reader.detect_file_type(sample) == "html"
