from __future__ import annotations

import importlib
import sys
import threading as _threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from iocparser.domain.models import ExtractionOptions
from iocparser.errors import FileSizeError, SourceNotFoundError
from iocparser.infrastructure.file_parser import HTMLParser, PDFParser
from iocparser.infrastructure.logger import get_logger
from iocparser.interfaces.ports import TextSourceReader

MAX_FILE_SIZE = 100 * 1024 * 1024
logger = get_logger(__name__)


def _load_magic_module(
    platform: str = sys.platform,
    import_module: Callable[[str], Any] = importlib.import_module,
) -> Any | None:
    if platform == "win32":
        return None
    try:
        return import_module("magic")
    except Exception:
        return None


def _magic_exception_type(magic_module: Any | None) -> type[Exception]:
    if magic_module is None:
        return Exception
    exception_type = getattr(magic_module, "MagicException", Exception)
    if isinstance(exception_type, type) and issubclass(exception_type, Exception):
        return exception_type
    return Exception


_MAGIC_MODULE = _load_magic_module()
MagicExceptionType = _magic_exception_type(_MAGIC_MODULE)

_DEFAULT_READER_HOLDER: list[MagicTextSourceReader] = []
_DEFAULT_READER_LOCK = _threading.Lock()


def _default_reader() -> MagicTextSourceReader:
    if not _DEFAULT_READER_HOLDER:
        with _DEFAULT_READER_LOCK:
            if not _DEFAULT_READER_HOLDER:
                _DEFAULT_READER_HOLDER.append(MagicTextSourceReader())
    return _DEFAULT_READER_HOLDER[0]


class MagicTextSourceReader(TextSourceReader):
    """Read text from files using magic + parser adapters."""

    def validate_file_size(self, file_path: Path, max_size: int = MAX_FILE_SIZE) -> None:
        """Validate that file size is within acceptable limits."""
        file_size = file_path.stat().st_size
        if file_size > max_size:
            raise FileSizeError(file_size / 1024 / 1024, max_size / 1024 / 1024)

    def detect_file_type_by_mime(self, file_type: str) -> str | None:
        """Detect file type from MIME type."""
        file_type_lower = file_type.lower()
        if "pdf" in file_type_lower:
            return "pdf"
        if any(value in file_type_lower for value in ["html", "xml"]):
            return "html"
        if "text" in file_type_lower:
            return "text"
        return None

    def detect_file_type_by_extension(self, file_path: Path) -> str:
        """Detect file type from extension."""
        extension_map = {
            ".pdf": "pdf",
            ".html": "html",
            ".htm": "html",
            ".xml": "html",
            ".txt": "text",
            ".log": "text",
            ".md": "text",
            ".csv": "text",
            ".json": "text",
        }
        return extension_map.get(file_path.suffix.lower(), "text")

    # Thread-local storage for magic instances - libmagic is not thread-safe.
    _magic_local = _threading.local()

    def _magic(self) -> Any:
        magic_module = _MAGIC_MODULE
        if magic_module is None:
            raise OSError
        instance = getattr(self._magic_local, "instance", None)
        if instance is None:
            instance = magic_module.Magic(mime=True)
            self._magic_local.instance = instance
        return instance

    def detect_file_type(self, file_path: Path) -> str:
        """Detect file type using magic with extension fallback."""
        try:
            mime = self._magic()
            file_type = str(mime.from_file(str(file_path)))
            detected = self.detect_file_type_by_mime(file_type)
            if detected:
                return detected

            if "text/plain" in file_type.lower() and file_path.suffix.lower() in {
                ".html",
                ".htm",
                ".xml",
            }:
                return "html"
        except (OSError, ValueError, MagicExceptionType) as exc:
            logger.warning("Error detecting file type: %s, falling back to extension", exc)
        return self.detect_file_type_by_extension(file_path)

    def read(self, source_path: str, options: ExtractionOptions) -> str:
        """Read text from a local file source."""
        path = Path(source_path)
        if not path.is_file():
            raise SourceNotFoundError(source_path)
        self.validate_file_size(path)
        file_type = options.file_type or self.detect_file_type(path)
        logger.info("Processing %s as %s", path, file_type.upper())
        if file_type == "pdf":
            return PDFParser(str(path)).extract_text()
        if file_type == "html":
            return HTMLParser(str(path)).extract_text()
        with path.open(encoding="utf-8", errors="ignore") as handle:
            return handle.read()


def validate_file_size(file_path: Path, max_size: int = MAX_FILE_SIZE) -> None:
    """Module-level convenience wrapper for file size validation."""
    _default_reader().validate_file_size(file_path, max_size)


def detect_file_type_by_mime(file_type: str) -> str | None:
    """Module-level convenience wrapper for MIME detection."""
    return _default_reader().detect_file_type_by_mime(file_type)


def detect_file_type_by_extension(file_path: Path) -> str:
    """Module-level convenience wrapper for extension detection."""
    return _default_reader().detect_file_type_by_extension(file_path)


def detect_file_type(file_path: Path) -> str:
    """Module-level convenience wrapper for file type detection."""
    return _default_reader().detect_file_type(file_path)


def read_text_content(file_path: str, options: ExtractionOptions) -> str:
    """Module-level convenience wrapper for reading a text source."""
    return _default_reader().read(file_path, options)
