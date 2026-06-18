#!/usr/bin/env python3

"""
Module for extracting text from different file types

Author: Marc Rivero | @seifreed
"""

import codecs
import html as html_module
import io
import re
import urllib.parse
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, TextIO, cast

import pdfplumber
from bs4 import BeautifulSoup
from pdfplumber.utils.exceptions import PdfminerException
from tqdm import tqdm

from iocparser.errors import (
    DownloadError,
    FileExistenceError,
    HTMLProcessingError,
    InvalidURLError,
    IOCParserError,
    IOCTimeoutError,
    PDFProcessingError,
    UnsupportedFileTypeError,
    URLAccessError,
)
from iocparser.infrastructure.logger import get_logger

# Constants
MAX_URL_CONTENT_LINES = 5

logger = get_logger(__name__)

# Byte-order marks, longest-first so a UTF-32 BOM is not misread as UTF-16.
_BOM_ENCODINGS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def detect_bom_encoding(raw: bytes) -> str:
    """Return the text encoding implied by a leading BOM, or utf-8 if none."""
    for bom, encoding in _BOM_ENCODINGS:
        if raw.startswith(bom):
            return encoding
    return "utf-8"


def decode_file_bytes(raw: bytes) -> str:
    """Decode file bytes, honoring a UTF-8/UTF-16/UTF-32 BOM when present.

    The text and HTML read paths previously assumed UTF-8, so a UTF-16 file
    (common from Windows tooling) had its interleaved NUL bytes dropped by
    ``errors="ignore"``, destroying every IOC. Detect the BOM and decode
    accordingly, defaulting to UTF-8 for BOM-less content.
    """
    for bom, encoding in _BOM_ENCODINGS:
        if raw.startswith(bom):
            return raw.decode(encoding, errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def wrap_binary_stream_for_bom(
    stream: BinaryIO | TextIO,
    *,
    is_text: bool,
) -> tuple[BinaryIO | TextIO, bool]:
    if is_text or isinstance(stream, io.TextIOBase):
        return stream, is_text
    try:
        binary_stream = cast("BinaryIO", stream)
        current_pos = binary_stream.tell()
        if current_pos != 0:
            binary_stream.seek(current_pos)
            return stream, is_text
        encoding = detect_bom_encoding(binary_stream.read(4))
        binary_stream.seek(0)
        if encoding == "utf-8":
            return stream, is_text
        return io.TextIOWrapper(binary_stream, encoding=encoding, errors="ignore"), True
    except (AttributeError, OSError, io.UnsupportedOperation):
        return stream, is_text


def _is_remote_source(file_path: str) -> bool:
    return file_path.lower().startswith(("http://", "https://"))


def _download_remote_source(file_path: str) -> Path:
    from iocparser.infrastructure.http_download import RequestsURLDownloader

    try:
        return Path(RequestsURLDownloader().download(file_path))
    except (DownloadError, InvalidURLError, IOCTimeoutError) as exc:
        raise URLAccessError(str(exc)) from exc


@contextmanager
def _local_parse_path(file_path: str) -> Iterator[str]:
    if not _is_remote_source(file_path):
        yield file_path
        return

    temp_path = _download_remote_source(file_path)
    primary_exc: BaseException | None = None
    try:
        yield str(temp_path)
    except BaseException as exc:
        primary_exc = exc
        raise
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            if primary_exc is None:
                raise
            logger.warning("Failed to remove temporary parse file", exc_info=True)


class FileParser(ABC):
    """Abstract base class for all file parsers."""

    def __init__(self, file_path: str) -> None:
        """
        Initialize the file parser.

        Args:
            file_path: Path to the file to parse
        """
        self.file_path = file_path

        # Verify the file exists if it's not a URL
        if not _is_remote_source(file_path) and not Path(self.file_path).is_file():
            raise FileExistenceError(self.file_path)

    @abstractmethod
    def extract_text(self) -> str:
        """
        Extract text from the file.

        Returns:
            The extracted text content
        """


class PDFParser(FileParser):
    """Class for extracting text from PDF files."""

    @staticmethod
    def _extract_pdf_text(pdf: Any) -> str:
        text_content = ""
        total_pages: int = len(pdf.pages)

        for page_num in tqdm(range(total_pages), desc="Processing pages"):
            page = pdf.pages[page_num]
            page_text: str = str(page.extract_text() or "")
            if page_text:
                text_content += page_text
                if not text_content.endswith("\n"):
                    text_content += "\n"

            tables = page.extract_tables() or []
            for table in tables:
                text_content += PDFParser._extract_table_text(table)

        return text_content

    def extract_text(self) -> str:
        """
        Extract text from a PDF file.

        Returns:
            The extracted text content
        """
        logger.info("Extracting text from PDF: %s", self.file_path)

        text_content = ""

        try:
            with (
                _local_parse_path(self.file_path) as parse_path,
                pdfplumber.open(parse_path) as pdf,
            ):
                text_content = self._extract_pdf_text(pdf)
        except (OSError, ValueError, PdfminerException) as exc:
            raise PDFProcessingError(str(exc)) from exc

        return text_content

    @staticmethod
    def _extract_table_text(table: list[list[str | None]] | None) -> str:
        """Return table text with rows joined and filtered."""
        if not table:
            return ""
        lines: list[str] = []
        for row in table:
            if not row:
                continue
            row_text = " ".join(str(cell) for cell in row if cell)
            if row_text:
                lines.append(row_text)
        if not lines:
            return ""
        return "\n".join(lines) + "\n"


class HTMLParser(FileParser):
    """Class for extracting text from HTML files."""

    def extract_text(self) -> str:
        """
        Extract text from an HTML file.

        Returns:
            The extracted text content
        """
        logger.info("Extracting text from %s: %s", self._kind, self.file_path)

        try:
            with _local_parse_path(self.file_path) as parse_path:
                content = decode_file_bytes(Path(parse_path).read_bytes())

            # Check if the content looks like a URL instead of HTML
            content_starts_with_url = content.strip().startswith(
                ("http://", "https://", "hxxp://", "hxxps://"),
            )
            is_short_content = len(content.strip().splitlines()) < MAX_URL_CONTENT_LINES
            if content_starts_with_url and is_short_content:
                # If the content appears to be just a URL, return the text as is
                return content.strip()

            return self._text_from_content(content)

        except IOCParserError:
            raise
        except Exception as exc:
            raise HTMLProcessingError(str(exc)) from exc

    _kind: ClassVar[str] = "HTML"

    # URLs/IOCs in malware and phishing pages overwhelmingly live in link attributes
    # (href/src/action/...), which get_text() drops entirely. Harvest these so the IOC
    # regexes see them; any data-* attribute is included too (lazy-loading puts URLs there).
    _URL_BEARING_ATTRS: ClassVar[tuple[str, ...]] = (
        "href",
        "src",
        "srcset",
        "action",
        "formaction",
        "cite",
        "poster",
        "background",
        "longdesc",
    )

    def _attribute_iocs(self, soup: BeautifulSoup) -> list[str]:
        values: list[str] = []
        for element in soup.find_all(True):
            for attr, value in element.attrs.items():
                if attr not in self._URL_BEARING_ATTRS and not attr.startswith("data-"):
                    continue
                text = " ".join(value) if isinstance(value, list) else value
                if isinstance(text, str) and text.strip():
                    values.append(text)
        return values

    def _text_from_content(self, content: str) -> str:
        soup = BeautifulSoup(content, "html.parser")
        # script/style/etc. are HTML rendering noise, not indicators.
        for tag in soup(["script", "style", "meta", "noscript", "head"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        combined = " ".join([text, *self._attribute_iocs(soup)])
        return re.sub(r"\s+", " ", combined)


class XMLParser(HTMLParser):
    """Extract IOC-bearing text from XML.

    HTML parsing is wrong for XML: html.parser special-cases <script>/<style>
    (dropping their contents) and stripping those elements deletes data, since in
    XML they are ordinary data-bearing element names. Decode the raw text and
    unescape entities instead; IOC regexes match across the tag markup.
    """

    _kind: ClassVar[str] = "XML"

    def _text_from_content(self, content: str) -> str:
        return html_module.unescape(content)


# Extension to parser mapping
EXTENSION_PARSERS: dict[str, type[FileParser]] = {
    ".pdf": PDFParser,
    ".html": HTMLParser,
    ".htm": HTMLParser,
    ".xml": XMLParser,
}


def _parser_suffix(file_path: str) -> str:
    if _is_remote_source(file_path):
        return Path(urllib.parse.urlparse(file_path).path).suffix.lower()
    return Path(file_path).suffix.lower()


def get_parser(file_path: str) -> FileParser:
    """
    Determine the file type and return the appropriate parser.

    Args:
        file_path: Path to the file or URL

    Returns:
        The appropriate parser for the file type
    """
    # Check extension against known parsers
    parser_class = EXTENSION_PARSERS.get(_parser_suffix(file_path))
    if parser_class is not None:
        return parser_class(file_path)

    # For URLs without recognized extension, default to HTML
    if _is_remote_source(file_path):
        return HTMLParser(file_path)

    raise UnsupportedFileTypeError(file_path)
