#!/usr/bin/env python3

"""
Module for extracting text from different file types

Author: Marc Rivero | @seifreed
"""

import re
import urllib.parse
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

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
    try:
        yield str(temp_path)
    finally:
        with suppress(OSError):
            temp_path.unlink(missing_ok=True)


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
            text_content += page_text

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
        logger.info("Extracting text from HTML: %s", self.file_path)

        try:
            with (
                _local_parse_path(self.file_path) as parse_path,
                Path(parse_path).open(encoding="utf-8", errors="ignore") as f,
            ):
                content = f.read()

            # Check if the content looks like a URL instead of HTML
            content_starts_with_url = content.strip().startswith(
                ("http://", "https://", "hxxp://", "hxxps://"),
            )
            is_short_content = len(content.strip().splitlines()) < MAX_URL_CONTENT_LINES
            if content_starts_with_url and is_short_content:
                # If the content appears to be just a URL, return the text as is
                return content.strip()

            # Parse the HTML with BeautifulSoup
            soup = BeautifulSoup(content, "html.parser")

            # Remove scripts and styles that we're not interested in
            for tag in soup(["script", "style", "meta", "noscript", "head"]):
                tag.decompose()

            # Get the text
            text = soup.get_text(separator=" ", strip=True)

            # Clean multiple whitespaces and return
            return re.sub(r"\s+", " ", text)

        except IOCParserError:
            raise
        except Exception as exc:
            raise HTMLProcessingError(str(exc)) from exc


# Extension to parser mapping
EXTENSION_PARSERS: dict[str, type[FileParser]] = {
    ".pdf": PDFParser,
    ".html": HTMLParser,
    ".htm": HTMLParser,
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
