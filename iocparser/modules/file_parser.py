#!/usr/bin/env python3

"""
Module for extracting text from different file types

Author: Marc Rivero | @seifreed
"""

import re
from abc import ABC, abstractmethod
from pathlib import Path

import pdfplumber
import pdfplumber.pdf
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

from iocparser.modules.exceptions import (
    FileExistenceError,
    HTMLProcessingError,
    PDFProcessingError,
    UnsupportedFileTypeError,
    URLAccessError,
)

# Constants
MAX_URL_CONTENT_LINES = 5


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
        if not file_path.startswith(('http://', 'https://')) and not Path(self.file_path).is_file():
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

    def extract_text(self) -> str:
        """
        Extract text from a PDF file.

        Returns:
            The extracted text content
        """
        print(f"Extracting text from PDF: {self.file_path}")

        text_content = ""

        try:
            with pdfplumber.open(self.file_path) as pdf:
                # Cast to specific type instead of Any
                pdf_obj = pdf  # MyPy can infer the correct type from context
                total_pages: int = len(pdf_obj.pages)

                # Use tqdm to show progress
                for page_num in tqdm(range(total_pages), desc="Processing pages"):
                    page = pdf_obj.pages[page_num]
                    page_text: str = str(page.extract_text() or "")
                    text_content += page_text

                    # Also extract tables as they might contain IOCs
                    tables = page.extract_tables()
                    if tables:
                        for table in tables:
                            if table:
                                for row in table:
                                    if row:
                                        row_text = " ".join([str(cell) for cell in row if cell])
                                        text_content += row_text + "\n"

        except Exception as e:
            raise PDFProcessingError(str(e)) from e

        return text_content


class HTMLParser(FileParser):
    """Class for extracting text from HTML files."""

    def extract_text(self) -> str:
        """
        Extract text from an HTML file.

        Returns:
            The extracted text content
        """
        print(f"Extracting text from HTML: {self.file_path}")

        try:
            # Check if it's a URL or a local file
            if self.file_path.startswith(('http://', 'https://')):
                response = requests.get(self.file_path, timeout=30)
                response.raise_for_status()  # Ensure request was successful
                content = response.text
            else:
                with Path(self.file_path).open(encoding='utf-8', errors='ignore') as f:
                    content = f.read()

            # Check if the content looks like a URL instead of HTML
            content_starts_with_url = content.strip().startswith(
                ('http://', 'https://', 'hxxp://', 'hxxps://'),
            )
            is_short_content = len(content.strip().splitlines()) < MAX_URL_CONTENT_LINES
            if content_starts_with_url and is_short_content:
                # If the content appears to be just a URL, return the text as is
                return content.strip()

            # Parse the HTML with BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')

            # Remove scripts and styles that we're not interested in
            for tag in soup(['script', 'style', 'meta', 'noscript', 'head']):
                tag.decompose()

            # Get the text
            text = soup.get_text(separator=' ', strip=True)

            # Clean multiple whitespaces and return
            return re.sub(r'\s+', ' ', text)

        except requests.exceptions.RequestException as e:
            raise URLAccessError(str(e)) from e
        except Exception as e:
            raise HTMLProcessingError(str(e)) from e


# Function to determine the file type and return the appropriate parser
def get_parser(file_path: str) -> FileParser:
    """
    Determine the file type and return the appropriate parser.

    Args:
        file_path: Path to the file or URL

    Returns:
        The appropriate parser for the file type
    """
    # If it's a URL, determine the type by extension or assume HTML
    if file_path.startswith(('http://', 'https://')):
        if file_path.endswith('.pdf'):
            return PDFParser(file_path)
        return HTMLParser(file_path)

    # For local files, determine by extension
    if file_path.endswith('.pdf'):
        return PDFParser(file_path)
    if file_path.endswith(('.html', '.htm')):
        return HTMLParser(file_path)
    raise UnsupportedFileTypeError(file_path)
