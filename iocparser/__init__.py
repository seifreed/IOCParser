"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
"""

from pathlib import Path
from typing import cast

__version__ = "5.0.0"

from iocparser.core import detect_file_type, get_output_filename
from iocparser.modules.exceptions import FileExistenceError
from iocparser.modules.extractor import IOCExtractor
from iocparser.modules.file_parser import HTMLParser, PDFParser
from iocparser.modules.output_formatter import JSONFormatter, STIXFormatter, TextFormatter
from iocparser.modules.warninglists import MISPWarningLists

# Export main functionality for library use
__all__ = [
    "HTMLParser",
    "IOCExtractor",
    "JSONFormatter",
    "MISPWarningLists",
    "PDFParser",
    "STIXFormatter",
    "TextFormatter",
    "detect_file_type",
    "extract_iocs_from_file",
    "extract_iocs_from_text",
    "get_output_filename",
]


def extract_iocs_from_file(
    file_path: str | Path,
    check_warnings: bool = True,
    force_update: bool = False,
    file_type: str | None = None,
    defang: bool = True,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    """
    Extract IOCs from a file.

    Args:
        file_path (str): Path to the file
        check_warnings (bool): Whether to check IOCs against MISP warning lists
        force_update (bool): Whether to force update the MISP warning lists
        file_type (str): Force a specific file type (pdf, html, text)
        defang (bool): Whether to defang the IOCs

    Returns:
        tuple: (normal_iocs, warning_iocs) where each is a dict with IOC types as keys
    """
    # Verify the file exists
    file_pathobj = Path(file_path)
    if not file_pathobj.is_file():
        raise FileExistenceError(str(file_path))

    # Detect file type if not specified
    detected_type = file_type if file_type else detect_file_type(file_pathobj)

    # Parse the file according to its type
    file_path_str = str(file_path)
    if detected_type == "pdf":
        parser: PDFParser = PDFParser(file_path_str)
        text_content = parser.extract_text()
    elif detected_type == "html":
        parser_html: HTMLParser = HTMLParser(file_path_str)
        text_content = parser_html.extract_text()
    else:  # text or unknown format
        # For plain text files, simply read the content
        with file_pathobj.open(encoding="utf-8", errors="ignore") as f:
            text_content = f.read()

    # Process the text content
    return extract_iocs_from_text(text_content, check_warnings, force_update, defang)


def extract_iocs_from_text(
    text_content: str,
    check_warnings: bool = True,
    force_update: bool = False,
    defang: bool = True,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    """
    Extract IOCs from text content.

    Args:
        text_content (str): The text to extract IOCs from
        check_warnings (bool): Whether to check IOCs against MISP warning lists
        force_update (bool): Whether to force update the MISP warning lists
        defang (bool): Whether to defang the IOCs

    Returns:
        tuple: (normal_iocs, warning_iocs) where each is a dict with IOC types as keys
    """
    # Extract IOCs
    extractor = IOCExtractor(defang=defang)
    raw_iocs = extractor.extract_all(text_content)
    # Convert to Union type for compatibility
    iocs: dict[str, list[str | dict[str, str]]] = {
        k: cast("list[str | dict[str, str]]", v) for k, v in raw_iocs.items()
    }

    # Check against warning lists if enabled
    if check_warnings:
        warning_lists = MISPWarningLists(force_update=force_update)
        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)
        return normal_iocs, warning_iocs
    # If not checking warnings, all IOCs are considered normal
    return iocs, {}
