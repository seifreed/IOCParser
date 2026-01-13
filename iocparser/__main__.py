#!/usr/bin/env python3

"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
Version: 5.0.0
"""

import argparse
import concurrent.futures
import logging
import re
from typing import cast
import sys
from pathlib import Path
from urllib.parse import ParseResult, urlparse

import magic
import requests
from colorama import Fore, Style, init
from requests.exceptions import RequestException, Timeout

from iocparser.modules.config import AppConfig, load_config
from iocparser.modules.exceptions import (
    DownloadSizeError,
    FileParsingError,
    FileProcessingError,
    FileSizeError,
    InvalidURLError,
    IOCParserError,
    IOCTimeoutError,
    NetworkDownloadError,
    NetworkError,
    UnexpectedDownloadError,
    ValidationError,
)
from iocparser.modules.extractor import IOCExtractor
from iocparser.modules.file_parser import HTMLParser, PDFParser
from iocparser.modules.logger import get_logger, setup_logger
from iocparser.modules.output_formatter import JSONFormatter, STIXFormatter, TextFormatter
from iocparser.modules.persistence import PersistenceManager, PersistOptions
from iocparser.modules.utils import deduplicate_iocs
from iocparser.modules.warninglists import MISPWarningLists

# Initialize colorama only when running as a script, not when imported
if __name__ == "__main__":
    init(autoreset=True)

# Colorama color constants (typed to avoid Any issues with strict mypy)
COLOR_CYAN: str = str(Fore.CYAN)
COLOR_RED: str = str(Fore.RED)
COLOR_YELLOW: str = str(Fore.YELLOW)
COLOR_GREEN: str = str(Fore.GREEN)
STYLE_RESET: str = str(Style.RESET_ALL)

# Constants
VERSION = "5.0.0"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_URL_SIZE = 50 * 1024 * 1024  # 50MB for URLs
REQUEST_TIMEOUT = 30  # seconds
MAX_WORKERS = 4  # for parallel processing
MAX_FILENAME_LENGTH = 50  # Maximum filename length

# Initialize logger
logger = get_logger(__name__)


def get_str_arg(args: argparse.Namespace, name: str, default: str = "") -> str:
    """Get string argument from argparse namespace."""
    value: object = getattr(args, name, None)
    return str(value) if value is not None else default


def get_bool_arg(args: argparse.Namespace, name: str) -> bool:
    """Get boolean argument from argparse namespace."""
    value: object = getattr(args, name, False)
    return bool(value)


def get_int_arg(args: argparse.Namespace, name: str, default: int = 0) -> int:
    """Get integer argument from argparse namespace."""
    value: object = getattr(args, name, None)
    return int(str(value)) if value is not None else default


def get_list_arg(args: argparse.Namespace, name: str) -> list[str]:
    """Get list argument from argparse namespace."""
    value: object = getattr(args, name, None)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def get_optional_str_arg(args: argparse.Namespace, name: str) -> str | None:
    """Get optional string argument from argparse namespace."""
    value: object = getattr(args, name, None)
    return str(value) if value is not None else None


class ProcessingOptions:
    """Options for IOC extraction processing."""

    def __init__(
        self,
        file_type: str | None = None,
        defang: bool = True,
        check_warnings: bool = True,
        force_update: bool = False,
    ) -> None:
        self.file_type = file_type
        self.defang = defang
        self.check_warnings = check_warnings
        self.force_update = force_update

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "ProcessingOptions":
        """Create ProcessingOptions from command line arguments."""
        return cls(
            file_type=get_optional_str_arg(args, "type"),
            defang=not get_bool_arg(args, "no_defang"),
            check_warnings=not get_bool_arg(args, "no_check_warnings"),
            force_update=get_bool_arg(args, "force_update"),
        )


def validate_file_size(file_path: Path, max_size: int = MAX_FILE_SIZE) -> None:
    """
    Validate that file size is within acceptable limits.

    Args:
        file_path: Path to the file
        max_size: Maximum allowed file size in bytes

    Raises:
        FileSizeError: If file exceeds size limit
    """
    file_size = file_path.stat().st_size
    if file_size > max_size:
        raise FileSizeError(
            file_size / 1024 / 1024,
            max_size / 1024 / 1024,
        )


def banner() -> None:
    """Display the tool banner."""
    print(f"""{COLOR_CYAN}
╔═══════════════════════════════════════════════╗
║                                               ║
║              IOC Parser v{VERSION}                ║
║                                               ║
║     Indicators of Compromise Extractor        ║
║                                               ║
║       Author: Marc Rivero | @seifreed         ║
║                                               ║
╚═══════════════════════════════════════════════╝
{STYLE_RESET}""")


def detect_file_type_by_mime(file_type: str) -> str | None:
    """Detect file type from MIME type."""
    file_type_lower = file_type.lower()
    if "pdf" in file_type_lower:
        return "pdf"
    if any(x in file_type_lower for x in ["html", "xml"]):
        return "html"
    if "text" in file_type_lower:
        return "text"
    return None


def detect_file_type_by_extension(file_path: Path) -> str:
    """Detect file type from file extension."""
    ext = file_path.suffix.lower()
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
    return extension_map.get(ext, "text")


def detect_file_type(file_path: Path) -> str:
    """
    Automatically detect the file type.

    Args:
        file_path: Path to the file

    Returns:
        Detected file type ('pdf', 'html', or 'text')

    Raises:
        FileParsingError: If file type cannot be determined
    """
    try:
        mime = magic.Magic(mime=True)
        file_type = str(mime.from_file(str(file_path)))

        # Try MIME type detection
        detected = detect_file_type_by_mime(file_type)
        if detected:
            return detected

        # Special case for text/plain with HTML-like extensions
        if "text/plain" in file_type.lower():
            ext = file_path.suffix.lower()
            if ext in [".html", ".htm", ".xml"]:
                return "html"
    except Exception as e:
        logger.warning(f"Error detecting file type: {e!s}, falling back to extension")

    # Fall back to extension-based detection
    return detect_file_type_by_extension(file_path)


def _validate_url(url: str) -> ParseResult:
    """Validate URL format and return parsed URL."""
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise InvalidURLError(url)
    return parsed_url


def _check_content_size(content_length: str | None) -> None:
    """Check if content size exceeds limit."""
    if content_length and int(content_length) > MAX_URL_SIZE:
        raise FileSizeError(
            int(content_length) / 1024 / 1024,
            MAX_URL_SIZE / 1024 / 1024,
            "URL content",
        )


def _generate_temp_filename(parsed_url: ParseResult, content_type: str) -> str:
    """Generate filename with appropriate extension."""
    file_name = Path(parsed_url.path).name or parsed_url.netloc.replace(".", "_")

    if "application/pdf" in content_type and not file_name.endswith(".pdf"):
        file_name += ".pdf"
    elif "text/html" in content_type and not file_name.endswith((".html", ".htm")):
        file_name += ".html"

    return file_name


def _download_with_size_check(
    response: requests.Response,
    temp_file: Path,
    max_size: int,
) -> int:
    """Download content with size checking."""
    downloaded_size = 0
    with temp_file.open("wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                downloaded_size += len(chunk)
                if downloaded_size > max_size:
                    f.close()
                    temp_file.unlink()
                    raise DownloadSizeError(max_size / 1024 / 1024)
                f.write(chunk)
    return downloaded_size


def download_url_to_temp(url: str, timeout: int = REQUEST_TIMEOUT) -> Path:
    """
    Download URL content to a temporary file.

    Args:
        url: URL to download
        timeout: Request timeout in seconds

    Returns:
        Path to the downloaded temporary file

    Raises:
        NetworkError: If download fails
        ValidationError: If URL is invalid
        FileSizeError: If downloaded content exceeds size limit
    """
    try:
        # Validate URL
        parsed_url = _validate_url(url)
        logger.info(f"Downloading content from {url}")

        # Stream download to check size
        response = requests.get(url, timeout=timeout, stream=True)
        response.raise_for_status()

        # Check content size
        _check_content_size(response.headers.get("Content-Length"))

        # Create temporary directory
        temp_dir = Path(__file__).parent.parent / "temp"
        temp_dir.mkdir(exist_ok=True)

        # Generate filename
        content_type = response.headers.get("Content-Type", "").lower()
        file_name = _generate_temp_filename(parsed_url, content_type)
        temp_file = temp_dir / file_name

        # Download with size check
        downloaded_size = _download_with_size_check(response, temp_file, MAX_URL_SIZE)

    except Timeout as e:
        raise IOCTimeoutError("Download", url) from e
    except RequestException as e:
        raise NetworkDownloadError(url, str(e)) from e
    except Exception as e:
        if isinstance(e, (ValidationError, FileSizeError, IOCTimeoutError)):
            raise
        raise UnexpectedDownloadError(url, str(e)) from e
    else:
        logger.info(f"Downloaded {downloaded_size / 1024:.2f}KB to {temp_file}")
        return temp_file


def get_output_filename(
    input_source: str,
    is_json: bool = False,
    output_format: str | None = None,
) -> str:
    """
    Generate an output filename based on the input name.

    Args:
        input_source: The input file or URL
        is_json: If True, use .json extension, else .txt
        output_format: Explicit output format (text, json, stix)

    Returns:
        Output filename
    """
    base_name: str
    # Handle URLs
    if input_source.startswith(("http://", "https://")):
        url_parts = urlparse(input_source)
        base_name = url_parts.netloc
        if url_parts.path and url_parts.path != "/":
            path_parts = url_parts.path.strip("/").split("/")
            if path_parts[-1]:
                base_name += "_" + path_parts[-1]
        # Clean invalid filename characters
        base_name = re.sub(r"[^\w\-\.]", "_", base_name)
    else:
        # Handle files
        base_name = Path(input_source).stem

    # Limit filename length
    if len(base_name) > MAX_FILENAME_LENGTH:
        base_name = base_name[:MAX_FILENAME_LENGTH]

    chosen_format = output_format if output_format else ("json" if is_json else "text")
    if chosen_format == "stix":
        extension = ".stix.json"
    elif chosen_format == "json":
        extension = ".json"
    else:
        extension = ".txt"
    return f"{base_name}_iocs{extension}"


def print_warning_lists(warnings: dict[str, list[dict[str, str]]]) -> None:
    """
    Print warnings from MISP warning lists.

    Args:
        warnings: Dictionary with warnings by IOC type
    """
    if not warnings:
        return

    logger.warning("IOCs found that might be false positives according to MISP warning lists:")

    for ioc_type, type_warnings in warnings.items():
        print(f"\n{COLOR_YELLOW}IOCs of type {ioc_type} with warnings:{STYLE_RESET}")
        for warning in type_warnings:
            print(
                f"  {COLOR_RED}- {warning['value']} - List: {warning['warning_list']}{STYLE_RESET}",
            )
            print(f"    {COLOR_YELLOW}Description: {warning['description']}{STYLE_RESET}")


def process_file(
    file_path: Path,
    file_type: str | None = None,
    defang: bool = True,
    check_warnings: bool = True,
    force_update: bool = False,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    """
    Process a single file and extract IOCs.

    Args:
        file_path: Path to the file
        file_type: Force specific file type
        defang: Whether to defang IOCs
        check_warnings: Whether to check against MISP warning lists
        force_update: Force update of warning lists

    Returns:
        Tuple of (normal_iocs, warning_iocs)

    Raises:
        FileParsingError: If file parsing fails
        ExtractionError: If IOC extraction fails
    """
    try:
        # Validate file size
        validate_file_size(file_path)

        # Detect file type if not specified
        if not file_type:
            file_type = detect_file_type(file_path)

        logger.info(f"Processing {file_path} as {file_type.upper()}")

        # Parse file based on type
        if file_type == "pdf":
            pdf_parser = PDFParser(str(file_path))
            text_content = pdf_parser.extract_text()
        elif file_type == "html":
            html_parser = HTMLParser(str(file_path))
            text_content = html_parser.extract_text()
        else:
            # Plain text file
            with file_path.open(encoding="utf-8", errors="ignore") as f:
                text_content = f.read()
            logger.debug(f"Read {len(text_content)} characters from text file")

        # Extract IOCs
        extractor = IOCExtractor(defang=defang)
        raw_iocs: dict[str, list[str]] = extractor.extract_all(text_content)
        # Convert to Union type for compatibility with warning list processing
        iocs: dict[str, list[str | dict[str, str]]] = {k: list(v) for k, v in raw_iocs.items()}

        # Check against warning lists
        if check_warnings:
            logger.info("Checking IOCs against MISP warning lists")
            warning_lists = MISPWarningLists(force_update=force_update)
            normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)
        else:
            normal_iocs = iocs
            warning_iocs = {}

    except Exception as e:
        logger.exception(f"Error processing file {file_path}")
        raise FileProcessingError(str(file_path), str(e)) from e
    else:
        return normal_iocs, warning_iocs


def process_multiple_files(
    file_paths: list[Path],
    file_type: str | None = None,
    defang: bool = True,
    check_warnings: bool = True,
    force_update: bool = False,
    max_workers: int = MAX_WORKERS,
) -> dict[str, tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]]:
    """
    Process multiple files in parallel.

    Args:
        file_paths: List of file paths to process
        file_type: Force specific file type
        defang: Whether to defang IOCs
        check_warnings: Whether to check against MISP warning lists
        force_update: Force update of warning lists
        max_workers: Maximum number of parallel workers

    Returns:
        Dictionary mapping file paths to (normal_iocs, warning_iocs) tuples
    """
    # Type alias to avoid long lines
    result_type = tuple[
        dict[str, list[str | dict[str, str]]],
        dict[str, list[dict[str, str]]],
    ]
    results: dict[str, result_type] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {
            executor.submit(
                process_file,
                file_path,
                file_type,
                defang,
                check_warnings,
                force_update,
            ): file_path
            for file_path in file_paths
        }

        # Collect results
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                result = future.result()
                results[str(file_path)] = result
                logger.info(f"Successfully processed {file_path}")
            except Exception:
                logger.exception(f"Failed to process {file_path}")
                empty_result: tuple[
                    dict[str, list[str | dict[str, str]]],
                    dict[str, list[dict[str, str]]],
                ] = ({}, {})
                results[str(file_path)] = empty_result

    return results


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Indicators of Compromise (IOCs) Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("-f", "--file", help="Path to the file to analyze")
    input_group.add_argument("-u", "--url", help="URL of the report to analyze")
    input_group.add_argument("-m", "--multiple", nargs="+", help="Multiple files to analyze")
    input_group.add_argument("url_direct", nargs="?", help="Direct URL as positional argument")

    parser.add_argument("-o", "--output", help="Output file path (use - for stdout)")
    parser.add_argument(
        "-t", "--type", choices=["pdf", "html", "text"], help="Force specific file type"
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="Output in JSON format")
    output_group.add_argument("--stix", action="store_true", help="Output in STIX 2.1 format")
    parser.add_argument("--no-defang", action="store_true", help="Disable automatic defanging")
    parser.add_argument(
        "--no-check-warnings", action="store_true", help="Don't check against MISP warning lists"
    )
    parser.add_argument(
        "--force-update", action="store_true", help="Force update of MISP warning lists"
    )
    parser.add_argument("--init", action="store_true", help="Initialize MISP warning lists")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--log-file", help="Path to log file")
    parser.add_argument("--version", action="version", version=f"IOCParser v{VERSION}")
    parser.add_argument(
        "--parallel", type=int, default=1, help="Number of parallel workers for multiple files"
    )
    parser.add_argument(
        "--persist",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable persistence (uses config/env if not set)",
    )
    parser.add_argument("--db-uri", help="Database URI for persistence")
    parser.add_argument("--config", help="Path to config file (INI)")

    return parser


def setup_application(args: argparse.Namespace) -> None:
    """Set up logging and display banner."""
    debug = get_bool_arg(args, "debug")
    verbose = get_bool_arg(args, "verbose")
    log_file_path = get_optional_str_arg(args, "log_file")

    log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    log_file = Path(log_file_path) if log_file_path else None
    setup_logger(level=log_level, log_file=log_file)

    if not debug and not verbose:
        banner()


def handle_misp_init() -> None:
    """Handle MISP warning lists initialization."""
    logger.info("Initializing and updating MISP warning lists...")
    warning_lists = MISPWarningLists(cache_duration=0, force_update=True)
    total_lists = len(warning_lists.warning_lists)
    logger.info(f"Initialization completed. Downloaded {total_lists} warning lists.")

    # Show available list categories
    categories: dict[str, list[str]] = {}
    for list_id, wlist in warning_lists.warning_lists.items():
        category = str(wlist.get("name", "")).split(" ")[0].lower() if "name" in wlist else "other"
        if category not in categories:
            categories[category] = []
        categories[category].append(list_id)

    for category, lists in sorted(categories.items()):
        print(f"{COLOR_CYAN}  {category.capitalize()}: {len(lists)} lists{STYLE_RESET}")


def process_multiple_files_input(
    args: argparse.Namespace,
) -> tuple[
    dict[str, list[str | dict[str, str]]],
    dict[str, list[dict[str, str]]],
    str,
    dict[str, tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]],
]:
    """Process multiple files input."""
    multiple_files = get_list_arg(args, "multiple")
    file_paths = [Path(f) for f in multiple_files]

    # Validate all files exist
    for file_path in file_paths:
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            sys.exit(1)

    parallel_workers = get_int_arg(args, "parallel", default=1)
    logger.info(f"Processing {len(file_paths)} files with {parallel_workers} workers")

    opts = ProcessingOptions.from_args(args)
    results = process_multiple_files(
        file_paths,
        file_type=opts.file_type,
        defang=opts.defang,
        check_warnings=opts.check_warnings,
        force_update=opts.force_update,
        max_workers=parallel_workers,
    )

    # Aggregate results
    all_normal_iocs: dict[str, list[str | dict[str, str]]] = {}
    all_warning_iocs: dict[str, list[dict[str, str]]] = {}

    for normal_iocs, warning_iocs in results.values():
        for ioc_type, ioc_list in normal_iocs.items():
            if ioc_type not in all_normal_iocs:
                all_normal_iocs[ioc_type] = []
            all_normal_iocs[ioc_type].extend(ioc_list)

        for ioc_type, warning_list in warning_iocs.items():
            if ioc_type not in all_warning_iocs:
                all_warning_iocs[ioc_type] = []
            all_warning_iocs[ioc_type].extend(warning_list)

    # Remove duplicates
    all_normal_iocs = deduplicate_iocs(all_normal_iocs)

    return all_normal_iocs, all_warning_iocs, f"{len(file_paths)} files", results


def process_single_input(
    args: argparse.Namespace,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]], str]:
    """Process single file or URL input."""
    file_arg = get_optional_str_arg(args, "file")
    url_arg = get_optional_str_arg(args, "url")
    url_direct_arg = get_optional_str_arg(args, "url_direct")

    if file_arg:
        input_source = Path(file_arg)
        input_display = str(input_source)
        is_from_url = False

        if not input_source.exists():
            logger.error(f"File not found: {input_source}")
            sys.exit(1)

    else:
        url = url_arg if url_arg else url_direct_arg
        if not url:
            logger.error("No URL provided")
            sys.exit(1)
        input_display = url
        is_from_url = True

        try:
            input_source = download_url_to_temp(url)
        except (NetworkError, ValidationError, FileSizeError, IOCTimeoutError):
            logger.exception("Failed to download URL")
            sys.exit(1)

    # Process the file
    try:
        opts = ProcessingOptions.from_args(args)
        normal_iocs, warning_iocs = process_file(
            input_source,
            file_type=opts.file_type,
            defang=opts.defang,
            check_warnings=opts.check_warnings,
            force_update=opts.force_update,
        )
    except (FileParsingError, IOCParserError):
        logger.exception("Failed to process file")
        sys.exit(1)
    finally:
        # Clean up temporary file if from URL
        if is_from_url and input_source.exists() and "temp" in str(input_source):
            try:
                input_source.unlink()
                logger.debug("Temporary file deleted")
            except Exception:
                logger.debug("Failed to delete temporary file")

    return normal_iocs, warning_iocs, input_display


def resolve_persistence(args: argparse.Namespace) -> AppConfig:
    """Resolve persistence configuration from CLI/env/config."""
    cli_persist = cast("bool | None", getattr(args, "persist", None))
    cli_db_uri = get_optional_str_arg(args, "db_uri")
    cli_config = get_optional_str_arg(args, "config")
    return load_config(cli_persist, cli_db_uri, cli_config)


def persist_results(
    config: AppConfig,
    source_kind: str,
    source_value: str,
    normal_iocs: dict[str, list[str | dict[str, str]]],
    warning_iocs: dict[str, list[dict[str, str]]],
    options: PersistOptions,
    tool_version: str,
) -> None:
    """Persist a single run if enabled."""
    if not config.persist:
        return
    if not config.db_uri:
        logger.error("Persistence enabled but no database URI provided")
        return
    manager = PersistenceManager(config.db_uri)
    manager.persist_run(
        source_kind=source_kind,
        source_value=source_value,
        normal_iocs=normal_iocs,
        warning_iocs=warning_iocs,
        tool_version=tool_version,
        options=options,
    )


def display_results(
    normal_iocs: dict[str, list[str | dict[str, str]]],
    warning_iocs: dict[str, list[dict[str, str]]],
) -> None:
    """Display extraction results summary."""
    total_iocs = sum(len(iocs) for iocs in normal_iocs.values())
    logger.info(f"Found {total_iocs} indicators of compromise")

    for ioc_type, ioc_list in normal_iocs.items():
        if ioc_list:
            print(f"    {COLOR_CYAN}- {ioc_type}: {len(ioc_list)}{STYLE_RESET}")

    if warning_iocs:
        print_warning_lists(warning_iocs)
        warnings_count = sum(len(warnings) for warnings in warning_iocs.values())
        logger.warning(f"Found {warnings_count} potential false positives")


def save_output(
    args: argparse.Namespace,
    normal_iocs: dict[str, list[str | dict[str, str]]],
    warning_iocs: dict[str, list[dict[str, str]]],
    input_display: str,
) -> None:
    """Format and save output."""
    use_json = get_bool_arg(args, "json")
    use_stix = get_bool_arg(args, "stix")
    output_path = get_optional_str_arg(args, "output")

    formatter: JSONFormatter | TextFormatter | STIXFormatter
    output_format: str
    if use_stix:
        formatter = STIXFormatter(normal_iocs, warning_iocs=warning_iocs, source=input_display)
        output_format = "STIX 2.1"
    elif use_json:
        formatter = JSONFormatter(normal_iocs, warning_iocs=warning_iocs)
        output_format = "JSON"
    else:
        formatter = TextFormatter(normal_iocs, warning_iocs=warning_iocs)
        output_format = "text"

    formatted_output = formatter.format()

    if output_path:
        if output_path == "-":
            print(formatted_output)
            logger.info(f"Results displayed in {output_format} format")
        else:
            output_file = Path(output_path)
            formatter.save(str(output_file))
            logger.info(f"Results saved to {output_file}")
    else:
        # Auto-save with generated filename
        print(formatted_output)
        chosen_format = "stix" if use_stix else ("json" if use_json else "text")
        output_filename = get_output_filename(
            input_display,
            is_json=use_json,
            output_format=chosen_format,
        )
        formatter.save(output_filename)
        logger.info(f"Results saved to {output_filename}")


def has_input_args(args: argparse.Namespace) -> bool:
    """Check if any input arguments are provided."""
    return bool(
        get_optional_str_arg(args, "file")
        or get_optional_str_arg(args, "url")
        or get_optional_str_arg(args, "url_direct")
        or get_list_arg(args, "multiple"),
    )


if __name__ == "__main__":
    """Main function."""
    try:
        parser = create_argument_parser()
        args = parser.parse_args()
        config = resolve_persistence(args)

        setup_application(args)

        # Handle initialization or force update request
        if get_bool_arg(args, "init") or get_bool_arg(args, "force_update"):
            handle_misp_init()
            return

        # Verify input is provided
        if not has_input_args(args):
            parser.print_help()
            logger.error("No input provided. Use -f, -u, -m, --init, or --force-update")
            sys.exit(1)

        # Process input based on type
        if get_list_arg(args, "multiple"):
            normal_iocs, warning_iocs, input_display, results = process_multiple_files_input(args)
        else:
            normal_iocs, warning_iocs, input_display = process_single_input(args)
            results = None

        # Display and save results
        display_results(normal_iocs, warning_iocs)
        save_output(args, normal_iocs, warning_iocs, input_display)

        if get_bool_arg(args, "stix"):
            output_format = "stix"
        elif get_bool_arg(args, "json"):
            output_format = "json"
        else:
            output_format = "text"
        options = PersistOptions(
            defang=not get_bool_arg(args, "no_defang"),
            check_warnings=not get_bool_arg(args, "no_check_warnings"),
            force_update=get_bool_arg(args, "force_update"),
            output_format=output_format,
        )

        if results:
            for source_path, (file_iocs, file_warnings) in results.items():
                persist_results(
                    config=config,
                    source_kind="file",
                    source_value=source_path,
                    normal_iocs=file_iocs,
                    warning_iocs=file_warnings,
                    options=options,
                    tool_version=VERSION,
                )
        else:
            source_kind = (
                "url"
                if get_optional_str_arg(args, "url") or get_optional_str_arg(args, "url_direct")
                else "file"
            )
            persist_results(
                config=config,
                source_kind=source_kind,
                source_value=input_display,
                normal_iocs=normal_iocs,
                warning_iocs=warning_iocs,
                options=options,
                tool_version=VERSION,
            )

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e!s}", exc_info=True)
        sys.exit(1)
