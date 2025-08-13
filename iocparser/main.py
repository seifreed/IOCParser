#!/usr/bin/env python3

"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
Version: 1.0.1
"""

import argparse
import concurrent.futures
import logging
import re
import sys

# Removed functools import as timeit decorator was removed for type safety
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, cast
from urllib.parse import ParseResult, urlparse

import magic
import requests
from colorama import Fore, Style, init
from requests.exceptions import RequestException, Timeout

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
from iocparser.modules.output_formatter import JSONFormatter, TextFormatter
from iocparser.modules.warninglists import MISPWarningLists

# Initialize colorama only when running as a script, not when imported
if __name__ == "__main__":
    init(autoreset=True)

# Constants
VERSION = "1.0.1"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_URL_SIZE = 50 * 1024 * 1024    # 50MB for URLs
REQUEST_TIMEOUT = 30  # seconds
MAX_WORKERS = 4  # for parallel processing
MAX_FILENAME_LENGTH = 50  # Maximum filename length

# Initialize logger
logger = get_logger(__name__)


def get_arg(args: argparse.Namespace, attr: str) -> object:
    """Helper to safely get argparse attributes."""
    return cast("object", getattr(args, attr))


# Removed timeit decorator to avoid complex typing issues in strict mode


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
    print(f"""{Fore.CYAN}
╔═══════════════════════════════════════════════╗
║                                               ║
║              IOC Parser v{VERSION}                ║
║                                               ║
║     Indicators of Compromise Extractor        ║
║                                               ║
║       Author: Marc Rivero | @seifreed         ║
║                                               ║
╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def detect_file_type_by_mime(file_type: str) -> Optional[str]:
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
        '.pdf': 'pdf',
        '.html': 'html',
        '.htm': 'html',
        '.xml': 'html',
        '.txt': 'text',
        '.log': 'text',
        '.md': 'text',
        '.csv': 'text',
        '.json': 'text',
    }
    return extension_map.get(ext, 'text')


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
            if ext in ['.html', '.htm', '.xml']:
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

def _check_content_size(content_length: Optional[str]) -> None:
    """Check if content size exceeds limit."""
    if content_length and int(content_length) > MAX_URL_SIZE:
        raise FileSizeError(
            int(content_length) / 1024 / 1024,
            MAX_URL_SIZE / 1024 / 1024,
            "URL content",
        )

def _generate_temp_filename(parsed_url: ParseResult, content_type: str) -> str:
    """Generate filename with appropriate extension."""
    file_name = Path(parsed_url.path).name or parsed_url.netloc.replace('.', '_')

    if 'application/pdf' in content_type and not file_name.endswith('.pdf'):
        file_name += '.pdf'
    elif 'text/html' in content_type and not file_name.endswith(('.html', '.htm')):
        file_name += '.html'

    return file_name

def _download_with_size_check(
    response: requests.Response, temp_file: Path, max_size: int,
) -> int:
    """Download content with size checking."""
    downloaded_size = 0
    with temp_file.open('wb') as f:
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
        _check_content_size(response.headers.get('Content-Length'))

        # Create temporary directory
        temp_dir = Path(__file__).parent.parent / 'temp'
        temp_dir.mkdir(exist_ok=True)

        # Generate filename
        content_type = response.headers.get('Content-Type', '').lower()
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


def get_output_filename(input_source: str, is_json: bool = False) -> str:
    """
    Generate an output filename based on the input name.

    Args:
        input_source: The input file or URL
        is_json: If True, use .json extension, else .txt

    Returns:
        Output filename
    """
    base_name: str
    # Handle URLs
    if input_source.startswith(('http://', 'https://')):
        url_parts = urlparse(input_source)
        base_name = url_parts.netloc
        if url_parts.path and url_parts.path != '/':
            path_parts = url_parts.path.strip('/').split('/')
            if path_parts[-1]:
                base_name += '_' + path_parts[-1]
        # Clean invalid filename characters
        base_name = re.sub(r'[^\w\-\.]', '_', base_name)
    else:
        # Handle files
        base_name = Path(input_source).stem

    # Limit filename length
    if len(base_name) > MAX_FILENAME_LENGTH:
        base_name = base_name[:MAX_FILENAME_LENGTH]

    extension = '.json' if is_json else '.txt'
    return f"{base_name}_iocs{extension}"


def print_warning_lists(warnings: Dict[str, List[Dict[str, str]]]) -> None:
    """
    Print warnings from MISP warning lists.

    Args:
        warnings: Dictionary with warnings by IOC type
    """
    if not warnings:
        return

    logger.warning("IOCs found that might be false positives according to MISP warning lists:")

    for ioc_type, type_warnings in warnings.items():
        print(f"\n{Fore.YELLOW}IOCs of type {ioc_type} with warnings:{Style.RESET_ALL}")
        for warning in type_warnings:
            print(
                f"  {Fore.RED}● {warning['value']} - "
                f"List: {warning['warning_list']}{Style.RESET_ALL}",
            )
            print(f"    {Fore.YELLOW}Description: {warning['description']}{Style.RESET_ALL}")


def process_file(
    file_path: Path,
    file_type: Optional[str] = None,
    defang: bool = True,
    check_warnings: bool = True,
    force_update: bool = False,
) -> Tuple[Dict[str, List[Union[str, Dict[str, str]]]], Dict[str, List[Dict[str, str]]]]:
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
            with file_path.open(encoding='utf-8', errors='ignore') as f:
                text_content = f.read()
            logger.debug(f"Read {len(text_content)} characters from text file")

        # Extract IOCs
        extractor = IOCExtractor(defang=defang)
        raw_iocs: Dict[str, List[str]] = extractor.extract_all(text_content)
        # Convert to Union type for compatibility
        iocs: Dict[str, List[Union[str, Dict[str, str]]]] = {
            k: cast("List[Union[str, Dict[str, str]]]", v) for k, v in raw_iocs.items()
        }

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
    file_paths: List[Path],
    file_type: Optional[str] = None,
    defang: bool = True,
    check_warnings: bool = True,
    force_update: bool = False,
    max_workers: int = MAX_WORKERS,
) -> Dict[str, Tuple[Dict[str, List[Union[str, Dict[str, str]]]], Dict[str, List[Dict[str, str]]]]]:
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
    result_type = Tuple[
        Dict[str, List[Union[str, Dict[str, str]]]],
        Dict[str, List[Dict[str, str]]],
    ]
    results: Dict[str, result_type] = {}

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
                empty_result: Tuple[
                    Dict[str, List[Union[str, Dict[str, str]]]], Dict[str, List[Dict[str, str]]],
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
    input_group.add_argument("-m", "--multiple", nargs='+', help="Multiple files to analyze")
    input_group.add_argument("url_direct", nargs="?", help="Direct URL as positional argument")

    parser.add_argument("-o", "--output", help="Output file path (use - for stdout)")
    parser.add_argument("-t", "--type", choices=["pdf", "html", "text"],
                      help="Force specific file type")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--no-defang", action="store_true", help="Disable automatic defanging")
    parser.add_argument("--no-check-warnings", action="store_true",
                      help="Don't check against MISP warning lists")
    parser.add_argument("--force-update", action="store_true",
                      help="Force update of MISP warning lists")
    parser.add_argument("--init", action="store_true",
                      help="Initialize MISP warning lists")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--log-file", help="Path to log file")
    parser.add_argument("--version", action="version", version=f"IOCParser v{VERSION}")
    parser.add_argument("--parallel", type=int, default=1,
                      help="Number of parallel workers for multiple files")

    return parser


def setup_application(args: argparse.Namespace) -> None:
    """Set up logging and display banner."""
    debug = cast("bool", get_arg(args, 'debug'))
    verbose = cast("bool", get_arg(args, 'verbose'))
    log_file_path = get_arg(args, 'log_file')

    log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    log_file = Path(str(log_file_path)) if log_file_path else None
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
    categories: Dict[str, List[str]] = {}
    for list_id, wlist in warning_lists.warning_lists.items():
        category = (
            str(wlist.get('name', '')).split(' ')[0].lower() if 'name' in wlist else 'other'
        )
        if category not in categories:
            categories[category] = []
        categories[category].append(list_id)

    for category, lists in sorted(categories.items()):
        print(f"{Fore.CYAN}  {category.capitalize()}: {len(lists)} lists{Style.RESET_ALL}")


def process_multiple_files_input(
    args: argparse.Namespace,
) -> Tuple[Dict[str, List[Union[str, Dict[str, str]]]], Dict[str, List[Dict[str, str]]], str]:
    """Process multiple files input."""
    multiple_files = cast("List[str]", get_arg(args, 'multiple'))
    file_paths = [Path(f) for f in multiple_files]

    # Validate all files exist
    for file_path in file_paths:
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            sys.exit(1)

    parallel_workers = cast("int", get_arg(args, 'parallel'))
    logger.info(f"Processing {len(file_paths)} files with {parallel_workers} workers")

    file_type = cast("Optional[str]", get_arg(args, 'type'))
    no_defang = cast("bool", get_arg(args, 'no_defang'))
    no_check_warnings = cast("bool", get_arg(args, 'no_check_warnings'))
    force_update = cast("bool", get_arg(args, 'force_update'))

    results = process_multiple_files(
        file_paths,
        file_type=file_type,
        defang=not no_defang,
        check_warnings=not no_check_warnings,
        force_update=force_update,
        max_workers=parallel_workers,
    )

    # Aggregate results
    all_normal_iocs: Dict[str, List[Union[str, Dict[str, str]]]] = {}
    all_warning_iocs: Dict[str, List[Dict[str, str]]] = {}

    for normal_iocs, warning_iocs in results.values():
        for ioc_type, ioc_list in normal_iocs.items():
            if ioc_type not in all_normal_iocs:
                all_normal_iocs[ioc_type] = []
            all_normal_iocs[ioc_type].extend(ioc_list)

        for ioc_type, warning_list in warning_iocs.items():
            if ioc_type not in all_warning_iocs:
                all_warning_iocs[ioc_type] = []
            all_warning_iocs[ioc_type].extend(warning_list)

    # Remove duplicates automatically while preserving order
    for ioc_type, ioc_list in all_normal_iocs.items():
        unique_items: List[Union[str, Dict[str, str]]] = []
        seen_keys: Set[str] = set()

        for item in ioc_list:
            # Create a unique key for each item (dicts use sorted items, strings use themselves)
            key = str(sorted(item.items())) if isinstance(item, dict) else str(item)

            # Only add if we haven't seen this key before
            if key not in seen_keys:
                seen_keys.add(key)
                unique_items.append(item)

        all_normal_iocs[ioc_type] = unique_items

    return all_normal_iocs, all_warning_iocs, f"{len(file_paths)} files"


def process_single_input(
    args: argparse.Namespace,
) -> Tuple[Dict[str, List[Union[str, Dict[str, str]]]], Dict[str, List[Dict[str, str]]], str]:
    """Process single file or URL input."""
    file_arg = get_arg(args, 'file')
    url_arg = get_arg(args, 'url')
    url_direct_arg = get_arg(args, 'url_direct')

    if file_arg:
        input_source = Path(cast("str", file_arg))
        input_display = str(input_source)
        is_from_url = False

        if not input_source.exists():
            logger.error(f"File not found: {input_source}")
            sys.exit(1)

    else:
        if url_arg or url_direct_arg:
            url = str(url_arg if url_arg else url_direct_arg)
        input_display = url
        is_from_url = True

        try:
            input_source = download_url_to_temp(url)
        except (NetworkError, ValidationError, FileSizeError, IOCTimeoutError):
            logger.exception("Failed to download URL")
            sys.exit(1)

    # Process the file
    try:
        file_type_arg = cast("Optional[str]", get_arg(args, 'type'))
        no_defang_arg = cast("bool", get_arg(args, 'no_defang'))
        no_check_warnings_arg = cast("bool", get_arg(args, 'no_check_warnings'))
        force_update_arg = cast("bool", get_arg(args, 'force_update'))

        normal_iocs, warning_iocs = process_file(
            input_source,
            file_type=file_type_arg,
            defang=not no_defang_arg,
            check_warnings=not no_check_warnings_arg,
            force_update=force_update_arg,
        )
    except (FileParsingError, IOCParserError):
        logger.exception("Failed to process file")
        sys.exit(1)
    finally:
        # Clean up temporary file if from URL
        if is_from_url and input_source.exists() and 'temp' in str(input_source):
            try:
                input_source.unlink()
                logger.debug("Temporary file deleted")
            except Exception:
                logger.debug("Failed to delete temporary file")

    return normal_iocs, warning_iocs, input_display


def display_results(
    normal_iocs: Dict[str, List[Union[str, Dict[str, str]]]],
    warning_iocs: Dict[str, List[Dict[str, str]]],
) -> None:
    """Display extraction results summary."""
    total_iocs = sum(len(iocs) for iocs in normal_iocs.values())
    logger.info(f"Found {total_iocs} indicators of compromise")

    for ioc_type, ioc_list in normal_iocs.items():
        if ioc_list:
            print(f"    {Fore.CYAN}● {ioc_type}: {len(ioc_list)}{Style.RESET_ALL}")

    if warning_iocs:
        print_warning_lists(warning_iocs)
        warnings_count = sum(len(warnings) for warnings in warning_iocs.values())
        logger.warning(f"Found {warnings_count} potential false positives")


def save_output(
    args: argparse.Namespace,
    normal_iocs: Dict[str, List[Union[str, Dict[str, str]]]],
    warning_iocs: Dict[str, List[Dict[str, str]]],
    input_display: str,
) -> None:
    """Format and save output."""
    formatter: Union[JSONFormatter, TextFormatter]
    if cast("bool", args.json):
        formatter = JSONFormatter(normal_iocs, warning_iocs=warning_iocs)
        output_format = "JSON"
    else:
        formatter = TextFormatter(normal_iocs, warning_iocs=warning_iocs)
        output_format = "text"

    formatted_output = formatter.format()

    if cast("object", args.output):
        if cast("str", args.output) == "-":
            print(formatted_output)
            logger.info(f"Results displayed in {output_format} format")
        else:
            output_file = Path(str(cast("object", args.output)))
            formatter.save(str(output_file))
            logger.info(f"Results saved to {output_file}")
    else:
        # Auto-save with generated filename
        print(formatted_output)
        output_filename = get_output_filename(input_display, is_json=cast("bool", args.json))
        formatter.save(output_filename)
        logger.info(f"Results saved to {output_filename}")


def main() -> None:
    """Main function."""
    try:
        parser = create_argument_parser()
        args = parser.parse_args()

        setup_application(args)

        # Handle initialization or force update request
        if cast("bool", args.init) or cast("bool", args.force_update):
            handle_misp_init()
            return

        # Verify input is provided
        # Check if any input arguments are provided
        input_args = [
            cast("object", args.file),
            cast("object", args.url),
            cast("object", args.url_direct),
            cast("object", args.multiple),
        ]
        if not any(input_args):
            parser.print_help()
            logger.error("No input provided. Use -f, -u, -m, --init, or --force-update")
            sys.exit(1)

        # Process input based on type
        if cast("object", args.multiple):
            normal_iocs, warning_iocs, input_display = process_multiple_files_input(args)
        else:
            normal_iocs, warning_iocs, input_display = process_single_input(args)

        # Display and save results
        display_results(normal_iocs, warning_iocs)
        save_output(args, normal_iocs, warning_iocs, input_display)

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e!s}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
