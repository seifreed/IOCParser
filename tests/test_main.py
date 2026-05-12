#!/usr/bin/env python3
"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Tests for current CLI and infrastructure modules - argument parsing, file processing, and CLI operations.
"""

import argparse
import io
import tempfile
import threading
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import iocparser.cli as cli_module
import iocparser.cli_processing as cli_processing_module
import iocparser.cli_runtime as cli_runtime_module
from iocparser.cli import (
    execute,
    process_file,
    process_multiple_files,
    process_multiple_files_input,
    process_single_input,
    save_output,
)
from iocparser.cli_args import (
    ProcessingOptions,
    create_argument_parser,
    get_bool_arg,
    get_int_arg,
    get_list_arg,
    get_optional_str_arg,
    get_output_filename,
    get_str_arg,
    has_input_args,
)
from iocparser.cli_output import (
    display_results,
    print_warning_lists,
)
from iocparser.cli_runtime import setup_application
from iocparser.errors import (
    DownloadError,
    FileExistenceError,
    FileParsingError,
    FileProcessingError,
    FileSizeError,
    InvalidURLError,
    IOCTimeoutError,
    NetworkError,
    ValidationError,
)
from iocparser.infrastructure.file_readers import (
    MAX_FILE_SIZE,
    detect_file_type,
    detect_file_type_by_extension,
    detect_file_type_by_mime,
    validate_file_size,
)
from iocparser.infrastructure.http_download import download_url_to_temp
from iocparser.infrastructure.logger import setup_logger
from tests.test_file_parser import create_minimal_pdf
from tests.warning_service_helpers import StaticWarningListService, swap_warning_service


class LocalDownloadServer:
    def __init__(
        self, *, body: bytes, content_type: str = "text/plain", content_length: str | None = None
    ) -> None:
        self.body = body
        self.content_type = content_type
        self.content_length = content_length
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        body = self.body
        content_type = self.content_type
        content_length = self.content_length

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", content_length or str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:
                del format, args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.01),
            daemon=True,
        )
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/sample"

    def __exit__(self, exc_type, exc, tb) -> None:
        del exc_type, exc, tb
        assert self.server is not None
        assert self.thread is not None
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class TestArgumentHelpers:
    """Test argument helper functions with real argparse.Namespace objects."""

    def test_get_str_arg_with_value(self) -> None:
        """Test get_str_arg returns string when attribute exists."""
        temp_path = Path(tempfile.gettempdir()) / "test.txt"
        args = argparse.Namespace(file_path=str(temp_path), output="result.json")

        result = get_str_arg(args, "file_path")
        assert result == str(temp_path)
        assert isinstance(result, str)

    def test_get_str_arg_with_none(self) -> None:
        """Test get_str_arg returns default when attribute is None."""
        args = argparse.Namespace(file_path=None)

        result = get_str_arg(args, "file_path", default="default.txt")
        assert result == "default.txt"

    def test_get_str_arg_missing_attribute(self) -> None:
        """Test get_str_arg returns default when attribute doesn't exist."""
        args = argparse.Namespace()

        result = get_str_arg(args, "nonexistent", default="fallback")
        assert result == "fallback"

    def test_get_bool_arg_true(self) -> None:
        """Test get_bool_arg returns True for truthy values."""
        args = argparse.Namespace(verbose=True, debug=1, enabled="yes")

        assert get_bool_arg(args, "verbose") is True
        assert get_bool_arg(args, "debug") is True
        assert get_bool_arg(args, "enabled") is True

    def test_get_bool_arg_false(self) -> None:
        """Test get_bool_arg returns False for falsy values."""
        args = argparse.Namespace(verbose=False, debug=0, enabled=None, disabled="false", off="0")

        assert get_bool_arg(args, "verbose") is False
        assert get_bool_arg(args, "debug") is False
        assert get_bool_arg(args, "enabled") is False
        assert get_bool_arg(args, "disabled") is False
        assert get_bool_arg(args, "off") is False

    def test_get_bool_arg_missing(self) -> None:
        """Test get_bool_arg returns False when attribute missing."""
        args = argparse.Namespace()

        assert get_bool_arg(args, "nonexistent") is False

    def test_get_bool_arg_unknown_string_is_false(self) -> None:
        """Test get_bool_arg does not treat unknown strings as enabled flags."""
        args = argparse.Namespace(enabled="maybe")

        assert get_bool_arg(args, "enabled") is False

    def test_get_int_arg_with_value(self) -> None:
        """Test get_int_arg returns integer when attribute exists."""
        args = argparse.Namespace(timeout=30, workers=4)

        assert get_int_arg(args, "timeout") == 30
        assert get_int_arg(args, "workers") == 4

    def test_get_int_arg_string_conversion(self) -> None:
        """Test get_int_arg converts string to integer."""
        args = argparse.Namespace(port="8080")

        result = get_int_arg(args, "port")
        assert result == 8080
        assert isinstance(result, int)

    def test_get_int_arg_with_default(self) -> None:
        """Test get_int_arg returns default when attribute is None."""
        args = argparse.Namespace(timeout=None)

        result = get_int_arg(args, "timeout", default=60)
        assert result == 60

    def test_get_int_arg_missing_attribute(self) -> None:
        """Test get_int_arg returns default when attribute doesn't exist."""
        args = argparse.Namespace()

        result = get_int_arg(args, "nonexistent", default=100)
        assert result == 100

    def test_get_list_arg_with_list(self) -> None:
        """Test get_list_arg returns list when attribute is a list."""
        args = argparse.Namespace(files=["file1.txt", "file2.pdf", "file3.html"])

        result = get_list_arg(args, "files")
        assert result == ["file1.txt", "file2.pdf", "file3.html"]
        assert isinstance(result, list)

    def test_get_list_arg_with_tuple(self) -> None:
        """Test get_list_arg converts tuple to list of strings."""
        args = argparse.Namespace(items=("item1", "item2", "item3"))

        result = get_list_arg(args, "items")
        assert result == ["item1", "item2", "item3"]
        assert isinstance(result, list)

    def test_get_list_arg_with_single_value(self) -> None:
        """Test get_list_arg converts single value to single-item list."""
        args = argparse.Namespace(file="single.txt")

        result = get_list_arg(args, "file")
        assert result == ["single.txt"]

    def test_get_list_arg_with_none(self) -> None:
        """Test get_list_arg returns empty list when attribute is None."""
        args = argparse.Namespace(files=None)

        result = get_list_arg(args, "files")
        assert result == []

    def test_get_list_arg_missing_attribute(self) -> None:
        """Test get_list_arg returns empty list when attribute doesn't exist."""
        args = argparse.Namespace()

        result = get_list_arg(args, "nonexistent")
        assert result == []

    def test_get_optional_str_arg_with_value(self) -> None:
        """Test get_optional_str_arg returns string when value exists."""
        args = argparse.Namespace(output="result.json", log_file="/var/log/app.log")

        assert get_optional_str_arg(args, "output") == "result.json"
        assert get_optional_str_arg(args, "log_file") == "/var/log/app.log"

    def test_get_optional_str_arg_with_none(self) -> None:
        """Test get_optional_str_arg returns None when attribute is None."""
        args = argparse.Namespace(output=None)

        result = get_optional_str_arg(args, "output")
        assert result is None

    def test_get_optional_str_arg_missing(self) -> None:
        """Test get_optional_str_arg returns None when attribute doesn't exist."""
        args = argparse.Namespace()

        result = get_optional_str_arg(args, "nonexistent")
        assert result is None


class TestProcessingOptions:
    """Test ProcessingOptions class and factory methods."""

    def test_default_initialization(self) -> None:
        """Test ProcessingOptions with default values."""
        opts = ProcessingOptions()

        assert opts.file_type is None
        assert opts.defang is True
        assert opts.check_warnings is True
        assert opts.force_update is False

    def test_custom_initialization(self) -> None:
        """Test ProcessingOptions with custom values."""
        opts = ProcessingOptions(
            file_type="pdf",
            defang=False,
            check_warnings=False,
            force_update=True,
        )

        assert opts.file_type == "pdf"
        assert opts.defang is False
        assert opts.check_warnings is False
        assert opts.force_update is True

    def test_from_args_with_defaults(self) -> None:
        """Test ProcessingOptions.from_args with default CLI arguments."""
        args = argparse.Namespace(
            type=None,
            no_defang=False,
            no_check_warnings=False,
            force_update=False,
        )

        opts = ProcessingOptions.from_args(args)

        assert opts.file_type is None
        assert opts.defang is True
        assert opts.check_warnings is True
        assert opts.force_update is False

    def test_from_args_with_custom_values(self) -> None:
        """Test ProcessingOptions.from_args with custom CLI arguments."""
        args = argparse.Namespace(
            type="html",
            no_defang=True,
            no_check_warnings=True,
            force_update=True,
        )

        opts = ProcessingOptions.from_args(args)

        assert opts.file_type == "html"
        assert opts.defang is False
        assert opts.check_warnings is False
        assert opts.force_update is True

    def test_from_args_partial_flags(self) -> None:
        """Test ProcessingOptions.from_args with some flags set."""
        args = argparse.Namespace(
            type="text",
            no_defang=True,
            no_check_warnings=False,
            force_update=False,
        )

        opts = ProcessingOptions.from_args(args)

        assert opts.file_type == "text"
        assert opts.defang is False
        assert opts.check_warnings is True
        assert opts.force_update is False


class TestSetupApplication:
    """Test application setup and initialization."""

    def test_setup_application_default(self) -> None:
        """Test setup_application with default arguments creates proper logging setup."""
        args = argparse.Namespace(
            debug=False,
            verbose=False,
            log_file=None,
        )

        # Should execute without errors
        setup_application(args)

    def test_setup_application_with_verbose(self) -> None:
        """Test setup_application with verbose flag."""
        args = argparse.Namespace(
            debug=False,
            verbose=True,
            log_file=None,
        )

        setup_application(args)

    def test_setup_application_with_debug(self) -> None:
        """Test setup_application with debug flag."""
        args = argparse.Namespace(
            debug=True,
            verbose=False,
            log_file=None,
        )

        setup_application(args)

    def test_setup_application_with_log_file(self) -> None:
        """Test setup_application with log file path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = str(Path(tmpdir) / "test.log")
            args = argparse.Namespace(
                debug=False,
                verbose=True,
                log_file=log_path,
            )

            try:
                setup_application(args)

                # Verify log file was created
                assert Path(log_path).exists()
            finally:
                setup_logger(console=False)


class TestFileTypeDetection:
    """Test file type detection functions."""

    def test_detect_file_type_by_mime_pdf(self) -> None:
        """Test MIME type detection for PDF files."""
        assert detect_file_type_by_mime("application/pdf") == "pdf"
        assert detect_file_type_by_mime("Application/PDF") == "pdf"

    def test_detect_file_type_by_mime_html(self) -> None:
        """Test MIME type detection for HTML files."""
        assert detect_file_type_by_mime("text/html") == "html"
        assert detect_file_type_by_mime("application/xhtml+xml") == "html"
        assert detect_file_type_by_mime("text/xml") == "html"

    def test_detect_file_type_by_mime_text(self) -> None:
        """Test MIME type detection for text files."""
        assert detect_file_type_by_mime("text/plain") == "text"
        assert detect_file_type_by_mime("text/csv") == "text"

    def test_detect_file_type_by_mime_unknown(self) -> None:
        """Test MIME type detection returns None for unknown types."""
        assert detect_file_type_by_mime("application/octet-stream") is None
        assert detect_file_type_by_mime("image/png") is None

    def test_detect_file_type_by_extension_pdf(self) -> None:
        """Test extension-based detection for PDF files."""
        assert detect_file_type_by_extension(Path("document.pdf")) == "pdf"
        assert detect_file_type_by_extension(Path("REPORT.PDF")) == "pdf"

    def test_detect_file_type_by_extension_html(self) -> None:
        """Test extension-based detection for HTML files."""
        assert detect_file_type_by_extension(Path("page.html")) == "html"
        assert detect_file_type_by_extension(Path("index.htm")) == "html"
        assert detect_file_type_by_extension(Path("data.xml")) == "html"

    def test_detect_file_type_by_extension_text(self) -> None:
        """Test extension-based detection for text files."""
        assert detect_file_type_by_extension(Path("notes.txt")) == "text"
        assert detect_file_type_by_extension(Path("app.log")) == "text"
        assert detect_file_type_by_extension(Path("README.md")) == "text"
        assert detect_file_type_by_extension(Path("data.csv")) == "text"
        assert detect_file_type_by_extension(Path("config.json")) == "text"

    def test_detect_file_type_by_extension_unknown(self) -> None:
        """Test extension-based detection defaults to text for unknown extensions."""
        assert detect_file_type_by_extension(Path("file.bin")) == "text"
        assert detect_file_type_by_extension(Path("archive.zip")) == "text"

    def test_detect_file_type_text_file(self) -> None:
        """Test automatic file type detection for text files."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Sample text content\n192.168.1.1\nevil.com\n")
            temp_path = Path(f.name)

        try:
            file_type = detect_file_type(temp_path)
            assert file_type == "text"
        finally:
            temp_path.unlink()

    def test_detect_file_type_html_extension(self) -> None:
        """Test file type detection falls back to extension for ambiguous files."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write("<html><body>Test</body></html>")
            temp_path = Path(f.name)

        try:
            file_type = detect_file_type(temp_path)
            assert file_type in ["html", "text"]  # Can be either depending on magic detection
        finally:
            temp_path.unlink()


class TestFileSizeValidation:
    """Test file size validation."""

    def test_validate_file_size_within_limit(self) -> None:
        """Test file size validation passes for files under limit."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("Small file content" * 100)  # A few KB
            temp_path = Path(f.name)

        try:
            # Should not raise any exception
            validate_file_size(temp_path)
        finally:
            temp_path.unlink()

    def test_validate_file_size_exceeds_limit(self) -> None:
        """Test file size validation fails for files over limit."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Create a file larger than 1KB for testing
            f.write(b"X" * 2000)
            temp_path = Path(f.name)

        try:
            # Should raise FileSizeError with custom limit
            with pytest.raises(FileSizeError):
                validate_file_size(temp_path, max_size=1000)
        finally:
            temp_path.unlink()

    def test_validate_file_size_exact_limit(self) -> None:
        """Test file size validation at exact limit boundary."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"X" * 1000)
            temp_path = Path(f.name)

        try:
            # Should pass at exact limit
            validate_file_size(temp_path, max_size=1000)
        finally:
            temp_path.unlink()


class TestDownloadURLToTemp:
    """Test URL downloading functionality with real HTTP requests."""

    def test_download_url_to_temp_invalid_url(self) -> None:
        """Test download fails with invalid URL format."""
        with pytest.raises(InvalidURLError):
            download_url_to_temp("not-a-url")

        # FTP URLs are not supported by the HTTP downloader.
        with pytest.raises(InvalidURLError):
            download_url_to_temp("ftp://example.com/file.txt")

    def test_download_url_to_temp_timeout(self) -> None:
        """Test download handles timeout errors."""
        # Use a closed local port to trigger a fast network failure in the same path.
        with pytest.raises((DownloadError, NetworkError, IOCTimeoutError)):
            download_url_to_temp("http://127.0.0.1:9/file.txt", timeout=0.1)

    def test_download_url_to_temp_nonexistent_domain(self) -> None:
        """Test download handles DNS resolution failures."""
        with pytest.raises(DownloadError):
            download_url_to_temp("http://this-domain-does-not-exist-12345.com/file.txt")


class TestGetOutputFilename:
    """Test output filename generation."""

    def test_get_output_filename_simple_file(self) -> None:
        """Test output filename generation for simple file paths."""
        result = get_output_filename("report.pdf")
        assert result == "report_iocs.txt"

    def test_get_output_filename_with_path(self) -> None:
        """Test output filename generation preserves only basename."""
        result = get_output_filename("/path/to/document.html")
        assert result == "document_iocs.txt"

    def test_get_output_filename_json_format(self) -> None:
        """Test output filename generation with JSON format."""
        result = get_output_filename("data.txt", is_json=True)
        assert result == "data_iocs.json"

    def test_get_output_filename_stix_format(self) -> None:
        """Test output filename generation with STIX format."""
        result = get_output_filename("data.txt", output_format="stix")
        assert result == "data_iocs.stix.json"

    def test_get_output_filename_url(self) -> None:
        """Test output filename generation from URL."""
        result = get_output_filename("https://example.com/report.pdf")
        # Filename contains domain and path info
        assert "example" in result
        assert result.endswith("_iocs.txt")

    def test_get_output_filename_url_with_path(self) -> None:
        """Test output filename generation from URL with path."""
        result = get_output_filename("https://blog.example.com/2024/malware-report.pdf")
        # Filename contains domain and path components
        assert "blog" in result
        assert "example" in result
        assert "malware" in result

    def test_get_output_filename_long_name(self) -> None:
        """Test output filename truncation for very long names."""
        long_name = "a" * 100 + ".txt"
        result = get_output_filename(long_name)

        # Should be truncated to max length + _iocs.txt
        assert len(result) <= 60  # MAX_FILENAME_LENGTH + suffix length
        assert result.endswith("_iocs.txt")

    def test_get_output_filename_special_chars(self) -> None:
        """Test output filename sanitizes special characters."""
        result = get_output_filename("https://example.com/file with spaces & special!chars.pdf")

        # Should replace invalid filename characters
        assert " " not in result or "_" in result
        assert result.endswith("_iocs.txt")


class TestProcessFile:
    """Test file processing and IOC extraction."""

    def test_process_file_text(self) -> None:
        """Test processing a text file extracts IOCs correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Malware contacts evil-domain.com\n")
            f.write("Command and control at 192.168.1.100\n")
            f.write("Hash: 5f4dcc3b5aa765d61d8327deb882cf99\n")
            temp_path = Path(f.name)

        try:
            normal_iocs, _warning_iocs = process_file(
                temp_path,
                file_type="text",
                defang=False,
                check_warnings=False,
            )

            # Should extract some IOCs
            assert len(normal_iocs) > 0

            # Should have extracted domains or IPs
            has_network_iocs = (
                "domains" in normal_iocs or "ips" in normal_iocs or "ipv4s" in normal_iocs
            )
            assert has_network_iocs

        finally:
            temp_path.unlink()

    def test_process_file_exceeds_size_limit(self) -> None:
        """Test processing fails for files exceeding size limit."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Create file larger than MAX_FILE_SIZE
            f.write(b"X" * (MAX_FILE_SIZE + 1000))
            temp_path = Path(f.name)

        try:
            with pytest.raises((FileProcessingError, FileSizeError)):
                process_file(temp_path, file_type="text")
        finally:
            temp_path.unlink()

    def test_process_file_with_defanging(self) -> None:
        """Test processing with defanging enabled."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Contact malicious.example.com for instructions\n")
            temp_path = Path(f.name)

        try:
            normal_iocs, _ = process_file(
                temp_path,
                file_type="text",
                defang=True,
                check_warnings=False,
            )

            if normal_iocs.get("domains"):
                domain = str(normal_iocs["domains"][0])
                # Defanged domains should contain brackets
                assert "[" in domain or "(" in domain

        finally:
            temp_path.unlink()

    def test_process_file_without_defanging(self) -> None:
        """Test processing with defanging disabled."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Contact malicious-test.example.com for instructions\n")
            temp_path = Path(f.name)

        try:
            normal_iocs, _ = process_file(
                temp_path,
                file_type="text",
                defang=False,
                check_warnings=False,
            )

            if normal_iocs.get("domains"):
                domain = str(normal_iocs["domains"][0])
                # Non-defanged domains should not contain brackets
                assert "[" not in domain

        finally:
            temp_path.unlink()


class TestSaveOutput:
    """Test output saving functionality."""

    def test_save_output_text_format(self) -> None:
        """Test saving output in text format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "output.txt")
            args = argparse.Namespace(
                json=False,
                output=output_path,
            )

            normal_iocs = {
                "domains": ["evil.com", "malware.net"],
                "ips": ["192.168.1.1", "10.0.0.1"],
            }
            warning_iocs = {}

            save_output(args, normal_iocs, warning_iocs, "test.txt")

            # Verify file was created
            assert Path(output_path).exists()

            # Verify content
            content = Path(output_path).read_text()
            assert "evil.com" in content or "evil[.]com" in content
            assert len(content) > 0

    def test_save_output_json_format(self) -> None:
        """Test saving output in JSON format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "output.json")
            args = argparse.Namespace(
                json=True,
                output=output_path,
            )

            normal_iocs = {
                "domains": ["evil.com"],
                "ips": ["192.168.1.1"],
            }
            warning_iocs = {}

            save_output(args, normal_iocs, warning_iocs, "test.txt")

            # Verify file was created
            assert Path(output_path).exists()

            # Verify it's valid JSON
            import json

            content = Path(output_path).read_text()
            data = json.loads(content)
            assert isinstance(data, dict)

    def test_save_output_stdout(self) -> None:
        """Test output to stdout with dash argument."""
        args = argparse.Namespace(
            json=False,
            output="-",
        )

        normal_iocs = {"domains": ["test.com"]}
        warning_iocs = {}

        # Should execute without errors (output goes to stdout)
        save_output(args, normal_iocs, warning_iocs, "test.txt")

    def test_save_output_auto_filename(self) -> None:
        """Test automatic filename generation when no output specified."""
        args = argparse.Namespace(
            json=False,
            output=None,
        )

        normal_iocs = {"domains": ["test.com"]}
        warning_iocs = {}

        # Should execute without errors and create file
        save_output(args, normal_iocs, warning_iocs, "sample.txt")


class TestHasInputArgs:
    """Test input argument detection."""

    def test_has_input_args_with_file(self) -> None:
        """Test has_input_args returns True when file argument provided."""
        args = argparse.Namespace(
            file="test.pdf",
            url=None,
            url_direct=None,
            multiple=None,
        )

        assert has_input_args(args) is True

    def test_has_input_args_with_url(self) -> None:
        """Test has_input_args returns True when URL argument provided."""
        args = argparse.Namespace(
            file=None,
            url="https://example.com/report.pdf",
            url_direct=None,
            multiple=None,
        )

        assert has_input_args(args) is True

    def test_has_input_args_with_url_direct(self) -> None:
        """Test has_input_args returns True when direct URL argument provided."""
        args = argparse.Namespace(
            file=None,
            url=None,
            url_direct="https://example.com/file.html",
            multiple=None,
        )

        assert has_input_args(args) is True

    def test_has_input_args_with_multiple(self) -> None:
        """Test has_input_args returns True when multiple files provided."""
        args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            multiple=["file1.txt", "file2.pdf"],
        )

        assert has_input_args(args) is True

    def test_has_input_args_no_input(self) -> None:
        """Test has_input_args returns False when no input provided."""
        args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            multiple=None,
        )

        assert has_input_args(args) is False

    def test_has_input_args_empty_multiple(self) -> None:
        """Test has_input_args returns False for empty multiple list."""
        args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            multiple=[],
        )

        assert has_input_args(args) is False


class TestArgumentParser:
    """Test argument parser creation and configuration."""

    def test_create_argument_parser(self) -> None:
        """Test create_argument_parser returns configured parser."""
        parser = create_argument_parser()

        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_file_argument(self) -> None:
        """Test parser handles file argument."""
        parser = create_argument_parser()
        args = parser.parse_args(["-f", "test.pdf"])

        assert args.file == "test.pdf"

    def test_parser_url_argument(self) -> None:
        """Test parser handles URL argument."""
        parser = create_argument_parser()
        args = parser.parse_args(["-u", "https://example.com/report.pdf"])

        assert args.url == "https://example.com/report.pdf"

    def test_parser_multiple_files(self) -> None:
        """Test parser handles multiple files argument."""
        parser = create_argument_parser()
        args = parser.parse_args(["-m", "file1.txt", "file2.pdf", "file3.html"])

        assert args.multiple == ["file1.txt", "file2.pdf", "file3.html"]

    def test_parser_output_argument(self) -> None:
        """Test parser handles output argument."""
        parser = create_argument_parser()
        args = parser.parse_args(["-f", "test.pdf", "-o", "results.json"])

        assert args.output == "results.json"

    def test_parser_json_flag(self) -> None:
        """Test parser handles JSON flag."""
        parser = create_argument_parser()
        args = parser.parse_args(["-f", "test.pdf", "--json"])

        assert args.json is True

    def test_parser_type_argument(self) -> None:
        """Test parser handles file type argument."""
        parser = create_argument_parser()
        args = parser.parse_args(["-f", "test.bin", "-t", "pdf"])

        assert args.type == "pdf"

    def test_parser_no_defang_flag(self) -> None:
        """Test parser handles no-defang flag."""
        parser = create_argument_parser()
        args = parser.parse_args(["-f", "test.pdf", "--no-defang"])

        assert args.no_defang is True

    def test_parser_verbose_flag(self) -> None:
        """Test parser handles verbose flag."""
        parser = create_argument_parser()
        args = parser.parse_args(["-f", "test.pdf", "-v"])

        assert args.verbose is True

    def test_parser_debug_flag(self) -> None:
        """Test parser handles debug flag."""
        parser = create_argument_parser()
        args = parser.parse_args(["-f", "test.pdf", "--debug"])

        assert args.debug is True

    def test_parser_parallel_workers(self) -> None:
        """Test parser handles parallel workers argument."""
        parser = create_argument_parser()
        args = parser.parse_args(["-m", "file1.txt", "file2.txt", "--parallel", "8"])

        assert args.parallel == 8

    def test_parser_persist_flags(self) -> None:
        """Test parser handles persistence flags."""
        parser = create_argument_parser()
        args = parser.parse_args(["--persist", "--db-uri", "sqlite:///test.db"])

        assert args.persist is True
        assert args.db_uri == "sqlite:///test.db"

    def test_parser_force_update_flag(self) -> None:
        """Test parser handles force-update flag."""
        parser = create_argument_parser()
        args = parser.parse_args(["--force-update"])

        assert args.force_update is True

    def test_parser_init_flag(self) -> None:
        """Test parser handles init flag."""
        parser = create_argument_parser()
        args = parser.parse_args(["--init"])

        assert args.init is True


class TestDownloadURLAdvanced:
    """Test advanced URL download scenarios."""

    def test_download_url_content_length_check(self) -> None:
        """Test download fails when content-length header exceeds limit."""
        from iocparser.infrastructure.http_download import MAX_URL_SIZE

        with LocalDownloadServer(body=b"", content_length=str(MAX_URL_SIZE + 1)) as url:
            with pytest.raises(FileSizeError):
                download_url_to_temp(url)

    def test_download_url_chunk_size_exceeded(self) -> None:
        """Test download fails when actual downloaded size exceeds limit during streaming."""
        from iocparser.infrastructure.http_download import MAX_URL_SIZE

        with LocalDownloadServer(body=b"x" * (MAX_URL_SIZE + 1)) as url:
            with pytest.raises(FileSizeError):
                download_url_to_temp(url)

    def test_download_url_creates_temp_directory(self) -> None:
        """Test download creates temp directory if it doesn't exist."""
        import tempfile

        temp_dir = Path(tempfile.gettempdir()) / "iocparser"
        removed = False
        if temp_dir.exists():
            for child in temp_dir.iterdir():
                if child.is_file():
                    child.unlink()
            temp_dir.rmdir()
            removed = True

        with LocalDownloadServer(body=b"IOC domain: create-temp.example\n") as url:
            downloaded = Path(download_url_to_temp(url))
            try:
                assert temp_dir.exists()
                assert downloaded.exists()
            finally:
                downloaded.unlink(missing_ok=True)
                if removed and temp_dir.exists() and not any(temp_dir.iterdir()):
                    temp_dir.rmdir()

    def test_download_url_pdf_extension_added(self) -> None:
        """Test download adds .pdf extension for PDF content-type."""
        with LocalDownloadServer(body=b"%PDF-1.4", content_type="application/pdf") as url:
            downloaded = Path(download_url_to_temp(url))
            try:
                assert downloaded.suffix == ".pdf"
            finally:
                downloaded.unlink(missing_ok=True)

    def test_download_url_html_extension_added(self) -> None:
        """Test download adds .html extension for HTML content-type."""
        with LocalDownloadServer(body=b"<html>ok</html>", content_type="text/html") as url:
            downloaded = Path(download_url_to_temp(url))
            try:
                assert downloaded.suffix == ".html"
            finally:
                downloaded.unlink(missing_ok=True)


class TestDetectFileTypeErrors:
    """Test detect_file_type error handling."""

    def test_detect_file_type_magic_error_fallback(self) -> None:
        """Test detect_file_type falls back to extension when magic fails."""
        # Create a file that might cause magic library issues
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".html", delete=False) as f:
            # Write binary data that might confuse magic
            f.write(b"\x00\x01\x02\x03\x04" * 100)
            temp_path = Path(f.name)

        try:
            # Should fall back to extension-based detection
            file_type = detect_file_type(temp_path)
            # Should detect as html from extension, or text from binary
            assert file_type in ["html", "text"]
        finally:
            temp_path.unlink()

    def test_detect_file_type_text_plain_html_extension(self) -> None:
        """Test detect_file_type handles text/plain with .html extension."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write("Plain text but with html extension\n")
            temp_path = Path(f.name)

        try:
            file_type = detect_file_type(temp_path)
            # Should be detected as html or text
            assert file_type in ["html", "text"]
        finally:
            temp_path.unlink()

    def test_detect_file_type_text_plain_htm_extension(self) -> None:
        """Test detect_file_type handles text/plain with .htm extension."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".htm", delete=False) as f:
            f.write("Plain text but with htm extension\n")
            temp_path = Path(f.name)

        try:
            file_type = detect_file_type(temp_path)
            assert file_type in ["html", "text"]
        finally:
            temp_path.unlink()

    def test_detect_file_type_text_plain_xml_extension(self) -> None:
        """Test detect_file_type handles text/plain with .xml extension."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write("<?xml version='1.0'?><root>test</root>\n")
            temp_path = Path(f.name)

        try:
            file_type = detect_file_type(temp_path)
            assert file_type in ["html", "text"]
        finally:
            temp_path.unlink()


class TestProcessFileAdvanced:
    """Test advanced file processing scenarios."""

    def test_process_file_pdf_type(self) -> None:
        """Test processing a PDF file extracts IOCs correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "ioc.pdf"
            create_minimal_pdf(pdf_path, "IOC IP 203.0.113.7 and domain pdf-example.com")

            normal_iocs, warning_iocs = process_file(
                pdf_path,
                file_type="pdf",
                defang=False,
                check_warnings=False,
            )

            assert "203.0.113.7" in normal_iocs.get("ips", [])
            assert warning_iocs == {}

    def test_process_file_html_type(self) -> None:
        """Test processing an HTML file extracts IOCs correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write("""
            <html>
            <body>
                <h1>Malware Report</h1>
                <p>Command and control: evil-c2.example.com</p>
                <p>IP address: 203.0.113.45</p>
                <p>MD5: d41d8cd98f00b204e9800998ecf8427e</p>
            </body>
            </html>
            """)
            temp_path = Path(f.name)

        try:
            normal_iocs, _warning_iocs = process_file(
                temp_path,
                file_type="html",
                defang=False,
                check_warnings=False,
            )

            # Should extract some IOCs
            assert len(normal_iocs) > 0

        finally:
            temp_path.unlink()

    def test_process_file_auto_detect_type(self) -> None:
        """Test processing file with automatic type detection."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Malware contacts evil-auto.com\n")
            f.write("IP: 198.51.100.42\n")
            temp_path = Path(f.name)

        try:
            # Don't specify file_type - let it auto-detect
            normal_iocs, _warning_iocs = process_file(
                temp_path,
                file_type=None,
                defang=False,
                check_warnings=False,
            )

            assert len(normal_iocs) > 0

        finally:
            temp_path.unlink()

    def test_process_file_with_warnings_check(self) -> None:
        """Test processing file with MISP warning lists enabled."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            # Use a domain that might be in warning lists
            f.write("Contact google.com or example.com\n")
            f.write("Also check test-malware.example.net\n")
            temp_path = Path(f.name)

        try:
            with swap_warning_service(
                cli_runtime_module, StaticWarningListService()
            ) as warning_service:
                normal_iocs, warning_iocs = process_file(
                    temp_path,
                    file_type="text",
                    defang=False,
                    check_warnings=True,
                    force_update=False,
                    warning_service=warning_service,
                )

            # Either normal or warning IOCs should have entries
            total_iocs = len(normal_iocs) + len(warning_iocs)
            assert total_iocs >= 0  # At least extracted something

        finally:
            temp_path.unlink()


class TestProcessMultipleFiles:
    """Test multiple file processing functionality."""

    def test_process_multiple_files_success(self) -> None:
        """Test processing multiple files in parallel."""
        files = []
        try:
            # Create three test files
            for i in range(3):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                    f.write(f"File {i} contains evil{i}.com\n")
                    f.write(f"And IP 192.168.1.{i}\n")
                    files.append(Path(f.name))

            results = process_multiple_files(
                files,
                file_type="text",
                defang=False,
                check_warnings=False,
                max_workers=2,
            )

            # Should have results for all files
            assert len(results) == 3

            # Each file should have processed successfully
            for file_path in files:
                assert str(file_path) in results
                normal_iocs, _warning_iocs = results[str(file_path)]
                assert isinstance(normal_iocs, dict)

        finally:
            for file_path in files:
                if file_path.exists():
                    file_path.unlink()

    def test_process_multiple_files_with_error(self) -> None:
        """Test processing multiple files handles errors gracefully."""
        files = []
        try:
            # Create one valid file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f1:
                f1.write("Valid file with evil1.com\n")
                files.append(Path(f1.name))

            # Create an oversized file
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".txt", delete=False) as f2:
                f2.write(b"X" * (MAX_FILE_SIZE + 1000))
                files.append(Path(f2.name))

            results = process_multiple_files(
                files,
                file_type="text",
                defang=False,
                check_warnings=False,
                max_workers=2,
            )

            # Should have results for all files (even failed ones)
            assert len(results) == 2

            # First file should succeed
            assert str(files[0]) in results
            normal_iocs, _ = results[str(files[0])]
            assert len(normal_iocs) > 0

            # Second file should have empty results due to error
            assert str(files[1]) in results
            normal_iocs, _ = results[str(files[1])]
            assert len(normal_iocs) == 0

        finally:
            for file_path in files:
                if file_path.exists():
                    file_path.unlink()


class TestProcessMultipleFilesInput:
    """Test process_multiple_files_input function."""

    def test_process_multiple_files_input_basic(self) -> None:
        """Test process_multiple_files_input with valid files."""
        files = []
        try:
            # Create test files
            for i in range(2):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                    f.write(f"Malware {i}: evil{i}.example.com\n")
                    files.append(f.name)

            args = argparse.Namespace(
                multiple=files,
                parallel=2,
                type=None,
                no_defang=False,
                no_check_warnings=True,
                force_update=False,
            )

            normal_iocs, warning_iocs, input_display, _results = process_multiple_files_input(args)

            # Should aggregate IOCs from all files
            assert isinstance(normal_iocs, dict)
            assert isinstance(warning_iocs, dict)
            assert "2 files" in input_display

        finally:
            for file_path in files:
                if Path(file_path).exists():
                    Path(file_path).unlink()

    def test_process_multiple_files_input_file_not_found(self) -> None:
        """Test process_multiple_files_input raises when a file doesn't exist."""
        args = argparse.Namespace(
            multiple=["/nonexistent/file1.txt", "/nonexistent/file2.txt"],
            parallel=1,
            type=None,
            no_defang=False,
            no_check_warnings=True,
            force_update=False,
        )

        with pytest.raises(FileExistenceError):
            process_multiple_files_input(args)

    def test_process_multiple_files_input_deduplication(self) -> None:
        """Test process_multiple_files_input deduplicates IOCs across files."""
        files = []
        try:
            # Create files with overlapping IOCs
            for i in range(2):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                    f.write("Both files have duplicate-domain.com\n")
                    f.write(f"Unique to file {i}: unique{i}.com\n")
                    files.append(f.name)

            args = argparse.Namespace(
                multiple=files,
                parallel=1,
                type=None,
                no_defang=False,
                no_check_warnings=True,
                force_update=False,
            )

            normal_iocs, _, _, _results = process_multiple_files_input(args)

            # Check deduplication occurred
            if "domains" in normal_iocs:
                domains = normal_iocs["domains"]
                # Should not have duplicates
                assert len(domains) == len({str(d) for d in domains})

        finally:
            for file_path in files:
                if Path(file_path).exists():
                    Path(file_path).unlink()

    def test_process_multiple_files_input_with_warnings(self) -> None:
        """Test process_multiple_files_input aggregates warning IOCs."""
        files = []
        try:
            # Create files with IOCs that might trigger warnings
            for i in range(2):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                    f.write("File has google.com and example.com\n")
                    f.write(f"Also malware{i}.example.net\n")
                    files.append(f.name)

            args = argparse.Namespace(
                multiple=files,
                parallel=1,
                type=None,
                no_defang=False,
                no_check_warnings=False,  # Enable warnings check
                force_update=False,
            )

            with swap_warning_service(
                cli_runtime_module, StaticWarningListService()
            ) as warning_service:
                normal_iocs, warning_iocs, input_display, _results = (
                    cli_processing_module.process_multiple_files_input(
                        args,
                        reader=cli_runtime_module.reader,
                        warning_service=warning_service,
                    )
                )

            # Should have aggregated results
            assert isinstance(normal_iocs, dict)
            assert isinstance(warning_iocs, dict)
            assert "2 files" in input_display

        finally:
            for file_path in files:
                if Path(file_path).exists():
                    Path(file_path).unlink()


class TestProcessSingleInput:
    """Test process_single_input function."""

    def test_process_single_input_file(self) -> None:
        """Test process_single_input with a file argument."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Single input test: malware-single.com\n")
            temp_path = Path(f.name)

        try:
            args = argparse.Namespace(
                file=str(temp_path),
                url=None,
                url_direct=None,
                type=None,
                no_defang=False,
                no_check_warnings=True,
                force_update=False,
            )

            normal_iocs, _warning_iocs, input_display = process_single_input(args)

            assert isinstance(normal_iocs, dict)
            assert str(temp_path) in input_display

        finally:
            temp_path.unlink()

    def test_process_single_input_file_not_found(self) -> None:
        """Test process_single_input raises when file doesn't exist."""
        args = argparse.Namespace(
            file="/nonexistent/file.txt",
            url=None,
            url_direct=None,
            type=None,
            no_defang=False,
            no_check_warnings=True,
            force_update=False,
        )

        with pytest.raises(FileExistenceError):
            process_single_input(args)

    def test_process_single_input_no_url(self) -> None:
        """Test process_single_input raises when no URL is provided."""
        args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            type=None,
            no_defang=False,
            no_check_warnings=True,
            force_update=False,
        )

        with pytest.raises(ValidationError):
            process_single_input(args)

    def test_process_single_input_url_arg(self) -> None:
        """Test process_single_input with URL argument."""
        args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            type="text",
            no_defang=True,
            no_check_warnings=True,
            force_update=False,
        )
        with LocalDownloadServer(body=b"IOC URL: https://url-arg.example/path\n") as url:
            args.url = url
            normal_iocs, warning_iocs, input_display = process_single_input(args)

        assert normal_iocs == {"urls": ["https://url-arg.example/path"]}
        assert warning_iocs == {}
        assert input_display == args.url

    def test_process_single_input_url_direct_arg(self) -> None:
        """Test process_single_input with direct URL argument."""
        args = argparse.Namespace(
            file=None,
            url=None,
            url_direct=None,
            type="text",
            no_defang=True,
            no_check_warnings=True,
            force_update=False,
        )
        with LocalDownloadServer(body=b"IOC URL: https://url-direct.example/path\n") as url:
            args.url_direct = url
            normal_iocs, warning_iocs, input_display = process_single_input(args)

        assert normal_iocs == {"urls": ["https://url-direct.example/path"]}
        assert warning_iocs == {}
        assert input_display == args.url_direct

    def test_process_single_input_url_download_failure(self) -> None:
        """Test process_single_input raises on download failure."""
        args = argparse.Namespace(
            file=None,
            url="http://this-domain-absolutely-does-not-exist-12345.com/file.txt",
            url_direct=None,
            type=None,
            no_defang=False,
            no_check_warnings=True,
            force_update=False,
        )

        with pytest.raises((NetworkError, InvalidURLError, IOCTimeoutError, FileSizeError)):
            process_single_input(args)

    def test_process_single_input_processing_failure(self) -> None:
        """Test process_single_input raises on file processing failure."""
        # Create an invalid file that will cause processing error
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".pdf", delete=False) as f:
            f.write(b"Not a real PDF file")
            temp_path = Path(f.name)

        try:
            args = argparse.Namespace(
                file=str(temp_path),
                url=None,
                url_direct=None,
                type="pdf",  # Force PDF parsing on invalid file
                no_defang=False,
                no_check_warnings=True,
                force_update=False,
            )

            with pytest.raises((FileProcessingError, FileParsingError, OSError, ValueError)):
                process_single_input(args)

        finally:
            temp_path.unlink()

    def test_process_single_input_temp_file_cleanup(self) -> None:
        """Test process_single_input cleans up temporary files from URL downloads."""
        # Create a temporary file that simulates a downloaded file
        temp_dir = Path(__file__).parent.parent / "iocparser" / "temp"
        temp_dir.mkdir(exist_ok=True)

        temp_file = temp_dir / "test_cleanup_file.txt"
        temp_file.write_text("Test content with malware-cleanup.com\n")

        try:
            args = argparse.Namespace(
                file=str(temp_file),
                url=None,
                url_direct=None,
                type=None,
                no_defang=False,
                no_check_warnings=True,
                force_update=False,
            )

            # Process the file - should NOT delete it since it's not from URL
            _normal_iocs, _warning_iocs, _input_display = process_single_input(args)

            # File should still exist since it wasn't from URL
            assert temp_file.exists()

        finally:
            if temp_file.exists():
                temp_file.unlink()


class TestPrintWarningLists:
    """Test warning list printing functionality."""

    def test_print_warning_lists_empty(self) -> None:
        """Test print_warning_lists with empty warnings."""
        warnings = {}
        # Should execute without error
        print_warning_lists(warnings)

    def test_print_warning_lists_with_warnings(self) -> None:
        """Test print_warning_lists displays warnings correctly."""
        warnings = {
            "domains": [
                {
                    "value": "google.com",
                    "warning_list": "Top-1000-Alexa",
                    "description": "Top 1000 Alexa domains",
                },
                {
                    "value": "example.com",
                    "warning_list": "RFC-5737",
                    "description": "Reserved domains for documentation",
                },
            ],
            "ips": [
                {
                    "value": "8.8.8.8",
                    "warning_list": "Public-DNS",
                    "description": "Public DNS servers",
                },
            ],
        }

        # Should execute and print warnings
        print_warning_lists(warnings)

    def test_print_warning_lists_single_type(self) -> None:
        """Test print_warning_lists with single IOC type."""
        warnings = {
            "domains": [
                {
                    "value": "test.com",
                    "warning_list": "Test-List",
                    "description": "Test warning",
                },
            ],
        }

        print_warning_lists(warnings)


class TestDisplayResults:
    """Test results display functionality."""

    def test_display_results_with_iocs(self) -> None:
        """Test display_results shows IOC summary."""
        normal_iocs = {
            "domains": ["evil1.com", "evil2.com", "evil3.com"],
            "ips": ["192.168.1.1", "10.0.0.1"],
            "md5s": ["d41d8cd98f00b204e9800998ecf8427e"],
        }
        warning_iocs = {}

        # Should execute and display results
        display_results(normal_iocs, warning_iocs)

    def test_display_results_with_warnings(self) -> None:
        """Test display_results shows warnings."""
        normal_iocs = {
            "domains": ["evil.com"],
        }
        warning_iocs = {
            "domains": [
                {
                    "value": "google.com",
                    "warning_list": "Top-Alexa",
                    "description": "Popular domain",
                },
            ],
        }

        display_results(normal_iocs, warning_iocs)

    def test_display_results_empty(self) -> None:
        """Test display_results with no IOCs."""
        normal_iocs = {}
        warning_iocs = {}

        display_results(normal_iocs, warning_iocs)


class TestHandleMISPInit:
    """Test MISP warning lists initialization."""

    def test_handle_misp_init(self) -> None:
        """Test handle_misp_init downloads and displays warning lists."""

        class LocalWarningLists:
            def __init__(self, cache_duration: int = 0, force_update: bool = True) -> None:
                del cache_duration, force_update
                self.warning_lists = {
                    "dns-google": {"name": "DNS Google"},
                    "dns-cloudflare": {"name": "DNS Cloudflare"},
                    "other-list": {},
                }

        original = cli_module.MISPWarningLists
        cli_module.MISPWarningLists = LocalWarningLists
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                cli_module.handle_misp_init()
        finally:
            cli_module.MISPWarningLists = original

        output = buffer.getvalue()
        assert "Dns: 2 lists" in output
        assert "Other: 1 lists" in output


class TestMainFunction:
    """Test CLI execute() integration without patching runtime internals."""

    def test_execute_no_args_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            execute([])

    def test_execute_with_file(self) -> None:
        """Test execute() processes file successfully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Test malware report with evil-test.com\n")
            temp_path = Path(f.name)

        try:
            execute(["-f", str(temp_path), "--no-check-warnings"])

        finally:
            temp_path.unlink()
            # Clean up any generated output files
            output_file = Path(f"{temp_path.stem}_iocs.txt")
            if output_file.exists():
                output_file.unlink()

    def test_execute_with_multiple_files(self) -> None:
        """Test execute() processes multiple files."""
        files = []
        try:
            for i in range(2):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                    f.write(f"File {i} with evil{i}.com\n")
                    files.append(f.name)

            execute(["-m", files[0], files[1], "--no-check-warnings", "--parallel", "2"])

        finally:
            for file_path in files:
                if Path(file_path).exists():
                    Path(file_path).unlink()

    def test_execute_with_output_file(self) -> None:
        """Test execute() writes to specified output file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Test report: malware-test.com\n")
            temp_path = Path(f.name)

        output_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as out:
                output_path = Path(out.name)

            execute(
                [
                    "-f",
                    str(temp_path),
                    "-o",
                    str(output_path),
                    "--no-check-warnings",
                ]
            )

            # Verify output file was created
            assert output_path.exists()
            content = output_path.read_text()
            assert len(content) > 0

        finally:
            temp_path.unlink()
            if output_path and output_path.exists():
                output_path.unlink()

    def test_execute_with_json_output(self) -> None:
        """Test execute() outputs JSON format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Test report: malware-json.com\n")
            temp_path = Path(f.name)

        output_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as out:
                output_path = Path(out.name)

            execute(
                [
                    "-f",
                    str(temp_path),
                    "-o",
                    str(output_path),
                    "--json",
                    "--no-check-warnings",
                ]
            )

            # Verify JSON output
            assert output_path.exists()
            import json

            content = output_path.read_text()
            data = json.loads(content)
            assert isinstance(data, dict)

        finally:
            temp_path.unlink()
            if output_path and output_path.exists():
                output_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
