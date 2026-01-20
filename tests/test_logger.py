#!/usr/bin/env python3

# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive unit tests for logger module

Tests cover ColoredFormatter, setup_logger with different configurations,
get_logger, and TTY detection - all using real logging infrastructure.

Author: Marc Rivero | @seifreed
"""

import logging
import sys
from pathlib import Path

import pytest

from iocparser.modules.logger import (
    ColoredFormatter,
    get_logger,
    setup_logger,
)


class TestColoredFormatter:
    """Test colored log formatting functionality."""

    def test_format_debug_level_with_color(self) -> None:
        """
        Test ColoredFormatter applies cyan color to DEBUG level.

        Validates that ANSI color codes are correctly applied to log records.
        """
        # Arrange: Create formatter and log record
        formatter = ColoredFormatter("%(levelname)s - %(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="test.py",
            lineno=1,
            msg="Debug message",
            args=(),
            exc_info=None,
        )

        # Act: Format the record
        formatted = formatter.format(record)

        # Assert: Should contain cyan color code and reset
        assert "\033[36m" in formatted  # Cyan color for DEBUG
        assert "\033[0m" in formatted  # Reset code
        assert "DEBUG" in formatted
        assert "Debug message" in formatted

    def test_format_info_level_with_color(self) -> None:
        """
        Test ColoredFormatter applies green color to INFO level.
        """
        # Arrange: Create formatter and INFO record
        formatter = ColoredFormatter("%(levelname)s - %(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Info message",
            args=(),
            exc_info=None,
        )

        # Act: Format the record
        formatted = formatter.format(record)

        # Assert: Should contain green color code
        assert "\033[32m" in formatted  # Green color for INFO
        assert "\033[0m" in formatted
        assert "INFO" in formatted

    def test_format_warning_level_with_color(self) -> None:
        """
        Test ColoredFormatter applies yellow color to WARNING level.
        """
        # Arrange: Create formatter and WARNING record
        formatter = ColoredFormatter("%(levelname)s - %(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Warning message",
            args=(),
            exc_info=None,
        )

        # Act: Format the record
        formatted = formatter.format(record)

        # Assert: Should contain yellow color code
        assert "\033[33m" in formatted  # Yellow color for WARNING
        assert "\033[0m" in formatted
        assert "WARNING" in formatted

    def test_format_error_level_with_color(self) -> None:
        """
        Test ColoredFormatter applies red color to ERROR level.
        """
        # Arrange: Create formatter and ERROR record
        formatter = ColoredFormatter("%(levelname)s - %(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error message",
            args=(),
            exc_info=None,
        )

        # Act: Format the record
        formatted = formatter.format(record)

        # Assert: Should contain red color code
        assert "\033[31m" in formatted  # Red color for ERROR
        assert "\033[0m" in formatted
        assert "ERROR" in formatted

    def test_format_critical_level_with_color(self) -> None:
        """
        Test ColoredFormatter applies magenta color to CRITICAL level.
        """
        # Arrange: Create formatter and CRITICAL record
        formatter = ColoredFormatter("%(levelname)s - %(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.CRITICAL,
            pathname="test.py",
            lineno=1,
            msg="Critical message",
            args=(),
            exc_info=None,
        )

        # Act: Format the record
        formatted = formatter.format(record)

        # Assert: Should contain magenta color code
        assert "\033[35m" in formatted  # Magenta color for CRITICAL
        assert "\033[0m" in formatted
        assert "CRITICAL" in formatted

    def test_format_preserves_message_content(self) -> None:
        """
        Test that ColoredFormatter preserves complete message content.

        Validates that formatting doesn't corrupt or truncate messages.
        """
        # Arrange: Create formatter with detailed format
        formatter = ColoredFormatter("%(levelname)s - %(message)s")
        long_message = "This is a detailed log message with special chars: @#$% 192.168.1.1"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg=long_message,
            args=(),
            exc_info=None,
        )

        # Act: Format the record
        formatted = formatter.format(record)

        # Assert: Full message should be present
        assert long_message in formatted
        assert "192.168.1.1" in formatted


class TestSetupLogger:
    """Test logger setup and configuration."""

    def test_setup_logger_creates_logger_with_default_name(self) -> None:
        """
        Test setup_logger creates logger with default 'iocparser' name.

        Validates basic logger creation with default parameters.
        """
        # Act: Setup logger with defaults
        logger = setup_logger()

        # Assert: Should create logger with correct name
        assert logger.name == "iocparser"
        assert isinstance(logger, logging.Logger)

    def test_setup_logger_creates_logger_with_custom_name(self) -> None:
        """
        Test setup_logger creates logger with custom name.
        """
        # Arrange: Use custom name
        custom_name = "test_custom_logger"

        # Act: Setup logger
        logger = setup_logger(name=custom_name)

        # Assert: Logger should have custom name
        assert logger.name == custom_name

    def test_setup_logger_sets_info_level_by_default(self) -> None:
        """
        Test setup_logger uses INFO level by default.

        Validates default logging level configuration.
        """
        # Act: Setup logger with defaults
        logger = setup_logger(name="test_info_default")

        # Assert: Should be set to INFO level
        assert logger.level == logging.INFO

    def test_setup_logger_sets_custom_debug_level(self) -> None:
        """
        Test setup_logger can be configured with DEBUG level.
        """
        # Act: Setup logger with DEBUG level
        logger = setup_logger(name="test_debug", level=logging.DEBUG)

        # Assert: Should be set to DEBUG level
        assert logger.level == logging.DEBUG

    def test_setup_logger_sets_custom_warning_level(self) -> None:
        """
        Test setup_logger can be configured with WARNING level.
        """
        # Act: Setup logger with WARNING level
        logger = setup_logger(name="test_warning", level=logging.WARNING)

        # Assert: Should be set to WARNING level
        assert logger.level == logging.WARNING

    def test_setup_logger_adds_console_handler_by_default(self) -> None:
        """
        Test setup_logger adds console handler when console=True.

        Validates that console output is configured by default.
        """
        # Act: Setup logger with default console=True
        logger = setup_logger(name="test_console_default")

        # Assert: Should have at least one handler (console)
        assert len(logger.handlers) > 0
        # Should have StreamHandler
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)

    def test_setup_logger_no_console_handler_when_disabled(self) -> None:
        """
        Test setup_logger doesn't add console handler when console=False.
        """
        # Act: Setup logger without console
        logger = setup_logger(name="test_no_console", console=False)

        # Assert: Should have no handlers
        assert len(logger.handlers) == 0

    def test_setup_logger_adds_file_handler_when_log_file_provided(
        self,
        tmp_path: Path,
    ) -> None:
        """
        Test setup_logger adds file handler when log_file is specified.

        Validates file logging configuration.
        """
        # Arrange: Create log file path
        log_file = tmp_path / "test.log"

        # Act: Setup logger with file handler
        logger = setup_logger(name="test_file_handler", log_file=log_file)

        # Assert: Should have FileHandler
        assert any(isinstance(h, logging.FileHandler) for h in logger.handlers)
        # File handler should point to correct file
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 1
        assert file_handlers[0].baseFilename == str(log_file)

    def test_setup_logger_file_handler_creates_log_file(self, tmp_path: Path) -> None:
        """
        Test that file handler actually creates and writes to log file.

        End-to-end validation of file logging functionality.
        """
        # Arrange: Create log file path
        log_file = tmp_path / "output.log"

        # Act: Setup logger and write log message
        logger = setup_logger(
            name="test_file_write",
            level=logging.INFO,
            log_file=log_file,
            console=False,
        )
        test_message = "Test log entry for file handler"
        logger.info(test_message)

        # Assert: Log file should exist and contain message
        assert log_file.exists()
        log_content = log_file.read_text(encoding="utf-8")
        assert test_message in log_content
        assert "INFO" in log_content

    def test_setup_logger_file_handler_includes_timestamp(self, tmp_path: Path) -> None:
        """
        Test that file handler includes timestamp in log entries.

        Validates file log format includes timestamp.
        """
        # Arrange: Create log file path
        log_file = tmp_path / "timestamped.log"

        # Act: Setup logger and write message
        logger = setup_logger(
            name="test_timestamp",
            log_file=log_file,
            console=False,
        )
        logger.info("Timestamped message")

        # Assert: Log should contain timestamp pattern (YYYY-MM-DD HH:MM:SS)
        log_content = log_file.read_text(encoding="utf-8")
        # Should match pattern like "2026-01-11 09:30:45"
        import re

        timestamp_pattern = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
        assert re.search(timestamp_pattern, log_content)

    def test_setup_logger_clears_existing_handlers(self) -> None:
        """
        Test setup_logger clears existing handlers before configuration.

        Prevents duplicate handlers when logger is reconfigured.
        """
        # Arrange: Setup logger twice with same name
        logger_name = "test_clear_handlers"
        logger1 = setup_logger(name=logger_name, console=True)
        initial_handler_count = len(logger1.handlers)

        # Act: Setup logger again with same name
        logger2 = setup_logger(name=logger_name, console=True)

        # Assert: Should still have same number of handlers (not doubled)
        assert len(logger2.handlers) == initial_handler_count
        # Both loggers should be the same instance (same name)
        assert logger1 is logger2

    def test_setup_logger_console_and_file_handlers_together(
        self,
        tmp_path: Path,
    ) -> None:
        """
        Test setup_logger can configure both console and file handlers.

        Validates dual-output configuration.
        """
        # Arrange: Create log file
        log_file = tmp_path / "dual_output.log"

        # Act: Setup logger with both console and file
        logger = setup_logger(
            name="test_dual_output",
            console=True,
            log_file=log_file,
        )

        # Assert: Should have both handlers
        assert len(logger.handlers) == 2
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
        assert any(isinstance(h, logging.FileHandler) for h in logger.handlers)

    def test_setup_logger_respects_level_for_console_handler(self) -> None:
        """
        Test console handler respects the configured logging level.

        Validates that console handler filters by level.
        """
        # Act: Setup logger with WARNING level
        logger = setup_logger(name="test_console_level", level=logging.WARNING)

        # Assert: Console handler should have WARNING level
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert len(console_handlers) > 0
        assert console_handlers[0].level == logging.WARNING

    def test_setup_logger_respects_level_for_file_handler(self, tmp_path: Path) -> None:
        """
        Test file handler respects the configured logging level.
        """
        # Arrange: Create log file
        log_file = tmp_path / "level_test.log"

        # Act: Setup logger with ERROR level
        logger = setup_logger(
            name="test_file_level",
            level=logging.ERROR,
            log_file=log_file,
            console=False,
        )

        # Assert: File handler should have ERROR level
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) > 0
        assert file_handlers[0].level == logging.ERROR


class TestSetupLoggerTTYDetection:
    """Test TTY detection and conditional colored formatting."""

    def test_setup_logger_uses_colored_formatter_when_tty_available(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        Test setup_logger uses ColoredFormatter when TTY is available.

        Simulates TTY environment by providing isatty() that returns True.
        """

        # Arrange: Create a fake stdout with isatty returning True
        class FakeTTYStdout:
            def isatty(self) -> bool:
                return True

            def write(self, s: str) -> int:
                return len(s)

            def flush(self) -> None:
                pass

        fake_stdout = FakeTTYStdout()
        monkeypatch.setattr(sys, "stdout", fake_stdout)

        # Act: Setup logger (should detect TTY)
        logger = setup_logger(name="test_tty_colored", console=True)

        # Assert: Console handler should use ColoredFormatter
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert len(console_handlers) > 0
        assert isinstance(console_handlers[0].formatter, ColoredFormatter)

    def test_setup_logger_uses_plain_formatter_when_no_tty(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        Test setup_logger uses plain Formatter when TTY is not available.

        Simulates non-TTY environment (e.g., piped output, file redirection).
        """

        # Arrange: Create a fake stdout with isatty returning False
        class FakeNonTTYStdout:
            def isatty(self) -> bool:
                return False

            def write(self, s: str) -> int:
                return len(s)

            def flush(self) -> None:
                pass

        fake_stdout = FakeNonTTYStdout()
        monkeypatch.setattr(sys, "stdout", fake_stdout)

        # Act: Setup logger (should detect no TTY)
        logger = setup_logger(name="test_no_tty_plain", console=True)

        # Assert: Console handler should use plain Formatter, not ColoredFormatter
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert len(console_handlers) > 0
        assert not isinstance(console_handlers[0].formatter, ColoredFormatter)
        assert isinstance(console_handlers[0].formatter, logging.Formatter)

    def test_setup_logger_handles_stdout_without_isatty_method(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        Test setup_logger handles stdout that lacks isatty() method.

        Some environments may have stdout objects without isatty().
        """

        # Arrange: Create stdout without isatty method
        class MinimalStdout:
            def write(self, s: str) -> int:
                return len(s)

            def flush(self) -> None:
                pass

        minimal_stdout = MinimalStdout()
        monkeypatch.setattr(sys, "stdout", minimal_stdout)

        # Act: Setup logger (should handle missing isatty gracefully)
        logger = setup_logger(name="test_no_isatty", console=True)

        # Assert: Should use plain formatter (fallback)
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert len(console_handlers) > 0
        # Should not crash and should use plain formatter
        assert isinstance(console_handlers[0].formatter, logging.Formatter)


class TestGetLogger:
    """Test get_logger function."""

    def test_get_logger_returns_existing_logger(self) -> None:
        """
        Test get_logger returns existing logger instance.

        Validates that get_logger retrieves previously created loggers.
        """
        # Arrange: Setup a logger first
        original_logger = setup_logger(name="test_existing")

        # Act: Get logger with same name
        retrieved_logger = get_logger(name="test_existing")

        # Assert: Should return the same logger instance
        assert retrieved_logger is original_logger
        assert retrieved_logger.name == "test_existing"

    def test_get_logger_returns_logger_with_default_name(self) -> None:
        """
        Test get_logger returns logger with default 'iocparser' name.
        """
        # Act: Get logger with default name
        logger = get_logger()

        # Assert: Should return logger with default name
        assert logger.name == "iocparser"
        assert isinstance(logger, logging.Logger)

    def test_get_logger_returns_logger_with_custom_name(self) -> None:
        """
        Test get_logger returns logger with custom name.
        """
        # Arrange: Use custom name
        custom_name = "custom_logger_test"

        # Act: Get logger
        logger = get_logger(name=custom_name)

        # Assert: Should return logger with custom name
        assert logger.name == custom_name

    def test_get_logger_multiple_calls_return_same_instance(self) -> None:
        """
        Test multiple get_logger calls return same logger instance.

        Validates logger singleton behavior for same name.
        """
        # Act: Call get_logger twice with same name
        logger1 = get_logger(name="test_singleton")
        logger2 = get_logger(name="test_singleton")

        # Assert: Should be the exact same object
        assert logger1 is logger2


class TestLoggerIntegration:
    """Integration tests for complete logging workflows."""

    def test_complete_logging_workflow_to_file(self, tmp_path: Path) -> None:
        """
        Test complete workflow: setup -> get -> log -> verify file.

        End-to-end validation of file logging pipeline.
        """
        # Arrange: Setup logger with file
        log_file = tmp_path / "integration.log"
        setup_logger(
            name="integration_test",
            level=logging.DEBUG,
            log_file=log_file,
            console=False,
        )

        # Act: Get logger and write various log levels
        logger = get_logger(name="integration_test")
        logger.debug("Debug entry")
        logger.info("Info entry")
        logger.warning("Warning entry")
        logger.error("Error entry")

        # Assert: All messages should be in log file
        log_content = log_file.read_text(encoding="utf-8")
        assert "Debug entry" in log_content
        assert "Info entry" in log_content
        assert "Warning entry" in log_content
        assert "Error entry" in log_content
        assert "DEBUG" in log_content
        assert "INFO" in log_content
        assert "WARNING" in log_content
        assert "ERROR" in log_content

    def test_logger_level_filtering_works_correctly(self, tmp_path: Path) -> None:
        """
        Test that logging level filtering works as expected.

        Messages below configured level should not appear.
        """
        # Arrange: Setup logger with WARNING level
        log_file = tmp_path / "filtered.log"
        setup_logger(
            name="filter_test",
            level=logging.WARNING,
            log_file=log_file,
            console=False,
        )

        # Act: Log messages at different levels
        logger = get_logger(name="filter_test")
        logger.debug("Should not appear")
        logger.info("Should not appear either")
        logger.warning("Should appear")
        logger.error("Should appear too")

        # Assert: Only WARNING and ERROR should be in log
        log_content = log_file.read_text(encoding="utf-8")
        assert "Should not appear" not in log_content
        assert "Should appear" in log_content
        assert "Should appear too" in log_content

    def test_logger_handles_unicode_and_special_characters(self, tmp_path: Path) -> None:
        """
        Test logger correctly handles Unicode and special characters.

        Validates encoding handling in log messages.
        """
        # Arrange: Setup logger
        log_file = tmp_path / "unicode.log"
        setup_logger(
            name="unicode_test",
            log_file=log_file,
            console=False,
        )

        # Act: Log message with Unicode
        logger = get_logger(name="unicode_test")
        unicode_message = "IOC from café: résumé.exe, IP: 192.168.1.1 (€)"
        logger.info(unicode_message)

        # Assert: Unicode should be preserved
        log_content = log_file.read_text(encoding="utf-8")
        assert unicode_message in log_content
        assert "café" in log_content
        assert "résumé" in log_content
        assert "€" in log_content

    def test_reconfiguring_logger_updates_handlers(self, tmp_path: Path) -> None:
        """
        Test that reconfiguring logger properly updates handlers.

        Validates that setup_logger can reconfigure existing loggers.
        """
        # Arrange: Setup logger initially without file
        logger_name = "reconfig_test"
        logger = setup_logger(name=logger_name, console=True)
        # Act: Reconfigure with file handler
        log_file = tmp_path / "reconfig.log"
        logger = setup_logger(
            name=logger_name,
            console=True,
            log_file=log_file,
        )

        # Assert: Should now have both console and file handlers
        assert len(logger.handlers) == 2
        # Log a message to verify both handlers work
        logger.info("Reconfiguration test")
        assert log_file.exists()
        assert "Reconfiguration test" in log_file.read_text(encoding="utf-8")
