#!/usr/bin/env python3

"""
Diagnostic helpers for MISP warning lists.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import ClassVar

from iocparser.domain.enums import IOCType, ioc_type_name
from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.warninglists_types import matching_attribute_name

# Type aliases for diagnostics
WarningListEntry = str | dict[str, str] | int | bool | None
WarningListValue = str | list[WarningListEntry] | int | bool
WarningListDict = dict[str, WarningListValue]
IOCValue = str | int | float | bool | None

logger = get_logger("iocparser.infrastructure.warninglists")


class WarningListDiagnosticsMixin(ABC):
    """Diagnostic helpers for warning list matching."""

    TYPE_KEYWORDS: ClassVar[dict[str, list[str]]]
    warning_lists: dict[str, WarningListDict]

    @abstractmethod
    def _check_value_in_list(self, value: str, values: list[IOCValue], list_type: str) -> bool: ...

    @abstractmethod
    def _clean_defanged_value(self, value: str) -> str: ...

    @abstractmethod
    def check_value(self, value: str, ioc_type: str) -> tuple[bool, dict[str, str] | None]: ...

    def _is_list_relevant_for_expected(
        self,
        name: str,
        description: str,
        expected_lists: list[str] | None,
    ) -> bool:
        """Check if list is relevant based on expected lists."""
        if not expected_lists:
            return False
        haystack_tokens = {
            token
            for text in (name, description)
            for token in re.split(r"[|\-_ /.]+", text.lower())
            if token
        }
        for expected in expected_lists:
            expected_tokens = {
                token for token in re.split(r"[|\-_ /.]+", expected.lower()) if token
            }
            if expected_tokens and expected_tokens.issubset(haystack_tokens):
                return True
        return False

    def _is_list_relevant_for_type(
        self,
        name: str,
        description: str,
        ioc_type: str,
        matching_attributes: list[WarningListEntry] | None = None,
    ) -> bool:
        """Check if list is relevant based on IOC type."""
        if ioc_type not in self.TYPE_KEYWORDS:
            return False

        text_tokens = {
            token
            for text in (name, description)
            for token in re.split(r"[|\-_ /.]+", text.lower())
            if token
        }
        if any(keyword in text_tokens
            for keyword in self.TYPE_KEYWORDS[ioc_type]
        ):
            return True
        if not matching_attributes:
            return False
        attrs = {
            token
            for attr in matching_attributes
            for token in re.split(r"[|\-_ /]", matching_attribute_name(attr).lower())
            if token
        }
        return any(keyword in attrs for keyword in self.TYPE_KEYWORDS[ioc_type])

    def _log_matched_value(self, clean_val: str, vals: list[IOCValue]) -> None:
        """Log which specific entry matched."""
        for val in vals:
            if str(val).lower() == clean_val.lower():
                logger.info("    Matched: %s", val)
                break

    def _log_list_check_result(
        self,
        clean_val: str,
        warning_list: WarningListDict,
        list_id: str,
        vals: list[IOCValue],
    ) -> None:
        """Log the result of checking a value against a warning list."""
        name = warning_list.get("name", list_id)
        list_type = warning_list.get("type", "string")
        matching_attrs = warning_list.get("matching_attributes", [])

        logger.info("\nChecking list: %s", name)
        logger.info("  Type: %s", list_type)
        logger.info("  Matching attributes: %s", matching_attrs)
        logger.info("  Number of values: %s", len(vals))

        list_type_str = str(list_type) if list_type is not None else "string"
        if self._check_value_in_list(clean_val, vals, list_type_str):
            logger.info("  ✓ VALUE FOUND IN THIS LIST")
            if list_type == "string":
                self._log_matched_value(clean_val, vals)
        else:
            logger.info("  ✗ Value not in this list")
            if vals:
                logger.info("    Sample values: %s", vals[:3])

    def _get_relevant_lists(
        self,
        ioc_type: str,
        expected_lists: list[str] | None,
    ) -> list[tuple[str, WarningListDict]]:
        """Find relevant lists for diagnostics."""
        relevant_lists: list[tuple[str, WarningListDict]] = []
        for list_id, warning_list in self.warning_lists.items():
            name_val = warning_list.get("name", "")
            desc_val = warning_list.get("description", "")
            name = str(name_val) if name_val is not None else ""
            description = str(desc_val) if desc_val is not None else ""

            is_relevant = self._is_list_relevant_for_expected(
                name, description, expected_lists
            ) or self._is_list_relevant_for_type(
                name,
                description,
                ioc_type,
                warning_list.get("matching_attributes")
                if isinstance(warning_list.get("matching_attributes"), list)
                else None,
            )

            if is_relevant:
                relevant_lists.append((list_id, warning_list))
        return relevant_lists

    def _get_warning_list_values(self, warning_list: WarningListDict) -> list[IOCValue]:
        """Return normalized values list for a warning list."""
        values_raw = warning_list.get("list", [])
        if isinstance(values_raw, list):
            return [str(v) if v is not None else None for v in values_raw]
        return []

    def diagnose_value_detection(
        self,
        value: str,
        ioc_type: str,
        expected_lists: list[str] | None = None,
    ) -> None:
        """
        Diagnostic tool to understand why a value is or isn't detected in MISP lists.

        Args:
            value: The value to diagnose
            ioc_type: The type of IOC
            expected_lists: Optional list of expected warning list names
        """
        logger.info("Diagnosing detection for %s (type: %s)", value, ioc_type)
        try:
            normalized_ioc_type = ioc_type_name(IOCType.from_name(ioc_type))
        except ValueError:
            normalized_ioc_type = ioc_type.strip().lower()

        clean_value = self._clean_defanged_value(value)
        logger.info("Cleaned value: %s", clean_value)

        relevant_lists = self._get_relevant_lists(normalized_ioc_type, expected_lists)
        logger.info("Found %s potentially relevant lists", len(relevant_lists))

        for list_id, warning_list in relevant_lists:
            values = self._get_warning_list_values(warning_list)
            self._log_list_check_result(clean_value, warning_list, list_id, values)

        in_warning_list, warning_info = self.check_value(value, normalized_ioc_type)
        if in_warning_list and warning_info:
            logger.info(
                "\n✓ FINAL RESULT: Value IS in warning list: %s",
                warning_info["name"],
            )
        else:
            logger.info("\n✗ FINAL RESULT: Value is NOT in any warning list")
