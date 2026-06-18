from __future__ import annotations

import ipaddress
import re
from contextlib import suppress
from logging import Logger
from typing import ClassVar

from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.warninglists_types import (
    WarningListDict,
    WarningListEntry,
    WarningListLookups,
    get_mixin_logger,
    matching_attribute_name,
)

logger = get_logger("iocparser.infrastructure.warninglists")


class WarningListPreprocessMixin:
    """Preprocessing helpers for optimized warning-list lookups."""

    logger: Logger
    warning_lists: dict[str, WarningListDict]
    lookup_data: WarningListLookups
    IOC_TYPE_MAPPING: ClassVar[dict[str, str]]
    DEFANG_CLEANERS: ClassVar[list[tuple[str, str]]]
    _clean_value_cache: dict[str, str]
    _warning_lookup_cache: dict[tuple[str, str], tuple[bool, dict[str, str] | None]]

    def _get_logger(self) -> Logger:
        return get_mixin_logger(self, logger)

    def _ensure_clean_value_cache(self) -> dict[str, str]:
        try:
            return self._clean_value_cache
        except AttributeError:
            cache: dict[str, str] = {}
            self._clean_value_cache = cache
            return cache

    def _clear_preprocessed_data(self) -> None:
        self.lookup_data.string_lookups.clear()
        self.lookup_data.compiled_regex.clear()
        self.lookup_data.cidr_networks.clear()
        self.lookup_data.lists_by_ioc_type.clear()
        self._ensure_clean_value_cache().clear()
        with suppress(AttributeError):
            self._warning_lookup_cache.clear()

    def _add_string_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        for value in values_val:
            if value is None:
                continue
            value_lower = str(value).lower()
            if value_lower not in self.lookup_data.string_lookups:
                self.lookup_data.string_lookups[value_lower] = set()
            self.lookup_data.string_lookups[value_lower].add(list_id)

    @staticmethod
    def _is_safe_regex(pattern: str) -> bool:
        """Reject patterns with nested quantifiers that can cause ReDoS.

        Catches the quantifier-group-quantifier shape `(X+)+`, `(X*)*`, `(X+)*`,
        etc. A previous `\\)[+*?]\\)` check was dropped: it matched the harmless
        `)+)` substring in safe patterns like `(\\w(\\d)+)`, wrongly discarding
        them, while catching no dangerous pattern the check below misses.
        """
        import re as _re

        return _re.search(r"[+*?]\)[+*?]", pattern) is None

    def _add_regex_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        compiled_patterns: list[re.Pattern[str]] = []
        for pattern in values_val:
            if pattern is None:
                continue
            pattern_str = str(pattern)
            if not self._is_safe_regex(pattern_str):
                self._get_logger().warning(
                    "Skipping potentially unsafe regex pattern: %s", pattern_str
                )
                continue
            try:
                compiled_patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except (re.error, TypeError):
                self._get_logger().debug("Invalid regex pattern: %s", pattern)
        if compiled_patterns:
            self.lookup_data.compiled_regex[list_id] = compiled_patterns

    def _add_cidr_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr_value in values_val:
            if cidr_value is None:
                continue
            cidr_text = str(cidr_value)
            try:
                networks.append(ipaddress.ip_network(cidr_text, strict=False))
            except (ValueError, ipaddress.AddressValueError):
                self._get_logger().debug("Invalid CIDR entry: %s", cidr_text)
        if networks:
            self.lookup_data.cidr_networks[list_id] = networks

    def _index_matching_attributes(self, list_id: str, warning_list: WarningListDict) -> None:
        matching_attrs = warning_list.get("matching_attributes", [])
        if not isinstance(matching_attrs, list):
            return
        for attr in matching_attrs:
            attr_lower = matching_attribute_name(attr).lower()
            attr_parts = set(re.split(r"[|\-_ /]", attr_lower))
            for keyword, ioc_type in self.IOC_TYPE_MAPPING.items():
                if keyword == attr_lower or keyword in attr_parts:
                    if ioc_type not in self.lookup_data.lists_by_ioc_type:
                        self.lookup_data.lists_by_ioc_type[ioc_type] = []
                    if list_id not in self.lookup_data.lists_by_ioc_type[ioc_type]:
                        self.lookup_data.lists_by_ioc_type[ioc_type].append(list_id)

    def _preprocess_lists(self) -> None:
        current_logger = self._get_logger()
        current_logger.info("Pre-processing warning lists for optimized lookups...")
        self._clear_preprocessed_data()
        for list_id, warning_list in self.warning_lists.items():
            list_type = str(warning_list.get("type", "string"))
            values_val = warning_list.get("list", [])
            if not isinstance(values_val, list):
                continue
            if list_type in ("string", "hostname"):
                # MISP "hostname" lists (Alexa, bank domains, whitelists, ...) match
                # exactly like "string" lists; without this branch their entries were
                # never indexed, so 19 shipped lists never produced a single match.
                self._add_string_values(list_id, values_val)
            elif list_type == "regex":
                self._add_regex_values(list_id, values_val)
            elif list_type == "cidr":
                self._add_cidr_values(list_id, values_val)
            self._index_matching_attributes(list_id, warning_list)
        current_logger.info("Pre-processing complete")

    def _clean_defanged_value(self, value: str) -> str:
        cache = self._ensure_clean_value_cache()
        cached = cache.get(value)
        if cached is not None:
            return cached
        clean_value = value.strip()
        for old, new in self.DEFANG_CLEANERS:
            clean_value = clean_value.replace(old, new)
        if len(cache) >= 10000:
            cache.clear()
        cache[value] = clean_value
        return clean_value
