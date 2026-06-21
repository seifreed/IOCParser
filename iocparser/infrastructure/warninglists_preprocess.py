from __future__ import annotations

import ipaddress
import re
from contextlib import suppress
from logging import Logger
from typing import ClassVar

import regex

from iocparser.errors import TypeValidationError
from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.warninglists_types import (
    TimeoutRegexPattern,
    WarningListDict,
    WarningListEntry,
    WarningListLookups,
    get_mixin_logger,
    matching_attribute_name,
    normalized_warning_list_text,
)

logger = get_logger("iocparser.infrastructure.warninglists")


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeValidationError(field, "string", value)
    return value


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
        self.lookup_data.suffix_lookups.clear()
        self.lookup_data.compiled_regex.clear()
        self.lookup_data.cidr_networks.clear()
        self.lookup_data.lists_by_ioc_type.clear()
        self._ensure_clean_value_cache().clear()
        with suppress(AttributeError):
            self._warning_lookup_cache.clear()

    def _add_string_values(
        self,
        list_id: str,
        values_val: list[WarningListEntry],
        list_type: str,
    ) -> None:
        for value in values_val:
            if value is None:
                continue
            value_lower = normalized_warning_list_text(value, list_type=list_type)
            # A leading-dot "hostname" entry (".duckdns.org") matches the apex and every
            # subdomain per MISP convention; index its apex for parent-suffix matching
            # instead of as a dead exact key no extracted domain ever equals.
            if list_type == "hostname" and value_lower.startswith("."):
                apex = value_lower.lstrip(".")
                if apex:
                    self.lookup_data.suffix_lookups.setdefault(apex, set()).add(list_id)
                continue
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

    @staticmethod
    def _normalize_regex_pattern(pattern: str) -> tuple[str, int]:
        """Normalize raw or slash-delimited regex text into a Python pattern.

        MISP warning lists may store regexes either as plain expressions or in
        ``/pattern/flags`` form. We only need to support the common flags that
        map cleanly to Python's ``re`` module.
        """
        pattern = pattern.strip()
        if not pattern.startswith("/") or pattern.count("/") < 2:
            return pattern, re.IGNORECASE

        closing = pattern.rfind("/")
        body = pattern[1:closing]
        flags_text = pattern[closing + 1 :]
        if not body or (flags_text and not flags_text.isalpha()):
            return pattern, re.IGNORECASE

        flags = re.IGNORECASE
        for flag in flags_text.lower():
            if flag == "g":
                continue
            if flag == "m":
                flags |= re.MULTILINE
            elif flag == "s":
                flags |= re.DOTALL
            elif flag == "x":
                flags |= re.VERBOSE
        return body, flags

    def _add_regex_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        compiled_patterns: list[TimeoutRegexPattern] = []
        for pattern in values_val:
            if pattern is None:
                continue
            pattern_str = _require_str(pattern, field="regex pattern")
            normalized_pattern, pattern_flags = self._normalize_regex_pattern(pattern_str)
            if not self._is_safe_regex(normalized_pattern):
                self._get_logger().warning(
                    "Skipping potentially unsafe regex pattern: %s", pattern_str
                )
                continue
            try:
                # Compile via the `regex` engine so matching can be time-bounded
                # (re has no per-match timeout); _is_safe_regex above is only a cheap
                # pre-filter, the timeout in the matching paths is the real guard.
                compiled_patterns.append(regex.compile(normalized_pattern, pattern_flags))
            except (re.error, regex.error, TypeError):
                self._get_logger().debug("Invalid regex pattern: %s", pattern)
        if compiled_patterns:
            self.lookup_data.compiled_regex[list_id] = compiled_patterns

    def _add_cidr_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr_value in values_val:
            if cidr_value is None:
                continue
            cidr_text = _require_str(cidr_value, field="cidr entry").strip()
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
            try:
                attr_lower = matching_attribute_name(attr).lower()
            except TypeError:
                continue
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
            list_type = _require_str(warning_list.get("type", "string"), field="type")
            values_val = warning_list.get("list", [])
            if not isinstance(values_val, list):
                continue
            if list_type in ("string", "hostname"):
                # MISP "hostname" lists (Alexa, bank domains, whitelists, ...) match
                # exactly like "string" lists; without this branch their entries were
                # never indexed, so 19 shipped lists never produced a single match.
                self._add_string_values(list_id, values_val, list_type)
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
