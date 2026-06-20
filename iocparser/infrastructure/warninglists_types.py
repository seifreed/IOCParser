from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from logging import Logger

WarningListEntry = str | dict[str, str] | int | bool | None
WarningListValue = str | list[WarningListEntry] | int | bool
WarningListDict = dict[str, WarningListValue]
IOCValue = str | int | float | bool | None
JSONValue = str | int | bool | list[str] | list[dict[str, str]] | dict[str, str]
JSONData = dict[str, JSONValue] | list[JSONValue]


def matching_attribute_name(attr: WarningListEntry) -> str:
    """Resolve a matching-attribute entry to its name string."""
    if isinstance(attr, str):
        return attr
    if isinstance(attr, dict):
        name = attr.get("name", "")
        if isinstance(name, str):
            return name
        raise TypeError(f"Expected matching attribute name to be string-like, got {type(name).__name__}")
    raise TypeError(f"Expected matching attribute to be string-like, got {type(attr).__name__}")


def normalized_warning_list_text(value: WarningListEntry, *, list_type: str) -> str:
    """Normalize warning-list text entries for exact/string-style matching."""
    if not isinstance(value, str):
        raise TypeError(f"Expected warning-list entry to be string-like, got {type(value).__name__}")
    text = value.strip()
    if list_type == "hostname":
        text = text.rstrip("\\")
    return text.lower()


def get_mixin_logger(instance: object, fallback: Logger) -> Logger:
    """Shared logger accessor for warning-list mixins."""
    logger = getattr(instance, "logger", None)
    if isinstance(logger, Logger):
        return logger
    return fallback


@dataclass
class WarningListLookups:
    """Lookup containers for optimized warning list checks."""

    string_lookups: dict[str, set[str]]
    compiled_regex: dict[str, list[re.Pattern[str]]]
    cidr_networks: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]
    lists_by_ioc_type: dict[str, list[str]]
    # Apex domains from leading-dot "hostname" entries (e.g. ".duckdns.org" -> "duckdns.org").
    # MISP's convention is that a leading dot matches the apex AND every subdomain, so these
    # are matched against a candidate's parent suffixes rather than by exact key.
    suffix_lookups: dict[str, set[str]] = field(default_factory=dict)
