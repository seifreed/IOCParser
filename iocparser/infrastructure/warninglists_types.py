from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
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
        return str(attr.get("name", ""))
    return str(attr)


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
