from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from logging import Logger

from iocparser.infrastructure.warninglists_types import IOCValue, normalized_warning_list_text


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Expected {field} to be string-like, got {type(value).__name__}")
    return value


def check_string_type(value: str, values: list[IOCValue]) -> bool:
    return value.strip().lower() in [
        normalized_warning_list_text(v, list_type="string") for v in values if v is not None
    ]


def check_substring_type(value: str, values: list[IOCValue]) -> bool:
    value_lower = value.strip().lower()
    for list_value in values:
        if list_value is None:
            continue
        list_value_str = normalized_warning_list_text(list_value, list_type="string")
        if not list_value_str:
            continue
        if list_value_str in value_lower:
            return True
    return False


def check_regex_type(get_logger: Callable[[], Logger], value: str, values: list[IOCValue]) -> bool:
    value = value.strip()
    for regex_pattern in values:
        if regex_pattern is None:
            continue
        pattern_text = _require_str(regex_pattern, field="regex pattern")
        pattern_text = pattern_text.strip()
        if not pattern_text:
            continue
        pattern = pattern_text
        flags = re.IGNORECASE
        if pattern_text.startswith("/") and pattern_text.count("/") >= 2:
            closing = pattern_text.rfind("/")
            body = pattern_text[1:closing]
            flags_text = pattern_text[closing + 1 :]
            if body and (not flags_text or flags_text.isalpha()):
                pattern = body
                for flag in flags_text.lower():
                    if flag == "g":
                        continue
                    if flag == "m":
                        flags |= re.MULTILINE
                    elif flag == "s":
                        flags |= re.DOTALL
                    elif flag == "x":
                        flags |= re.VERBOSE
        try:
            if re.search(pattern, value, flags):
                return True
        except (re.error, TypeError):
            get_logger().debug("Invalid regex pattern: %s", regex_pattern)
    return False


def check_cidr(get_logger: Callable[[], Logger], ip_value: str, cidr_list: list[IOCValue]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_value.strip())
        for cidr_value in cidr_list:
            if cidr_value is None:
                continue
            cidr_str = _require_str(cidr_value, field="cidr entry").strip()
            try:
                if "/" in cidr_str:
                    network = ipaddress.ip_network(cidr_str, strict=False)
                    if ip_obj in network:
                        return True
                elif ipaddress.ip_address(cidr_str) == ip_obj:
                    return True
            except (ValueError, ipaddress.AddressValueError):
                get_logger().debug("Invalid CIDR/IP entry: %s", cidr_str)
    except (ValueError, ipaddress.AddressValueError):
        get_logger().debug("Invalid IP address: %s", ip_value)
        return False
    return False


def check_value_in_list(
    get_logger: Callable[[], Logger],
    value: str,
    values: list[IOCValue],
    list_type: str,
) -> bool:
    if not values:
        return False
    if list_type in ("string", "hostname"):
        # Preprocessing indexes "hostname" lists with the string lookups, so the
        # diagnostic must match them the same way or it contradicts check_value.
        if list_type == "hostname":
            return value.strip().lower() in [
                normalized_warning_list_text(v, list_type=list_type) for v in values if v is not None
            ]
        return check_string_type(value, values)
    if list_type == "substring":
        return check_substring_type(value, values)
    if list_type == "regex":
        return check_regex_type(get_logger, value, values)
    if list_type == "cidr":
        return check_cidr(get_logger, value, values)
    return False
