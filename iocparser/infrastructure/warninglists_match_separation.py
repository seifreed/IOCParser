from __future__ import annotations

from collections.abc import Callable
from logging import Logger


def extract_ioc_value(ioc: str | dict[str, str]) -> str:
    """Return an IOC's string value, unwrapping the ``value`` key of dict IOCs."""
    if isinstance(ioc, dict) and "value" in ioc:
        return str(ioc["value"])
    return str(ioc)


def get_warnings_for_iocs(
    check_value: Callable[[str, str], tuple[bool, dict[str, str] | None]],
    iocs: dict[str, list[str | dict[str, str]]],
) -> dict[str, list[dict[str, str]]]:
    warnings: dict[str, list[dict[str, str]]] = {}
    for ioc_type, ioc_list in iocs.items():
        type_warnings: list[dict[str, str]] = []
        for ioc in ioc_list:
            value = extract_ioc_value(ioc)
            in_warning_list, warning_info = check_value(value, ioc_type)
            if in_warning_list and warning_info:
                type_warnings.append(
                    {
                        "value": value,
                        "warning_list": warning_info["name"],
                        "description": warning_info["description"],
                    }
                )
        if type_warnings:
            warnings[ioc_type] = type_warnings
    return warnings


def separate_iocs_by_warnings(
    *,
    get_logger: Callable[[], Logger],
    extract_ioc_value: Callable[[str | dict[str, str]], str],
    email_domain_in_warning_list: Callable[[str], tuple[bool, dict[str, str] | None]],
    check_value: Callable[[str, str], tuple[bool, dict[str, str] | None]],
    build_warning_entry: Callable[[str, dict[str, str], str | dict[str, str]], dict[str, str]],
    iocs: dict[str, list[str | dict[str, str]]],
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    current_logger = get_logger()
    current_logger.info("Checking IOCs against MISP Warning Lists...")
    normal_iocs: dict[str, list[str | dict[str, str]]] = {}
    warning_iocs: dict[str, list[dict[str, str]]] = {}
    for ioc_type, ioc_list in iocs.items():
        normal_list: list[str | dict[str, str]] = []
        warning_list: list[dict[str, str]] = []
        for ioc in ioc_list:
            value = extract_ioc_value(ioc)
            in_warning_list, warning_info = check_value(value, ioc_type)
            if in_warning_list and warning_info:
                warning_list.append(build_warning_entry(value, warning_info, ioc))
                continue
            if ioc_type == "emails":
                domain_match, domain_info = email_domain_in_warning_list(value)
                if domain_match and domain_info:
                    current_logger.info("Email IOC has warning-listed domain: %s", value)
                    warning_list.append(build_warning_entry(value, domain_info, ioc))
                    continue
            normal_list.append(ioc)
        if normal_list:
            normal_iocs[ioc_type] = normal_list
        if warning_list:
            warning_iocs[ioc_type] = warning_list
    current_logger.info("IOCs verification against MISP Warning Lists completed")
    normal_count = sum(len(values) for values in normal_iocs.values())
    warning_count = sum(len(values) for values in warning_iocs.values())
    current_logger.info("Normal IOCs: %s, Warning IOCs: %s", normal_count, warning_count)
    return normal_iocs, warning_iocs
