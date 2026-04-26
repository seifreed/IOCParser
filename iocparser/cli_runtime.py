from __future__ import annotations

import argparse
import logging
from pathlib import Path

from iocparser.cli_args import get_bool_arg, get_int_arg, get_list_arg, get_optional_str_arg
from iocparser.cli_runtime_defaults import (
    _apply_boolean_defaults,
    _apply_filter_defaults,
    _apply_network_defaults,
    _apply_numeric_defaults,
    _apply_output_defaults,
    apply_config_defaults,
)
from iocparser.cli_runtime_defaults import (
    parse_http_mapping as _parse_http_mapping,
)
from iocparser.config import AppConfig, load_config
from iocparser.infrastructure.extraction import MagicTextSourceReader, RequestsURLDownloader
from iocparser.infrastructure.runtime import LocalFileWriter, get_logger, setup_logger
from iocparser.infrastructure.warninglists import MISPWarningLists
from iocparser.infrastructure.warninglists_service import (
    CompositeWarningListService,
    MISPWarningListService,
)
from iocparser.interfaces.ports import FileWriter, TextSourceReader, WarningListService
from iocparser.plugins import get_enricher

__all__ = [
    "AppConfig",
    "_apply_boolean_defaults",
    "_apply_filter_defaults",
    "_apply_network_defaults",
    "_apply_numeric_defaults",
    "_apply_output_defaults",
    "_parse_http_mapping",
    "apply_config_defaults",
    "downloader",
    "downloader_for_args",
    "file_writer",
    "handle_misp_init_with",
    "load_config",
    "logger",
    "reader",
    "resolve_persistence",
    "setup_application",
    "warning_service",
    "warning_service_for_args",
]

logger = get_logger(__name__)
downloader = RequestsURLDownloader()
reader: TextSourceReader = MagicTextSourceReader()
warning_service: WarningListService = MISPWarningListService()
file_writer: FileWriter = LocalFileWriter()


def resolve_persistence(args: argparse.Namespace) -> AppConfig:
    persist_value: object = getattr(args, "persist", None)
    cli_persist = persist_value if isinstance(persist_value, bool) else None
    config = load_config(
        cli_persist,
        get_optional_str_arg(args, "db_uri"),
        get_optional_str_arg(args, "config"),
    )
    apply_config_defaults(args, config)
    return config


def setup_application(args: argparse.Namespace) -> None:
    debug = get_bool_arg(args, "debug")
    verbose = get_bool_arg(args, "verbose")
    log_file_path = get_optional_str_arg(args, "log_file")
    log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    log_file = Path(log_file_path) if log_file_path else None
    setup_logger(level=log_level, log_file=log_file)


def _unsupported_float_argument_type(name: str, value: object) -> TypeError:
    return TypeError(f"Unsupported float argument type for {name}: {type(value).__name__}")


def _optional_float_arg(args: argparse.Namespace, name: str) -> float | None:
    value: object = getattr(args, name, None)
    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value.strip())
    raise _unsupported_float_argument_type(name, value)


def downloader_for_args(args: argparse.Namespace) -> RequestsURLDownloader:
    header_items: object = getattr(args, "header", None)
    cookie_items: object = getattr(args, "cookie", None)
    headers_json: object = getattr(args, "headers_json", None)
    cookies_json: object = getattr(args, "cookies_json", None)
    headers_source = header_items if header_items is not None else headers_json
    cookies_source = cookie_items if cookie_items is not None else cookies_json
    headers = _parse_http_mapping(headers_source, separator=":")
    cookies = _parse_http_mapping(cookies_source, separator="=")
    ca_bundle = get_optional_str_arg(args, "ca_bundle")
    verify: bool | str = get_bool_arg(args, "tls_verify")
    if verify and ca_bundle:
        verify = ca_bundle
    connect_timeout = _optional_float_arg(args, "connect_timeout")
    read_timeout = _optional_float_arg(args, "read_timeout")
    timeout: int | tuple[float, float]
    if connect_timeout is not None or read_timeout is not None:
        timeout = (
            float(connect_timeout if connect_timeout is not None else RequestsURLDownloader.default_connect_timeout()),
            float(read_timeout if read_timeout is not None else RequestsURLDownloader.default_read_timeout()),
        )
    else:
        timeout = RequestsURLDownloader.default_timeout()
    return RequestsURLDownloader(
        timeout=timeout,
        retries=get_int_arg(args, "url_retries", 0),
        backoff=_optional_float_arg(args, "url_backoff") or 0.0,
        rate_limit_delay=_optional_float_arg(args, "rate_limit") or 0.0,
        headers=headers,
        cookies=cookies,
        user_agent=get_optional_str_arg(args, "user_agent"),
        proxies={"http": proxy, "https": proxy} if (proxy := get_optional_str_arg(args, "proxy")) else None,
        allow_redirects=get_bool_arg(args, "allow_redirects"),
        verify=verify,
        cert=get_optional_str_arg(args, "tls_cert"),
    )


def warning_service_for_args(args: argparse.Namespace) -> WarningListService:
    enrichers = get_list_arg(args, "enricher")
    if not enrichers:
        return warning_service
    services = tuple(get_enricher(name) for name in enrichers)
    if len(services) == 1:
        return services[0]
    return CompositeWarningListService(services)


def handle_misp_init_with(factory: type[MISPWarningLists]) -> None:
    logger.info("Initializing and updating MISP warning lists...")
    warning_lists = factory(cache_duration=0, force_update=True)
    total_lists = len(warning_lists.warning_lists)
    logger.info("Initialization completed. Downloaded %s warning lists.", total_lists)
    categories: dict[str, list[str]] = {}
    for list_id, wlist in warning_lists.warning_lists.items():
        if "name" in wlist:
            category = str(wlist.get("name", "")).split(" ", maxsplit=1)[0].lower()
        else:
            category = "other"
        categories.setdefault(category, []).append(list_id)
    from colorama import Fore, Style

    color_cyan = str(Fore.CYAN)
    style_reset = str(Style.RESET_ALL)
    import sys

    for category, lists in sorted(categories.items()):
        sys.stdout.write(f"{color_cyan}  {category.capitalize()}: {len(lists)} lists{style_reset}\n")
