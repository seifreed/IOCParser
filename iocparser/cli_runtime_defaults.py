from __future__ import annotations

import argparse
import json

from iocparser.cli_args import get_bool_arg
from iocparser.config import AppConfig
from iocparser.errors import ValidationError

INVALID_DIFF_ONLY_ERROR = "Invalid diff_only: {value}"
VALID_DIFF_ONLY_VALUES = {"all", "added", "removed"}


def apply_config_defaults(args: argparse.Namespace, config: AppConfig) -> None:
    _apply_filter_defaults(args, config)
    _apply_boolean_defaults(args, config)
    _apply_output_defaults(args, config)
    _apply_numeric_defaults(args, config)
    _apply_network_defaults(args, config)


def _apply_filter_defaults(args: argparse.Namespace, config: AppConfig) -> None:
    text_defaults = {
        "only": config.only,
        "exclude": config.exclude,
        "stix_types": config.stix_types,
        "severity": config.severity,
        "tag": config.tag,
        "headers_json": config.headers_json,
        "cookies_json": config.cookies_json,
    }
    for name, configured in text_defaults.items():
        current: object = getattr(args, name, None)
        if current is None and configured:
            setattr(args, name, configured)


def _apply_boolean_defaults(args: argparse.Namespace, config: AppConfig) -> None:
    boolean_defaults = {
        "with_context": config.with_context,
        "streaming": config.streaming,
        "summary": config.summary,
        "skip_processed": config.skip_processed,
    }
    for name, configured in boolean_defaults.items():
        if not get_bool_arg(args, name) and configured is True:
            setattr(args, name, True)


def _apply_output_defaults(args: argparse.Namespace, config: AppConfig) -> None:
    if not any(
        get_bool_arg(args, name) for name in ("json", "jsonl", "csv", "stix")
    ) and config.output_format in {"json", "jsonl", "csv", "stix"}:
        setattr(args, config.output_format, True)


def _apply_numeric_defaults(args: argparse.Namespace, config: AppConfig) -> None:
    numeric_defaults: dict[str, tuple[int | float, int | float]] = {
        "url_workers": (4, config.url_workers),
        "url_retries": (0, config.url_retries),
        "url_backoff": (0.0, config.url_backoff),
        "rate_limit": (0.0, config.rate_limit),
        "parallel": (1, config.parallel),
        "chunk_size": (1024 * 1024, config.chunk_size),
        "overlap": (1024, config.overlap),
        "max_queue_size": (64, config.max_queue_size),
    }
    for name, (default_value, configured) in numeric_defaults.items():
        current: object = getattr(args, name, default_value)
        if current == default_value and configured != default_value:
            setattr(args, name, configured)
    optional_numeric_defaults: dict[str, float | None] = {
        "max_input_size_mb": config.max_input_size_mb,
        "max_input_seconds": config.max_input_seconds,
    }
    for name, optional_configured in optional_numeric_defaults.items():
        current_numeric: object = getattr(args, name, None)
        if current_numeric is None and optional_configured is not None:
            setattr(args, name, optional_configured)


def _apply_network_defaults(args: argparse.Namespace, config: AppConfig) -> None:
    current_diff_only: object = getattr(args, "diff_only", "all")
    if current_diff_only == "all" and config.diff_only != "all":
        args.diff_only = _validated_diff_only(config.diff_only)
    network_defaults: dict[str, str | float | None] = {
        "user_agent": config.user_agent,
        "proxy": config.proxy,
        "tls_cert": config.tls_cert,
        "ca_bundle": config.ca_bundle,
        "connect_timeout": config.connect_timeout,
        "read_timeout": config.read_timeout,
    }
    for name, configured in network_defaults.items():
        current_network: object = getattr(args, name, None)
        if current_network is None and configured:
            setattr(args, name, configured)
    allow_redirects_value: object = getattr(args, "allow_redirects", True)
    if allow_redirects_value is True and config.allow_redirects is False:
        args.allow_redirects = False
    tls_verify_value: object = getattr(args, "tls_verify", True)
    if tls_verify_value is True and config.tls_verify is False:
        args.tls_verify = False


def _validated_diff_only(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in VALID_DIFF_ONLY_VALUES:
        raise ValidationError(INVALID_DIFF_ONLY_ERROR.format(value=value))
    return normalized


def parse_http_mapping(value: object, *, separator: str) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return {}
        if stripped.startswith("{"):
            parsed: object = json.loads(stripped)
            return (
                {str(key): str(item) for key, item in parsed.items()}
                if isinstance(parsed, dict)
                else {}
            )
        items = [stripped]
    elif isinstance(value, (list, tuple)):
        items = [str(item) for item in value if str(item).strip()]
    else:
        items = [str(value)]
    mapping: dict[str, str] = {}
    for item in items:
        if separator not in item:
            continue
        name, raw_value = item.split(separator, maxsplit=1)
        mapping[name.strip()] = raw_value.strip()
    return mapping
