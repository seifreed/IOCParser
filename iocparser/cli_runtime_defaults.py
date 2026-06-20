from __future__ import annotations

import argparse
import json
from pathlib import Path

from iocparser.cli_args import get_bool_arg, get_optional_str_arg
from iocparser.config import AppConfig
from iocparser.errors import ValidationError
from iocparser.shared_utils import validated_diff_only

INVALID_HTTP_MAPPING_ERROR = "Invalid HTTP mapping JSON: {value}"
INVALID_HTTP_MAPPING_ITEM_ERROR = "Invalid HTTP mapping item: {value}"
INVALID_CHUNK_SIZE = "Invalid chunk_size: {value}"
INVALID_OVERLAP = "Invalid overlap: {value}"
INVALID_MAX_INPUT_SIZE_MB = "Invalid max_input_size_mb: {value}"
INVALID_OUTPUT_FORMAT = "Invalid output_format: {value}"
TLS_FILE_NOT_FOUND = "{flag} file does not exist: {path}"


def mb_to_bytes(megabytes: float | None) -> int | None:
    """Convert a megabyte limit (e.g. --max-input-size-mb) to bytes, preserving None."""
    if megabytes is None:
        return None
    if megabytes < 0:
        raise ValidationError(INVALID_MAX_INPUT_SIZE_MB.format(value=megabytes))
    return int(megabytes * 1024 * 1024)


def _validated_tls_file(value: str | None, *, flag: str) -> str | None:
    """Reject a missing --ca-bundle/--tls-cert path at the CLI boundary.

    Left unchecked, requests raises an OSError mid-download that surfaces as a
    generic "Unexpected error download <url>", looking like a crash rather than the
    bad-path user error it is.
    """
    if value is None:
        return None
    expanded = str(Path(value).expanduser())
    if not Path(expanded).is_file():
        raise ValidationError(TLS_FILE_NOT_FOUND.format(flag=flag, path=value))
    return expanded


def resolve_tls_options(args: argparse.Namespace) -> tuple[bool | str, str | None]:
    """Resolve (verify, cert) from TLS args, validating file paths up front."""
    ca_bundle = _validated_tls_file(get_optional_str_arg(args, "ca_bundle"), flag="--ca-bundle")
    verify: bool | str = get_bool_arg(args, "tls_verify", True)
    if verify and ca_bundle:
        verify = ca_bundle
    cert = _validated_tls_file(get_optional_str_arg(args, "tls_cert"), flag="--tls-cert")
    return verify, cert


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
    # Normalize case/whitespace so an INI/env "output_format = JSON" is honored rather than
    # silently falling back to text; the CLI flags and the valid set are lowercase.
    raw_output_format = config.output_format
    output_format = (raw_output_format or "").strip().lower()
    if output_format and output_format not in {"text", "json", "jsonl", "csv", "stix"}:
        raise ValidationError(INVALID_OUTPUT_FORMAT.format(value=raw_output_format))
    if not any(get_bool_arg(args, name) for name in ("json", "jsonl", "csv", "stix")) and (
        output_format in {"json", "jsonl", "csv", "stix"}
    ):
        setattr(args, output_format, True)


def _apply_numeric_defaults(args: argparse.Namespace, config: AppConfig) -> None:
    # Precedence is CLI > env > INI, so only validate the INI/env value when the CLI
    # did not override it; an explicit --chunk-size/--overlap already passed argparse's
    # positive/non-negative type check and must win over a bad config value.
    if getattr(args, "chunk_size", None) is None and config.chunk_size < 1:
        raise ValidationError(INVALID_CHUNK_SIZE.format(value=config.chunk_size))
    if getattr(args, "overlap", None) is None and config.overlap < 0:
        raise ValidationError(INVALID_OVERLAP.format(value=config.overlap))
    numeric_defaults: dict[str, int | float] = {
        "url_workers": config.url_workers,
        "url_retries": config.url_retries,
        "url_backoff": config.url_backoff,
        "rate_limit": config.rate_limit,
        "parallel": config.parallel,
        "chunk_size": config.chunk_size,
        "overlap": config.overlap,
        "max_queue_size": config.max_queue_size,
    }
    for name, configured in numeric_defaults.items():
        current: object = getattr(args, name, None)
        if current is None:
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
    current_diff_only: object = getattr(args, "diff_only", None)
    if current_diff_only is None:
        args.diff_only = validated_diff_only(config.diff_only)
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
        if current_network is None and configured is not None:
            setattr(args, name, configured)
    if getattr(args, "allow_redirects", None) is None:
        args.allow_redirects = config.allow_redirects
    if getattr(args, "tls_verify", None) is None:
        args.tls_verify = config.tls_verify


def parse_http_mapping(value: object, *, separator: str) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return {}
        if stripped.startswith(("{", "[")):
            return _parse_json_http_mapping(stripped)
        items = [stripped]
    elif isinstance(value, (list, tuple)):
        items = []
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(INVALID_HTTP_MAPPING_ITEM_ERROR.format(value=item))
            stripped_item = item.strip()
            if stripped_item:
                items.append(stripped_item)
    else:
        return {}
    mapping: dict[str, str] = {}
    for item in items:
        if separator not in item:
            raise ValidationError(INVALID_HTTP_MAPPING_ITEM_ERROR.format(value=item))
        name, raw_value = item.split(separator, maxsplit=1)
        normalized_name = name.strip()
        if not normalized_name:
            continue
        mapping[normalized_name] = raw_value.strip()
    return mapping


def _parse_json_http_mapping(value: str) -> dict[str, str]:
    try:
        parsed: object = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValidationError(INVALID_HTTP_MAPPING_ERROR.format(value=value)) from exc
    if not isinstance(parsed, dict):
        raise ValidationError(INVALID_HTTP_MAPPING_ERROR.format(value=value))
    mapping: dict[str, str] = {}
    for key, item in parsed.items():
        if not isinstance(key, str):
            raise ValidationError(INVALID_HTTP_MAPPING_ITEM_ERROR.format(value=key))
        if not isinstance(item, str):
            raise ValidationError(INVALID_HTTP_MAPPING_ITEM_ERROR.format(value=item))
        mapping[key] = item
    return mapping
