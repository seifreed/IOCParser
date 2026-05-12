from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import urlparse

from iocparser.cli_args_values import (
    get_bool_arg,
    get_list_arg,
    get_optional_str_arg,
)

MAX_FILENAME_LENGTH = 50


def get_output_filename(
    input_source: str,
    is_json: bool = False,
    output_format: str | None = None,
) -> str:
    """Generate an output filename based on the input name."""
    if input_source.lower().startswith(("http://", "https://")):
        url_parts = urlparse(input_source)
        base_name = url_parts.netloc
        if url_parts.path and url_parts.path != "/":
            path_parts = url_parts.path.strip("/").split("/")
            if path_parts[-1]:
                base_name += "_" + path_parts[-1]
        base_name = re.sub(r"[^\w\-\.]", "_", base_name)
    else:
        base_name = Path(input_source).stem

    if len(base_name) > MAX_FILENAME_LENGTH:
        base_name = base_name[:MAX_FILENAME_LENGTH]

    chosen_format = output_format if output_format else ("json" if is_json else "text")
    if chosen_format == "stix":
        extension = ".stix.json"
    elif chosen_format == "json":
        extension = ".json"
    elif chosen_format == "jsonl":
        extension = ".jsonl"
    elif chosen_format == "csv":
        extension = ".csv"
    else:
        extension = ".txt"
    return f"{base_name}_iocs{extension}"


def has_input_args(args: argparse.Namespace) -> bool:
    """Check if any input or query arguments are provided."""
    diff_runs: object = getattr(args, "diff_runs", None)
    diff_latest: object = getattr(args, "diff_latest", None)
    export_run: object = getattr(args, "export_run", None)
    delete_run: object = getattr(args, "delete_run", None)
    prune_before: object = getattr(args, "prune_before", None)
    retain_days: object = getattr(args, "retain_days", None)
    batch_job: object = getattr(args, "batch_job", None)
    batch_runs: object = getattr(args, "batch_runs", None)
    return bool(
        get_optional_str_arg(args, "file")
        or get_optional_str_arg(args, "url")
        or get_optional_str_arg(args, "url_direct")
        or get_list_arg(args, "multiple")
        or get_optional_str_arg(args, "directory")
        or get_optional_str_arg(args, "url_file")
        or get_optional_str_arg(args, "retry_failed_from")
        or get_optional_str_arg(args, "retry_batch_job")
        or get_bool_arg(args, "stdin")
        or get_bool_arg(args, "list_runs")
        or get_optional_str_arg(args, "search_ioc")
        or diff_runs
        or diff_latest is not None
        or export_run is not None
        or delete_run is not None
        or prune_before is not None
        or retain_days is not None
        or get_optional_str_arg(args, "export_history")
        or get_optional_str_arg(args, "import_history")
        or get_optional_str_arg(args, "archive_history")
        or get_optional_str_arg(args, "restore_history")
        or get_bool_arg(args, "compact_history")
        or get_bool_arg(args, "schema_version")
        or get_bool_arg(args, "migrate")
        or get_bool_arg(args, "validate_schema")
        or get_bool_arg(args, "list_failed_batches")
        or get_bool_arg(args, "list_batches")
        or batch_job is not None
        or batch_runs is not None
        or get_bool_arg(args, "list_plugins")
    )
