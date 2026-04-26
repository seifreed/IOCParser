from __future__ import annotations

import argparse
import time
from collections.abc import Callable

from iocparser import cli_args as _cli_args
from iocparser import cli_dispatch_workflow as _workflow
from iocparser import cli_runtime as _cli_runtime
from iocparser.cli_processing_support import BatchResultsCollection, GroupedIocs, GroupedWarnings
from iocparser.errors import ValidationError

NO_INPUT_MESSAGE = "No input provided. Use -f, -u, -m, -d, --url-file, --stdin, or a query command"
BatchResults = BatchResultsCollection


def run_cli(
    args: argparse.Namespace,
    *,
    handle_misp_init: Callable[[], None],
    process_multiple_files_input: Callable[[argparse.Namespace], tuple[GroupedIocs, GroupedWarnings, str, BatchResults]],
    process_single_input: Callable[[argparse.Namespace], tuple[GroupedIocs, GroupedWarnings, str]],
    save_output: Callable[[argparse.Namespace, GroupedIocs, GroupedWarnings, str], None],
) -> None:
    """Execute the CLI workflow for parsed arguments."""
    config = _cli_runtime.resolve_persistence(args)
    _cli_runtime.setup_application(args)
    workflow_started = time.perf_counter()

    if _workflow.handle_preprocessing_commands(args, config=config, handle_misp_init=handle_misp_init):
        return

    payload = _workflow.resolve_input_payload(
        args,
        config=config,
        process_multiple_files_input=process_multiple_files_input,
        process_single_input=process_single_input,
    )
    _workflow.finalize_cli_run(
        args,
        config=config,
        workflow_started=workflow_started,
        normal_iocs=payload.normal_iocs,
        warning_iocs=payload.warning_iocs,
        input_display=payload.input_display,
        results=payload.results,
        batch_report=payload.batch_report,
        save_output=save_output,
    )


def execute(
    argv: list[str] | None = None,
    *,
    create_argument_parser: Callable[[], argparse.ArgumentParser],
    run_cli: Callable[[argparse.Namespace], None],
) -> None:
    """Entry point helper used by the CLI facade."""
    parser = create_argument_parser()
    args = parser.parse_args(argv)
    if (
        not _cli_args.has_input_args(args)
        and not _cli_args.get_bool_arg(args, "init")
        and not _cli_args.get_bool_arg(args, "force_update")
    ):
        parser.print_help()
        raise ValidationError(NO_INPUT_MESSAGE)
    run_cli(args)
