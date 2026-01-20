#!/usr/bin/env python3

"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
Version: 5.0.0
"""

import sys

from iocparser.core import (
    VERSION,
    create_argument_parser,
    display_results,
    get_bool_arg,
    get_list_arg,
    get_optional_str_arg,
    handle_misp_init,
    has_input_args,
    logger,
    persist_results,
    process_multiple_files_input,
    process_single_input,
    resolve_persistence,
    save_output,
    setup_application,
)
from iocparser.modules.persistence import PersistOptions


def main() -> None:
    """Main function."""
    try:
        parser = create_argument_parser()
        args = parser.parse_args()
        config = resolve_persistence(args)

        setup_application(args)

        # Handle initialization or force update request
        if get_bool_arg(args, "init") or get_bool_arg(args, "force_update"):
            handle_misp_init()
            return

        # Verify input is provided
        if not has_input_args(args):
            parser.print_help()
            logger.error("No input provided. Use -f, -u, -m, --init, or --force-update")
            sys.exit(1)

        # Process input based on type
        if get_list_arg(args, "multiple"):
            normal_iocs, warning_iocs, input_display, results = process_multiple_files_input(args)
        else:
            normal_iocs, warning_iocs, input_display = process_single_input(args)
            results = None

        # Display and save results
        display_results(normal_iocs, warning_iocs)
        save_output(args, normal_iocs, warning_iocs, input_display)

        if get_bool_arg(args, "stix"):
            output_format = "stix"
        elif get_bool_arg(args, "json"):
            output_format = "json"
        else:
            output_format = "text"
        options = PersistOptions(
            defang=not get_bool_arg(args, "no_defang"),
            check_warnings=not get_bool_arg(args, "no_check_warnings"),
            force_update=get_bool_arg(args, "force_update"),
            output_format=output_format,
        )

        if results:
            for source_path, (file_iocs, file_warnings) in results.items():
                persist_results(
                    config=config,
                    source_kind="file",
                    source_value=source_path,
                    normal_iocs=file_iocs,
                    warning_iocs=file_warnings,
                    options=options,
                    tool_version=VERSION,
                )
        else:
            source_kind = (
                "url"
                if get_optional_str_arg(args, "url") or get_optional_str_arg(args, "url_direct")
                else "file"
            )
            persist_results(
                config=config,
                source_kind=source_kind,
                source_value=input_display,
                normal_iocs=normal_iocs,
                warning_iocs=warning_iocs,
                options=options,
                tool_version=VERSION,
            )

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e!s}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__": main()
