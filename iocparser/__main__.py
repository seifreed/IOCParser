#!/usr/bin/env python3

"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
"""

import sys

from colorama import init

from iocparser.cli import execute, logger
from iocparser.errors import IOCParserError


def main() -> None:
    """Main function."""
    init(autoreset=True)
    try:
        execute()
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(0)
    except IOCParserError as exc:
        # IOCParserError (incl. ValidationError, FileExistenceError, ...) is the app's
        # intentional signalling for expected, user-facing conditions, so report a
        # concise message instead of a stack trace that reads like a crash.
        logger.error("%s", exc)
        sys.exit(1)
    except (OSError, ValueError, RuntimeError) as exc:
        logger.error("Unexpected error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
