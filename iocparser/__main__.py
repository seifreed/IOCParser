#!/usr/bin/env python3

"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
Version: 5.0.0
"""

import sys

from colorama import init

from iocparser.cli import execute, logger
from iocparser.errors import IOCParserError, ValidationError


def main() -> None:
    """Main function."""
    init(autoreset=True)
    try:
        execute()
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(0)
    except ValidationError as exc:
        logger.error("%s", exc)
        sys.exit(1)
    except (IOCParserError, OSError, ValueError, RuntimeError) as exc:
        logger.error("Unexpected error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
