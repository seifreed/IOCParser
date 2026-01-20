#!/usr/bin/env python3
"""
Backward-compatible entrypoint for legacy imports.

Keep this module so existing code that imports iocparser.main keeps working.
"""

from iocparser.__main__ import main  # noqa: F401
from iocparser.core import *  # noqa: F403
