#!/usr/bin/env python3
"""
Backward-compatible entrypoint for legacy imports.

Keep this module so existing code that imports iocparser.main keeps working.
"""

from typing import cast

from iocparser import core as _core
from iocparser.__main__ import main as _main

main = _main
__all__ = ["main"] + [name for name in dir(_core) if not name.startswith("_")]

for _name in __all__:
    if _name == "main":
        continue
    globals_dict: dict[str, object] = globals()
    globals_dict[_name] = cast("object", getattr(_core, _name))

del _core
