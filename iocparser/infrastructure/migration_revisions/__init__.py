from __future__ import annotations

from collections.abc import Callable

RevisionStep = tuple[object, Callable[[object, object], None]]
