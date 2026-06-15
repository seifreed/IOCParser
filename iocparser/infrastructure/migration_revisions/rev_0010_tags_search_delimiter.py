from __future__ import annotations

from sqlalchemy import Engine, Inspector

from iocparser.infrastructure.persistence_repository_support import rebuild_tags_search


def apply(engine: Engine, inspector: Inspector) -> None:
    """Rebuild run_iocs.tags_search with the delimiter-wrapped format.

    The previous space-joined format made a search for a single-word tag wrongly
    match a compound tag that merely contained that word (e.g. searching
    ``network`` matched ``internal network``).
    """
    rebuild_tags_search(engine, inspector)
