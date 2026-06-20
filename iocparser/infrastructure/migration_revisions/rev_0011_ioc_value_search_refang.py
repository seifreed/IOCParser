from __future__ import annotations

from sqlalchemy import Engine, Inspector

from iocparser.infrastructure.persistence_repository_support import rebuild_ioc_value_search


def apply(engine: Engine, inspector: Inspector) -> None:
    """Recompute iocs.value_search with the refanged normalization used at write time.

    The v3 backfill used lower(trim(value)) with no refang, so legacy defanged IOCs
    were unsearchable by their real value (and poisoned the FTS index rebuilt from
    value_search). Rebuild value_search and the FTS index from it.
    """
    rebuild_ioc_value_search(engine, inspector)
