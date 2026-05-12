from __future__ import annotations

import re

from sqlalchemy import Engine, Inspector, inspect, text
from sqlalchemy.orm import Session

FTS_TABLE = "ioc_search_fts"


def has_fts_table(engine: Engine) -> bool:
    """Return whether the configured database contains the IOC FTS table."""
    with engine.connect() as connection:
        inspector: Inspector = inspect(connection)
        return FTS_TABLE in set(inspector.get_table_names())


def build_fts_query(value: str) -> str | None:
    """Convert a free-text IOC search into an FTS5 phrase query.

    We use NEAR(..., 0) with ordered terms so that tokens must appear
    consecutively in the same order as the original value.  This avoids
    the previous bug where ``192.168.1.1`` was tokenised into independent
    prefix terms that could match unrelated IOCs containing e.g. ``"1"``.
    """
    terms = [term for term in re.split(r"[^a-zA-Z0-9]+", value.lower()) if term]
    if not terms:
        return None
    if len(terms) == 1:
        return f'"{terms[0]}"*'
    return "NEAR(" + " ".join(f'"{term}"' for term in terms) + ", 0)"


def sync_fts_index(session: Session) -> None:
    """Rebuild the IOC FTS index from the canonical IOC table."""
    bind = session.get_bind()
    if not has_fts_table(bind):
        return
    session.execute(text("INSERT INTO ioc_search_fts(ioc_search_fts) VALUES ('rebuild')"))
