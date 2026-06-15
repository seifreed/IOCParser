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

    Tokens are joined into a single ordered phrase so they must appear
    consecutively in the same order as the original value, with a prefix on
    the final token for partial matches. This avoids the previous bug where
    ``192.168.1.1`` was tokenised into independent terms that could match
    unrelated IOCs containing e.g. ``"1"`` -- while still matching values of
    four or more tokens (such as an IPv4 address), which ``NEAR(..., 0)``
    failed to match at all.
    """
    terms = [term for term in re.split(r"[^a-zA-Z0-9]+", value.lower()) if term]
    if not terms:
        return None
    return '"' + " ".join(terms) + '"*'


def sync_fts_index(session: Session) -> None:
    """Rebuild the IOC FTS index from the canonical IOC table."""
    bind = session.get_bind()
    if not has_fts_table(bind):
        return
    session.execute(text("INSERT INTO ioc_search_fts(ioc_search_fts) VALUES ('rebuild')"))
