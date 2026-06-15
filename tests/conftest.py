from __future__ import annotations

import os
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def allow_private_urls_for_local_test_servers() -> Iterator[None]:
    # The test suite downloads from loopback test servers (127.0.0.1), which the
    # SSRF guard blocks by default. Opt out for the session via the same env var
    # operators use; dedicated SSRF tests delete it to exercise the block.
    previous = os.environ.get("IOCPARSER_ALLOW_PRIVATE_URLS")
    os.environ["IOCPARSER_ALLOW_PRIVATE_URLS"] = "1"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("IOCPARSER_ALLOW_PRIVATE_URLS", None)
        else:
            os.environ["IOCPARSER_ALLOW_PRIVATE_URLS"] = previous


@pytest.fixture(autouse=True)
def cleanup_persistence_engines() -> Iterator[None]:
    yield

    from iocparser.infrastructure import persistence_uow

    with persistence_uow._ENGINE_LOCK:
        engines = tuple(persistence_uow._ENGINE_CACHE.values())
        persistence_uow._ENGINE_CACHE.clear()
    persistence_uow.SQLAlchemyUnitOfWork._MIGRATED_URIS.clear()
    for engine in engines:
        engine.dispose()
