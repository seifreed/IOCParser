from __future__ import annotations

from collections.abc import Iterator

import pytest


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
