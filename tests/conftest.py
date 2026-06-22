from __future__ import annotations

import os
import os.path
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def expanduser_honors_home(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``~`` expansion follow the ``HOME`` env var on every platform.

    Many tests redirect ``~`` by monkeypatching ``HOME`` to a tmp dir. POSIX
    ``expanduser`` honors ``HOME``, but Windows ``ntpath.expanduser`` uses
    ``USERPROFILE``/``HOMEDRIVE``+``HOMEPATH`` and ignores ``HOME``, so those tests
    expanded ``~`` to the real profile and failed only on Windows. Reading ``HOME``
    at call time (``pathlib.Path.expanduser`` delegates here) keeps the behavior
    identical across OSes; it is a no-op on POSIX, which already honors ``HOME``.
    """
    real_expanduser = os.path.expanduser

    def expanduser(path: str) -> str:
        home = os.environ.get("HOME")
        if home and isinstance(path, str) and (path == "~" or path[:2] in ("~/", "~\\")):
            return home + path[1:]
        return real_expanduser(path)

    monkeypatch.setattr(os.path, "expanduser", expanduser)


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
