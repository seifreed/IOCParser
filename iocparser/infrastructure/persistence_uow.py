from __future__ import annotations

import threading
from types import TracebackType
from typing import ClassVar, Literal

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository
from iocparser.infrastructure.persistence_run_repository import SQLAlchemyRunRepository
from iocparser.infrastructure.persistence_source_repository import SQLAlchemySourceRepository

# Module-level engine cache: db_uri -> Engine
# Engines are expensive to create and should be reused across units of work.
_ENGINE_CACHE: dict[str, Engine] = {}
_ENGINE_LOCK = threading.Lock()


def _get_or_create_engine(db_uri: str) -> Engine:
    """Return a cached Engine for *db_uri*, creating it if necessary."""
    engine = _ENGINE_CACHE.get(db_uri)
    if engine is not None:
        return engine
    with _ENGINE_LOCK:
        engine = _ENGINE_CACHE.get(db_uri)
        if engine is not None:
            return engine
        new_engine = create_engine(db_uri, future=True)
        _ENGINE_CACHE[db_uri] = new_engine
        return new_engine


class SQLAlchemyUnitOfWork:
    _MIGRATED_URIS: ClassVar[set[str]] = set()
    _MIGRATE_LOCK: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, db_uri: str) -> None:
        self.engine = _get_or_create_engine(db_uri)
        SQLAlchemyUnitOfWork.migrate(db_uri)
        self.session = Session(self.engine)
        self.source_repository = SQLAlchemySourceRepository(self.session)
        self.ioc_repository = SQLAlchemyIOCRepository(self.session)
        self.run_repository = SQLAlchemyRunRepository(self.session)

    @classmethod
    def migrate(cls, db_uri: str) -> None:
        """Run schema migrations for *db_uri* at most once per process."""
        if db_uri in cls._MIGRATED_URIS:
            return
        with cls._MIGRATE_LOCK:
            if db_uri in cls._MIGRATED_URIS:
                return
            from iocparser.infrastructure.persistence_migrations import migrate_engine

            engine = _get_or_create_engine(db_uri)
            migrate_engine(engine)
            cls._MIGRATED_URIS.add(db_uri)

    def __enter__(self) -> SQLAlchemyUnitOfWork:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        self.close()
        return False

    def commit(self) -> None:
        self.session.commit()

    def rollback(self) -> None:
        self.session.rollback()

    def close(self) -> None:
        self.session.close()
        if self.engine.dialect.name == "sqlite":
            self.engine.dispose()
