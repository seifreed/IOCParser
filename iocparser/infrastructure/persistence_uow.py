from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from iocparser.infrastructure.persistence_ioc_repository import SQLAlchemyIOCRepository
from iocparser.infrastructure.persistence_run_repository import SQLAlchemyRunRepository
from iocparser.infrastructure.persistence_source_repository import SQLAlchemySourceRepository


class SQLAlchemyUnitOfWork:
    def __init__(self, db_uri: str) -> None:
        from iocparser.infrastructure.persistence_migrations import migrate_engine

        self.engine = create_engine(db_uri, future=True)
        migrate_engine(self.engine)
        self.session = Session(self.engine)
        self.source_repository = SQLAlchemySourceRepository(self.session)
        self.ioc_repository = SQLAlchemyIOCRepository(self.session)
        self.run_repository = SQLAlchemyRunRepository(self.session)

    def commit(self) -> None:
        self.session.commit()

    def rollback(self) -> None:
        self.session.rollback()

    def close(self) -> None:
        self.session.close()
