from __future__ import annotations

from contextlib import nullcontext

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from iocparser.domain.models import ExtractionResult
from iocparser.infrastructure.persistence_models import IOCModel
from iocparser.infrastructure.persistence_repository_support import (
    IOC_MODEL,
    ExtractionResultLike,
    normalize_ioc_search,
    normalized_ioc_type_name,
)
from iocparser.interfaces.ports import IOCRepository


class SQLAlchemyIOCRepository(IOCRepository):
    def __init__(self, session: Session) -> None:
        self.session = session

    def _get_or_create(
        self,
        *,
        ioc_type: str,
        value: str,
        is_warning: bool,
        warning_list: str,
        warning_description: str,
    ) -> int:
        stmt = select(IOC_MODEL).where(
            IOCModel.ioc_type == ioc_type,
            IOCModel.value == value,
            IOCModel.is_warning == is_warning,
            IOCModel.warning_list == warning_list,
            IOCModel.warning_description == warning_description,
        )
        ioc_rows: list[IOCModel] = self.session.execute(stmt).scalars().all()
        ioc = ioc_rows[0] if ioc_rows else None
        if ioc is not None:
            return ioc.id
        ioc = IOC_MODEL(
            ioc_type=ioc_type,
            value=value,
            value_search=normalize_ioc_search(value),
            is_warning=is_warning,
            warning_list=warning_list,
            warning_description=warning_description,
        )
        savepoint = self.session.begin_nested()
        try:
            self.session.add(ioc)
            self.session.flush()
        except IntegrityError:
            try:
                savepoint.rollback()
            except Exception:
                self.session.rollback()
                raise
            with getattr(self.session, "no_autoflush", nullcontext()):
                ioc_rows = self.session.execute(stmt).scalars().all()
            if not ioc_rows:
                raise
            return ioc_rows[0].id
        return ioc.id

    def get_or_create_normal(self, result: ExtractionResultLike | ExtractionResult) -> list[int]:
        return [
            self._get_or_create(
                ioc_type=normalized_ioc_type_name(ioc.ioc_type),
                value=ioc.value.raw,
                is_warning=False,
                warning_list="",
                warning_description="",
            )
            for ioc in result.iocs
        ]

    def get_or_create_warnings(self, result: ExtractionResultLike | ExtractionResult) -> list[int]:
        return [
            self._get_or_create(
                ioc_type=normalized_ioc_type_name(warning.ioc.ioc_type),
                value=warning.ioc.value.raw,
                is_warning=True,
                warning_list=warning.warning_list,
                warning_description=warning.description,
            )
            for warning in result.warnings
        ]
