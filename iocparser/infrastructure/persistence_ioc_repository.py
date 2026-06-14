from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from iocparser.domain.models import ExtractionResult
from iocparser.infrastructure.persistence_models import IOCModel
from iocparser.infrastructure.persistence_repository_support import (
    IOC_MODEL,
    ExtractionResultLike,
    insert_or_refetch,
    normalize_ioc_search,
    normalized_ioc_type_name,
)
from iocparser.interfaces.ports import IOCRepository


def _refresh_search_value(ioc: IOCModel, search_value: str) -> None:
    if getattr(ioc, "value_search", search_value) != search_value:
        ioc.value_search = search_value


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
        search_value = normalize_ioc_search(value)
        stmt = select(IOC_MODEL).where(
            IOCModel.ioc_type == ioc_type,
            IOCModel.value == value,
            IOCModel.is_warning == is_warning,
            IOCModel.warning_list == warning_list,
            IOCModel.warning_description == warning_description,
        )
        ioc_rows: list[IOCModel] = self.session.execute(stmt).scalars().all()
        existing = ioc_rows[0] if ioc_rows else None
        if existing is not None:
            _refresh_search_value(existing, search_value)
            return existing.id
        ioc = IOC_MODEL(
            ioc_type=ioc_type,
            value=value,
            value_search=search_value,
            is_warning=is_warning,
            warning_list=warning_list,
            warning_description=warning_description,
        )

        def _on_conflict(row: IOCModel) -> int:
            _refresh_search_value(row, search_value)
            return row.id

        return insert_or_refetch(
            self.session,
            ioc,
            stmt,
            on_insert=lambda: ioc.id,
            on_conflict=_on_conflict,
        )

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
