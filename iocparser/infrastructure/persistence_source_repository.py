from __future__ import annotations

from datetime import UTC, datetime
from typing import override

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from iocparser.infrastructure.persistence_models import SourceModel
from iocparser.infrastructure.persistence_repository_support import (
    SOURCE_MODEL,
    insert_or_refetch,
    normalize_search,
    normalize_source_value,
    source_dedup_hash,
)
from iocparser.domain.sources import normalize_url_value
from iocparser.infrastructure.persistence_support import normalized_source_filter
from iocparser.interfaces.ports import SourceRepository


def _strip_optional(value: str | None) -> str | None:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    return stripped or None


class SQLAlchemySourceRepository(SourceRepository):
    def __init__(self, session: Session) -> None:
        self.session = session

    @override
    def get_or_create(
        self,
        *,
        kind: str,
        value: str,
        original_url: str | None = None,
        normalized_url: str | None = None,
        mime_type: str | None = None,
        input_size: int | None = None,
        content_hash: str | None = None,
        fingerprint: str | None = None,
    ) -> int:
        kind = normalized_source_filter(kind)
        value = normalize_source_value(kind, value)
        original_url = _strip_optional(original_url)
        normalized_url = _strip_optional(normalized_url)
        mime_type = _strip_optional(mime_type)
        content_hash = _strip_optional(content_hash)
        fingerprint = _strip_optional(fingerprint)
        if kind == "url":
            normalized_url = normalize_url_value(normalized_url) or normalize_url_value(value)
        stmt = select(SOURCE_MODEL).where(SourceModel.kind == kind)
        if kind == "url":
            if normalized_url:
                stmt = stmt.where(
                    or_(
                        SourceModel.normalized_url == normalized_url,
                        func.trim(SourceModel.value) == value,
                    )
                )
            else:
                stmt = stmt.where(func.trim(SourceModel.value) == value)
        else:
            stmt = stmt.where(func.trim(SourceModel.value) == value)
        source_rows: list[SourceModel] = self.session.execute(stmt).scalars().all()
        source = next(
            (
                row
                for row in source_rows
                if kind == "url" and normalized_url and row.normalized_url == normalized_url
            ),
            None,
        )
        if source is None:
            source = source_rows[0] if source_rows else None
        now = datetime.now(UTC)
        if source is not None:
            source.last_seen = now
            if kind == "url":
                source.value = value
            source.original_url = original_url or source.original_url
            source.normalized_url = normalized_url or source.normalized_url
            source.mime_type = mime_type or source.mime_type
            source.input_size = input_size if input_size is not None else source.input_size
            source.content_hash = content_hash or source.content_hash
            source.fingerprint = fingerprint or source.fingerprint
            source.dedup_hash = source_dedup_hash(kind, value)
            source.value_search = normalize_search(source.value)
            return source.id
        source = SOURCE_MODEL(
            kind=kind,
            value=value,
            value_search=normalize_search(value),
            dedup_hash=source_dedup_hash(kind, value),
            original_url=original_url,
            normalized_url=normalized_url,
            mime_type=mime_type,
            input_size=input_size,
            content_hash=content_hash,
            fingerprint=fingerprint,
            first_seen=now,
            last_seen=now,
        )
        refetch_stmt = select(SOURCE_MODEL).where(
            SourceModel.kind == kind,
            func.trim(SourceModel.value) == value,
        )

        def _on_conflict(existing: SourceModel) -> int:
            existing.last_seen = now
            if kind == "url":
                existing.value = value
            existing.original_url = original_url or existing.original_url
            existing.normalized_url = normalized_url or existing.normalized_url
            existing.mime_type = mime_type or existing.mime_type
            existing.input_size = input_size if input_size is not None else existing.input_size
            existing.content_hash = content_hash or existing.content_hash
            existing.fingerprint = fingerprint or existing.fingerprint
            existing.dedup_hash = source_dedup_hash(kind, value)
            existing.value_search = normalize_search(existing.value)
            return existing.id

        return insert_or_refetch(
            self.session,
            source,
            refetch_stmt,
            on_insert=lambda: source.id,
            on_conflict=_on_conflict,
        )
