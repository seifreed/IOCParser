#!/usr/bin/env python3

"""
Persistence layer for IOCParser.

Supports SQLite and MariaDB via SQLAlchemy.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""


class Source(Base):
    """Input source (URL or file)."""

    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (UniqueConstraint("kind", "value", name="uq_sources_kind_value"),)


class Run(Base):
    """Extraction run for a source."""

    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    options_json: Mapped[str] = mapped_column(Text, nullable=False)

    source: Mapped[Source] = relationship()


class IOC(Base):
    """IOC entries (deduplicated)."""

    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    is_warning: Mapped[bool] = mapped_column(Boolean, nullable=False)
    warning_list: Mapped[str] = mapped_column(Text, nullable=False, default="")
    warning_description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        UniqueConstraint(
            "ioc_type",
            "value",
            "is_warning",
            "warning_list",
            "warning_description",
            name="uq_iocs_value",
        ),
    )


class RunIOC(Base):
    """Mapping between runs and IOCs."""

    __tablename__ = "run_iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), nullable=False)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"), nullable=False)

    __table_args__ = (UniqueConstraint("run_id", "ioc_id", name="uq_run_ioc"),)


@dataclass(frozen=True)
class PersistOptions:
    """Options captured for persistence."""

    defang: bool
    check_warnings: bool
    force_update: bool
    output_format: str

    def to_json(self) -> str:
        payload: dict[str, bool | str] = {
            "defang": self.defang,
            "check_warnings": self.check_warnings,
            "force_update": self.force_update,
            "output_format": self.output_format,
        }
        return json.dumps(payload)


class PersistenceManager:
    """Manage persistence operations."""

    def __init__(self, db_uri: str) -> None:
        self.engine = create_engine(db_uri, future=True)
        Base.metadata.create_all(self.engine)

    def _get_or_create_source(self, session: Session, kind: str, value: str) -> Source:
        stmt = select(Source).where(Source.kind == kind, Source.value == value)
        source = session.execute(stmt).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if source:
            source.last_seen = now
            return source

        source = Source(
            kind=kind,
            value=value,
            content_hash=None,
            first_seen=now,
            last_seen=now,
        )
        session.add(source)
        session.flush()
        return source

    def _get_or_create_ioc(
        self,
        session: Session,
        *,
        ioc_type: str,
        value: str,
        is_warning: bool,
        warning_list: str,
        warning_description: str,
    ) -> IOC:
        stmt = select(IOC).where(
            IOC.ioc_type == ioc_type,
            IOC.value == value,
            IOC.is_warning == is_warning,
            IOC.warning_list == warning_list,
            IOC.warning_description == warning_description,
        )
        ioc = session.execute(stmt).scalar_one_or_none()
        if ioc:
            return ioc

        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            is_warning=is_warning,
            warning_list=warning_list,
            warning_description=warning_description,
        )
        session.add(ioc)
        session.flush()
        return ioc

    def _collect_normal_ioc_ids(
        self,
        session: Session,
        normal_iocs: dict[str, list[str | dict[str, str]]],
    ) -> list[int]:
        ioc_ids: list[int] = []
        for ioc_type, values in normal_iocs.items():
            for value in values:
                val = value.get("value") if isinstance(value, dict) else str(value)
                if not val:
                    continue
                ioc = self._get_or_create_ioc(
                    session,
                    ioc_type=ioc_type,
                    value=val,
                    is_warning=False,
                    warning_list="",
                    warning_description="",
                )
                ioc_ids.append(ioc.id)
        return ioc_ids

    def _collect_warning_ioc_ids(
        self,
        session: Session,
        warning_iocs: dict[str, list[dict[str, str]]],
    ) -> list[int]:
        ioc_ids: list[int] = []
        for ioc_type, warnings in warning_iocs.items():
            for warning in warnings:
                val = warning.get("value")
                if not val:
                    continue
                ioc = self._get_or_create_ioc(
                    session,
                    ioc_type=ioc_type,
                    value=val,
                    is_warning=True,
                    warning_list=warning.get("warning_list", "") or "",
                    warning_description=warning.get("description", "") or "",
                )
                ioc_ids.append(ioc.id)
        return ioc_ids

    def persist_run(
        self,
        source_kind: str,
        source_value: str,
        *,
        normal_iocs: dict[str, list[str | dict[str, str]]],
        warning_iocs: dict[str, list[dict[str, str]]],
        tool_version: str,
        options: PersistOptions,
    ) -> int:
        """Persist a run and all associated IOCs."""
        with Session(self.engine) as session:
            started_at = datetime.now(timezone.utc)
            source = self._get_or_create_source(session, source_kind, source_value)
            run = Run(
                source_id=source.id,
                started_at=started_at,
                finished_at=started_at,
                tool_version=tool_version,
                options_json=options.to_json(),
            )
            session.add(run)
            session.flush()

            ioc_ids = self._collect_normal_ioc_ids(session, normal_iocs)
            ioc_ids.extend(self._collect_warning_ioc_ids(session, warning_iocs))

            for ioc_id in ioc_ids:
                session.add(RunIOC(run_id=run.id, ioc_id=ioc_id))

            session.commit()
            return run.id

    def persist_multiple_runs(
        self,
        runs: Iterable[
            tuple[str, str, dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]
        ],
        tool_version: str,
        options: PersistOptions,
    ) -> list[int]:
        """Persist multiple runs, returning run IDs."""
        run_ids: list[int] = []
        for kind, value, normal_iocs, warning_iocs in runs:
            run_id = self.persist_run(
                source_kind=kind,
                source_value=value,
                normal_iocs=normal_iocs,
                warning_iocs=warning_iocs,
                tool_version=tool_version,
                options=options,
            )
            run_ids.append(run_id)
        return run_ids
