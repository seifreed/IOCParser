from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from iocparser.domain.models import ExtractionResult
from iocparser.infrastructure.persistence_repository_support import (
    RUN_IOC_MODEL,
    RUN_MODEL,
    ExtractionResultLike,
    PersistOptionsLike,
    build_tags_search,
    int_metadata_value,
    metadata_ioc,
    optional_int_metadata_value,
    result_items,
    serialize_evidence,
    serialize_tags,
    string_metadata_value,
)
from iocparser.interfaces.ports import RunRepository


class SQLAlchemyRunRepository(RunRepository):
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_run(
        self,
        *,
        source_id: int,
        tool_version: str,
        options: PersistOptionsLike,
        metadata: Mapping[str, int | str | None] | None = None,
    ) -> int:
        started_at = datetime.now(UTC)
        run_metadata = dict(metadata or {})
        duration_ms = int_metadata_value(run_metadata, "duration_ms", 0)
        run = RUN_MODEL(
            source_id=source_id,
            batch_job_id=optional_int_metadata_value(run_metadata, "batch_job_id"),
            started_at=started_at,
            finished_at=started_at + timedelta(milliseconds=duration_ms),
            tool_version=tool_version,
            options_json=json.dumps(options.to_dict()),
            normal_ioc_count=int_metadata_value(run_metadata, "normal_ioc_count", 0),
            warning_ioc_count=int_metadata_value(run_metadata, "warning_ioc_count", 0),
            processed_items=int_metadata_value(run_metadata, "processed_items", 1),
            successful_items=int_metadata_value(run_metadata, "successful_items", 1),
            failed_items=int_metadata_value(run_metadata, "failed_items", 0),
            partial_error_count=int_metadata_value(run_metadata, "partial_error_count", 0),
            duration_ms=duration_ms,
            status=string_metadata_value(run_metadata, "status", "success") or "success",
            error_message=string_metadata_value(run_metadata, "error_message", "") or "",
        )
        self.session.add(run)
        self.session.flush()
        return run.id

    def attach_iocs(
        self,
        *,
        run_id: int,
        ioc_ids: list[int],
        result: ExtractionResultLike | ExtractionResult | None = None,
    ) -> None:
        metadata_items = result_items(result)
        attached_ioc_ids: set[int] = set()
        for index, ioc_id in enumerate(ioc_ids):
            if ioc_id in attached_ioc_ids:
                continue
            attached_ioc_ids.add(ioc_id)
            item = metadata_items[index] if index < len(metadata_items) else None
            if item is None:
                severity = ""
                tags_json = "[]"
                tags_search = ""
                evidence_json = "[]"
            else:
                domain_ioc = metadata_ioc(item)
                severity = domain_ioc.severity
                tags_json = serialize_tags(domain_ioc.tags)
                tags_search = build_tags_search(domain_ioc.tags)
                evidence_json = serialize_evidence(domain_ioc.evidence)
            self.session.add(
                RUN_IOC_MODEL(
                    run_id=run_id,
                    ioc_id=ioc_id,
                    severity=severity,
                    tags_json=tags_json,
                    tags_search=tags_search,
                    evidence_json=evidence_json,
                ),
            )
