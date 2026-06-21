from __future__ import annotations

from collections.abc import Iterable

from iocparser.domain.models import ExtractionResult, PersistOptions
from iocparser.domain.sources import Source
from iocparser.infrastructure.persistence import (
    SQLAlchemyPersistenceService,
    SQLAlchemyUnitOfWork,
)


def persist_multiple_runs(
    service: SQLAlchemyPersistenceService,
    runs: Iterable[tuple[str, str, ExtractionResult]],
    tool_version: str,
    options: PersistOptions,
) -> list[int]:
    """Persist several runs at once and return their run ids.

    Formerly a production method on the persistence service; relocated here because
    only tests need bulk persistence -- production persists one run at a time through
    the persist-run use case. The body is unchanged so existing tests keep their exact
    setup behavior.
    """
    run_ids: list[int] = []
    for kind, value, result in runs:
        unit_of_work = SQLAlchemyUnitOfWork(service.db_uri)
        try:
            source = Source.from_raw(kind, value)
            source_id = unit_of_work.source_repository.get_or_create(
                kind=kind,
                value=value,
                original_url=source.original_url,
                normalized_url=source.normalized_url,
                mime_type=source.mime_type,
                input_size=source.input_size,
                content_hash=source.content_hash,
                fingerprint=source.fingerprint,
            )
            metadata: dict[str, int | str | None] = {
                "normal_ioc_count": len(result.iocs),
                "warning_ioc_count": len(result.warnings),
                "processed_items": 1,
                "successful_items": 1,
                "failed_items": 0,
                "partial_error_count": 0,
            }
            run_id = unit_of_work.run_repository.create_run(
                source_id=source_id,
                tool_version=tool_version,
                options=options,
                metadata=metadata,
            )
            ioc_ids = unit_of_work.ioc_repository.get_or_create_normal(result)
            ioc_ids.extend(unit_of_work.ioc_repository.get_or_create_warnings(result))
            unit_of_work.run_repository.attach_iocs(run_id=run_id, ioc_ids=ioc_ids, result=result)
            unit_of_work.commit()
            run_ids.append(run_id)
        finally:
            unit_of_work.close()
    return run_ids
