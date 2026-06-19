from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from iocparser._version import resolve_version
from iocparser.application.contracts import PersistRunInput
from iocparser.application.use_cases import persist_run
from iocparser.domain.models import ExtractionResult, PersistOptions, Source
from iocparser.domain.persisted import PersistedRunExport, PersistedRunSummary
from iocparser.domain.pipeline import PipelineJobRequest, PipelineJobResult, ResourceLimits
from iocparser.errors import IOCTimeoutError, SourceNotFoundError, ValidationError
from iocparser.infrastructure.persistence import (
    SQLAlchemyIOCRepository,
    SQLAlchemyPersistenceService,
    SQLAlchemyRunRepository,
    SQLAlchemyUnitOfWork,
)
from iocparser.infrastructure.persistence_repository_support import (
    ExtractionResultLike,
    _IOCMetadataLike,
    _WarningMatchLike,
)
from iocparser.interfaces.ports import (
    IOCRepository,
    ProcessedRunLookup,
    RunRepository,
    SourceRepository,
)
from iocparser.pipeline_errors import classify_pipeline_exception
from iocparser.shared_utils import normalize_metadata_values, rollback_and_log

BACKPRESSURE_MESSAGE = "worker queue is at capacity"
logger = logging.getLogger(__name__)


@dataclass
class RepositoryResult:
    iocs: tuple[_IOCMetadataLike, ...]
    warnings: tuple[_WarningMatchLike, ...]


class PipelineUnitOfWork:
    def __init__(self, db_uri: str) -> None:
        self._inner = SQLAlchemyUnitOfWork(db_uri)
        self.source_repository: SourceRepository = self._inner.source_repository
        self.ioc_repository: IOCRepository = IOCRepositoryAdapter(self._inner.ioc_repository)
        self.run_repository: RunRepository = RunRepositoryAdapter(self._inner.run_repository)

    def commit(self) -> None:
        self._inner.commit()

    def rollback(self) -> None:
        self._inner.rollback()

    def close(self) -> None:
        self._inner.close()


class IOCRepositoryAdapter:
    def __init__(self, inner: SQLAlchemyIOCRepository) -> None:
        self._inner = inner

    def get_or_create_normal(self, result: ExtractionResult) -> list[int]:
        bridged = RepositoryResult(
            iocs=cast("tuple[_IOCMetadataLike, ...]", result.iocs),
            warnings=cast("tuple[_WarningMatchLike, ...]", result.warnings),
        )
        return self._inner.get_or_create_normal(bridged)

    def get_or_create_warnings(self, result: ExtractionResult) -> list[int]:
        bridged = RepositoryResult(
            iocs=cast("tuple[_IOCMetadataLike, ...]", result.iocs),
            warnings=cast("tuple[_WarningMatchLike, ...]", result.warnings),
        )
        return self._inner.get_or_create_warnings(bridged)


class RunRepositoryAdapter:
    def __init__(self, inner: SQLAlchemyRunRepository) -> None:
        self._inner = inner

    def create_run(
        self,
        *,
        source_id: int,
        tool_version: str,
        options: PersistOptions,
        metadata: Mapping[str, object] | None = None,
    ) -> int:
        normalized_metadata = normalize_run_metadata(metadata)
        return self._inner.create_run(
            source_id=source_id,
            tool_version=tool_version,
            options=options,
            metadata=normalized_metadata,
        )

    def attach_iocs(
        self, *, run_id: int, ioc_ids: list[int], result: ExtractionResult | None = None
    ) -> None:
        bridged_result: ExtractionResultLike | None = None
        if result is not None:
            bridged_result = RepositoryResult(
                iocs=cast("tuple[_IOCMetadataLike, ...]", result.iocs),
                warnings=cast("tuple[_WarningMatchLike, ...]", result.warnings),
            )
        self._inner.attach_iocs(run_id=run_id, ioc_ids=ioc_ids, result=bridged_result)


class PipelineProcessedRunLookup:
    def __init__(self, db_uri: str) -> None:
        self._service = SQLAlchemyPersistenceService(db_uri)

    def find_existing_run(
        self,
        *,
        fingerprint: str | None = None,
        content_hash: str | None = None,
        status: str = "success",
    ) -> PersistedRunSummary | None:
        return self._service.find_existing_run(
            fingerprint=fingerprint,
            content_hash=content_hash,
            status=status,
        )

    def export_run(self, *, run_id: int) -> PersistedRunExport:
        return self._service.export_run(run_id=run_id)


def normalize_run_metadata(
    metadata: Mapping[str, object] | None,
) -> dict[str, int | str | None] | None:
    if metadata is None:
        return None
    return normalize_metadata_values(metadata)


class Downloader(Protocol):
    last_download_metadata: dict[str, object] | None

    def download(self, url: str) -> str: ...


@dataclass(frozen=True)
class PreparedInput:
    fingerprint: str | None
    content_hash: str | None
    metadata: dict[str, object]


def metadata_int(metadata: dict[str, object], key: str) -> int | None:
    raw_value = metadata.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        raise invalid_int_error(key=key, raw_value=raw_value)
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, str):
        try:
            return int(raw_value)
        except ValueError as exc:
            raise invalid_int_error(key=key, raw_value=raw_value) from exc
    raise invalid_int_error(key=key, raw_value=raw_value)


def prepared_temp_file(prepared: PreparedInput) -> str:
    raw_value = prepared.metadata.get("temp_file")
    if not isinstance(raw_value, str) or not raw_value:
        raise missing_temp_file_error()
    return raw_value


def cleanup_prepared_input(*, request: PipelineJobRequest, prepared: PreparedInput) -> None:
    if request.input_kind != "url":
        return
    raw_value = prepared.metadata.get("temp_file")
    if isinstance(raw_value, str) and raw_value:
        Path(raw_value).unlink(missing_ok=True)


def enforce_size_limit(*, limits: ResourceLimits, input_size_bytes: int) -> None:
    if limits.max_input_size_bytes is not None and input_size_bytes > limits.max_input_size_bytes:
        raise size_limit_error(
            input_size_bytes=input_size_bytes, configured_limit=limits.max_input_size_bytes
        )


def input_deadline_error(source_value: str) -> IOCTimeoutError:
    return IOCTimeoutError("Pipeline input", source_value)


def invalid_int_error(*, key: str, raw_value: object) -> TypeError:
    return TypeError(f"Expected {key} to be int-compatible, got {type(raw_value).__name__}")


def missing_temp_file_error() -> ValueError:
    return ValueError("Prepared URL input is missing temp_file metadata")


def size_limit_error(*, input_size_bytes: int, configured_limit: int) -> ValidationError:
    return ValidationError(
        f"Input size {input_size_bytes} exceeds configured limit {configured_limit}"
    )


def unsupported_input_kind_error(input_kind: str) -> ValueError:
    return ValueError(f"Unsupported pipeline input kind: {input_kind}")


def _prepare_text_input(*, limits: ResourceLimits, text: str) -> PreparedInput:
    encoded = text.encode("utf-8")
    enforce_size_limit(limits=limits, input_size_bytes=len(encoded))
    content_hash = hashlib.sha256(encoded).hexdigest()
    return PreparedInput(
        fingerprint=content_hash[:16],
        content_hash=content_hash,
        metadata={"input_size": len(encoded), "source_kind": "text"},
    )


def _prepare_file_input(*, limits: ResourceLimits, path: Path) -> PreparedInput:
    if not path.is_file():
        raise SourceNotFoundError(str(path))
    input_size = path.stat().st_size
    enforce_size_limit(limits=limits, input_size_bytes=input_size)
    content = path.read_bytes()
    content_hash = hashlib.sha256(content).hexdigest()
    return PreparedInput(
        fingerprint=content_hash[:16],
        content_hash=content_hash,
        metadata={"input_size": input_size, "source_kind": "file"},
    )


class ExtractionClient(Protocol):
    downloader: Downloader

    def extract_result_from_text(
        self,
        text_content: str,
        *,
        check_warnings: bool = True,
        force_update: bool = False,
        defang: bool = True,
        only: str | None = None,
        exclude: str | None = None,
    ) -> ExtractionResult: ...

    def extract_result_from_file(self, file_path: str, **kwargs: object) -> ExtractionResult: ...


def _prepare_url_input(
    *, client: ExtractionClient, limits: ResourceLimits, url: str
) -> PreparedInput:
    temp_file = client.downloader.download(url)
    try:
        metadata = dict(client.downloader.last_download_metadata or {})
        downloaded_path = Path(temp_file)
        input_size = metadata_int(metadata, "input_size")
        if input_size is None:
            input_size = downloaded_path.stat().st_size
            metadata["input_size"] = input_size
        enforce_size_limit(limits=limits, input_size_bytes=input_size)
        if not isinstance(metadata.get("content_hash"), str):
            content_hash = hashlib.sha256(downloaded_path.read_bytes()).hexdigest()
            metadata["content_hash"] = content_hash
            metadata["fingerprint"] = content_hash[:16]
        elif not isinstance(metadata.get("fingerprint"), str):
            metadata["fingerprint"] = str(metadata["content_hash"])[:16]
        url_metadata = dict(metadata)
        url_metadata["temp_file"] = temp_file
        url_metadata["source_kind"] = "url"
        return PreparedInput(
            fingerprint=cast("str | None", metadata.get("fingerprint")),
            content_hash=cast("str | None", metadata.get("content_hash")),
            metadata=url_metadata,
        )
    except Exception:
        try:
            Path(temp_file).unlink(missing_ok=True)
        except OSError:
            logger.warning("Failed to remove temporary URL input after preparation error", exc_info=True)
        raise


def prepare_input(
    *, client: ExtractionClient, limits: ResourceLimits, request: PipelineJobRequest
) -> PreparedInput:
    if request.input_kind == "text":
        return _prepare_text_input(limits=limits, text=request.source_value)
    if request.input_kind == "file":
        return _prepare_file_input(limits=limits, path=Path(request.source_value))
    if request.input_kind == "url":
        return _prepare_url_input(client=client, limits=limits, url=request.source_value)
    raise unsupported_input_kind_error(request.input_kind)


@dataclass(frozen=True)
class ProcessContext:
    request: PipelineJobRequest
    job_id: str
    correlation_id: str
    started: float
    started_at: str
    phase_timings_ms: dict[str, int]


def new_job_identifiers(request: PipelineJobRequest) -> tuple[str, str]:
    job_id = request.job_id or str(uuid4())
    return job_id, request.correlation_id or job_id


def maybe_skipped_result(
    *,
    context: ProcessContext,
    processed_run_lookup: ProcessedRunLookup | None,
    prepared: PreparedInput,
    skip_processed: bool,
) -> PipelineJobResult | None:
    if not (skip_processed and processed_run_lookup and prepared.fingerprint):
        return None
    existing = processed_run_lookup.find_existing_run(
        fingerprint=prepared.fingerprint,
        content_hash=prepared.content_hash,
    )
    if existing is None:
        return None
    exported = processed_run_lookup.export_run(run_id=existing.run_id)
    return PipelineJobResult(
        input_kind=context.request.input_kind,
        source_value=context.request.source_value,
        status="skipped",
        skipped=True,
        result=exported.result,
        run_id=existing.run_id,
        fingerprint=existing.fingerprint,
        content_hash=existing.content_hash,
        job_id=context.job_id,
        correlation_id=context.correlation_id,
        duration_ms=int((time.perf_counter() - context.started) * 1000),
        phase_timings_ms=context.phase_timings_ms,
        metadata={"skip_reason": "already_processed"},
        started_at=context.started_at,
        finished_at=datetime.now(UTC).isoformat(),
    )


def persist_result(
    *,
    request: PipelineJobRequest,
    prepared: PreparedInput,
    result: ExtractionResult,
    started: float,
) -> int | None:
    if not (request.persist and request.db_uri and not request.emit_only):
        return None
    input_size = metadata_int(prepared.metadata, "input_size")
    original_url = prepared.metadata.get("original_url")
    normalized_url = prepared.metadata.get("normalized_url")
    mime_type = prepared.metadata.get("mime_type")
    unit = PipelineUnitOfWork(request.db_uri)
    primary_exc: BaseException | None = None
    try:
        return persist_run(
            PersistRunInput(
                source=Source.from_raw(
                    request.input_kind,
                    request.source_value,
                    original_url=original_url
                    if isinstance(original_url, str) and original_url
                    else None,
                    normalized_url=normalized_url
                    if isinstance(normalized_url, str) and normalized_url
                    else None,
                    mime_type=mime_type if isinstance(mime_type, str) and mime_type else None,
                    input_size=input_size,
                    content_hash=prepared.content_hash,
                    fingerprint=prepared.fingerprint,
                ),
                result=result,
                tool_version=resolve_version(),
                options=PersistOptions(
                    defang=request.defang,
                    check_warnings=request.check_warnings,
                    force_update=request.force_update,
                    output_format="json",
                ),
                duration_ms=int((time.perf_counter() - started) * 1000),
                status="success",
            ),
            unit_of_work=unit,
        ).run_id
    except BaseException as exc:
        primary_exc = exc
        if not isinstance(exc, (KeyboardInterrupt, SystemExit)):
            rollback_and_log(
                unit,
                logger=logger,
                message="Rollback failed while persisting pipeline result",
            )
        raise
    finally:
        try:
            unit.close()
        except Exception:
            if primary_exc is None:
                raise
            logger.warning("Close failed after persisting pipeline result error", exc_info=True)


def extract_result(
    *, client: ExtractionClient, request: PipelineJobRequest, prepared: PreparedInput
) -> ExtractionResult:
    if request.input_kind == "text":
        return client.extract_result_from_text(
            request.source_value,
            check_warnings=request.check_warnings,
            force_update=request.force_update,
            defang=request.defang,
            only=request.only,
            exclude=request.exclude,
        )
    if request.input_kind == "file":
        return client.extract_result_from_file(
            request.source_value,
            file_type=request.file_type,
            check_warnings=request.check_warnings,
            force_update=request.force_update,
            defang=request.defang,
            only=request.only,
            exclude=request.exclude,
        )
    temp_file = prepared_temp_file(prepared)
    return client.extract_result_from_file(
        temp_file,
        check_warnings=request.check_warnings,
        force_update=request.force_update,
        defang=request.defang,
        only=request.only,
        exclude=request.exclude,
    )


def ensure_input_deadline(*, limits: ResourceLimits, started: float, source_value: str) -> None:
    if (
        limits.max_input_seconds is not None
        and (time.perf_counter() - started) > limits.max_input_seconds
    ):
        raise input_deadline_error(source_value)


def success_result(
    *,
    context: ProcessContext,
    prepared: PreparedInput,
    result: ExtractionResult,
    run_id: int | None,
) -> PipelineJobResult:
    return PipelineJobResult(
        input_kind=context.request.input_kind,
        source_value=context.request.source_value,
        status="success",
        result=result,
        run_id=run_id,
        fingerprint=prepared.fingerprint,
        content_hash=prepared.content_hash,
        job_id=context.job_id,
        correlation_id=context.correlation_id,
        duration_ms=int((time.perf_counter() - context.started) * 1000),
        phase_timings_ms=context.phase_timings_ms,
        metadata=dict(prepared.metadata),
        started_at=context.started_at,
        finished_at=datetime.now(UTC).isoformat(),
    )


def failed_result(
    *,
    request: PipelineJobRequest,
    exc: Exception,
    job_id: str,
    correlation_id: str,
    started: float,
    started_at: str,
    phase_timings_ms: dict[str, int],
) -> PipelineJobResult:
    return PipelineJobResult(
        input_kind=request.input_kind,
        source_value=request.source_value,
        status="failed",
        result=ExtractionResult(),
        job_id=job_id,
        correlation_id=correlation_id,
        duration_ms=int((time.perf_counter() - started) * 1000),
        phase_timings_ms=phase_timings_ms,
        error=classify_pipeline_exception(exc),
        metadata={"job_id": job_id, "correlation_id": correlation_id},
        started_at=started_at,
        finished_at=datetime.now(UTC).isoformat(),
    )
