from __future__ import annotations

import time
from re import escape, finditer

from iocparser.application.contracts import (
    ExtractFileInput,
    ExtractTextInput,
    ExtractURLInput,
    PersistRunInput,
)
from iocparser.domain.models import (
    IOC,
    ExtractionResult,
    IOCEvidence,
    IOCType,
    PersistedRun,
    classify_ioc,
)
from iocparser.errors import SourceNotFoundError, SourceProcessingError, ValidationError
from iocparser.interfaces.ports import (
    FileBatchExecutor,
    IOCExtractionEngine,
    TemporaryResourceCleaner,
    TextSourceReader,
    UnitOfWork,
    URLDownloader,
    WarningListService,
)


def _build_evidence(text_content: str, value: str, *, source: str = "") -> tuple[IOCEvidence, ...]:
    """Extract a small set of contextual snippets for an IOC value."""
    from iocparser.shared_utils import refang_ioc

    if not value:
        return ()

    search_variants = [value]
    refanged = refang_ioc(value)
    if refanged != value:
        search_variants.append(refanged)

    evidences: list[IOCEvidence] = []
    for index, line in enumerate(text_content.splitlines(), start=1):
        if any(variant in line for variant in search_variants):
            evidences.append(
                IOCEvidence(excerpt=line.strip()[:240], line_number=index, source=source)
            )
            if len(evidences) >= 3:
                return tuple(evidences)

    for variant in search_variants:
        for match in finditer(escape(variant), text_content):
            start = max(0, match.start() - 60)
            end = min(len(text_content), match.end() + 60)
            snippet = text_content[start:end].replace("\n", " ").strip()
            if snippet:
                evidences.append(IOCEvidence(excerpt=snippet[:240], source=source))
            if len(evidences) >= 3:
                return tuple(evidences)
    return tuple(evidences)


def _build_result_from_raw_iocs(
    raw_iocs: dict[str, list[str]], text_content: str
) -> ExtractionResult:
    """Build a normalized result with evidence and classification."""
    iocs = []
    for ioc_type, values in raw_iocs.items():
        canonical_type = IOCType.from_name(ioc_type)
        severity, tags = classify_ioc(canonical_type)
        for value in values:
            if not value:
                continue
            iocs.append(
                IOC.from_raw(
                    ioc_type,
                    value,
                    evidence=_build_evidence(text_content, value),
                    severity=severity,
                    tags=tags,
                ),
            )
    return ExtractionResult(iocs=tuple(iocs))


def extract_from_text(
    request: ExtractTextInput,
    *,
    extractor_engine: IOCExtractionEngine,
    warning_service: WarningListService | None = None,
) -> ExtractionResult:
    """Extract IOCs from raw text."""
    raw_iocs = extractor_engine.extract_all(request.text_content, defang=request.options.defang)
    filtered_iocs = {
        ioc_type: values
        for ioc_type, values in raw_iocs.items()
        if request.options.allows(IOCType.from_name(ioc_type))
    }
    result = _build_result_from_raw_iocs(filtered_iocs, request.text_content)

    if not request.options.check_warnings or warning_service is None:
        return result

    return warning_service.separate(result.iocs, force_update=request.options.force_update)


def extract_from_file(
    request: ExtractFileInput,
    *,
    reader: TextSourceReader,
    extractor_engine: IOCExtractionEngine,
    warning_service: WarningListService | None = None,
) -> ExtractionResult:
    """Extract IOCs from a file path."""
    try:
        text_content = reader.read(request.file_path, request.options)
        return extract_from_text(
            ExtractTextInput(text_content=text_content, options=request.options),
            extractor_engine=extractor_engine,
            warning_service=warning_service,
        )
    except SourceNotFoundError:
        raise
    except ValidationError:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise SourceProcessingError(request.file_path, str(exc)) from exc


def extract_from_url(
    request: ExtractURLInput,
    *,
    downloader: URLDownloader,
    reader: TextSourceReader,
    extractor_engine: IOCExtractionEngine,
    temporary_resource_cleaner: TemporaryResourceCleaner,
    warning_service: WarningListService | None = None,
) -> ExtractionResult:
    """Extract IOCs from a downloaded URL."""
    temp_file = downloader.download(request.url)
    try:
        return extract_from_file(
            ExtractFileInput(file_path=temp_file, options=request.options),
            reader=reader,
            extractor_engine=extractor_engine,
            warning_service=warning_service,
        )
    finally:
        temporary_resource_cleaner.cleanup(temp_file)


def extract_from_files(
    requests: list[ExtractFileInput],
    *,
    reader: TextSourceReader,
    extractor_engine: IOCExtractionEngine,
    batch_executor: FileBatchExecutor,
    warning_service: WarningListService | None = None,
) -> dict[str, ExtractionResult]:
    """Extract IOCs from multiple files in parallel."""
    return batch_executor.execute(
        requests,
        handler=lambda current: extract_from_file(
            current,
            reader=reader,
            extractor_engine=extractor_engine,
            warning_service=warning_service,
        ),
        key_for=lambda current: current.file_path,
    )


def persist_run(
    request: PersistRunInput,
    *,
    unit_of_work: UnitOfWork,
) -> PersistedRun:
    """Persist a normalized extraction run."""
    started_at = time.perf_counter()
    try:
        status = request.status or (
            "failed"
            if request.successful_items <= 0 and request.failed_items > 0
            else "partial"
            if request.failed_items > 0 or request.partial_error_count > 0
            else "success"
        )
        metadata: dict[str, int | str | None] = {
            "normal_ioc_count": len(request.result.iocs),
            "warning_ioc_count": len(request.result.warnings),
            "processed_items": request.processed_items,
            "successful_items": request.successful_items,
            "failed_items": request.failed_items,
            "partial_error_count": request.partial_error_count,
            "duration_ms": request.duration_ms
            if request.duration_ms is not None
            else int((time.perf_counter() - started_at) * 1000),
            "status": status,
            "error_message": request.error_message,
        }
        source_id = unit_of_work.source_repository.get_or_create(
            kind=request.source.kind.value,
            value=request.source.value,
            original_url=request.source.original_url,
            normalized_url=request.source.normalized_url,
            mime_type=request.source.mime_type,
            input_size=request.source.input_size,
            content_hash=request.source.content_hash,
            fingerprint=request.source.fingerprint,
        )
        normal_ioc_ids = unit_of_work.ioc_repository.get_or_create_normal(request.result)
        warning_ioc_ids = unit_of_work.ioc_repository.get_or_create_warnings(request.result)
        run_id = unit_of_work.run_repository.create_run(
            source_id=source_id,
            tool_version=request.tool_version,
            options=request.options,
            metadata=metadata,
        )
        unit_of_work.run_repository.attach_iocs(
            run_id=run_id,
            ioc_ids=normal_ioc_ids + warning_ioc_ids,
            result=request.result,
        )
        unit_of_work.commit()
        return PersistedRun(run_id=run_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        unit_of_work.rollback()
        raise
