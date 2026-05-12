from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import cast

from iocparser.domain.pipeline import PipelineJobRequest, PipelineJobResult, ResourceLimits
from iocparser.interfaces.ports import ProcessedRunLookup
from iocparser.pipeline_worker_support import (
    BACKPRESSURE_MESSAGE,
    ExtractionClient,
    IOCRepositoryAdapter,
    PipelineProcessedRunLookup,
    PipelineUnitOfWork,
    PreparedInput,
    ProcessContext,
    RunRepositoryAdapter,
    cleanup_prepared_input,
    ensure_input_deadline,
    extract_result,
    failed_result,
    maybe_skipped_result,
    metadata_int,
    new_job_identifiers,
    persist_result,
    prepare_input,
    prepared_temp_file,
    success_result,
)

_PreparedInput = PreparedInput
_metadata_int = metadata_int
_prepared_temp_file = prepared_temp_file
_PipelineUnitOfWork = PipelineUnitOfWork
_IOCRepositoryAdapter = IOCRepositoryAdapter
_RunRepositoryAdapter = RunRepositoryAdapter


class PipelineWorker:
    """Non-CLI worker interface for large pipeline integration."""

    def __init__(
        self,
        *,
        client: ExtractionClient | None = None,
        limits: ResourceLimits | None = None,
        processed_run_lookup: ProcessedRunLookup | None = None,
        processed_run_lookup_factory: Callable[[str], ProcessedRunLookup] | None = None,
    ) -> None:
        resolved_client: ExtractionClient
        if client is None:
            from iocparser.client_extraction import IOCParserClient

            resolved_client = cast("ExtractionClient", IOCParserClient())
        else:
            resolved_client = client
        resolved_lookup_factory = processed_run_lookup_factory or PipelineProcessedRunLookup
        self.client: ExtractionClient = resolved_client
        self.limits = limits or ResourceLimits()
        self.processed_run_lookup = processed_run_lookup
        self.processed_run_lookup_factory = resolved_lookup_factory
        self._lock = threading.Lock()
        self._inflight = 0

    def process(self, request: PipelineJobRequest) -> PipelineJobResult:
        with self._reservation():
            return self._process(request)

    def _process(self, request: PipelineJobRequest) -> PipelineJobResult:
        started = time.perf_counter()
        started_at = datetime.now(UTC).isoformat()
        phase_timings_ms: dict[str, int] = {}
        job_id, correlation_id = new_job_identifiers(request)
        context = ProcessContext(
            request=request,
            job_id=job_id,
            correlation_id=correlation_id,
            started=started,
            started_at=started_at,
            phase_timings_ms=phase_timings_ms,
        )
        prepared: PreparedInput | None = None
        try:
            prepare_started = time.perf_counter()
            prepared = prepare_input(client=self.client, limits=self.limits, request=request)
            phase_timings_ms["prepare"] = int((time.perf_counter() - prepare_started) * 1000)
            processed_run_lookup = self.processed_run_lookup
            db_uri = request.db_uri
            if (
                processed_run_lookup is None
                and self.processed_run_lookup_factory is not None
                and db_uri
            ):
                processed_run_lookup = self.processed_run_lookup_factory(db_uri)
            skipped = maybe_skipped_result(
                context=context,
                processed_run_lookup=processed_run_lookup,
                prepared=prepared,
                skip_processed=self.limits.skip_processed,
            )
            if skipped is not None:
                cleanup_prepared_input(request=request, prepared=prepared)
                return skipped

            extract_started = time.perf_counter()
            result = extract_result(client=self.client, request=request, prepared=prepared)
            phase_timings_ms["extract"] = int((time.perf_counter() - extract_started) * 1000)
            ensure_input_deadline(
                limits=self.limits, started=started, source_value=request.source_value
            )

            persist_started = time.perf_counter()
            run_id = persist_result(
                request=request, prepared=prepared, result=result, started=started
            )
            if run_id is not None:
                phase_timings_ms["persist"] = int((time.perf_counter() - persist_started) * 1000)
            return success_result(
                context=context,
                prepared=prepared,
                result=result,
                run_id=run_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except (MemoryError, RecursionError, SystemError):
            raise
        except Exception as exc:
            if prepared is not None:
                cleanup_prepared_input(request=request, prepared=prepared)
            return failed_result(
                request=request,
                exc=exc,
                job_id=job_id,
                correlation_id=correlation_id,
                started=started,
                started_at=started_at,
                phase_timings_ms=phase_timings_ms,
            )

    @contextmanager
    def _reservation(self) -> Iterator[None]:
        with self._lock:
            if self._inflight >= self.limits.max_queue_size:
                raise RuntimeError(BACKPRESSURE_MESSAGE)
            self._inflight += 1
        try:
            yield
        finally:
            with self._lock:
                self._inflight = max(0, self._inflight - 1)
