"""Coverage for cleanup-after-error branches in the URL use case and pipeline worker."""

from __future__ import annotations

import pytest


def test_extract_from_url_logs_cleanup_failure_after_extraction_error() -> None:
    from iocparser.application.use_cases import extract_from_url
    from iocparser.domain.options import ExtractionOptions

    class _Downloader:
        def download(self, url: str) -> str:
            del url
            return "/nonexistent/path/file.txt"  # extract_from_file will fail to read it

    class _Cleaner:
        def cleanup(self, path: str) -> None:
            del path
            raise OSError("cleanup failed")

    class _ExtractURLInput:
        url = "https://host.example/x"
        options = ExtractionOptions()

    # extract_from_file raises (missing file); the finally's cleanup also raises, so the
    # original error propagates and the cleanup failure is only logged.
    with pytest.raises(Exception):  # noqa: B017,PT011  (the extraction error, whatever its type)
        extract_from_url(
            _ExtractURLInput(),  # type: ignore[arg-type]
            downloader=_Downloader(),  # type: ignore[arg-type]
            reader=None,  # type: ignore[arg-type]
            extractor_engine=None,  # type: ignore[arg-type]
            temporary_resource_cleaner=_Cleaner(),  # type: ignore[arg-type]
        )


def test_pipeline_worker_logs_cleanup_failure_after_processing_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iocparser import pipeline_worker
    from iocparser.domain.pipeline import PipelineJobRequest
    from iocparser.pipeline_worker import PipelineWorker

    worker = PipelineWorker()

    def _boom_prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        raise RuntimeError("prepare boom")

    def _boom_cleanup(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("cleanup boom")

    # Force prepare to produce a value, then make extraction fail and cleanup fail too.
    class _Prepared:
        pass

    monkeypatch.setattr(pipeline_worker, "prepare_input", lambda **_k: _Prepared())
    monkeypatch.setattr(
        pipeline_worker, "extract_result", lambda **_k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    monkeypatch.setattr(pipeline_worker, "maybe_skipped_result", lambda **_k: None)
    monkeypatch.setattr(pipeline_worker, "cleanup_prepared_input", _boom_cleanup)

    # The failed_result path returns a result; cleanup raising afterwards is only logged
    # because a primary error already occurred.
    result = worker.process(PipelineJobRequest(input_kind="text", source_value="x", job_id="j1"))
    assert result.status == "failed"
