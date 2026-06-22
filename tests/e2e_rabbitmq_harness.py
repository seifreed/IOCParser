from __future__ import annotations

import os
import time

import pytest

from iocparser import pipeline


@pytest.mark.slow
def test_rabbitmq_e2e_roundtrip() -> None:
    queue_url = os.environ["IOCPARSER_E2E_RABBITMQ_URL"]
    db_uri = os.environ["IOCPARSER_E2E_DB_URI"]
    client = pipeline.DistributedPipelineClient(
        db_uri=db_uri,
        queue_backend="rabbitmq",
        queue_url=queue_url,
    )
    job = client.submit(
        pipeline.PipelineJobRequest(
            input_kind="text",
            source_value="IOC hxxp://evil.example",
            persist=True,
            db_uri=db_uri,
            check_warnings=False,
        ),
        queue_name="ingest",
    )
    for _ in range(10):
        if client.process_next(queue_name="ingest") is not None:
            break
        time.sleep(0.1)
    stored = client.get_job(job_id=job.job_id)
    assert stored is not None
    assert stored.status == "completed"
