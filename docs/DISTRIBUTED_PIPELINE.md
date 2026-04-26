# Distributed Pipeline Integration

IOCParser supports queue-backed distributed execution for large pipelines.

## Default backend

The default queue backend is `filesystem`.

Why:

- zero external infrastructure
- deterministic local staging
- straightforward E2E testing

Use another backend explicitly when your platform already standardizes on it.

## Supported backends

- `filesystem`
- `rabbitmq`
- `sqs`
- `celery`

Create the adapter through `iocparser.create_queue_adapter(...)` or use `DistributedPipelineClient`.

## Lifecycle

Distributed jobs persist these lifecycle states:

- `queued`
- `running`
- `completed`
- `failed`
- `dead-lettered`

## Retry and dead-letter

Retry policy is driven by the stable pipeline error taxonomy:

- retryable failures are requeued until `max_attempts`
- terminal failures are moved to dead-letter storage

Dead-letter entries are persisted and queryable through the distributed job service/client.

## Runtime policy

The worker still enforces logical limits from `ResourceLimits`.
Infra/runtime limits should also be enforced by the orchestrator or container runtime.

## Example

```python
from iocparser import DistributedPipelineClient, PipelineJobRequest

client = DistributedPipelineClient(
    db_uri="sqlite:///iocparser.db",
    queue_backend="filesystem",
    queue_path=".iocparser-queue",
)

job = client.submit(
    PipelineJobRequest(
        input_kind="text",
        source_value="See hxxp://evil.example",
        persist=True,
        db_uri="sqlite:///iocparser.db",
        check_warnings=False,
    ),
    queue_name="ingest",
)

client.process_next(queue_name="ingest")
state = client.get_job(job_id=job.job_id)
```
