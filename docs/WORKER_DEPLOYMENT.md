# Worker Deployment

IOCParser ships a standalone worker entrypoint: `iocparser-worker`.

## Runtime model

- one worker process polls one configured queue
- scale horizontally with more replicas
- per-worker concurrency is configured through environment
- CPU, memory, and hard timeout limits must be enforced by the container runtime/orchestrator

## Configuration first

Local usage needs no extra setup: `filesystem` remains the default backend.

For scaled deployments, prefer mounting one INI config file and passing:

```bash
iocparser-worker --config /etc/iocparser/iocparser.ini
```

Recommended profiles included in the repo:

- `deploy/iocparser.local.example.ini`
- `deploy/iocparser.scale.example.ini`
- `deploy/iocparser.production.example.ini`

Local profile:

```ini
[database]
uri = sqlite:///iocparser.local.db

[worker]
queue_backend = filesystem
queue_name = ingest
queue_path = .iocparser-queue
poll_interval_seconds = 0.2
max_messages_per_cycle = 2
concurrency = 1
telemetry_mode = logging
```

Production profile:

```ini
[worker]
queue_backend = rabbitmq
queue_name = ingest
max_messages_per_cycle = 8
concurrency = 4
telemetry_mode = logging

[runtime]
max_input_size_bytes = 10485760
memory_limit_bytes = 1073741824
cpu_seconds = 300
hard_timeout_seconds = 60

[network]
max_input_seconds = 30
max_queue_size = 128
skip_processed = true
```

Keep secrets out of the base file. Inject these through environment or secret mounts:

- `IOCPARSER_WORKER_QUEUE_URL`
- `IOCPARSER_WORKER_DB_URI`
- optional TLS/cert environment overrides

## Environment

- `IOCPARSER_WORKER_QUEUE_BACKEND`
- `IOCPARSER_WORKER_QUEUE_URL`
- `IOCPARSER_WORKER_QUEUE_PATH`
- `IOCPARSER_WORKER_QUEUE_NAME`
- `IOCPARSER_WORKER_DEAD_LETTER_QUEUE_URL`
- `IOCPARSER_WORKER_DB_URI`
- `IOCPARSER_WORKER_POLL_INTERVAL_SECONDS`
- `IOCPARSER_WORKER_MAX_MESSAGES_PER_CYCLE`
- `IOCPARSER_WORKER_CONCURRENCY`
- `IOCPARSER_WORKER_MAX_INPUT_SIZE_BYTES`
- `IOCPARSER_WORKER_MAX_INPUT_SECONDS`
- `IOCPARSER_WORKER_MEMORY_LIMIT_BYTES`
- `IOCPARSER_WORKER_CPU_SECONDS`
- `IOCPARSER_WORKER_HARD_TIMEOUT_SECONDS`
- `IOCPARSER_WORKER_MAX_QUEUE_SIZE`
- `IOCPARSER_WORKER_SKIP_PROCESSED`
- `IOCPARSER_WORKER_TELEMETRY_MODE`

## Included assets

- `Dockerfile.worker`
- `deploy/docker-compose.rabbitmq.yml`
- `deploy/k8s/worker-configmap.yaml`
- `deploy/k8s/worker-secret.example.yaml`
- `deploy/k8s/worker-deployment.yaml`
- `deploy/k8s/worker-hpa.yaml`

The deployment examples are intended to mount a config file plus secrets, instead of setting every runtime knob as a separate environment variable.
