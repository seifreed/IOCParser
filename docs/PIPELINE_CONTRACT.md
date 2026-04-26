# Pipeline Contract

IOCParser exposes a stable machine-to-machine contract for pipeline consumers.

## Schema Versions

- Extraction outputs use `schema_version = 1.0`
- Batch reports use `schema_version = 1.0`
- Worker job results use `schema_version = 1.0`

These constants are exported from:

- `iocparser.RESULT_SCHEMA_VERSION`
- `iocparser.BATCH_REPORT_SCHEMA_VERSION`
- `iocparser.PIPELINE_JOB_SCHEMA_VERSION`

## Output Formats

### JSON

Top-level fields:

- `schema_version`
- `format`
- `records`
- `counts_by_type`
- `total_count`

### JSONL

Each line contains:

- `schema_version`
- `format`
- IOC record fields

### CSV

The first column is `schema_version`.

### STIX

The serialized bundle contains:

- `x_iocparser_schema_version`
- `x_iocparser_format`

## Batch Reports

Structured batch reports contain:

- `schema_version`
- `report_type`
- `job_id`
- `correlation_id`
- `status`
- `failure_cause`
- `total`
- `successful`
- `failed`
- `items`
- `phase_timings_ms`
- `phase_timestamps`
- `metrics`

Failed items also contain stable error fields:

- `error_code`
- `error_category`
- `retryable`

## Worker API

Use `PipelineWorker` with `PipelineJobRequest` and `PipelineJobResult` for non-CLI integration.

`PipelineJobResult` contains:

- `schema_version`
- `job_id`
- `correlation_id`
- `status`
- `run_id`
- `skipped`
- `fingerprint`
- `content_hash`
- `duration_ms`
- `phase_timings_ms`
- `error`
- `result`

## Idempotency

When `ResourceLimits(skip_processed=True)` is enabled and persistence is configured, the worker checks
existing successful runs by `fingerprint` and `content_hash` and returns a `skipped` result instead of
reprocessing.
