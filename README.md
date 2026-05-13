<p align="center">
  <img src="https://img.shields.io/badge/IOCParser-Threat%20Intelligence-blue?style=for-the-badge" alt="IOCParser">
</p>

<h1 align="center">IOCParser</h1>

<p align="center">
  <strong>Extract, enrich, persist, query, and diff Indicators of Compromise from reports, feeds, and URLs</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/iocparser-tool/"><img src="https://img.shields.io/pypi/v/iocparser-tool?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/iocparser-tool/"><img src="https://img.shields.io/badge/python-3.13%20%7C%203.14-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.13 and 3.14"></a>
  <a href="https://github.com/seifreed/iocparser/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/iocparser/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/iocparser/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen?style=flat-square" alt="Coverage">
</p>

## Overview

IOCParser extracts IOCs from PDF, HTML, plain text, stdin, URLs, URL feeds, and directory trees. It can defang values, enrich with MISP warning lists, render rich outputs, persist runs to a database, and query or diff stored results later.

### Current feature set

| Area | Capabilities |
| --- | --- |
| Input | `--file`, `--url`, positional URL, `--stdin`, `--multiple`, `--directory`, `--recursive`, `--glob`, `--url-file` |
| Recovery | `--retry-failed-from` to replay only failed URLs from a prior batch report |
| Extraction | PDF/HTML/text readers, direct URL ingestion, streaming mode for large files |
| Filtering | `--only`, `--exclude`, `--severity`, `--tag`, `--only-warnings`, `--only-normal`, `--sort-by`, `--max-evidence`, persisted-query filters by date/source/type |
| Output | text, `--summary`, JSON, JSONL, CSV, STIX 2.1, `--with-context`, `--stix-types` |
| Persistence | SQLite/MariaDB-compatible SQLAlchemy backend, run history, IOC search, export, diff, diff against latest successful run of same source, evidence/context persistence |
| Operations | URL batch concurrency, retries, backoff, rate limiting, per-item batch failure reporting, persisted batch jobs, config via `.env`, env vars, and INI |
| Search | `LIKE` and SQLite FTS backends for persisted IOC queries |
| Schema | Built-in migrations and schema validation |
| Extensibility | Renderers, enrichers, extractors, postprocessors, and custom IOC types |
| Pipeline integration | Versioned machine-readable outputs, stable batch report schema, correlation IDs, and worker API |
| Distributed pipeline | Queue-backed execution with filesystem, RabbitMQ, SQS, or Celery adapters and persisted job lifecycle |

### Supported IOC families

```
Hashes          MD5, SHA1, SHA256, SHA512, SSDEEP, IMPHASH
Network         Domains, Hosts, IPv4, IPv6, URLs, Emails, ASNs
Windows         Registry keys, mutexes, named pipes, service names
Artifacts       Filenames, filepaths, certificate serials, JWT, user agents
Threat intel    CVEs, MITRE ATT&CK techniques, YARA rules
Crypto          Bitcoin, Ethereum, Monero
Other           MAC addresses
```

## Installation

### From PyPI

```bash
pip install iocparser-tool
```

### From source

```bash
git clone https://github.com/seifreed/iocparser.git
cd iocparser
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Development

```bash
pip install -e ".[dev]"
```

## Quick start

```bash
# Initialize warning lists once
iocparser --init

# File, URL, and stdin
iocparser -f report.pdf
iocparser -u https://example.com/report.html
cat report.txt | iocparser --stdin --json

# Output filters
iocparser -f report.txt --only urls,domains --severity medium --with-context

# Persist and later query
iocparser -f report.txt --persist --db-uri "sqlite:///iocparser.db"
iocparser --list-runs --db-uri "sqlite:///iocparser.db"
```

## CLI usage

### Inputs

```bash
# Single sources
iocparser -f report.pdf
iocparser -u https://example.com/report.html
iocparser https://example.com/report.html
iocparser --stdin < report.txt
iocparser -f -

# Batch files
iocparser -m report1.txt report2.txt report3.txt
iocparser -d reports --glob "*.txt"
iocparser -d reports --recursive --glob "*.html"

# Batch URLs
iocparser --url-file feeds.txt --url-workers 8 --url-retries 2 --url-backoff 0.25 --rate-limit 0.10
iocparser --url-file feeds.txt --batch-report-json batch-report.json
iocparser --retry-failed-from batch-report.json
```

### Output formats

```bash
iocparser -f report.txt --json
iocparser -f report.txt --jsonl
iocparser -f report.txt --csv
iocparser -f report.txt --stix
iocparser -f report.txt --stix --stix-types domains,urls,ips
iocparser -f report.txt --with-context --json
iocparser -f report.txt --summary
```

### Analyst filters

```bash
# IOC-type filters
iocparser -f report.txt --only urls,domains
iocparser -f report.txt --exclude yara,registry

# Analyst view filters
iocparser -f report.txt --severity high,medium
iocparser -f report.txt --tag network
iocparser -f report.txt --only-warnings
iocparser -f report.txt --only-normal
iocparser -f report.txt --sort-by severity --max-evidence 1
```

### Large files and streaming

```bash
iocparser -f large_report.txt --streaming
iocparser -f large_report.txt --streaming --chunk-size 2097152 --overlap 2048
```

### Persistence and queries

```bash
# Persist a run
iocparser -f report.txt --persist --db-uri "sqlite:///iocparser.db"

# List runs
iocparser --list-runs --run-limit 50 --db-uri "sqlite:///iocparser.db"

# Search persisted IOCs
iocparser --search-ioc evil.example --db-uri "sqlite:///iocparser.db"
iocparser --search-ioc evil.example --source-kind url --source-value example.com --ioc-type urls
iocparser --search-ioc evil.example --severity informational --tag warning-list-match
iocparser --search-ioc evil.example --query-limit 100 --offset 100 --query-sort source

# Export a run
iocparser --export-run 42 --json --db-uri "sqlite:///iocparser.db"
iocparser --export-run 42 --csv --only-warnings --max-evidence 1

# Diff runs
iocparser --diff-runs 40 42 --json --db-uri "sqlite:///iocparser.db"
iocparser --diff-runs 40 42 --diff-only added
iocparser --diff-runs 40 42 --diff-warnings-only --severity informational

# Compare a run against the latest successful run from the same source
iocparser --diff-latest 42 --summary --db-uri "sqlite:///iocparser.db"

# Maintenance
iocparser --delete-run 42 --db-uri "sqlite:///iocparser.db"
iocparser --prune-before 2026-01-01T00:00:00 --keep-latest 10 --db-uri "sqlite:///iocparser.db"
iocparser --schema-version --db-uri "sqlite:///iocparser.db"
iocparser --migrate --db-uri "sqlite:///iocparser.db"
```

### Common options

| Option | Meaning |
| --- | --- |
| `-o`, `--output` | Output file path. Use `-` for stdout |
| `-t`, `--type` | Force file type: `pdf`, `html`, `text` |
| `--no-defang` | Disable refanging/defanging logic |
| `--no-check-warnings` | Skip MISP warning-list matching |
| `--force-update` | Force warning-list refresh |
| `--parallel` | Parallel workers for multi-file input |
| `--persist / --no-persist` | Enable or disable persistence |
| `--db-uri` | Database URI |
| `--config` | Path to INI config |
| `--date-from`, `--date-to` | Restrict persisted queries to an ISO 8601 time range |
| `--source-kind`, `--source-value` | Restrict persisted queries by source metadata |
| `--ioc-type` | Restrict persisted queries or diffs to one IOC family |
| `--query-limit`, `--offset`, `--query-sort` | Paginate and sort persisted IOC searches |
| `--exclude-tag`, `--tag-mode`, `--min-severity` | Refine persisted IOC searches with richer analyst filters |
| `--delete-run`, `--prune-before`, `--keep-latest` | Basic persisted-history maintenance |
| `--url-workers`, `--url-retries`, `--url-backoff`, `--rate-limit` | Control URL feed batch processing |
| `--batch-report-json` | Save a structured JSON report for URL batches |
| `--retry-failed-from` | Replay only failed URLs from a previous batch report |
| `--renderer`, `--enricher`, `--extractor`, `--postprocessor` | Use registered plugins for rendering, enrichment, extraction, or post-processing |
| `--search-backend` | Choose persisted IOC query backend: `auto`, `fts`, `like` |
| `--user-agent`, `--header`, `--cookie`, `--proxy`, `--allow-redirects`, `--tls-verify`, `--tls-cert`, `--ca-bundle`, `--connect-timeout`, `--read-timeout` | Control HTTP transport policy |

## Python library

### Pipeline contract

- Output renderers include explicit schema versions.
- URL batch reports include `schema_version`, `job_id`, `correlation_id`, stable error codes, and per-item retryability.
- The non-CLI worker API is exposed as `PipelineWorker`, `PipelineJobRequest`, `PipelineJobResult`, and `ResourceLimits`.
- Contract details live in [docs/PIPELINE_CONTRACT.md](docs/PIPELINE_CONTRACT.md).
- Distributed queue integration details live in [docs/DISTRIBUTED_PIPELINE.md](docs/DISTRIBUTED_PIPELINE.md).
- Worker deployment guidance lives in [docs/WORKER_DEPLOYMENT.md](docs/WORKER_DEPLOYMENT.md).
- Schema publication details live in [docs/SCHEMA_ARTIFACTS.md](docs/SCHEMA_ARTIFACTS.md).
- Security and secret-handling guidance lives in [docs/SECURITY_OPERATIONS.md](docs/SECURITY_OPERATIONS.md).

### Distributed pipeline API

```python
from iocparser import pipeline

client = pipeline.DistributedPipelineClient(
    db_uri="sqlite:///iocparser.db",
    queue_backend="filesystem",  # default backend
    queue_path=".iocparser-queue",
)

job = client.submit(
    pipeline.PipelineJobRequest(
        input_kind="text",
        source_value="IOC hxxp://evil.example",
        persist=True,
        db_uri="sqlite:///iocparser.db",
        check_warnings=False,
    ),
    queue_name="ingest",
)

client.process_next(queue_name="ingest")
state = client.get_job(job_id=job.job_id)
```

Backends:

- `filesystem` (default)
- `rabbitmq`
- `sqs`
- `celery`

### Standalone worker service

```bash
IOCPARSER_WORKER_QUEUE_BACKEND=filesystem \
IOCPARSER_WORKER_QUEUE_PATH=.iocparser-queue \
IOCPARSER_WORKER_QUEUE_NAME=ingest \
IOCPARSER_WORKER_DB_URI=sqlite:///iocparser.db \
iocparser-worker
```

For scale, prefer one config file instead of many env vars:

```bash
iocparser-worker --config deploy/iocparser.scale.example.ini
```

Included profiles:

- local: [deploy/iocparser.local.example.ini](deploy/iocparser.local.example.ini)
- scale/staging: [deploy/iocparser.scale.example.ini](deploy/iocparser.scale.example.ini)
- production RabbitMQ + MariaDB: [deploy/iocparser.production.example.ini](deploy/iocparser.production.example.ini)

In production, keep secrets such as broker URLs and DB URIs outside the base file and inject them through env vars or secret mounts.

Deployment examples:

- [docs/WORKER_DEPLOYMENT.md](docs/WORKER_DEPLOYMENT.md)
- [deploy/docker-compose.rabbitmq.yml](deploy/docker-compose.rabbitmq.yml)
- [deploy/k8s/worker-deployment.yaml](deploy/k8s/worker-deployment.yaml)

### Extraction API

```python
from iocparser import extraction

normal_iocs, warning_iocs = extraction.extract_iocs_from_file("report.pdf")
normal_iocs, warning_iocs = extraction.extract_iocs_from_text("evil.example 198.51.100.10")
normal_iocs, warning_iocs = extraction.extract_iocs_from_url(
    "https://example.com/report.html",
    only="urls,domains",
    exclude="registry",
)

result = extraction.extract_result_from_file("report.pdf")
rich_text_result = extraction.extract_result_from_text("evil.example 198.51.100.10")
rich_url_result = extraction.extract_result_from_url("https://example.com/report.html")
```

The `extract_result_from_*()` family returns the normalized [ExtractionResult](/Users/seifreed/tools/malware/IOCParser/iocparser/domain/results.py) model with `severity`, `tags`, and `evidence`, instead of grouped dict payloads.

You can also use reusable clients for repeatable extraction and persistence workflows:

```python
from iocparser import integrations

extractor = integrations.IOCParserClient(
    extractors=("my-extractor",),
)
result = extractor.extract_result_from_file("report.pdf")

query = integrations.PersistenceClient("sqlite:///iocparser.db")
runs_page = query.query_runs(limit=25)
```

### Persistence query API

```python
from iocparser import persistence

db_uri = "sqlite:///iocparser.db"

runs = persistence.list_persisted_runs(db_uri=db_uri, limit=10)
runs_page = persistence.query_persisted_runs(db_uri=db_uri, limit=10, offset=10)
hits = persistence.search_persisted_iocs(
    db_uri=db_uri,
    value="evil.example",
    source_kind="url",
    ioc_type="urls",
    min_severity="medium",
    tag="network",
    exclude_tag="benign",
    tag_mode="any",
    limit=100,
    offset=0,
    sort_by="source",
)
hits_page = query_persisted_iocs(
    db_uri=db_uri,
    value="evil.example",
    limit=100,
    offset=100,
    tag="network",
    min_severity="medium",
)
exported = export_persisted_run(db_uri=db_uri, run_id=42)
diff = diff_persisted_runs(db_uri=db_uri, left_run_id=40, right_run_id=42)
previous = diff_run_against_previous_source(db_uri=db_uri, run_id=42)
structured_diff = export_structured_persisted_diff(
    db_uri=db_uri,
    left_run_id=40,
    right_run_id=42,
)
delete_persisted_run(db_uri=db_uri, run_id=12)
prune_persisted_runs(db_uri=db_uri, before="2026-01-01T00:00:00", keep_latest=10)
jsonl_export = render_persisted_run(
    db_uri=db_uri,
    run_id=42,
    output_format="jsonl",
    only_warnings=True,
)
summary_diff = render_persisted_diff(
    db_uri=db_uri,
    run_id=42,
    output_format="text",
    diff_only="added",
)
```

`export_structured_persisted_diff(...)` returns a serializable diff payload with:

- `baseline`
- `added`
- `removed`
- `counts`
- `count_by_type`

That makes it suitable for APIs, automation, and downstream reporting without having to parse rendered text.

`query_persisted_runs(...)` and `query_persisted_iocs(...)` return paginated objects with:

- `items`
- `total`
- `limit`
- `offset`
- `has_next`
- `page`

### Lower-level components

```python
from iocparser.infrastructure.extraction import IOCExtractor
from iocparser.infrastructure.file_parser import PDFParser, HTMLParser
from iocparser.infrastructure.warninglists import MISPWarningLists

text = PDFParser("report.pdf").extract_text()
extractor = IOCExtractor(defang=True)
raw_iocs = extractor.extract_all(text)
warning_lists = MISPWarningLists()
```

## Configuration

IOCParser resolves config in this order:

1. CLI arguments
2. Environment variables
3. INI file

### Environment variables

```bash
export IOCPARSER_PERSIST=1
export IOCPARSER_DB_URI="sqlite:///iocparser.db"
```

### INI file

IOCParser looks for `iocparser.ini` in the current directory or `~/.config/iocparser/config.ini`.

```ini
[database]
persist = true
uri = sqlite:///iocparser.db

[defaults]
only = urls,domains
exclude = yara
output_format = json
stix_types = domains,urls
with_context = true
streaming = false
summary = false
severity = medium,high
tag = network
parallel = 4
chunk_size = 2097152
overlap = 2048
diff_only = all

[network]
url_workers = 8
url_retries = 2
url_backoff = 0.25
rate_limit = 0.10
user_agent = IOCParser/5.0
headers_json = {"X-Trace": "iocparser"}
cookies_json = {"session": "demo"}
proxy =
allow_redirects = true
tls_verify = true
tls_cert =
ca_bundle =
connect_timeout = 5.0
read_timeout = 30.0
```

## Output notes

- `text`: human-readable full output.
- `--summary`: compact terminal summary with counts by IOC type.
- `json` / `jsonl` / `csv`: structured outputs that include severity, tags, and optional context.
- `stix`: STIX 2.1 bundle for supported IOC types only.
- `--with-context`: include evidence snippets and line numbers where available.
- URL-feed mode prints a per-item batch report with success/failure counts and failed URLs.
- `--batch-report-json` writes the same batch report as structured JSON.
- `--retry-failed-from report.json` replays only failed URL items from a previous batch report.
- Persisted runs now store source metadata, severity, tags, and evidence/context for analyst workflows.
- Persisted runs also store explicit run `status` and `error_message` for failed or partial executions.

Structured URL batch reports include per-item status, duration, IOC counts, and source metadata, for example:

```json
{
  "total": 2,
  "processed": 2,
  "succeeded": 1,
  "failed": 1,
  "items": [
    {
      "url": "https://example.com/report-1",
      "status": "ok",
      "duration_ms": 38,
      "normal_ioc_count": 4,
      "warning_ioc_count": 1
    },
    {
      "url": "https://example.com/report-2",
      "status": "failed",
      "error": "HTTP 404"
    }
  ]
}
```

## Extensibility

Renderer and enricher plugins can be registered without editing the core flow:

```python
from iocparser import register_renderer, register_enricher, renderer_names, enricher_names
from iocparser.plugins import get_renderer

register_renderer("my-text", lambda with_context, _stix: get_renderer("text", with_context=with_context))
register_enricher("my-enricher", lambda: ...)

print(renderer_names())
print(enricher_names())
```

Installed packages can also register entry points in:

- `iocparser.renderers`
- `iocparser.enrichers`

IOCParser loads those entry points automatically on first renderer/enricher resolution.

The plugin surface now also includes:

- `iocparser.extractors`
- `iocparser.postprocessors`
- `iocparser.ioc_types`

Use `iocparser --list-plugins` to inspect what the current environment exposes.

## Schema versioning

Persistence includes built-in schema migration/version stamping through `schema_migrations`. New databases are created at the latest schema, and older databases are upgraded in place when opened.

## Search backends

Persisted IOC search supports three modes:

- `auto`: chooses SQLite FTS when available, otherwise normalized `LIKE`
- `fts`: forces the local FTS backend
- `like`: forces indexed substring search

## Testing

Default local workflows:

```bash
make test-quick
make test
make test-benchmark
```

- `make test-quick`: fast feedback lane.
- `make test`: full functional suite with coverage enforcement.
- `make test-benchmark`: benchmark-only lane.

Coverage is enforced at `100%` in CI.
