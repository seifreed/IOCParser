<p align="center">
  <img src="https://img.shields.io/badge/IOCParser-Threat%20Intelligence-blue?style=for-the-badge" alt="IOCParser">
</p>

<h1 align="center">IOCParser</h1>

<p align="center">
  <strong>Production-grade IOC extraction, enrichment, persistence, and pipeline tooling for threat intelligence workflows</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/iocparser-tool/"><img src="https://img.shields.io/pypi/v/iocparser-tool?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/iocparser-tool/"><img src="https://img.shields.io/pypi/pyversions/iocparser-tool?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/IOCParser/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/IOCParser/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/IOCParser/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://codecov.io/gh/seifreed/IOCParser"><img src="https://codecov.io/gh/seifreed/IOCParser/branch/main/graph/badge.svg" alt="Codecov"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/IOCParser/stargazers"><img src="https://img.shields.io/github/stars/seifreed/IOCParser?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/IOCParser/issues"><img src="https://img.shields.io/github/issues/seifreed/IOCParser?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**IOCParser** extracts Indicators of Compromise from reports, feeds, URLs, stdin, and directory trees. It supports refanging, MISP warning-list enrichment, structured renderers, persisted run history, IOC search, run diffs, and queue-backed distributed processing.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-source ingestion** | Parse PDF, HTML, text, stdin, URLs, URL lists, multi-file batches, and directories |
| **IOC extraction** | Detect hashes, network indicators, Windows artifacts, threat-intel IDs, crypto addresses, YARA, and more |
| **Warning-list enrichment** | MISP warning-list matching with normal/warning separation and evidence context |
| **Structured outputs** | Render text, summary, JSON, JSONL, CSV, and STIX 2.1 |
| **Persistence** | Store runs in SQLite or MariaDB-compatible SQLAlchemy backends |
| **Search and diff** | Query persisted IOCs, export runs, diff runs, and compare against latest successful source runs |
| **Batch operations** | URL retries, backoff, rate limiting, concurrency, and failed-item replay reports |
| **Distributed pipeline** | Filesystem, RabbitMQ, SQS, and Celery queue adapters with persisted job lifecycle |
| **Plugin surface** | Custom renderers, enrichers, extractors, postprocessors, and IOC types |

### Supported Outputs

```text
Human reports    text, summary
Data formats     JSON, JSONL, CSV
Threat intel     STIX 2.1 bundles
Persistence      run exports, IOC search pages, structured run diffs
Operations       URL batch reports, pipeline job results, schema artifacts
```

### Supported IOC Families

```text
Hashes          MD5, SHA1, SHA256, SHA512, SSDEEP, IMPHASH
Network         Domains, Hosts, IPv4, IPv6, URLs, Emails, ASNs
Windows         Registry keys, mutexes, named pipes, service names
Artifacts       Filenames, filepaths, certificate serials, JWT, user agents
Threat intel    CVEs, MITRE ATT&CK techniques, YARA rules
Crypto          Bitcoin, Ethereum, Monero
Other           MAC addresses
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install iocparser-tool
```

### From Source

```bash
git clone https://github.com/seifreed/IOCParser.git
cd IOCParser
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### Development Extras

```bash
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Initialize warning lists once
iocparser --init

# Extract from file, URL, or stdin
iocparser -f report.pdf
iocparser -u https://example.com/report.html
cat report.txt | iocparser --stdin --json

# Persist and query later
iocparser -f report.txt --persist --db-uri "sqlite:///iocparser.db"
iocparser --list-runs --db-uri "sqlite:///iocparser.db"
```

---

## Usage

### Command Line Interface

```bash
# Single inputs
iocparser -f report.pdf
iocparser https://example.com/report.html
iocparser --stdin < report.txt

# Batch files and URL feeds
iocparser -m report1.txt report2.txt report3.txt
iocparser -d reports --recursive --glob "*.html"
iocparser --url-file feeds.txt --url-workers 8 --url-retries 2 --batch-report-json batch.json

# Output formats
iocparser -f report.txt --json
iocparser -f report.txt --jsonl
iocparser -f report.txt --csv
iocparser -f report.txt --stix --stix-types domains,urls,ips
iocparser -f report.txt --summary

# Analyst filters
iocparser -f report.txt --only urls,domains --severity medium --with-context
iocparser -f report.txt --exclude yara,registry --only-normal
iocparser -f report.txt --sort-by severity --max-evidence 1
```

### Available Options (Main Workflows)

| Workflow | Description |
|----------|-------------|
| `-f, --file` | Parse a single file or `-` for stdin |
| `-u, --url` | Download and parse one URL |
| `--stdin` | Read IOC text from stdin |
| `-m, --multiple` | Parse multiple files and merge results |
| `-d, --directory` | Parse files from a directory, with `--recursive` and `--glob` |
| `--url-file` | Parse a URL feed with workers, retries, backoff, and rate limiting |
| `--streaming` | Process large files in chunks |
| `--persist` | Save extraction run metadata and IOCs to a database |
| `--list-runs` | List persisted runs |
| `--search-ioc` | Search persisted IOC values with `auto`, `fts`, or `like` backends |
| `--export-run` | Export a persisted run as text, JSON, JSONL, CSV, or STIX |
| `--diff-runs` | Compare two persisted runs |
| `--diff-latest` | Compare a run with the latest successful run from the same source |
| `--retry-failed-from` | Replay failed URL items from a previous batch report |
| `--schema-version`, `--migrate` | Inspect or migrate the persistence schema |

### Persistence Examples

```bash
# Search persisted IOCs
iocparser --search-ioc evil.example --db-uri "sqlite:///iocparser.db"
iocparser --search-ioc evil.example --ioc-type urls --severity informational --tag warning-list-match

# Export and diff runs
iocparser --export-run 42 --json --db-uri "sqlite:///iocparser.db"
iocparser --diff-runs 40 42 --diff-only added --json --db-uri "sqlite:///iocparser.db"
iocparser --diff-latest 42 --summary --db-uri "sqlite:///iocparser.db"

# Maintenance
iocparser --delete-run 42 --db-uri "sqlite:///iocparser.db"
iocparser --prune-before 2026-01-01T00:00:00 --keep-latest 10 --db-uri "sqlite:///iocparser.db"
```

### HTTP and Batch Flags

| Option | Description |
|--------|-------------|
| `--url-workers` | Number of concurrent URL workers |
| `--url-retries` | Per-URL retry attempts |
| `--url-backoff` | Backoff between URL retries |
| `--rate-limit` | Delay between URL fetches |
| `--user-agent` | Custom HTTP user agent |
| `--header`, `--cookie`, `--proxy` | HTTP request customization |
| `--allow-redirects`, `--tls-verify`, `--tls-cert`, `--ca-bundle` | Redirect and TLS policy |
| `--connect-timeout`, `--read-timeout` | HTTP timeout policy |

---

## Python Library

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
print(result.total_count())
```

### Persistence API

```python
from iocparser import persistence

db_uri = "sqlite:///iocparser.db"

runs = persistence.list_persisted_runs(db_uri=db_uri, limit=10)
hits = persistence.search_persisted_iocs(
    db_uri=db_uri,
    value="evil.example",
    ioc_type="urls",
    min_severity="medium",
    tag="network",
)
exported = persistence.export_persisted_run(db_uri=db_uri, run_id=42)
diff = persistence.diff_persisted_runs(db_uri=db_uri, left_run_id=40, right_run_id=42)
```

### Distributed Pipeline API

```python
from iocparser import pipeline

client = pipeline.DistributedPipelineClient(
    db_uri="sqlite:///iocparser.db",
    queue_backend="filesystem",
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

### Lower-level Components

```python
from iocparser.infrastructure.extraction import IOCExtractor
from iocparser.infrastructure.file_parser import PDFParser
from iocparser.infrastructure.warninglists import MISPWarningLists

text = PDFParser("report.pdf").extract_text()
raw_iocs = IOCExtractor(defang=True).extract_all(text)
warning_lists = MISPWarningLists()
```

---

## Configuration

IOCParser resolves configuration in this order:

1. CLI arguments
2. Environment variables
3. INI file

```bash
export IOCPARSER_PERSIST=1
export IOCPARSER_DB_URI="sqlite:///iocparser.db"
```

```ini
[database]
persist = true
uri = sqlite:///iocparser.db

[defaults]
only = urls,domains
exclude = yara
output_format = json
with_context = true
severity = medium,high

[network]
url_workers = 8
url_retries = 2
url_backoff = 0.25
rate_limit = 0.10
```

Included deployment profiles:

- [deploy/iocparser.local.example.ini](deploy/iocparser.local.example.ini)
- [deploy/iocparser.scale.example.ini](deploy/iocparser.scale.example.ini)
- [deploy/iocparser.production.example.ini](deploy/iocparser.production.example.ini)

---

## Pipeline and Schemas

IOCParser exposes versioned machine-readable contracts for batch reporting and queue-backed processing.

| Document | Scope |
|----------|-------|
| [docs/PIPELINE_CONTRACT.md](docs/PIPELINE_CONTRACT.md) | Worker input/result contracts and resource limits |
| [docs/DISTRIBUTED_PIPELINE.md](docs/DISTRIBUTED_PIPELINE.md) | Queue-backed execution with filesystem, RabbitMQ, SQS, and Celery |
| [docs/WORKER_DEPLOYMENT.md](docs/WORKER_DEPLOYMENT.md) | Worker deployment guidance |
| [docs/SCHEMA_ARTIFACTS.md](docs/SCHEMA_ARTIFACTS.md) | JSON schema artifacts and release publication |
| [docs/SECURITY_OPERATIONS.md](docs/SECURITY_OPERATIONS.md) | Secret handling and operational guidance |

Standalone worker:

```bash
IOCPARSER_WORKER_QUEUE_BACKEND=filesystem \
IOCPARSER_WORKER_QUEUE_PATH=.iocparser-queue \
IOCPARSER_WORKER_QUEUE_NAME=ingest \
IOCPARSER_WORKER_DB_URI=sqlite:///iocparser.db \
iocparser-worker
```

---

## CI and Release Publishing

The project CI validates Python 3.13 and 3.14 across Linux, macOS, and Windows. The release workflow publishes from matching version tags, creates GitHub release assets, and uses PyPI trusted publishing through OIDC.

```bash
# Example release tag for pyproject version 5.0.2
git tag v5.0.2
git push origin v5.0.2
```

Release assets include:

- Python wheel
- Source distribution
- JSON schema artifacts from `iocparser/schemas/`

---

## Requirements

- Python 3.13 or 3.14
- libmagic runtime support for file type detection
- See [pyproject.toml](pyproject.toml) for dependencies and optional pipeline extras

---

## Testing

```bash
make test-quick
make test
make test-benchmark
```

- `make test-quick`: fast feedback lane
- `make test`: full functional suite with coverage enforcement
- `make test-benchmark`: benchmark-only lane

Coverage is enforced at `100%` in CI.

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/IOCParser](https://github.com/seifreed/IOCParser)

---

<p align="center">
  <sub>Built for practical IOC extraction, threat-intelligence automation, and security operations</sub>
</p>
