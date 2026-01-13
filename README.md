<p align="center">
  <img src="https://img.shields.io/badge/IOCParser-Threat%20Intelligence-blue?style=for-the-badge" alt="IOCParser">
</p>

<h1 align="center">IOCParser</h1>

<p align="center">
  <strong>Extract Indicators of Compromise from security reports with ease</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/iocparser-tool/"><img src="https://img.shields.io/pypi/v/iocparser-tool?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/iocparser-tool/"><img src="https://img.shields.io/pypi/pyversions/iocparser-tool?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/iocparser/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/iocparser/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/iocparser/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/coverage-93%25-brightgreen?style=flat-square" alt="Coverage">
</p>

<p align="center">
  <a href="https://github.com/seifreed/iocparser/stargazers"><img src="https://img.shields.io/github/stars/seifreed/iocparser?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/iocparser/issues"><img src="https://img.shields.io/github/issues/seifreed/iocparser?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**IOCParser** is a powerful Python tool for extracting Indicators of Compromise (IOCs) from security reports. It supports HTML, PDF, and plain text formats, making it ideal for threat intelligence analysts, security researchers, and incident responders.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-format Support** | Parse PDF, HTML, and plain text files |
| **URL Analysis** | Extract IOCs directly from web URLs |
| **MISP Integration** | Filter false positives using MISP warning lists |
| **Defanging** | Automatic defanging of domains and IPs |
| **Library Mode** | Use as CLI tool or Python library |
| **JSON/Text/STIX Output** | Flexible output formats |
| **Persistence** | Optional SQLite/MariaDB storage |

### Supported IOC Types

```
Hashes          MD5, SHA1, SHA256, SHA512
Network         Domains, IPs, URLs, Emails
Cryptocurrency  Bitcoin addresses
Vulnerabilities CVEs
Windows         Registry keys, Filepaths, Filenames
Detection       YARA rules
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install iocparser-tool
```

### From Source

```bash
git clone https://github.com/seifreed/iocparser.git
cd iocparser
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

---

## Quick Start

```bash
# Initialize MISP warning lists (first time only)
iocparser --init

# Analyze files
iocparser -f report.pdf
iocparser -f report.html
iocparser -u https://example.com/report.html
```

---

## Usage

### Command Line Interface

```bash
# Basic analysis
iocparser -f report.pdf

# Save output to file
iocparser -f report.pdf -o results.json

# JSON format output
iocparser -f report.pdf --json

# Analyze from URL
iocparser -u https://example.com/report.html

# Force specific file type
iocparser -f report -t pdf
```

### Available Options

| Option | Description |
|--------|-------------|
| `-f, --file` | Input file path |
| `-u, --url` | URL to analyze |
| `-o, --output` | Output file path |
| `-t, --type` | Force file type (pdf, html, text) |
| `--json` | Output in JSON format |
| `--stix` | Output in STIX 2.1 format |
| `--no-defang` | Disable IOC defanging |
| `--no-check-warnings` | Skip MISP warning list check |
| `--force-update` | Force update MISP lists |
| `--init` | Initialize MISP warning lists |
| `--persist/--no-persist` | Enable/disable persistence |
| `--db-uri` | Database URI for persistence |
| `--config` | Path to config file (INI) |

---

## Python Library

### Basic Usage

```python
from iocparser import extract_iocs_from_file, extract_iocs_from_text

# From file
normal_iocs, warning_iocs = extract_iocs_from_file('report.pdf')

# From text
text = "Malware contacts evil.com at 192.168.1.1"
normal_iocs, warning_iocs = extract_iocs_from_text(text)

# Print results
for ioc_type, iocs in normal_iocs.items():
    print(f"{ioc_type}: {iocs}")
```

### Advanced Usage

```python
from iocparser import IOCExtractor, PDFParser, MISPWarningLists

# Extract text from PDF
parser = PDFParser("report.pdf")
text = parser.extract_text()

# Extract IOCs
extractor = IOCExtractor(defang=True)
iocs = extractor.extract_all(text)

# Filter with MISP warning lists
warning_lists = MISPWarningLists()
normal, warnings = warning_lists.separate_iocs_by_warnings(iocs)
```

### Individual Extractors

```python
extractor = IOCExtractor(defang=True)

# Extract specific types
hashes_md5 = extractor.extract_md5(text)
hashes_sha256 = extractor.extract_sha256(text)
domains = extractor.extract_domains(text)
ips = extractor.extract_ips(text)
urls = extractor.extract_urls(text)
emails = extractor.extract_emails(text)
cves = extractor.extract_cves(text)
yara = extractor.extract_yara_rules(text)
registry = extractor.extract_registry(text)
```

---

## Examples

### Process Multiple Reports

```python
from iocparser import extract_iocs_from_file
from pathlib import Path

reports_dir = Path("reports")
for report in reports_dir.glob("*.pdf"):
    normal, warnings = extract_iocs_from_file(report)
    total = sum(len(v) for v in normal.values())
    print(f"{report.name}: {total} IOCs found")
```

### Export to JSON

```bash
iocparser -f apt_report.pdf --json -o iocs.json
```

### Export to STIX 2.1

```bash
iocparser -f apt_report.pdf --stix -o iocs.stix.json
```

### Persistence (SQLite/MariaDB)

```bash
# SQLite
iocparser -u https://example.com/report.html --persist --db-uri "sqlite:///iocparser.db"

# MariaDB
iocparser -u https://example.com/report.html --persist --db-uri "mysql+pymysql://user:pass@host:3306/iocparser"
```

### Config + Environment

Supports `.env`, environment variables, and INI config files.

**Environment variables**

```bash
export IOCPARSER_PERSIST=1
export IOCPARSER_DB_URI="sqlite:///iocparser.db"
```

**INI config (`iocparser.ini` or `~/.config/iocparser/config.ini`)**

```ini
[database]
persist=true
uri=sqlite:///iocparser.db
```

### Analyze Threat Intelligence Feed

```bash
iocparser -u https://securelist.com/report.html --json
```

---

## Requirements

- Python 3.10+
- See [pyproject.toml](pyproject.toml) for full dependency list

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If you find IOCParser useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/iocparser](https://github.com/seifreed/iocparser)

---

<p align="center">
  <sub>Made with dedication for the threat intelligence community</sub>
</p>
