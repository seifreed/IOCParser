# IOCParser Package

A Python package for extracting Indicators of Compromise (IOCs) from security reports in HTML or PDF format.

Author: Marc Rivero | @seifreed

## Installation

```bash
pip install iocparser-tool
```

## Using as a Library

### Recommended Public Entry Points

For new integrations, prefer the public extraction API and the normalized rendering API:

```python
from iocparser import extraction
from iocparser import renderers

result = extraction.extract_result_from_text(
    "IOC URL: https://evil.example/path and domain alpha.example",
    check_warnings=False,
)

print(renderers.JSONOutputRenderer().render(result))
```

### Basic Usage

```python
from iocparser import extraction, renderers

normal_iocs, warning_iocs = extraction.extract_iocs_from_text(
    "This malware contacts evil.com with hash 5f4dcc3b5aa765d61d8327deb882cf99",
    check_warnings=False,
)
result = extraction.extract_result_from_text(
    "This malware contacts evil.com with hash 5f4dcc3b5aa765d61d8327deb882cf99",
    check_warnings=False,
)

print(normal_iocs)
print(warning_iocs)
print(renderers.JSONOutputRenderer().render(result))
print(renderers.TextOutputRenderer().render(result))
```

### Processing Files

```python
from iocparser.infrastructure.file_parser import PDFParser, HTMLParser
from iocparser.infrastructure.extraction import IOCExtractor

# Process a PDF file
pdf_parser = PDFParser("report.pdf")
pdf_text = pdf_parser.extract_text()
extractor = IOCExtractor()
pdf_iocs = extractor.extract_all(pdf_text)

# Process an HTML file
html_parser = HTMLParser("report.html")
html_text = html_parser.extract_text()
extractor = IOCExtractor()
html_iocs = extractor.extract_all(html_text)
```

### Checking Against MISP Warning Lists

```python
from iocparser.infrastructure.warninglists import MISPWarningLists
from iocparser.infrastructure.extraction import IOCExtractor

# Extract IOCs
extractor = IOCExtractor()
iocs = extractor.extract_all("Check IP 8.8.8.8 and domain google.com")

# Check against warning lists
warning_lists = MISPWarningLists()
warnings = warning_lists.get_warnings_for_iocs(iocs)
print(warnings)
```

### Saving Results to Files

```python
from pathlib import Path

from iocparser import extraction, renderers

result = extraction.extract_result_from_text("Domain: evil.com, IP: 192.168.1.1", check_warnings=False)
Path("results.json").write_text(renderers.JSONOutputRenderer().render(result), encoding="utf-8")
Path("results.txt").write_text(renderers.TextOutputRenderer().render(result), encoding="utf-8")
```

### Specific Extraction Methods

The `IOCExtractor` class provides multiple methods for extracting specific types of IOCs:

```python
extractor = IOCExtractor(defang=True)

# Extract specific IOC types
md5_hashes = extractor.extract_md5(text)
sha1_hashes = extractor.extract_sha1(text)
sha256_hashes = extractor.extract_sha256(text)
sha512_hashes = extractor.extract_sha512(text)
domains = extractor.extract_domains(text)
ips = extractor.extract_ips(text)
urls = extractor.extract_urls(text)
bitcoin_addresses = extractor.extract_bitcoin(text)
yara_rules = extractor.extract_yara_rules(text)
hosts = extractor.extract_hosts(text)
emails = extractor.extract_emails(text)
cves = extractor.extract_cves(text)
registry_keys = extractor.extract_registry(text)
filenames = extractor.extract_filenames(text)
filepaths = extractor.extract_filepaths(text)
```

## Full Example

```python
from pathlib import Path

from iocparser import extraction, renderers

normal_iocs, warning_iocs = extraction.extract_iocs_from_file("path/to/threat_report.pdf")
result = extraction.extract_result_from_file("path/to/threat_report.pdf")

total_iocs = sum(len(values) for values in normal_iocs.values())
print(f"Found {total_iocs} indicators of compromise:")
for ioc_type, values in normal_iocs.items():
    if values:
        print(f"  - {ioc_type}: {len(values)}")

for ioc_type, values in warning_iocs.items():
    print(f"\nWarnings for {ioc_type}:")
    for warning in values:
        print(f"  - {warning['value']} - List: {warning['warning_list']}")
        print(f"    Description: {warning['description']}")

Path("iocs_results.json").write_text(renderers.JSONOutputRenderer().render(result), encoding="utf-8")
print("Results saved to iocs_results.json")
``` 
