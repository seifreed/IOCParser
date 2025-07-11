# IOCParser Package

A Python package for extracting Indicators of Compromise (IOCs) from security reports in HTML or PDF format.

Author: Marc Rivero | @seifreed

## Installation

```bash
pip install iocparser-tool
```

## Using as a Library

### Basic Usage

```python
from iocparser import IOCExtractor, PDFParser, HTMLParser, JSONFormatter, TextFormatter

# Extract IOCs from plain text
text = "This malware contacts evil.com with hash 5f4dcc3b5aa765d61d8327deb882cf99"
extractor = IOCExtractor(defang=True)
iocs = extractor.extract_all(text)
print(iocs)

# Format the results as JSON
formatter = JSONFormatter(iocs)
json_output = formatter.format()
print(json_output)

# Format the results as plain text
formatter = TextFormatter(iocs)
text_output = formatter.format()
print(text_output)
```

### Processing Files

```python
from iocparser import PDFParser, HTMLParser, IOCExtractor

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
from iocparser import MISPWarningLists, IOCExtractor

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
from iocparser import IOCExtractor, JSONFormatter, TextFormatter

# Extract IOCs
extractor = IOCExtractor()
iocs = extractor.extract_all("Domain: evil.com, IP: 192.168.1.1")

# Save as JSON
json_formatter = JSONFormatter(iocs)
json_formatter.save("results.json")

# Save as plain text
text_formatter = TextFormatter(iocs)
text_formatter.save("results.txt")
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
from iocparser import IOCExtractor, PDFParser, MISPWarningLists, JSONFormatter

# 1. Parse a PDF report
parser = PDFParser("path/to/threat_report.pdf")
text_content = parser.extract_text()

# 2. Extract IOCs
extractor = IOCExtractor(defang=True)
iocs = extractor.extract_all(text_content)

# 3. Check for false positives
warning_lists = MISPWarningLists()
warnings = warning_lists.get_warnings_for_iocs(iocs)

# 4. Print summary
total_iocs = sum(len(iocs[k]) for k in iocs)
print(f"Found {total_iocs} indicators of compromise:")
for ioc_type, ioc_list in iocs.items():
    if ioc_list:
        print(f"  - {ioc_type}: {len(ioc_list)}")

# 5. Print warnings
for ioc_type, type_warnings in warnings.items():
    print(f"\nWarnings for {ioc_type}:")
    for warning in type_warnings:
        print(f"  - {warning['value']} - List: {warning['warning_list']}")
        print(f"    Description: {warning['description']}")

# 6. Save results
formatter = JSONFormatter(iocs)
formatter.save("iocs_results.json")
print("Results saved to iocs_results.json")
``` 