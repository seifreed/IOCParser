# IOCParser

A tool for extracting Indicators of Compromise (IOCs) from security reports in HTML, PDF, and plain text formats.

Author: Marc Rivero | @seifreed  
Version: 1.0.1

## Features

- Extraction of multiple types of IOCs:
  - Hashes (MD5, SHA1, SHA256, SHA512)
  - Domains
  - IP Addresses
  - URLs
  - Bitcoin addresses
  - Email addresses
  - Hosts
  - CVEs
  - Windows Registry entries
  - Filenames
  - Filepaths
  - Yara rules
- Automatic defanging of domains and IPs
- Support for HTML, PDF, and plain text formats
- Support for direct analysis from URLs
- Output in JSON and plain text format
- Checking against MISP warning lists to identify false positives
- Can be used as a command-line tool or as a Python library

## Installation

### From PyPI (Recommended)

```bash
pip install iocparser-tool
```

### From Source

```bash
# Clone the repository
git clone https://github.com/seifreed/iocparser.git
cd iocparser

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install as a package with all dependencies
pip install -e .

# Or install just the requirements
pip install -r requirements.txt
```

## Quick Start

```bash
# Initialize and download MISP warning lists (do this first)
iocparser --init

# Analyze a PDF file
iocparser -f report.pdf

# Analyze an HTML file
iocparser -f report.html

# Analyze a text file
iocparser -f report.txt
```

## Command Line Usage

### Basic Usage

```bash
# Initialize and download MISP warning lists (do this first)
iocparser --init

# Analyze a PDF file
iocparser -f report.pdf

# Analyze an HTML file
iocparser -f report.html

# Analyze a text file
iocparser -f report.txt
```

### File Type Options

```bash
# Force specific file type (pdf, html, text)
iocparser -f report -t pdf
iocparser -f report -t html
iocparser -f report -t text
```

### Output Options

```bash
# Save outputs to a specific file
iocparser -f report.pdf -o results.json
iocparser -f report.pdf -o results.txt

# Print results to screen only
iocparser -f report.pdf -o -

# Use JSON format (default is text)
iocparser -f report.pdf --json
```

### Analyzing from URL

```bash
# Analyze a report from a URL
iocparser -u https://example.com/report.html

# Specify content type for a URL
iocparser -u https://example.com/report -t html
```

### Additional Options

```
--no-defang          Disable automatic defanging of IOCs
--no-check-warnings  Don't check IOCs against MISP warning lists
--force-update       Force update of MISP warning lists
--init               Download and initialize MISP warning lists
-h, --help           Show help message
```

## Using as a Library

You can use IOCParser as a library in your Python projects:

```python
# Example 1: Extract IOCs from a file
from iocparser import extract_iocs_from_file

# Process a file (automatically detects file type)
normal_iocs, warning_iocs = extract_iocs_from_file('path/to/report.pdf')
print(f"Found {len(normal_iocs.get('domains', []))} normal domains")
print(f"Found {len(warning_iocs.get('domains', []))} potential false positive domains")

# With additional options
normal_iocs, warning_iocs = extract_iocs_from_file(
    'path/to/report.html',
    check_warnings=True,      # Check against MISP warning lists
    force_update=False,       # Don't force update MISP lists
    file_type='html',         # Force file type (optional)
    defang=True               # Defang the IOCs
)

# Example 2: Extract IOCs from text content directly
from iocparser import extract_iocs_from_text

text = "This sample malware contacts evil.com with IP 192.168.1.1 and uses hash 5f4dcc3b5aa765d61d8327deb882cf99"
normal_iocs, warning_iocs = extract_iocs_from_text(text)

# Print the extracted IOCs
for ioc_type, iocs_list in normal_iocs.items():
    print(f"{ioc_type}: {iocs_list}")
```

### Using the Low-Level Components

If you need more control, you can use the individual components directly:

```python
from iocparser import IOCExtractor, PDFParser, HTMLParser, MISPWarningLists

# Extract text from a PDF or HTML file
parser = PDFParser("path/to/report.pdf")
# or
# parser = HTMLParser("path/to/report.html")
text_content = parser.extract_text()

# Extract IOCs
extractor = IOCExtractor(defang=True)
iocs = extractor.extract_all(text_content)

# Check against warning lists
warning_lists = MISPWarningLists()
normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)
```

### Available Extraction Methods

```python
from iocparser import IOCExtractor

extractor = IOCExtractor(defang=True)

# Extract specific IOC types
md5_hashes = extractor.extract_md5(text)
sha1_hashes = extractor.extract_sha1(text)
sha256_hashes = extractor.extract_sha256(text)
sha512_hashes = extractor.extract_sha512(text)
domains = extractor.extract_domains(text)
ips = extractor.extract_ips(text)
urls = extractor.extract_urls(text)
bitcoin = extractor.extract_bitcoin(text)
yara_rules = extractor.extract_yara_rules(text)
hosts = extractor.extract_hosts(text)
emails = extractor.extract_emails(text)
cves = extractor.extract_cves(text)
registry_keys = extractor.extract_registry(text)
filenames = extractor.extract_filenames(text)
filepaths = extractor.extract_filepaths(text)

# Extract all IOC types at once
all_iocs = extractor.extract_all(text)  # Returns a dictionary with all IOCs
```

## Examples

### Extract IOCs from a local PDF report
```bash
iocparser -f reports/APT28_report.pdf
```

### Extract IOCs from a URL and save in JSON format
```bash
iocparser -u https://example.com/security-report.pdf --json
```

### Extract IOCs from an HTML file without defanging
```bash
iocparser -f report.html --no-defang
```

### Use in a Python script to process multiple files
```python
from iocparser import extract_iocs_from_file
import os

reports_dir = "path/to/reports"
for filename in os.listdir(reports_dir):
    if filename.endswith(".pdf") or filename.endswith(".html"):
        file_path = os.path.join(reports_dir, filename)
        print(f"Processing {filename}...")
        normal_iocs, warning_iocs = extract_iocs_from_file(file_path)
        
        # Do something with the extracted IOCs
        print(f"Found {sum(len(iocs) for iocs in normal_iocs.values())} IOCs")
```

## License

This project is available under the MIT License. You are free to use, modify, and distribute it, provided that you include the original copyright notice and attribution to the original author.

**Required Attribution:**
- Original Author: Marc Rivero | @seifreed
- Repository: https://github.com/seifreed/iocparser

When using this project in your own work, please include a clear reference to the original author and repository. 