# IOCParser Examples

This directory contains sample security reports and scripts demonstrating the usage of IOCParser.

## Sample Files

### sample_report.txt
A comprehensive security incident report containing various types of IOCs including:
- MD5, SHA1, SHA256, SHA512, and SSDeep hashes
- IPv4 and IPv6 addresses
- Domain names and URLs
- Email addresses
- CVE identifiers
- MITRE ATT&CK technique IDs
- Windows registry keys
- File paths and names
- Cryptocurrency addresses
- User agents
- YARA rules
- And more...

## Usage Examples

### Basic Extraction
```bash
# Extract IOCs from the sample report
iocparser -f examples/sample_report.txt

# Save results to JSON
iocparser -f examples/sample_report.txt --json -o results.json

# Extract without defanging
iocparser -f examples/sample_report.txt --no-defang
```

### Python API Usage
```python
from iocparser import extract_iocs_from_file

# Extract IOCs from the sample report
normal_iocs, warning_iocs = extract_iocs_from_file('examples/sample_report.txt')

# Print extracted domains
for domain in normal_iocs.get('domains', []):
    print(f"Domain: {domain}")

# Print extracted IPs
for ip in normal_iocs.get('ips', []):
    print(f"IP: {ip}")
```

### Streaming Large Files
```python
from iocparser.modules.streaming import stream_iocs_from_file

# Stream IOCs from a large file
for ioc_batch in stream_iocs_from_file('large_report.txt'):
    for ioc_type, iocs in ioc_batch.items():
        print(f"Found {len(iocs)} {ioc_type}")
```

### Parallel Processing
```python
from pathlib import Path
from iocparser.modules.streaming import ParallelStreamingExtractor

# Process multiple files in parallel
files = list(Path('reports/').glob('*.txt'))
extractor = ParallelStreamingExtractor(max_workers=4)
results = extractor.extract_from_files(files)

for file_path, iocs in results.items():
    print(f"{file_path}: Found {sum(len(v) for v in iocs.values())} IOCs")
```

## Creating Test Reports

You can create your own test reports by including various IOC types. Here's a template:

```text
Malware Analysis Report
========================

Hashes:
- MD5: [32 hex characters]
- SHA256: [64 hex characters]

Network Indicators:
- C2 Server: malware.example.com
- IP Address: 192.168.1.1
- URL: https://evil.example.com/payload

Files:
- Dropped: C:\Windows\Temp\malware.exe
- Config: /etc/malware/config.json

Registry:
- Key: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Malware

Email:
- Attacker: attacker@malicious.com

Vulnerabilities:
- Exploits: CVE-2021-44228
- Techniques: T1055.001
```

## Testing New IOC Types

When adding support for new IOC types, create test files here with examples of the new indicators:

1. Create a file named `test_[ioc_type].txt`
2. Include various valid and edge-case examples
3. Run IOCParser against it to verify extraction
4. Add the test cases to the unit tests

## Performance Testing

For performance testing with large files:

```bash
# Generate a large test file (Linux/Mac)
for i in {1..1000}; do cat sample_report.txt >> large_test.txt; done

# Test extraction performance
time iocparser -f large_test.txt -o /dev/null
```

## Contributing Examples

If you have real-world (sanitized) examples of security reports that would help test IOCParser, please:

1. Remove any sensitive or proprietary information
2. Replace real malicious IPs/domains with reserved/example addresses
3. Ensure no PII is included
4. Submit via pull request

## License

These examples are provided under the same MIT license as IOCParser.