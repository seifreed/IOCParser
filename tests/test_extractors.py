#!/usr/bin/env python3
"""
Comprehensive unit tests for IOC extractors

Author: Marc Rivero | @seifreed
"""

import pytest

from iocparser.modules.extractor import IOCExtractor


class TestHashExtractors:
    """Test hash extraction methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)
        self.extractor_defang = IOCExtractor(defang=True)

    def test_extract_md5(self):
        """Test MD5 hash extraction."""
        text = """
        Valid MD5: 5f4dcc3b5aa765d61d8327deb882cf99
        Invalid MD5: 5f4dcc3b5aa765d61d8327deb882cf9  # Too short
        Invalid MD5: 5f4dcc3b5aa765d61d8327deb882cf99a  # Too long
        Invalid MD5: 00000000000000000000000000000000  # All zeros
        """
        result = self.extractor.extract_md5(text)
        assert len(result) == 1
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in result

    def test_extract_sha1(self):
        """Test SHA1 hash extraction."""
        text = """
        Valid SHA1: 356a192b7913b04c54574d18c28d46e6395428ab
        Invalid SHA1: 356a192b7913b04c54574d18c28d46e6395428a  # Too short
        """
        result = self.extractor.extract_sha1(text)
        assert len(result) == 1
        assert "356a192b7913b04c54574d18c28d46e6395428ab" in result

    def test_extract_sha256(self):
        """Test SHA256 hash extraction."""
        text = """
        Valid SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Invalid: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85  # Too short
        """
        result = self.extractor.extract_sha256(text)
        assert len(result) == 1
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in result

    def test_extract_sha512(self):
        """Test SHA512 hash extraction."""
        text = """
        Valid SHA512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
        """
        result = self.extractor.extract_sha512(text)
        assert len(result) == 1

    def test_extract_ssdeep(self):
        """Test ssdeep hash extraction."""
        text = """
        Valid ssdeep: 768:C7tsNKI7aU8Y1O5wjNHDwLxQJidNG3qGqDRTRRRRRRRRT:CtsI7aUwjNQidNG3GqDRTRT
        Another: 1536:87vbq1lGDAXSJ8+YKVbHpM0xcaECjBrJWhMfn2:87vbq1lGDAXSJ8+YKVbHpM0xcaECjBrJWhMfn2
        """
        result = self.extractor.extract_ssdeep(text)
        assert len(result) == 2


class TestNetworkExtractors:
    """Test network-related IOC extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)
        self.extractor_defang = IOCExtractor(defang=True)

    def test_extract_domains(self):
        """Test domain extraction."""
        text = """
        Valid domains: example.com, test.co.uk, subdomain.example.org
        Already defanged: example[.]com, test(.)co[.]uk
        Invalid: notadomain, test.invalidtld, localhost.localdomain
        """
        result = self.extractor.extract_domains(text)
        assert "example.com" in result
        assert "test.co.uk" in result
        assert "subdomain.example.org" in result
        assert "localhost.localdomain" not in result

    def test_extract_domains_defanged(self):
        """Test domain extraction with defanging."""
        text = "Visit malware.com for more info"
        result = self.extractor_defang.extract_domains(text)
        assert "malware[.]com" in result

    def test_extract_ips(self):
        """Test IPv4 extraction."""
        text = """
        Valid IPs: 192.168.1.1, 10.0.0.1, 8.8.8.8
        Defanged: 192[.]168[.]1[.]1
        Invalid: 256.256.256.256, 192.168.1, 192.168.1.1.1
        """
        result = self.extractor.extract_ips(text)
        assert "192.168.1.1" in result
        assert "10.0.0.1" in result
        assert "8.8.8.8" in result
        assert "256.256.256.256" not in result

    def test_extract_ipv6(self):
        """Test IPv6 extraction."""
        text = """
        Valid IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        Short form: 2001:db8::8a2e:370:7334
        Loopback: ::1
        """
        result = self.extractor.extract_ipv6(text)
        assert len(result) >= 2

    def test_extract_urls(self):
        """Test URL extraction."""
        text = """
        URLs: https://example.com/path, http://test.org:8080/file.php
        FTP: ftp://files.example.net/download.zip
        Defanged: hxxps://malware[.]com/payload
        """
        result = self.extractor.extract_urls(text)
        assert len(result) >= 3

    def test_extract_mac_addresses(self):
        """Test MAC address extraction."""
        text = """
        MAC addresses: 00:1B:44:11:3A:B7, 00-1B-44-11-3A-B8
        Cisco format: 001b.4411.3ab9
        """
        result = self.extractor.extract_mac_addresses(text)
        assert len(result) >= 2


class TestEmailAndCommunication:
    """Test email and communication IOC extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)
        self.extractor_defang = IOCExtractor(defang=True)

    def test_extract_emails(self):
        """Test email extraction."""
        text = """
        Emails: user@example.com, admin@test.co.uk
        Complex: firstname.lastname+tag@subdomain.example.org
        """
        result = self.extractor.extract_emails(text)
        assert "user@example.com" in result
        assert "admin@test.co.uk" in result

    def test_extract_emails_defanged(self):
        """Test email extraction with defanging."""
        text = "Contact: malware@evil.com"
        result = self.extractor_defang.extract_emails(text)
        assert any("[@]" in email for email in result)


class TestCryptocurrency:
    """Test cryptocurrency address extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)

    def test_extract_bitcoin(self):
        """Test Bitcoin address extraction."""
        text = """
        BTC addresses:
        Legacy: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        SegWit: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
        """
        result = self.extractor.extract_bitcoin(text)
        assert len(result) >= 1

    def test_extract_ethereum(self):
        """Test Ethereum address extraction."""
        text = "ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4"
        result = self.extractor.extract_ethereum(text)
        assert len(result) == 1
        assert "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4" in result

    def test_extract_monero(self):
        """Test Monero address extraction."""
        text = "XMR: 48ju2dwsRu3rJEMVPD6MNaT2BQNYdZBYHJYZ8F8nPRX2SHPVQgUCYGtjfUNz7KT5RjXrXkz9r7pPp8TpWaStXN7L7Wkn1zP"
        result = self.extractor.extract_monero(text)
        assert len(result) == 1


class TestVulnerabilities:
    """Test vulnerability and threat indicator extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)

    def test_extract_cves(self):
        """Test CVE extraction."""
        text = """
        CVEs: CVE-2021-44228, CVE-2022-0001, cve-2023-12345
        Invalid: CVE-2021-1, CVE-21-44228
        """
        result = self.extractor.extract_cves(text)
        assert "CVE-2021-44228" in result or "cve-2021-44228" in result
        assert len(result) >= 2

    def test_extract_mitre_attack(self):
        """Test MITRE ATT&CK ID extraction."""
        text = """
        Techniques: T1055, T1055.001, T1566.002
        Invalid: T999999, T1055.999
        """
        result = self.extractor.extract_mitre_attack(text)
        assert "T1055" in result
        assert "T1055.001" in result
        assert "T1566.002" in result


class TestWindowsArtifacts:
    """Test Windows-specific IOC extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)

    def test_extract_registry(self):
        """Test Windows registry key extraction."""
        text = """
        Registry keys:
        HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        HKEY_CURRENT_USER\\Software\\Classes
        HKCU\\Control Panel\\Desktop
        """
        result = self.extractor.extract_registry(text)
        assert len(result) >= 2

    def test_extract_mutex(self):
        """Test mutex name extraction."""
        text = """
        Mutexes: Global\\MyAppMutex, Local\\TestMutex
        Named: Mutex:AppInstanceMutex
        Service: UpdateServiceMutex
        """
        result = self.extractor.extract_mutex(text)
        assert len(result) >= 1

    def test_extract_service_names(self):
        """Test Windows service name extraction."""
        text = """
        Services: Service:WinDefend, MalwareService, UpdateSvc
        """
        result = self.extractor.extract_service_names(text)
        assert len(result) >= 1

    def test_extract_named_pipes(self):
        """Test named pipe extraction."""
        text = r"""
        Pipes: \\.\pipe\MyPipe, \\.\pipe\TestPipe123
        """
        result = self.extractor.extract_named_pipes(text)
        assert len(result) >= 1


class TestFileIndicators:
    """Test file-related IOC extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)

    def test_extract_filenames(self):
        """Test filename extraction."""
        text = """
        Files: malware.exe, document.pdf, script.ps1
        Archive: backup.zip, data.rar
        Office: report.docx, spreadsheet.xlsx
        """
        result = self.extractor.extract_filenames(text)
        assert "malware.exe" in result
        assert "document.pdf" in result
        assert "script.ps1" in result

    def test_extract_filepaths(self):
        """Test filepath extraction."""
        text = """
        Windows: C:\\Windows\\System32\\cmd.exe, D:\\Users\\Admin\\file.txt
        Linux: /usr/bin/python3, /etc/passwd, /var/log/syslog
        """
        result = self.extractor.extract_filepaths(text)
        assert len(result) >= 3


class TestMiscellaneous:
    """Test miscellaneous IOC extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)

    def test_extract_user_agents(self):
        """Test user agent extraction."""
        text = """
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
        Another: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/91.0.4472.124
        """
        result = self.extractor.extract_user_agents(text)
        assert len(result) >= 1

    def test_extract_asn(self):
        """Test AS number extraction."""
        text = "Network info: AS15169 (Google), AS13335 (Cloudflare)"
        result = self.extractor.extract_asn(text)
        assert "AS15169" in result
        assert "AS13335" in result

    def test_extract_jwt(self):
        """Test JWT token extraction."""
        text = """
        JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        """
        result = self.extractor.extract_jwt(text)
        assert len(result) == 1

    def test_extract_yara_rules(self):
        """Test YARA rule extraction."""
        text = """
        rule ExampleRule {
            meta:
                description = "Test rule"
            strings:
                $a = "test"
            condition:
                $a
        }
        """
        result = self.extractor.extract_yara_rules(text)
        assert len(result) >= 1


class TestExtractAll:
    """Test the extract_all method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=True)

    def test_extract_all_comprehensive(self):
        """Test extraction of multiple IOC types."""
        text = """
        Report Summary:
        - MD5: 5f4dcc3b5aa765d61d8327deb882cf99
        - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        - Domain: malware.example.com
        - IP: 192.168.1.100
        - URL: https://evil.example.org/payload.exe
        - Email: attacker@malicious.com
        - CVE: CVE-2021-44228
        - File: backdoor.exe at C:\\Windows\\Temp\\backdoor.exe
        - Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        - Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        """

        result = self.extractor.extract_all(text)

        # Check that multiple IOC types were extracted
        assert 'md5' in result
        assert 'sha256' in result
        assert 'domains' in result
        assert 'ips' in result
        assert 'urls' in result
        assert 'emails' in result
        assert 'cves' in result
        assert 'filenames' in result
        assert 'filepaths' in result
        assert 'registry' in result
        assert 'bitcoin' in result

        # Check defanging was applied
        if result.get('domains'):
            assert any('[.]' in d for d in result['domains'])
        if result.get('ips'):
            assert any('[.]' in ip for ip in result['ips'])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
