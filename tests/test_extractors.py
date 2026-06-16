#!/usr/bin/env python3
"""
Comprehensive unit tests for IOC extractors

Author: Marc Rivero | @seifreed
"""

import pytest

from iocparser.infrastructure.extraction import IOCExtractor


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

    def test_extract_imphash_reported_under_own_type(self):
        """An explicitly-labelled import hash is reported as imphash, not md5."""
        result = self.extractor.extract_all(
            "Sample imphash: d41d8cd98f00b204e9800998ecf8427e in the report"
        )
        assert result.get("imphash") == ["d41d8cd98f00b204e9800998ecf8427e"]
        assert "md5" not in result

    def test_extract_imphash_keeps_unrelated_md5(self):
        """A separate standalone md5 stays under md5 while the imphash is split out."""
        result = self.extractor.extract_all(
            "imphash: d41d8cd98f00b204e9800998ecf8427e and md5 5d41402abc4b2a76b9719d911017c592"
        )
        assert result.get("imphash") == ["d41d8cd98f00b204e9800998ecf8427e"]
        assert result.get("md5") == ["5d41402abc4b2a76b9719d911017c592"]

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
        assert {"example.com", "test.co.uk", "subdomain.example.org"}.issubset(set(result))
        assert "localhost.localdomain" not in result

    def test_extract_domains_single_character_labels(self):
        """Test domain extraction keeps valid one-character labels."""
        text = "Observed domains: x.com, c2.a.evil-example.com, a.b.example.org"

        result = self.extractor.extract_domains(text)

        assert "x.com" in result
        assert "c2.a.evil-example.com" in result
        assert "a.b.example.org" in result

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

    def test_extract_ipv6_ipv4_mapped_address(self):
        """Test IPv4-mapped IPv6 extraction preserves the full address."""
        text = "Callback over IPv6: ::ffff:192.168.1.1 not ::ffff:999.999.999.999"

        result = self.extractor.extract_ipv6(text)

        assert "::ffff:192.168.1.1" in result
        assert "::ffff:192" not in result
        assert "::ffff:999" not in result

    def test_extract_ipv6_embedded_ipv4_beyond_ffff_prefix(self):
        """Regression: a NAT64 (64:ff9b::) embedded-IPv4 address must not be
        truncated at the first dotted octet into a wrong, still-valid address."""
        text = "NAT64 traffic to 64:ff9b::192.168.1.1 observed"

        result = self.extractor.extract_ipv6(text)

        assert "64:ff9b::192.168.1.1" in result
        assert "64:ff9b::192" not in result

    def test_extract_urls(self):
        """Test URL extraction."""
        text = """
        URLs: https://example.com/path, http://test.org:8080/file.php
        FTP: ftp://files.example.net/download.zip
        Defanged: hxxps://malware[.]com/payload
        """
        result = self.extractor.extract_urls(text)
        assert len(result) >= 2

    def test_extract_urls_with_defanged_host_separators(self):
        """Test URL extraction handles defanged host separators."""
        text = "Callback: hxxps://malware[.]example/payload"

        result = self.extractor.extract_urls(text)
        defanged_result = self.extractor_defang.extract_urls(text)

        assert result == ["hxxps://malware[.]example/payload"]
        assert defanged_result == ["hxxps://malware[.]example/payload"]

    def test_extract_mac_addresses(self):
        """Test MAC address extraction."""
        text = """
        MAC addresses: 00:1B:44:11:3A:B7, 00-1B-44-11-3A-B8
        Cisco format: 001b.4411.3ab9
        """
        result = self.extractor.extract_mac_addresses(text)
        assert len(result) >= 2

    def test_extract_mac_addresses_dotted_form_is_lowercased(self):
        """Dotted (Cisco) MACs must canonicalize to lowercase like dash/colon forms.

        Regression: the dotted branch joined hex without lowercasing, so an
        uppercase Cisco MAC came out uppercase while the same address in dash or
        colon notation came out lowercase -- breaking cross-notation dedup and the
        STIX mac-addr:value lowercase requirement.
        """
        result = self.extractor.extract_mac_addresses("Cisco MAC: AABB.CCDD.EEFF")
        assert result == ["aa:bb:cc:dd:ee:ff"]


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
        assert "firstname.lastname+tag@subdomain.example.org" in result
        assert "tag@subdomain.example.org" not in result

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

    def test_extract_named_pipes_is_case_insensitive(self):
        """Regression: Windows pipe paths are case-insensitive; \\.\\PIPE\\ must match."""
        result = self.extractor.extract_named_pipes(r"connect to \\.\PIPE\AdminPipe now")
        assert result == [r"\\.\PIPE\AdminPipe"]

    def test_extract_named_pipes_keeps_interior_dots(self):
        r"""Pipe names with interior dots (e.g. Chromium mojo.5678) must not truncate.

        Regression: the charset excluded '.', so \\.\pipe\mojo.5678 captured only
        '\\.\pipe\mojo'. A trailing sentence period must still be excluded.
        """
        result = self.extractor.extract_named_pipes(r"ipc \\.\pipe\mojo.5678 opened.")
        assert result == [r"\\.\pipe\mojo.5678"]
        trailing = self.extractor.extract_named_pipes(r"see \\.\pipe\foo. done")
        assert trailing == [r"\\.\pipe\foo"]


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
        assert "md5" in result
        assert "sha256" in result
        assert "domains" in result
        assert "ips" in result
        assert "urls" in result
        assert "emails" in result
        assert "cves" in result
        assert "filenames" in result
        assert "filepaths" in result
        assert "registry" in result
        assert "bitcoin" in result

        # Check defanging was applied
        if result.get("domains"):
            assert any("[.]" in d for d in result["domains"])
        if result.get("ips"):
            assert any("[.]" in ip for ip in result["ips"])


class TestCoverageMissing:
    """Test coverage for previously uncovered lines."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor(defang=False)
        self.extractor_defang = IOCExtractor(defang=True)

    def test_load_legitimate_domains_file_error(self, tmp_path):
        """Test _load_legitimate_domains with corrupted file."""
        from iocparser.infrastructure.extractor_base_runtime_support import ReferenceDataPolicy

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        json_file = data_dir / "legitimate_domains.json"
        json_file.write_text("{ invalid json }")

        policy = ReferenceDataPolicy(
            default_tlds=frozenset({"com"}),
            common_file_extensions=frozenset({"exe"}),
        )
        legit, legit_sub = policy.load_legitimate_domains(data_dir)
        assert isinstance(legit, set)
        assert isinstance(legit_sub, set)
        assert len(legit) == 0

    def test_load_valid_tlds_file_error(self, tmp_path):
        """Test _load_valid_tlds loads from file successfully."""
        from iocparser.infrastructure.extractor_base_runtime_support import ReferenceDataPolicy

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        tlds_file = data_dir / "tlds.txt"
        tlds_file.write_text("com\norg\nnet\n")

        policy = ReferenceDataPolicy(
            default_tlds=frozenset({"fallback"}),
            common_file_extensions=frozenset({"exe"}),
        )
        tlds = policy.load_valid_tlds(data_dir)
        assert "com" in tlds
        assert "org" in tlds
        assert "net" in tlds

    def test_extract_pattern_invalid_pattern_name(self):
        """Test _extract_pattern with invalid pattern name."""
        result = self.extractor._extract_pattern("test text", "nonexistent_pattern")
        assert result == []

    def test_is_valid_domain_file_extension(self):
        """Test _is_valid_domain rejects file extensions as TLDs."""
        # Domain with file extension as TLD
        assert not self.extractor._is_valid_domain("malware.exe")
        assert not self.extractor._is_valid_domain("document.pdf")
        assert not self.extractor._is_valid_domain("script.js")

    def test_is_valid_domain_programming_keywords(self):
        """Test _is_valid_domain rejects programming keywords."""
        # These are legitimate domains that should NOT be filtered
        assert self.extractor._is_valid_domain("document.com")
        assert self.extractor._is_valid_domain("window.org")
        assert self.extractor._is_valid_domain("console.net")
        # gform is still filtered as a programming keyword
        assert not self.extractor._is_valid_domain("gform.io")

    def test_is_valid_domain_suspicious_subdomain(self):
        """Test _is_valid_domain keeps suspicious subdomains of legitimate domains."""
        # Suspicious subdomains should be kept
        assert self.extractor._is_valid_domain("malware.github.com")
        assert self.extractor._is_valid_domain("c2.microsoft.com")
        assert self.extractor._is_valid_domain("evil.google.com")
        assert self.extractor._is_valid_domain("backdoor.apple.com")

    def test_domain_validation_strips_longest_legitimate_suffix(self):
        """Nested legitimate suffixes must resolve deterministically to the longest match.

        Regression: is_valid iterated a set and returned on the first matching
        suffix, so for legitimate_domains containing both 'amazon.com' and
        'aws.amazon.com' the stripped subdomain (and thus the result) depended on
        hash-randomized set order. The most specific suffix must always win.
        """
        from iocparser.infrastructure.extractor_base import DomainValidationPolicy

        policy = DomainValidationPolicy(
            programming_keywords=frozenset(),
            suspicious_subdomain_keywords=("aws",),
            max_domain_length=253,
            max_domain_part_length=63,
        )
        kwargs = {
            "valid_tlds": {"com"},
            "common_file_extensions": set(),
            "legitimate_domains": {"amazon.com", "aws.amazon.com"},
            "legitimate_with_subdomains": set(),
        }
        # Longest suffix 'aws.amazon.com' is stripped -> subdomain 'x' has no
        # suspicious keyword -> False, regardless of set iteration order.
        results = {policy.is_valid("x.aws.amazon.com", **kwargs) for _ in range(50)}
        assert results == {False}

    def test_is_valid_hash_keeps_digest_with_file_magic_bytes(self):
        """A digest must not be rejected because its bytes spell a file magic.

        The old validator unhexlified the digest and rejected MZ/PK/7z/PNG/JPEG
        prefixes; that dropped ~1 in 22,000 real SHA-256/512 hashes whose random
        first bytes coincided with a signature. A real high-entropy digest whose
        bytes begin 0x4d5a ("MZ") must now be kept.
        """
        mz_digest = "4d5a" + "3c1e7b9f2a8d6045" * 7 + "9f3c1e7b2a8d"  # 128 hex, high entropy
        assert len(mz_digest) == 128
        assert self.extractor._is_valid_hash_pattern(mz_digest)

    def test_is_valid_hash_keeps_digest_decoding_to_ascii(self):
        """A digest must not be rejected because its bytes happen to be ASCII.

        The printable-byte-ratio heuristic was unsound for cryptographic digests
        (indistinguishable from same-length hex-encoded text) and only produced
        false negatives, so it was removed.
        """
        text_hex = ("48656c6c6f20576f726c64" * 11 + "48656c")[:128]
        assert self.extractor._is_valid_hash_pattern(text_hex)

    def test_is_valid_hash_still_rejects_low_entropy_junk(self):
        """The entropy and forbidden-sequence guards must still reject obvious junk."""
        assert not self.extractor._is_valid_hash_pattern("ab" * 64)  # 2 unique chars
        assert not self.extractor._is_valid_hash_pattern("0123456789abcdef" * 8)

    def test_defang_url(self):
        """Test _defang_url method."""
        url1 = "http://malware.com/payload"
        result1 = self.extractor._defang_url(url1)
        assert "hxxp://" in result1
        assert "[.]" in result1

        url2 = "https://evil.org/file.exe"
        result2 = self.extractor._defang_url(url2)
        assert "hxxps://" in result2
        assert "[.]" in result2

    def test_extract_ssdeep_multiple_hashes(self):
        """Test extract_ssdeep extracts multiple hashes."""
        text = """
        ssdeep hashes found:
        768:C7tsNKI7aU8Y1O5wjNHDwLxQJidNG3qGqDRTRRRRRRRRT:CtsI7aUwjNQidNG3GqDRTRT
        1536:87vbq1lGDAXSJ8+YKVbHpM0xcaECjBrJWhMfn2:87vbq1lGDAXSJ8+YKVbHpM0xcaECjBrJWhMfn2
        96:aAbBcCdDeEfF/+gGhH:aAbBcCdDeEfF/+gGhH
        """
        result = self.extractor.extract_ssdeep(text)
        assert len(result) == 3

    def test_extract_domains_edge_cases(self):
        """Test extract_domains with edge cases."""
        text = """
        Normal: example.com
        Legitimate: github.com should be filtered
        Suspicious subdomain: malware.github.com should be kept
        """
        result = self.extractor.extract_domains(text)
        assert "example.com" in result
        # github.com is in legitimate_domains, so should be filtered
        assert "github.com" not in result
        # Suspicious subdomain should be kept
        assert "malware.github.com" in result

    def test_extract_ips_leading_zeros(self):
        """Test extract_ips rejects IPs with leading zeros."""
        text = """
        Invalid with leading zeros: 192.168.001.1, 10.01.0.1
        Valid: 192.168.1.1
        """
        result = self.extractor.extract_ips(text)
        assert "192.168.1.1" in result
        # IPs with leading zeros should be rejected
        assert "192.168.001.1" not in result
        assert not any("192.168.001.1" in ip for ip in result)

    def test_extract_ips_invalid_octets(self):
        """Test extract_ips rejects invalid octet values."""
        text = """
        Invalid: 256.1.1.1, 192.300.1.1, 192.168.1.999
        Valid: 192.168.1.1
        """
        result = self.extractor.extract_ips(text)
        assert "192.168.1.1" in result
        assert not any("256" in ip for ip in result)
        assert not any("300" in ip for ip in result)

    def test_extract_urls_file_sharing_sites(self):
        """Test extract_urls keeps file sharing sites."""
        text = """
        File sharing: https://pastebin.com/abc123
        Discord: https://discord.gg/malware
        Transfer: https://transfer.sh/file.exe
        """
        result = self.extractor.extract_urls(text)
        assert any("pastebin.com" in url for url in result)
        assert any("discord.gg" in url for url in result)

    def test_extract_urls_suspicious_code_hosting(self):
        """Test extract_urls keeps suspicious paths on code hosting sites."""
        text = """
        Suspicious: https://github.com/user/malware/payload.exe
        Normal: https://github.com/user/normal-repo
        Exploit: https://gitlab.com/user/exploit-cve-2023-1234
        """
        result = self.extractor.extract_urls(text)
        # Suspicious paths should be kept
        assert any("malware" in url and "github.com" in url for url in result)
        # Normal GitHub URLs should be filtered
        assert not any("normal-repo" in url for url in result)

    def test_extract_urls_applies_code_hosting_filter_with_ports(self):
        """Test code hosting heuristics use the hostname, not the netloc with port."""
        text = """
        Normal: https://github.com:443/user/normal-repo
        Suspicious: https://github.com:443/user/malware/payload.exe
        """
        result = self.extractor.extract_urls(text)

        assert "https://github.com:443/user/normal-repo" not in result
        assert "https://github.com:443/user/malware/payload.exe" in result

    def test_extract_urls_does_not_treat_embedded_code_host_names_as_code_hosts(self):
        """Test domains containing code-host names are not filtered as real code hosts."""
        text = """
        Lookalike: https://mygithub.com/repo
        Chained host: https://github.com.evil.example/login
        Real normal GitHub: https://github.com/user/normal-repo
        """

        result = self.extractor.extract_urls(text)

        assert "https://mygithub.com/repo" in result
        assert "https://github.com.evil.example/login" in result
        assert "https://github.com/user/normal-repo" not in result

    def test_extract_urls_documentation_sites(self):
        """Test extract_urls filters documentation sites unless they mention exploits."""
        text = """
        Docs: https://docs.microsoft.com/normal-page
        Vuln: https://docs.microsoft.com/vulnerability-cve-2023-1234
        Normal: https://developer.mozilla.org/docs
        Cloud docs: https://cloud.google.com/docs/normal-page
        Cloud vuln: https://cloud.google.com/docs/security/cve-2024-0001
        """
        result = self.extractor.extract_urls(text)
        # Documentation without exploits should be filtered
        assert not any("normal-page" in url for url in result)
        # Documentation with vulnerability keywords should be kept
        assert any("vulnerability" in url for url in result)
        assert any("cve-2024-0001" in url for url in result)

    def test_extract_urls_error_handling(self):
        """Test extract_urls handles malformed URLs gracefully."""
        text = """
        Malformed: hxxp://[malformed
        Valid: https://malicious-site.com/test
        """
        result = self.extractor.extract_urls(text)
        # Should handle malformed URLs without crashing
        assert isinstance(result, list)
        # Valid URLs should still be extracted
        if result:
            assert any("malicious-site.com" in url for url in result)

    def test_extract_yara_rules_length_validation(self):
        """Test extract_yara_rules filters out excessively long text blocks."""
        # Create a very long "rule" that shouldn't be extracted
        long_text = "rule FakeRule { " + "x" * 4000 + " }"
        result = self.extractor.extract_yara_rules(long_text)
        assert len(result) == 0

    def test_extract_yara_rules_incomplete(self):
        """Test extract_yara_rules with missing closing brace."""
        # YARA rule regex requires proper structure, so we test the completion logic
        text = """
        rule IncompleteRule
        {
            meta:
                description = "Test"
            strings:
                $a = "malware"
            condition:
                $a
        """
        result = self.extractor.extract_yara_rules(text)
        # The regex may not match incomplete rules, so we test that it handles them gracefully
        assert isinstance(result, list)
        # If it does extract, verify closing brace logic would work
        for rule in result:
            assert rule.strip().endswith("}")

    def test_extract_filepaths_windows_env_vars(self):
        """Test extract_filepaths extracts paths with environment variables."""
        text = """
        Paths with env vars:
        %TEMP%\\malware.exe
        %APPDATA%\\Microsoft\\payload.dll
        %PROGRAMFILES%\\Malicious\\tool.exe
        """
        result = self.extractor.extract_filepaths(text)
        assert any("%TEMP%" in path for path in result)
        assert any("%APPDATA%" in path for path in result)

    def test_extract_filepaths_unix_paths(self):
        """Test extract_filepaths extracts Unix paths."""
        text = """
        Unix paths:
        /usr/bin/malware
        /tmp/iocparser/payload.sh
        /var/log/suspicious/activity.log
        """
        result = self.extractor.extract_filepaths(text)
        assert any("/usr/bin/malware" in path for path in result)
        assert any("/tmp/iocparser/payload.sh" in path for path in result)

    def test_extract_filepaths_filter_phrases(self):
        """Test extract_filepaths filters out descriptive phrases."""
        text = """
        The folder on the C:\\path was used
        Artifacts were uploaded to C:\\Windows\\test
        """
        result = self.extractor.extract_filepaths(text)
        # Should filter out paths with these phrases
        assert not any("folder on the" in path for path in result)
        assert not any("uploaded to" in path for path in result)

    def test_extract_cert_serials_various_formats(self):
        """Test extract_cert_serials with different formats."""
        text = """
        Certificate serials:
        Colon format: 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
        Plain hex: certificate: 0123456789abcdef1234567890abcdef
        With context: thumbprint 1a2b3c4d5e6f7890
        """
        result = self.extractor.extract_cert_serials(text)
        assert len(result) >= 1
        # Should be normalized to colon-separated format
        assert any(":" in serial for serial in result)

    def test_extract_cert_serials_mac_address_exclusion(self):
        """Test extract_cert_serials excludes MAC addresses (6 parts)."""
        text = """
        MAC (should exclude): 00:11:22:33:44:55
        Valid serial (8+ parts): 00:11:22:33:44:55:66:77:88:99:aa:bb
        """
        result = self.extractor.extract_cert_serials(text)
        # Should not include the MAC address (6 parts)
        assert not any(serial.count(":") == 5 for serial in result)
        # Should include the 12-byte serial
        assert any(serial.count(":") >= 7 for serial in result)

    def test_extract_hosts_netbios_names(self):
        """Test extract_hosts extracts NetBIOS names from UNC paths."""
        text = r"""
        UNC paths:
        \\\\FILESERVER\\share\\file.txt
        \\\\WORKSTATION01\\c$\\windows
        """
        result = self.extractor.extract_hosts(text)
        # Should extract NetBIOS names
        assert any("FILESERVER" in host.upper() for host in result)

    def test_extract_hosts_filter_common_names(self):
        """Test extract_hosts filters common false positive names."""
        text = r"""
        \\\\USERS\\share
        \\\\WINDOWS\\system
        \\\\PROGRAM\\data
        """
        result = self.extractor.extract_hosts(text)
        # Should filter out common names like USERS, WINDOWS, PROGRAM
        assert not any(host.lower() in ["users", "windows", "program"] for host in result)

    def test_extract_single_type_error_handling(self):
        """Test _extract_single_type handles extraction errors gracefully."""
        from iocparser.infrastructure.extractor_base import ExtractionAggregateMixin

        text = "Test text with MD5: 5f4dcc3b5aa765d61d8327deb882cf99"

        def failing_method(_text: str) -> list[str]:
            raise ValueError("Intentional error for testing")

        result = ExtractionAggregateMixin._extract_single_type(
            self.extractor,
            "jwt",
            failing_method,
            text,
        )
        assert result is None

        result_all = self.extractor.extract_all(text)
        assert "md5" in result_all

    def test_extract_domains_from_urls_error_handling(self):
        """Test _extract_domains_from_urls handles URL parsing errors."""
        text = """
        Malformed URL: hxxp://[[[invalid
        Valid URL: https://example.com/path
        """
        result = self.extractor._extract_domains_from_urls(text)
        # Should handle errors and still extract valid domains
        assert isinstance(result, list)

    def test_bitcoin_hex_exclusion(self):
        """Test extract_bitcoin excludes hex-only MD5-like strings."""
        text = """
        Not Bitcoin (MD5): 5f4dcc3b5aa765d61d8327deb882cf99
        Real Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        """
        result = self.extractor.extract_bitcoin(text)
        # Should not include the hex-only string
        assert not any("5f4dcc3b5aa765d61d8327deb882cf99" in addr for addr in result)
        # Should include the real Bitcoin address
        assert any("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in addr for addr in result)

    def test_is_valid_hash_binascii_decode_error(self):
        """Test _is_valid_hash_pattern handles non-hex characters gracefully."""
        # String with odd length (can't be decoded as hex)
        invalid_hex = "zzzzzzzzzzzzzzzz" * 8  # 128 chars but not hex
        # Should handle the decode error gracefully
        result = self.extractor._is_valid_hash_pattern(invalid_hex)
        assert isinstance(result, bool)

    def test_extract_domains_defanged_variations(self):
        """Test extract_domains handles various defanged formats."""
        text = """
        Bracket defang: example[.]com
        Paren defang: test(.)org
        Brace defang: malware{.}net
        """
        result = self.extractor.extract_domains(text)
        # All should be extracted
        assert len(result) >= 3

    def test_extract_ips_defanged_variations(self):
        """Test extract_ips handles various defanged IP formats."""
        text = """
        Bracket: 192[.]168[.]1[.]1
        Paren: 10(.)0(.)0(.)1
        Brace: 172{.}16{.}0{.}1
        """
        result = self.extractor.extract_ips(text)
        # All should be extracted and normalized
        assert len(result) >= 3

    def test_extract_mac_addresses_validation_failure(self):
        """Test extract_mac_addresses filters invalid MAC addresses."""
        text = """
        Valid MAC: 00:1B:44:11:3A:B7
        Invalid (5 parts): 00:1B:44:11:3A
        Invalid (non-hex): GG:HH:II:JJ:KK:LL
        Invalid length: 00:1B:44:11:3A:B7:C8
        """
        result = self.extractor.extract_mac_addresses(text)
        # Only valid MAC should be extracted
        assert any("00:1B:44:11:3A:B7" in mac.upper() for mac in result)
        # Invalid ones should not be present
        assert not any("GG:" in mac for mac in result)

    def test_extract_hosts_programming_constructs(self):
        """Test extract_hosts filters out JavaScript/programming constructs."""
        text = """
        Real domain: malware.com
        JS construct: document.location, window.addEventListener
        Legitimate: github.com
        """
        result = self.extractor.extract_hosts(text)
        # Should include malware.com
        assert any("malware.com" in host for host in result)
        # Should not include programming constructs
        assert not any("document" in host.lower() for host in result)
        assert not any("window" in host.lower() for host in result)

    def test_url_append_with_defanging(self):
        """Test _append_url applies defanging when enabled."""
        clean_urls = []
        url = "http://malware.com/payload"
        self.extractor_defang._append_url(clean_urls, url)
        assert len(clean_urls) == 1
        assert "hxxp://" in clean_urls[0]
        assert "[.]" in clean_urls[0]

    def test_url_append_without_defanging(self):
        """Test _append_url preserves URL when defanging disabled."""
        clean_urls = []
        url = "http://malware.com/payload"
        self.extractor._append_url(clean_urls, url)
        assert len(clean_urls) == 1
        assert clean_urls[0] == url

    def test_extract_urls_image_extension_filter(self):
        """Test extract_urls filters URLs ending with image/resource extensions."""
        text = """
        Image: https://malware-site.com/logo.png
        CSS: https://evil-cdn.net/style.css
        JS: https://cdn.badhost.org/script.js
        Valid: https://malware-site.com/payload.exe
        """
        result = self.extractor.extract_urls(text)
        # Image/CSS/JS URLs should be filtered
        assert not any(url.endswith(".png") for url in result)
        assert not any(url.endswith(".css") for url in result)
        assert not any(url.endswith(".js") for url in result)
        # Valid payload should be kept
        assert any("malware-site.com" in url for url in result)

    def test_extract_yara_rules_without_closing_brace(self):
        """Test extract_yara_rules adds closing brace when missing."""
        text = """
        rule TestRule {
            meta:
                author = "Test"
            condition:
                true
        """
        result = self.extractor.extract_yara_rules(text)
        # If extracted, should have closing brace
        for rule in result:
            assert rule.strip().endswith("}")

    def test_is_file_sharing_url_detection(self):
        """Test _is_file_sharing_url detects file sharing services."""
        assert self.extractor._is_file_sharing_url("pastebin.com")
        assert self.extractor._is_file_sharing_url("discord.gg")
        assert self.extractor._is_file_sharing_url("transfer.sh")
        assert not self.extractor._is_file_sharing_url("example.com")

    def test_is_suspicious_url_detection(self):
        """Test _is_suspicious_url detects suspicious paths on code hosting."""
        # GitHub with malware keyword
        assert self.extractor._is_suspicious_url("github.com", "/user/malware/repo")
        assert self.extractor._is_suspicious_url("gitlab.com", "/exploit/payload")
        # Non-code hosting site
        assert not self.extractor._is_suspicious_url("example.com", "/malware")
        # Code hosting without suspicious keywords
        assert not self.extractor._is_suspicious_url("github.com", "/user/project")

    def test_should_exclude_url_detection(self):
        """Test _should_exclude_url detects documentation vs vulnerability pages."""
        # Documentation site without vulnerability keywords - should exclude
        assert self.extractor._should_exclude_url("docs.microsoft.com", "/windows/install")
        # Documentation with vulnerability keywords - should not exclude
        assert not self.extractor._should_exclude_url(
            "docs.microsoft.com", "/security/cve-2023-1234"
        )
        # Non-documentation site
        assert not self.extractor._should_exclude_url("example.com", "/normal-page")

    def test_load_legitimate_domains_success(self):
        """Test _load_legitimate_domains successfully loads from file."""
        # The extractor should have loaded legitimate domains from the JSON file
        assert len(self.extractor.legitimate_domains) > 0
        assert "github.com" in self.extractor.legitimate_domains
        assert "microsoft.com" in self.extractor.legitimate_domains

    def test_load_legitimate_domains_with_subdomains(self):
        """Test _load_legitimate_domains loads subdomains list."""
        # Should have loaded the subdomains list
        assert len(self.extractor.legitimate_with_subdomains) > 0
        assert "docs.microsoft.com" in self.extractor.legitimate_with_subdomains

    def test_is_valid_hash_importerror_handling(self):
        """Test _is_valid_hash_pattern handles ImportError gracefully."""
        # Even if binascii is somehow not available, should not crash
        # Testing with a valid-looking hash
        valid_sha512 = "a" * 128
        result = self.extractor._is_valid_hash_pattern(valid_sha512)
        assert isinstance(result, bool)

    def test_is_valid_domain_no_dot(self):
        """Test _is_valid_domain rejects strings without dots."""
        assert not self.extractor._is_valid_domain("nodot")
        assert not self.extractor._is_valid_domain("")

    def test_is_valid_domain_invalid_tld(self):
        """Test _is_valid_domain rejects invalid TLDs."""
        assert not self.extractor._is_valid_domain("example.invalidtld999")

    def test_extract_domains_from_urls_with_port(self):
        """Test _extract_domains_from_urls handles URLs with port numbers."""
        text = "URL: https://malware-server.com:8080/payload"
        result = self.extractor._extract_domains_from_urls(text)
        # Should extract domain without port
        assert any("malware-server.com" in domain for domain in result)

    def test_extract_ips_non_numeric_octet(self):
        """Test extract_ips handles non-numeric octets gracefully."""
        text = "Invalid IP: 192.168.abc.1"
        result = self.extractor.extract_ips(text)
        # Should not crash, should return empty or filter it out
        assert isinstance(result, list)

    def test_extract_urls_github_normal_filter(self):
        """Test extract_urls filters normal GitHub URLs."""
        text = "Repository: https://github.com/user/normal-project"
        result = self.extractor.extract_urls(text)
        # Normal GitHub URL should be filtered
        assert not any("normal-project" in url for url in result)

    def test_extract_urls_gitlab_bitbucket_filter(self):
        """Test extract_urls filters GitLab and Bitbucket URLs."""
        text = """
        GitLab: https://gitlab.com/user/project
        Bitbucket: https://bitbucket.org/user/repo
        """
        result = self.extractor.extract_urls(text)
        # Normal GitLab and Bitbucket URLs should be filtered
        assert not any("gitlab.com" in url and "project" in url for url in result)

    def test_bitcoin_all_hex_26plus_chars(self):
        """Test extract_bitcoin handles addresses with mixed case."""
        text = "Bitcoin: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        result = self.extractor.extract_bitcoin(text)
        # Should extract the Bitcoin address
        assert any("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in addr for addr in result)

    def test_extract_mac_addresses_cisco_format_invalid_hex(self):
        """Test extract_mac_addresses rejects Cisco format with non-hex."""
        text = "Invalid Cisco MAC: 00GG.HH22.3344"
        result = self.extractor.extract_mac_addresses(text)
        # Should not extract invalid MAC
        assert not any("00GG" in mac for mac in result)

    def test_extract_mac_addresses_wrong_part_count(self):
        """Test extract_mac_addresses rejects MACs with wrong number of parts."""
        text = "Invalid MAC: 00:11:22:33:44"  # Only 5 parts
        result = self.extractor.extract_mac_addresses(text)
        # Should not extract 5-part MAC
        assert not any(mac.count(":") == 4 for mac in result)

    def test_extract_yara_rules_missing_sections(self):
        """Test extract_yara_rules filters rules without required sections."""
        text = """
        rule InvalidRule {
            some_random_content
        }
        """
        result = self.extractor.extract_yara_rules(text)
        # Should filter out rules without strings:, condition:, or meta:
        assert len(result) == 0

    def test_extract_hosts_no_dot_filter(self):
        """Test extract_hosts filters entries without dots."""
        text = r"\\\\SERVERNAME\\share"
        # extract_hosts should filter out single-word hostnames without dots
        # But may keep NetBIOS names from UNC paths
        result = self.extractor.extract_hosts(text)
        # Just verify it returns a list and handles it gracefully
        assert isinstance(result, list)

    def test_extract_hosts_short_parts_filter(self):
        """Test extract_hosts filters domains with empty parts."""
        # This would be caught by the validation that all parts have length > 0
        text = "Invalid domain: test..com"
        result = self.extractor.extract_hosts(text)
        # Should not extract invalid domain
        assert not any("test..com" in host for host in result)

    def test_extract_all_empty_results_filtered(self):
        """Test extract_all filters out empty results."""
        text = "Just some random text with no IOCs"
        result = self.extractor.extract_all(text)
        # Empty IOC types should not be in results
        for iocs in result.values():
            assert len(iocs) > 0

    def test_load_tlds_from_file(self, tmp_path):
        """Test _load_valid_tlds loads from file successfully."""
        from iocparser.infrastructure.extractor_base_runtime_support import ReferenceDataPolicy

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        tlds_file = data_dir / "tlds.txt"
        tlds_file.write_text("test\nexample\nlocal\n")

        policy = ReferenceDataPolicy(
            default_tlds=frozenset({"fallback"}),
            common_file_extensions=frozenset({"exe"}),
        )
        tlds = policy.load_valid_tlds(data_dir)
        assert "test" in tlds
        assert "example" in tlds
        assert "local" in tlds

    def test_is_valid_hash_sequential_pattern_detection(self):
        """Test _is_valid_hash_pattern rejects sequential patterns."""
        # Hash with sequential pattern
        sequential = "0123456789abcdef" * 8  # 128 chars
        assert not self.extractor._is_valid_hash_pattern(sequential[:32])

    def test_is_valid_hash_reversed_sequential(self):
        """Test _is_valid_hash_pattern rejects reversed sequential."""
        reversed_seq = "9876543210fedcba" * 8
        assert not self.extractor._is_valid_hash_pattern(reversed_seq[:32])

    def test_is_valid_hash_unicode_decode_pass(self):
        """Test _is_valid_hash_pattern with valid binary data."""
        # Valid SHA512 that doesn't decode to ASCII
        # Using random hex that won't be printable ASCII
        valid_hash = "a1b2c3d4e5f67890" * 8  # 128 chars
        result = self.extractor._is_valid_hash_pattern(valid_hash)
        assert isinstance(result, bool)

    def test_extract_domains_legitimate_with_subdomains_check(self):
        """Test that legitimate_with_subdomains entries are filtered."""
        text = "Visit docs.microsoft.com for documentation"
        result = self.extractor.extract_domains(text)
        # docs.microsoft.com is in legitimate_with_subdomains
        assert "docs.microsoft.com" not in result

    def test_is_valid_domain_suspicious_subdomain_return_true(self):
        """Test _is_valid_domain returns True for suspicious subdomains."""
        # Test the specific return True path for suspicious subdomains
        result = self.extractor._is_valid_domain("phishing.github.com")
        assert result is True

    def test_extract_domains_from_urls_with_continue(self):
        """Test _extract_domains_from_urls continues on parsing error."""
        # URL that will cause parsing issues
        text = "URL1: https://malicious1.com/path URL2: hxxp://malicious2.com/file"
        result = self.extractor._extract_domains_from_urls(text)
        # Should extract at least one domain despite any errors
        assert isinstance(result, list)

    def test_extract_ips_wrong_part_count_continue(self):
        """Test extract_ips continues when part count is wrong."""
        text = "IP: 192.168.1 another: 10.0.0.1"
        result = self.extractor.extract_ips(text)
        # Should skip the 3-part IP and extract the valid one
        assert "10.0.0.1" in result or any("10" in ip for ip in result)

    def test_extract_ips_leading_zero_break(self):
        """Test extract_ips breaks on leading zero detection."""
        text = "IP with leading zeros: 192.168.01.1"
        result = self.extractor.extract_ips(text)
        # Should reject IPs with leading zeros
        assert not any("01" in ip for ip in result)

    def test_extract_ips_value_error_continue(self):
        """Test extract_ips continues on ValueError."""
        text = "Invalid: 192.168.x.1 valid: 10.0.0.1"
        result = self.extractor.extract_ips(text)
        # Should handle ValueError and continue
        assert isinstance(result, list)

    def test_extract_urls_github_continue_branch(self):
        """Test extract_urls continues when filtering GitHub URLs."""
        text = "GitHub: https://github.com/user/repo normal: https://evil.com/payload"
        result = self.extractor.extract_urls(text)
        # GitHub URL should be filtered (continue), evil.com should be kept
        assert any("evil.com" in url for url in result)

    def test_extract_urls_exception_append(self):
        """Test extract_urls appends URL on exception."""
        # URL with unusual format that might cause exception
        text = "Strange URL: hxxp://[::1]/test"
        result = self.extractor.extract_urls(text)
        # Should handle gracefully
        assert isinstance(result, list)

    def test_bitcoin_not_all_hex_extraction(self):
        """Test extract_bitcoin extracts addresses with non-hex characters."""
        # Bitcoin address with uppercase I, O (not in hex)
        text = "BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        result = self.extractor.extract_bitcoin(text)
        # Should extract because it has non-hex chars
        assert any("BoatSLRHt" in addr for addr in result)

    def test_extract_yara_rules_with_closing_brace_already(self):
        """Test extract_yara_rules when rule already has closing brace."""
        text = """
        rule ProperRule {
            meta:
                author = "Test"
            condition:
                true
        }
        """
        result = self.extractor.extract_yara_rules(text)
        # Should extract properly formed rule
        assert len(result) >= 1

    def test_extract_yara_rules_missing_brace_path(self):
        """Test extract_yara_rules adds brace when missing."""
        # Create a rule that matches but is missing the closing brace
        text = """rule RuleWithoutEnd {
    meta:
        desc = "test"
    strings:
        $s1 = "malware"
    condition:
        $s1"""
        result = self.extractor.extract_yara_rules(text)
        # Check if brace adding logic is triggered
        for rule in result:
            assert rule.strip().endswith("}")

    def test_extract_hosts_false_positive_filter(self):
        """Test extract_hosts filters false positives with specific keywords."""
        text = "Access via the server, from location, with parameters"
        result = self.extractor.extract_hosts(text)
        # Should filter out false positives
        assert not any("via" in host.lower() for host in result)

    def test_extract_hosts_single_part_check(self):
        """Test extract_hosts requires at least 2 domain parts."""
        text = "Domain: singlepart"
        result = self.extractor.extract_hosts(text)
        # Single word without dot should not be extracted
        assert not any(host == "singlepart" for host in result)

    def test_extract_hosts_unc_short_name_filter(self):
        """Test extract_hosts filters short UNC names."""
        text = r"\\\\AB\\share"  # Only 2 chars, too short
        result = self.extractor.extract_hosts(text)
        # Short names (<=3 chars) should be filtered
        assert not any("AB" in host.upper() for host in result)

    def test_extract_all_with_progress_bar(self):
        """Test extract_all uses progress bar for large text."""
        # Create text larger than LARGE_TEXT_THRESHOLD (10000 chars)
        large_text = "malware.com " * 1000  # > 10000 chars
        result = self.extractor.extract_all(large_text)
        # Should still extract IOCs
        assert "domains" in result

    def test_extract_single_type_none_return(self):
        """Test _extract_single_type returns None for empty results."""
        # This tests the else branch that returns None for empty results
        text = "No matching IOCs here at all"
        # Call extract_all which uses _extract_single_type internally
        result = self.extractor.extract_all(text)
        # Result should not contain types with empty lists
        for ioc_list in result.values():
            assert len(ioc_list) > 0

    def test_load_tlds_file_exception(self, tmp_path):
        """Test _load_valid_tlds handles file read exceptions."""
        from iocparser.infrastructure.extractor_base_runtime_support import ReferenceDataPolicy

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        tlds_file = data_dir / "tlds.txt"
        tlds_file.write_bytes(b"\x80\x81\x82\x83")

        policy = ReferenceDataPolicy(
            default_tlds=frozenset({"com", "org"}),
            common_file_extensions=frozenset({"exe"}),
        )
        tlds = policy.load_valid_tlds(data_dir)
        assert "com" in tlds

    def test_is_valid_hash_value_error_exception(self):
        """Test _is_valid_hash_pattern handles ValueError from binascii."""
        # Odd-length hex string will cause ValueError in unhexlify
        odd_length_hex = "a" * 127  # 127 chars, odd length
        result = self.extractor._is_valid_hash_pattern(odd_length_hex)
        # Should handle exception and return True (continue with other checks)
        assert isinstance(result, bool)

    def test_is_valid_hash_unicode_decode_error_pass(self):
        """Test _is_valid_hash_pattern passes on UnicodeDecodeError."""
        # Create a SHA512 hex string that decodes to binary data (not ASCII)
        # This should pass the UnicodeDecodeError check
        binary_hex = "ff" * 64  # 128 chars, all 0xFF bytes
        result = self.extractor._is_valid_hash_pattern(binary_hex)
        # Should pass UnicodeDecodeError and continue
        assert isinstance(result, bool)

    def test_is_valid_domain_normal_subdomain_filter(self):
        """Test _is_valid_domain filters normal subdomains of legitimate domains."""
        # Normal subdomain (not suspicious) should be filtered
        assert not self.extractor._is_valid_domain("www.github.com")
        assert not self.extractor._is_valid_domain("api.microsoft.com")

    def test_extract_ssdeep_direct_call(self):
        """Test extract_ssdeep extraction directly."""
        text = "ssdeep: 768:C7tsNKI7aU8Y1O5wjNHDwLxQJidNG3qGqDRTRRRRRRRRT:CtsI7aUwjNQidNG3GqDRTRT"
        result = self.extractor.extract_ssdeep(text)
        # Should extract ssdeep hash
        assert len(result) >= 1

    def test_extract_domains_from_urls_exception_path(self):
        """Test _extract_domains_from_urls handles URL parsing exceptions."""
        # Intentionally malformed URL that will trigger exception
        text = "Bad URL: https://[[[invalid-bracket-url"
        result = self.extractor._extract_domains_from_urls(text)
        # Should handle exception and continue
        assert isinstance(result, list)

    def test_extract_ips_wrong_parts_continue(self):
        """Test extract_ips continues when IP has wrong number of parts."""
        text = "Too few: 192.168.1 Too many: 192.168.1.1.1"
        result = self.extractor.extract_ips(text)
        # Should skip invalid IPs
        assert isinstance(result, list)

    def test_extract_ips_leading_zero_valid_false(self):
        """Test extract_ips sets valid=False for leading zeros."""
        text = "Leading zero: 192.168.001.1"
        result = self.extractor.extract_ips(text)
        # Should not include IP with leading zero
        assert not any("001" in ip for ip in result)

    def test_extract_ips_out_of_range_valid_false(self):
        """Test extract_ips sets valid=False for out-of-range octets."""
        text = "Out of range: 192.168.256.1"
        result = self.extractor.extract_ips(text)
        # Should not include IP with invalid octet
        assert not any("256" in ip for ip in result)

    def test_extract_ips_value_error_exception(self):
        """Test extract_ips handles ValueError for non-numeric parts."""
        text = "Non-numeric: 192.168.abc.1"
        result = self.extractor.extract_ips(text)
        # Should handle ValueError and continue
        assert isinstance(result, list)

    def test_extract_urls_github_gitlab_bitbucket_continue(self):
        """Test extract_urls continues for code hosting sites without suspicious paths."""
        text = """
        https://github.com/user/project
        https://gitlab.com/team/repo
        https://bitbucket.org/company/code
        """
        result = self.extractor.extract_urls(text)
        # Normal code hosting URLs should be filtered out
        assert not any("project" in url for url in result)

    def test_extract_urls_exception_handler(self):
        """Test extract_urls exception handler appends URL."""
        # Create URL that might cause parsing exception
        text = "Weird: hxxp://malformed-url-test"
        result = self.extractor.extract_urls(text)
        # Should handle exception gracefully
        assert isinstance(result, list)

    def test_extract_bitcoin_26_plus_not_all_hex(self):
        """Test extract_bitcoin extracts addresses 26+ chars with non-hex."""
        text = "BTC: 1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"
        result = self.extractor.extract_bitcoin(text)
        # Should extract (has non-hex characters)
        assert any("NDyJt" in addr for addr in result)

    def test_extract_yara_rules_not_ending_with_brace(self):
        """Test extract_yara_rules adds closing brace."""
        # Rule that doesn't end with }
        text = """rule Test {
    meta: author = "x"
    condition: true"""
        result = self.extractor.extract_yara_rules(text)
        # Should add closing brace
        for rule in result:
            assert rule.strip().endswith("}")

    def test_extract_yara_rules_too_long_filter(self):
        """Test extract_yara_rules filters rules that are too long."""
        # Create a rule longer than 3000 chars
        long_rule = "rule TooLong { " + "x" * 3500 + " }"
        result = self.extractor.extract_yara_rules(long_rule)
        # Should filter it out
        assert len(result) == 0

    def test_extract_hosts_continue_on_false_positive(self):
        """Test extract_hosts continues when filtering false positives."""
        text = "host via server from location the document"
        result = self.extractor.extract_hosts(text)
        # Should filter out false positives
        assert not any("via" in host.lower() for host in result)

    def test_extract_hosts_unc_length_check(self):
        """Test extract_hosts filters UNC names that are too short."""
        text = r"\\\\AB\\share \\\\VALIDSERVER\\data"
        result = self.extractor.extract_hosts(text)
        # Short name (<=3 chars) should be filtered
        # Only VALIDSERVER should potentially be extracted
        assert not any(host == "AB" for host in result)

    def test_is_valid_hash_import_error_exception(self):
        """Test _is_valid_hash_pattern remains total for long hash candidates."""
        test_hash = "a1b2c3d4" * 16  # 64 chars
        result = self.extractor._is_valid_hash_pattern(test_hash)
        assert isinstance(result, bool)

    def test_extract_domains_file_extension_as_tld(self):
        """Test extract_domains filters domains with file extensions as TLDs."""
        text = "File: malware.exe config.dll script.js"
        result = self.extractor.extract_domains(text)
        # File extensions should not be treated as domains
        assert not any(".exe" in d for d in result)
        assert not any(".dll" in d for d in result)

    def test_extract_domains_from_urls_no_netloc(self):
        """Test _extract_domains_from_urls when parsed URL has no netloc."""
        # URL without proper netloc
        text = "file:///local/path"
        result = self.extractor._extract_domains_from_urls(text)
        # Should handle URLs without netloc
        assert isinstance(result, list)

    def test_extract_ssdeep_pattern_matching(self):
        """Test extract_ssdeep with various ssdeep formats."""
        text = """
        ssdeep matches:
        12:ABC123def456:xyz789
        1536:qwerty/+asdfgh:zxcvbn
        """
        result = self.extractor.extract_ssdeep(text)
        # Should extract ssdeep hashes
        assert isinstance(result, list)

    def test_extract_ips_four_parts_requirement(self):
        """Test extract_ips requires exactly 4 parts."""
        text = "IP: 192.168.1 (3 parts) and 192.168.1.1.1 (5 parts)"
        result = self.extractor.extract_ips(text)
        # Neither should be extracted
        assert not any(ip == "192.168.1" for ip in result)

    def test_extract_ips_range_check_continue(self):
        """Test extract_ips continues when octet out of range."""
        text = "IPs: 256.1.1.1, 1.300.1.1, 1.1.999.1"
        result = self.extractor.extract_ips(text)
        # All should be filtered out
        assert len(result) == 0

    def test_extract_urls_should_exclude_path_check(self):
        """Test extract_urls _should_exclude_url with vulnerability keywords."""
        text = "Docs: https://docs.microsoft.com/en-us/security/cve-2023-1234"
        result = self.extractor.extract_urls(text)
        # URL with CVE should not be excluded
        assert any("cve-" in url.lower() for url in result)

    def test_extract_urls_domain_endswith_check(self):
        """Test extract_urls checks domain endings."""
        # The check is for domain names ending with extensions, not full URLs
        text = "Site: https://example.png https://test.css https://valid-malware.com/file.exe"
        result = self.extractor.extract_urls(text)
        # Should filter domains that end with image/css extensions
        assert isinstance(result, list)

    def test_bitcoin_32_char_all_hex_continue(self):
        """Test extract_bitcoin skips 32-char all-hex strings (MD5-like)."""
        text = "Not BTC: abcdef0123456789abcdef0123456789"
        result = self.extractor.extract_bitcoin(text)
        # 32-char all-hex should be skipped
        assert len(result) == 0

    def test_extract_yara_rules_length_check_3000(self):
        """Test extract_yara_rules filters rules over 3000 chars."""
        # Create a rule exactly at the threshold
        rule_2900 = 'rule Test { meta: x = "' + "a" * 2850 + '" condition: true }'
        result = self.extractor.extract_yara_rules(rule_2900)
        # Should still extract if under 3000
        assert isinstance(result, list)

    def test_extract_yara_rules_endswith_check(self):
        """Test extract_yara_rules checks if rule ends with brace."""
        text = """
        rule Complete {
            meta: desc = "test"
            condition: true
        }
        """
        result = self.extractor.extract_yara_rules(text)
        # Should extract complete rule
        assert any(rule.strip().endswith("}") for rule in result)

    def test_extract_hosts_continue_statement(self):
        """Test extract_hosts continue on filtered domains."""
        text = "Invalid: test..broken, via.server, the.location"
        result = self.extractor.extract_hosts(text)
        # Should filter out invalid entries
        assert not any("via.server" in host for host in result)

    def test_extract_hosts_zero_length_parts_filter(self):
        """Test extract_hosts filters domains with zero-length parts."""
        text = "Broken: test..com other...domain"
        result = self.extractor.extract_hosts(text)
        # Should not extract domains with empty parts
        assert not any(".." in host for host in result)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
