#!/usr/bin/env python3

"""
Enhanced module for extracting indicators of compromise (IOCs) from text.
Includes additional IOC types and improved extraction methods.

Author: Marc Rivero | @seifreed
"""

import json
import re
import urllib.parse
from collections.abc import Callable, Iterable
from pathlib import Path
from re import Pattern
from typing import (
    ClassVar,
    cast,
)

from tqdm import tqdm

from iocparser.modules.logger import get_logger

# Constants for validation
MIN_HASH_UNIQUE_CHARS = 4
MAX_DOMAIN_LENGTH = 253
MAX_DOMAIN_PART_LENGTH = 63
IPv4_PARTS_COUNT = 4
IPv4_MAX_OCTET = 255
MIN_HOSTNAME_LENGTH = 3
LARGE_TEXT_THRESHOLD = 10000

logger = get_logger(__name__)


class IOCExtractor:
    """Enhanced class for extracting different types of IOCs from text."""

    FILE_SHARING_SITES: ClassVar[set[str]] = {
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "gist.github.com",
        "drive.google.com",
        "docs.google.com",
        "dropbox.com",
        "box.com",
        "mediafire.com",
        "mega.nz",
        "wetransfer.com",
        "sendspace.com",
        "discord.com",
        "discord.gg",
        "telegram.me",
        "t.me",
        "transfer.sh",
        "file.io",
        "anonfiles.com",
        "bayfiles.com",
    }

    SUSPICIOUS_PATH_KEYWORDS: ClassVar[list[str]] = [
        "malware",
        "exploit",
        "payload",
        "shellcode",
        "backdoor",
        "c2",
        "c&c",
        "rat",
        "trojan",
        "ransomware",
        "crypter",
        "loader",
        "dropper",
        "injector",
        "rootkit",
        "keylogger",
        "stealer",
        "miner",
        "botnet",
        "virus",
        "worm",
        "hack",
        "crack",
        "keygen",
        "poc",
        "cve-",
        "vulnerability",
        "pentest",
        "redteam",
        "bypass",
        "mimikatz",
        "cobalt",
        "empire",
        "metasploit",
        "dsefix",
    ]

    DOCUMENTATION_DOMAINS: ClassVar[list[str]] = [
        "docs.microsoft.com",
        "learn.microsoft.com",
        "support.microsoft.com",
        "developer.apple.com",
        "support.apple.com",
        "help.apple.com",
        "developers.google.com",
        "support.google.com",
        "cloud.google.com/docs",
        "docs.aws.amazon.com",
        "docs.oracle.com",
        "docs.python.org",
        "developer.mozilla.org",
        "stackoverflow.com",
        "serverfault.com",
    ]

    def __init__(self, defang: bool = True) -> None:
        """
        Initialize the extractor.

        Args:
            defang: If True, performs defanging on the results
        """
        self.defang = defang

        # Load valid TLDs
        self.valid_tlds: set[str] = self._load_valid_tlds()

        # Load legitimate domains from JSON file
        self.legitimate_domains: set[str] = set()
        self.legitimate_with_subdomains: set[str] = set()
        self._load_legitimate_domains()

        # Define regex patterns for all IOC types
        self.patterns: dict[str, Pattern[str]] = {
            # Hash patterns - more flexible to catch hashes in various contexts
            "md5": re.compile(r"(?:MD5|md5)\s*:?\s*([a-fA-F0-9]{32})|\b([a-fA-F0-9]{32})\b"),
            "sha1": re.compile(
                r"(?:SHA-1|SHA1|sha1)\s*:?\s*([a-fA-F0-9]{40})|\b([a-fA-F0-9]{40})\b",
            ),
            "sha256": re.compile(
                r"(?:SHA-256|SHA256|sha256)\s*:?\s*([a-fA-F0-9]{64})|\b([a-fA-F0-9]{64})\b",
            ),
            "sha512": re.compile(
                r"(?:SHA-512|SHA512|sha512)\s*:?\s*([a-fA-F0-9]{128})|"
                r"(?:^|\s)([a-fA-F0-9]{128})(?:\s|$)",
            ),
            "ssdeep": re.compile(r"\b\d{2,}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\b"),
            "imphash": re.compile(r"\b[a-fA-F0-9]{32}\b"),  # Same as MD5 but context-dependent
            # Network indicators
            "domains": re.compile(
                r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b|"
                r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\(\.\)|\{\.\}|\.)){1,}"
                r"[a-zA-Z]{2,63})\b",
            ),
            "ips": re.compile(
                # Match potential IPs - we'll validate octets later
                # Handles both normal and defanged formats
                r"\b\d{1,3}(?:[\[\(\{]?\.[\]\)\}]?\d{1,3}){3}\b",
            ),
            "ipv6": re.compile(
                r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?=\s|$)|"  # Full format
                r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?=\s|$)|"  # Compressed
                r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{1,4}(?=\s|$)|"  # xxxx::xxxx
                r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:)+::(?=\s|$)|"  # xxxx:: (ending)
                r"(?:^|(?<=\s))::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?=\s|$)|"  # ::xxxx
                r"(?:^|(?<=\s))::1(?=\s|$)|(?:^|(?<=\s))::(?=\s|$)|"  # Special cases ::1 and ::
                r"(?:^|(?<=\s))::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?=\s|$)",  # IPv4-mapped
            ),
            "urls": re.compile(
                r"\b(?:https?|hxxps?|h\[\.\]ttps?|s?ftp)://"
                r"(?!DOMAIN_NAME|IP:|\*\.|localhost|example\.)"
                r"[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]"
                r"(?:\.[a-zA-Z]{2,63})?(?::[0-9]{1,5})?"
                r"(?:/[-a-zA-Z0-9()@:%_\+.~#?&/=]*)?",
            ),
            "mac_addresses": re.compile(
                r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|"
                r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b",
            ),
            # Cryptocurrency
            "bitcoin": re.compile(
                r"\b(bc1[a-zA-HJ-NP-Z0-9]{39,59}|[13][a-zA-HJ-NP-Z0-9]{25,34})\b"
            ),
            "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
            "monero": re.compile(r"\b4[0-9AB][a-zA-Z0-9]{93}\b"),
            # Email and communication
            "emails": re.compile(
                r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*@"
                r"[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,63}\b",
            ),
            # Vulnerabilities and threats
            "cves": re.compile(r"\b(CVE-[0-9]{4}-[0-9]{4,7})\b", re.IGNORECASE),
            "mitre_attack": re.compile(r"\b(T[0-9]{4}(?:\.[0-9]{3})?)\b"),
            # Windows artifacts
            "registry": re.compile(
                r"\b((?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|"
                r"HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|"
                r"HKEY_CURRENT_CONFIG|HKCC)\\[\\A-Za-z0-9-_\s]+?)(?=\s|$)",
            ),
            "mutex": re.compile(
                r"\b(?:Global\\|Local\\)?[A-Za-z0-9][A-Za-z0-9_\-]{2,}(?:Mutex|MUTEX)\b|"
                r"\bMutex:[A-Za-z0-9_\-]+\b",
            ),
            "service_names": re.compile(
                r"\b(?:Service|SERVICE):\s*([A-Za-z0-9][A-Za-z0-9_\-]{2,})\b|"
                r"\b([A-Za-z0-9][A-Za-z0-9_\-]{2,})(?:Service|Svc)\b",
            ),
            "named_pipes": re.compile(r"\\\\\.\\pipe\\[A-Za-z0-9_\-]+"),
            # File indicators
            "filenames": re.compile(
                r"\b([A-Za-z0-9][A-Za-z0-9-_\.]{2,}\."
                r"(?:exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|"
                r"zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif|"
                r"ps1|vbs|wsf|hta|cmd|com|lnk|ini|inf|reg))\b",
                re.IGNORECASE,
            ),
            "filepaths": re.compile(
                r"(?:"
                r'(?:%[A-Z_]+%\\|[A-Za-z]:\\)(?:[^\s<>:"/|?*\r\n\\]+\\)*[^\s<>:"/|?*\r\n\\]+(?:\.[A-Za-z0-9]{1,10})?(?=[\s"\u201c\u201d,;]|$)|'
                r'/(?:usr|bin|etc|var|tmp|home|opt|proc|sys|lib|dev)/(?:[A-Za-z0-9-_\.]+/)*[A-Za-z0-9-_\.]+(?=[\s"\u201c\u201d,;]|$)'
                r")",
                re.IGNORECASE,
            ),
            # User agents
            "user_agents": re.compile(
                r"User-Agent:\s*([^\r\n]+)|"
                r"Mozilla/[0-9\.]+\s+\([^)]+\)[^\r\n]*",
            ),
            # YARA rules - pattern that handles nested content properly
            "yara": re.compile(r"rule\s+\w+\s*\{(?:[^{}]|\{[^}]*\})*\}", re.DOTALL),
            # AS numbers
            "asn": re.compile(r"\bAS[0-9]{1,10}\b"),
            # JWT tokens
            "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
            # Certificate serial numbers
            "cert_serials": re.compile(
                r"\b([a-fA-F0-9]{2}(?::[a-fA-F0-9]{2}){7,31})\b|"  # Colon-separated (8-32 bytes)
                r"(?:serial|certificate|cert|thumbprint)[\s:]+([a-fA-F0-9]{16,64})\b"  # Hex with context
            ),
        }

        # Common file extensions
        self.common_file_extensions: set[str] = {
            "exe",
            "dll",
            "sys",
            "cmd",
            "bat",
            "ps1",
            "vbs",
            "js",
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "txt",
            "jpg",
            "jpeg",
            "png",
            "gif",
            "bmp",
            "zip",
            "rar",
            "7z",
            "gz",
            "tar",
            "pif",
            "scr",
            "msi",
            "jar",
            "py",
            "pyc",
            "pyo",
            "php",
            "asp",
            "aspx",
            "jsp",
            "htm",
            "html",
            "css",
            "json",
            "xml",
            "reg",
            "ini",
            "cfg",
            "log",
            "tmp",
            "dat",
            "db",
            "sqlite",
            "iso",
            "img",
            "vhd",
            "vmdk",
        }

    def _load_valid_tlds(self) -> set[str]:
        """
        Load the list of valid TLDs.

        Returns:
            Set of valid TLDs
        """
        # Common TLDs
        common_tlds = {
            "com",
            "org",
            "net",
            "edu",
            "gov",
            "mil",
            "int",
            "info",
            "biz",
            "name",
            "pro",
            "museum",
            "aero",
            "coop",
            "jobs",
            "travel",
            "mobi",
            "asia",
            "tel",
            "xxx",
            "post",
            "cat",
            "arpa",
            "top",
            "xyz",
            "club",
            "online",
            "site",
            "shop",
            "app",
            "blog",
            "dev",
            "art",
            "web",
            "cloud",
            "page",
            "store",
            "host",
            "tech",
            "space",
            "live",
            "news",
            "io",
            "co",
            "me",
            "tv",
            "us",
            "uk",
            "ru",
            "fr",
            "de",
            "jp",
            "cn",
            "au",
            "ca",
            "in",
            "it",
            "nl",
            "se",
            "no",
            "fi",
            "dk",
            "ch",
            "at",
            "be",
            "es",
            "pt",
            "br",
            "mx",
            "ar",
            "cl",
            "pe",
            "ve",
            "za",
            "pl",
            "cz",
            "gr",
            "hu",
            "ro",
            "ua",
            "by",
            "kz",
            "th",
            "sg",
            "my",
            "ph",
            "vn",
            "id",
            "tr",
            "il",
            "ae",
            "sa",
            "ir",
            "pk",
            "eg",
            "ng",
            "kr",
            "tw",
            "hk",
            "mo",
            "eu",
            "nz",
            "ai",
            "gg",
            "im",
            "je",
        }

        # Try to load from file
        tlds_file = Path(__file__).parent / "data" / "tlds.txt"
        if tlds_file.exists():
            try:
                with tlds_file.open(encoding="utf-8") as f:
                    return {line.strip().lower() for line in f if line.strip()}
            except Exception:
                logger.debug("Failed to load TLD list from file")

        return common_tlds

    def _load_legitimate_domains(self) -> None:
        """Load legitimate domains from JSON file."""
        domains_file = Path(__file__).parent / "data" / "legitimate_domains.json"
        if domains_file.exists():
            try:
                with domains_file.open(encoding="utf-8") as f:
                    data = cast("dict[str, list[str]]", json.load(f))
                    self.legitimate_domains = set(data.get("legitimate_domains", []))
                    self.legitimate_with_subdomains = set(
                        data.get("legitimate_with_subdomains", [])
                    )
                    return
            except Exception:
                logger.debug("Failed to load legitimate domains from file")

        # Fallback to empty sets - will use hardcoded values in _is_valid_domain
        self.legitimate_domains = set()
        self.legitimate_with_subdomains = set()

    def _extract_pattern(
        self,
        text: str,
        pattern_name: str,
    ) -> list[str]:
        """
        Extract matches for a specific pattern.

        Args:
            text: Text to search in
            pattern_name: Name of the pattern to use

        Returns:
            List of matched strings
        """
        if pattern_name not in self.patterns:
            return []

        pattern = self.patterns[pattern_name]
        matches: list[str | tuple[str, ...]] = pattern.findall(text)

        # Clean up matches
        clean_matches: list[str] = []
        for match in matches:
            if isinstance(match, tuple):
                # Find first non-empty match in tuple
                for m in match:
                    if m:
                        clean_matches.append(m)
                        break
            elif match:
                clean_matches.append(match)

        return list(set(clean_matches))  # Remove duplicates

    def _is_valid_hash_pattern(self, hash_string: str) -> bool:
        """
        Check if a hash string has a valid pattern.

        Args:
            hash_string: Hash string to validate

        Returns:
            True if valid pattern, False otherwise
        """
        # Check for repeated characters (like all zeros or all f's)
        if len(set(hash_string.lower())) < MIN_HASH_UNIQUE_CHARS:
            return False

        # Check for sequential patterns
        if any(
            pattern in hash_string.lower()
            for pattern in [
                "0123456789",
                "abcdef",
                "fedcba",
                "9876543210",
            ]
        ):
            return False

        # Additional checks for long hashes (SHA512)
        if len(hash_string) >= 64:
            # Check for obvious text patterns in hex-decoded form
            try:
                import binascii

                decoded = binascii.unhexlify(hash_string)

                # Check for common file signatures that indicate it's not a hash
                if decoded.startswith((b"MZ", b"PK", b"7z", b"\x89PNG", b"\xff\xd8\xff")):
                    return False

                # Check for readable ASCII text (likely encoded strings, not hashes)
                try:
                    text = decoded.decode("ascii", errors="strict")
                    # If more than 50% are printable ASCII chars, likely not a hash
                    printable_chars = sum(1 for c in text if 32 <= ord(c) <= 126 or c in "\t\n\r")
                    if printable_chars / len(text) > 0.5:
                        return False
                except UnicodeDecodeError:
                    pass  # Good, binary data as expected for a hash

            except (ValueError, ImportError):
                pass  # If hex decode fails, continue with other checks

        return True

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate if a string is a valid domain.

        Args:
            domain: Domain string to validate

        Returns:
            True if valid domain, False otherwise
        """
        if not domain or "." not in domain:
            return False

        # Check TLD
        parts = domain.lower().split(".")
        tld = parts[-1]

        if tld not in self.valid_tlds:
            return False

        # Check if it's not a file extension
        if tld in self.common_file_extensions:
            return False

        # Exclude JavaScript/programming constructs
        programming_keywords = {
            "document",
            "window",
            "console",
            "function",
            "addEventListener",
            "getElementById",
            "querySelector",
            "prototype",
            "constructor",
            "toString",
            "valueOf",
            "typeof",
            "instanceof",
            "undefined",
            "gform",
            "jquery",
            "angular",
            "react",
            "vue",
        }

        # Check if any part is a programming keyword
        for part in parts:
            if part.lower() in programming_keywords:
                return False

        domain_lower = domain.lower()

        # If it's a known legitimate domain, exclude it
        if (
            domain_lower in self.legitimate_domains
            or domain_lower in self.legitimate_with_subdomains
        ):
            return False

        # If it's a subdomain of a legitimate domain but looks suspicious, keep it
        # For example: malware.github.com or c2.microsoft.com would be kept
        for legit in self.legitimate_domains:
            if domain_lower.endswith("." + legit):
                # Check if the subdomain part looks suspicious
                subdomain = domain_lower.replace("." + legit, "")
                suspicious_subdomain_keywords = [
                    "malware",
                    "c2",
                    "payload",
                    "evil",
                    "bad",
                    "attack",
                    "exploit",
                    "trojan",
                    "virus",
                    "worm",
                    "botnet",
                    "phishing",
                    "scam",
                    "backdoor",
                    "rootkit",
                    "keylogger",
                    "ransomware",
                    "crypter",
                ]
                if any(keyword in subdomain.lower() for keyword in suspicious_subdomain_keywords):
                    return True  # Keep suspicious subdomains
                return False  # Exclude normal subdomains of legitimate sites

        # Check domain length
        domain_length_valid = len(domain) <= MAX_DOMAIN_LENGTH
        parts_length_valid = all(len(part) <= MAX_DOMAIN_PART_LENGTH for part in parts)

        # Must have at least 2 parts (subdomain.tld)
        has_min_parts = len(parts) >= 2

        return domain_length_valid and parts_length_valid and has_min_parts

    def _defang_dotted(self, value: str) -> str:
        """
        Defang a dotted value (domain or IP) by replacing dots with [.].

        Args:
            value: Domain or IP address to defang

        Returns:
            Defanged value
        """
        return value.replace(".", "[.]")

    def _defang_url(self, url: str) -> str:
        """
        Defang a URL.

        Args:
            url: URL to defang

        Returns:
            Defanged URL
        """
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        return self._defang_dotted(defanged)

    def _clean_defanged(self, value: str) -> str:
        """
        Clean defanged notation from a value (domain or IP).

        Args:
            value: Defanged value to clean

        Returns:
            Cleaned value with standard dots
        """
        return value.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")

    def _extract_domains_from_urls(self, text: str) -> list[str]:
        """
        Extract domains from URLs in text.

        Args:
            text: Text to search in

        Returns:
            List of domains
        """
        urls = self._extract_pattern(text, "urls")
        domains = []

        for url in urls:
            # Clean defanged URLs
            clean_url = url.replace("[.]", ".").replace("hxxp", "http")

            try:
                parsed = urllib.parse.urlparse(clean_url)
                if parsed.netloc:
                    # Remove port if present
                    domain = parsed.netloc.split(":")[0]
                    if self._is_valid_domain(domain):
                        domains.append(domain)
            except Exception as e:
                logger.debug(f"Failed to parse URL {clean_url}: {e}")
                continue

        return domains

    def _extract_hash(self, text: str, hash_type: str) -> list[str]:
        """
        Extract hashes of a specific type from text.

        Args:
            text: Text to search in
            hash_type: Type of hash pattern to use (md5, sha1, sha256, sha512)

        Returns:
            List of valid hashes
        """
        candidates = self._extract_pattern(text, hash_type)
        return [h for h in candidates if self._is_valid_hash_pattern(h)]

    # Extraction methods for each IOC type
    def extract_md5(self, text: str) -> list[str]:
        """Extract MD5 hashes from text."""
        return self._extract_hash(text, "md5")

    def extract_sha1(self, text: str) -> list[str]:
        """Extract SHA1 hashes from text."""
        return self._extract_hash(text, "sha1")

    def extract_sha256(self, text: str) -> list[str]:
        """Extract SHA256 hashes from text."""
        return self._extract_hash(text, "sha256")

    def extract_sha512(self, text: str) -> list[str]:
        """Extract SHA512 hashes from text."""
        return self._extract_hash(text, "sha512")

    def extract_ssdeep(self, text: str) -> list[str]:
        """Extract ssdeep hashes from text."""
        return self._extract_pattern(text, "ssdeep")

    def extract_domains(self, text: str) -> list[str]:
        """Extract domain names from text."""
        domains = self._extract_pattern(text, "domains")
        domains_from_urls = self._extract_domains_from_urls(text)

        all_domains = domains + domains_from_urls
        clean_domains = []

        for domain in all_domains:
            clean_domain = self._clean_defanged(domain)

            if self._is_valid_domain(clean_domain):
                if self.defang:
                    clean_domain = self._defang_dotted(clean_domain)
                clean_domains.append(clean_domain)

        return list(set(clean_domains))

    def extract_ips(self, text: str) -> list[str]:
        """Extract IPv4 addresses from text."""
        ips = self._extract_pattern(text, "ips")
        clean_ips = []

        for ip in ips:
            clean_ip = self._clean_defanged(ip)
            # Handle additional defang patterns like [.] with brackets
            clean_ip = re.sub(r"[\[\(\{]\.[\]\)\}]", ".", clean_ip)

            # Validate IP
            parts = clean_ip.split(".")
            if len(parts) != IPv4_PARTS_COUNT:
                continue

            try:
                valid = True
                for part in parts:
                    # Check for leading zeros (except "0" itself)
                    if len(part) > 1 and part[0] == "0":
                        valid = False
                        break
                    # Check range 0-255
                    num = int(part)
                    if not (0 <= num <= IPv4_MAX_OCTET):
                        valid = False
                        break

                if valid:
                    if self.defang:
                        clean_ip = self._defang_dotted(clean_ip)
                    clean_ips.append(clean_ip)
            except ValueError:
                continue

        return list(set(clean_ips))

    def extract_ipv6(self, text: str) -> list[str]:
        """Extract IPv6 addresses from text."""
        return self._extract_pattern(text, "ipv6")

    def _is_file_sharing_url(self, domain: str) -> bool:
        """Check if domain belongs to a file sharing service."""
        return any(site in domain for site in self.FILE_SHARING_SITES)

    def _is_suspicious_url(self, domain: str, path: str) -> bool:
        """Check if URL path contains suspicious keywords for code hosting sites."""
        if not ("github.com" in domain or "gitlab.com" in domain or "bitbucket.org" in domain):
            return False
        return any(keyword in path for keyword in self.SUSPICIOUS_PATH_KEYWORDS)

    def _should_exclude_url(self, domain: str, path: str) -> bool:
        """Determine if URL should be excluded from results."""
        if not any(doc_domain in domain for doc_domain in self.DOCUMENTATION_DOMAINS):
            return False

        suspicious_terms = ["exploit", "vulnerability", "cve-", "poc", "bypass"]
        return not any(term in path for term in suspicious_terms)

    def _append_url(self, clean_urls: list[str], url: str) -> None:
        """Append URL to list, applying defanging if enabled."""
        if self.defang:
            clean_urls.append(self._defang_url(url))
        else:
            clean_urls.append(url)

    def extract_urls(self, text: str) -> list[str]:
        """Extract URLs from text, intelligently filtering based on context."""
        urls = self._extract_pattern(text, "urls")
        clean_urls: list[str] = []

        for url in urls:
            try:
                clean_for_parse = self._clean_defanged(url).replace("hxxp", "http")
                parsed = urllib.parse.urlparse(clean_for_parse)
                domain = parsed.netloc.lower()
                path = parsed.path.lower()

                if self._is_file_sharing_url(domain) or self._is_suspicious_url(domain, path):
                    self._append_url(clean_urls, url)
                elif (
                    "github.com" in domain
                    or "gitlab.com" in domain
                    or "bitbucket.org" in domain
                    or self._should_exclude_url(domain, path)
                ):
                    continue
                elif domain and not domain.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                    self._append_url(clean_urls, url)
            except Exception:
                self._append_url(clean_urls, url)

        return list(set(clean_urls))

    def extract_emails(self, text: str) -> list[str]:
        """Extract email addresses from text."""
        emails = self._extract_pattern(text, "emails")

        if self.defang:
            emails = [email.replace("@", "[@]").replace(".", "[.]") for email in emails]

        return list(set(emails))

    def extract_bitcoin(self, text: str) -> list[str]:
        """Extract Bitcoin addresses from text."""
        potential_addresses = self._extract_pattern(text, "bitcoin")
        validated_addresses = []

        for addr in potential_addresses:
            # Skip if it's clearly a hex-only MD5 (32 chars, all hex)
            if len(addr) == 32 and all(c in "0123456789abcdefABCDEF" for c in addr):
                continue
            # Bitcoin addresses should have mixed case or contain non-hex chars
            if len(addr) >= 26 and (not all(c in "0123456789abcdefABCDEF" for c in addr)):
                validated_addresses.append(addr)

        return validated_addresses

    def extract_ethereum(self, text: str) -> list[str]:
        """Extract Ethereum addresses from text."""
        return self._extract_pattern(text, "ethereum")

    def extract_monero(self, text: str) -> list[str]:
        """Extract Monero addresses from text."""
        return self._extract_pattern(text, "monero")

    def extract_cves(self, text: str) -> list[str]:
        """Extract CVE identifiers from text."""
        return self._extract_pattern(text, "cves")

    def extract_mitre_attack(self, text: str) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from text."""
        return self._extract_pattern(text, "mitre_attack")

    def extract_registry(self, text: str) -> list[str]:
        """Extract Windows registry keys from text."""
        return self._extract_pattern(text, "registry")

    def extract_mutex(self, text: str) -> list[str]:
        """Extract mutex names from text."""
        return self._extract_pattern(text, "mutex")

    def extract_service_names(self, text: str) -> list[str]:
        """Extract Windows service names from text."""
        matches = self._extract_pattern(text, "service_names")
        return list(set(matches))

    def extract_named_pipes(self, text: str) -> list[str]:
        """Extract Windows named pipes from text."""
        return self._extract_pattern(text, "named_pipes")

    def extract_filenames(self, text: str) -> list[str]:
        """Extract filenames from text, only real files with extensions."""
        matches = self._extract_pattern(text, "filenames")

        # Only keep matches that are actual full filenames (name + extension)
        real_filenames = []
        for match in matches:
            # Matches should always be strings from our pattern
            if isinstance(match, str) and "." in match and len(match) > 4:
                real_filenames.append(match)

        # Common legitimate processes to exclude
        legitimate_processes = {
            "svchost.exe",
            "explorer.exe",
            "winlogon.exe",
            "csrss.exe",
            "smss.exe",
            "lsass.exe",
            "services.exe",
            "spoolsv.exe",
            "taskhost.exe",
            "dwm.exe",
            "userinit.exe",
            "logonui.exe",
            "wininit.exe",
            "kernel32.dll",
            "ntdll.dll",
            "user32.dll",
            "notepad.exe",
            "calc.exe",
            "cmd.exe",
            "powershell.exe",
            "conhost.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "chrome.exe",
            "firefox.exe",
            "iexplore.exe",
            "msiexec.exe",
        }

        # Filter out legitimate processes
        filtered_matches = [
            match for match in real_filenames if match.lower() not in legitimate_processes
        ]

        return list(set(filtered_matches))

    def extract_filepaths(self, text: str) -> list[str]:
        """Extract file paths from text with validation."""
        raw_paths = self._extract_pattern(text, "filepaths")

        # Filter and clean paths
        valid_paths = []
        for path in raw_paths:
            # Clean up the path
            clean_path = path.strip()

            # Must be reasonable length and structure
            if (
                len(clean_path) >= 10
                and len(clean_path) < 300
                and ("\\" in clean_path or "/" in clean_path)
                and not any(
                    word in clean_path.lower()
                    for word in [
                        "folder on the",
                        "uploaded to",
                        "artifacts were",
                        "initially",
                    ]
                )
            ):
                # Clean up and validate path
                clean_part = clean_path.rstrip('",;\'"').strip()

                # Check if it's a valid Windows path (drive letter or env var)
                if (":\\" in clean_part or clean_part.startswith("%")) or (
                    clean_part.startswith("/") and len(clean_part) > 5
                ):
                    valid_paths.append(clean_part)

        return list(set(valid_paths))

    def extract_mac_addresses(self, text: str) -> list[str]:
        """Extract MAC addresses from text."""
        candidates = self._extract_pattern(text, "mac_addresses")
        valid_macs = []

        for mac in candidates:
            # Handle Cisco format (0011.2233.4455)
            if "." in mac and len(mac.replace(".", "")) == 12:
                # Convert Cisco format to standard
                hex_only = mac.replace(".", "")
                if all(c in "0123456789abcdefABCDEF" for c in hex_only):
                    formatted = ":".join([hex_only[i : i + 2] for i in range(0, 12, 2)])
                    valid_macs.append(formatted)
                continue

            # Normalize separators for validation
            normalized = mac.replace("-", ":").lower()

            # Must be exactly 12 hex chars when separators removed
            hex_only = normalized.replace(":", "")
            if len(hex_only) != 12:
                continue

            # Check if it's exactly 6 groups of 2 hex chars
            if ":" in normalized:
                parts = normalized.split(":")
                if len(parts) == 6 and all(
                    len(part) == 2 and all(c in "0123456789abcdef" for c in part) for part in parts
                ):
                    valid_macs.append(mac)

        return list(set(valid_macs))

    def extract_user_agents(self, text: str) -> list[str]:
        """Extract user agent strings from text."""
        return self._extract_pattern(text, "user_agents")

    def extract_yara_rules(self, text: str) -> list[str]:
        """Extract YARA rules from text with better validation."""
        raw_rules = self._extract_pattern(text, "yara")

        # Filter out invalid "rules" (like long text blocks)
        valid_rules = []
        for rule in raw_rules:
            # Must be reasonable length (not entire articles)
            if len(rule) < 3000 and "rule " in rule and "{" in rule:
                # Must have YARA-like structure (at least one section)
                if any(keyword in rule for keyword in ["strings:", "condition:", "meta:"]):
                    # Clean up the rule
                    clean_rule = rule.strip()
                    # If it's missing the closing brace (truncated), add it
                    if not clean_rule.endswith("}"):
                        clean_rule += "\n}"
                    valid_rules.append(clean_rule)

        return valid_rules

    def extract_asn(self, text: str) -> list[str]:
        """Extract AS numbers from text."""
        return self._extract_pattern(text, "asn")

    def extract_jwt(self, text: str) -> list[str]:
        """Extract JWT tokens from text."""
        return self._extract_pattern(text, "jwt")

    def extract_cert_serials(self, text: str) -> list[str]:
        """Extract certificate serial numbers from text."""
        candidates = self._extract_pattern(text, "cert_serials")
        valid_serials = []

        for candidate in candidates:
            # Normalize format - convert to colon-separated if it's plain hex
            if ":" not in candidate and len(candidate) >= 16:
                # Convert plain hex to colon-separated format
                normalized = ":".join([candidate[i : i + 2] for i in range(0, len(candidate), 2)])
            else:
                normalized = candidate

            # Basic validation - should be reasonable length and format
            if ":" in normalized:
                parts = normalized.split(":")
                # Valid serial numbers are typically 8-20 bytes (16-40 hex chars)
                # Minimum 8 parts to avoid short false positives like "ab:cd"
                if 8 <= len(parts) <= 32 and all(
                    len(part) == 2 and part.isalnum() for part in parts
                ):
                    # Avoid MAC addresses (exactly 6 parts) and IPv6 (contains non-hex)
                    if len(parts) != 6 and all(
                        c in "0123456789abcdefABCDEF" for c in normalized.replace(":", "")
                    ):
                        valid_serials.append(normalized.lower())

        return list(set(valid_serials))

    def extract_hosts(self, text: str) -> list[str]:
        """
        Extract actual network hostnames and domains from text.
        Returns only valid domains and explicitly mentioned machine names.
        """
        # Primary source: valid domains
        all_domains: list[str] = self.extract_domains(text)

        # Filter out domains that are clearly not hosts
        valid_hosts = []
        for domain in all_domains:
            # Skip single-word entries without dots (these aren't real hosts)
            if "." not in domain:
                continue

            # Skip common false positives that slip through
            domain_lower = domain.lower()
            if any(
                fp in domain_lower
                for fp in [
                    "view",
                    "via",
                    "the",
                    "and",
                    "for",
                    "with",
                    "from",
                    "document.",
                    "window.",
                    "console.",
                    "function.",
                    "gform.",
                    "jquery.",
                    ".addeventlistener",
                    ".prototype",
                ]
            ):
                continue

            # Must be a reasonable domain name
            parts = domain.split(".")
            if len(parts) >= 2 and all(len(part) > 0 for part in parts):
                valid_hosts.append(domain)

        # Secondary source: explicitly mentioned machine names (very rare)
        # Only from UNC paths or explicit NetBIOS contexts
        unc_pattern: Pattern[str] = re.compile(
            r"\\\\\\\\([A-Z][A-Z0-9\-]{2,14})(?:\\\\|\s)",
            re.IGNORECASE,
        )

        unc_matches: list[str] = unc_pattern.findall(text)
        for match in unc_matches:
            if match and len(match) > 3 and match.lower() not in ["users", "windows", "program"]:
                valid_hosts.append(match)

        # Remove duplicates and return
        return list(set(valid_hosts))

    def extract_all(self, text: str) -> dict[str, list[str]]:
        """
        Extract all types of IOCs from text.

        Args:
            text: Text to extract IOCs from

        Returns:
            Dictionary with IOC types as keys and lists of IOCs as values
        """
        iocs = {}

        # Extract all standard IOC types
        extraction_methods: list[tuple[str, Callable[[str], list[str]]]] = [
            ("md5", self.extract_md5),
            ("sha1", self.extract_sha1),
            ("sha256", self.extract_sha256),
            ("sha512", self.extract_sha512),
            ("ssdeep", self.extract_ssdeep),
            ("domains", self.extract_domains),
            ("ips", self.extract_ips),
            ("ipv6", self.extract_ipv6),
            ("urls", self.extract_urls),
            ("emails", self.extract_emails),
            ("bitcoin", self.extract_bitcoin),
            ("ethereum", self.extract_ethereum),
            ("monero", self.extract_monero),
            ("cves", self.extract_cves),
            ("mitre_attack", self.extract_mitre_attack),
            ("registry", self.extract_registry),
            ("mutex", self.extract_mutex),
            ("service_names", self.extract_service_names),
            ("named_pipes", self.extract_named_pipes),
            ("filenames", self.extract_filenames),
            ("filepaths", self.extract_filepaths),
            ("mac_addresses", self.extract_mac_addresses),
            ("user_agents", self.extract_user_agents),
            ("yara", self.extract_yara_rules),
            ("asn", self.extract_asn),
            ("jwt", self.extract_jwt),
            ("cert_serials", self.extract_cert_serials),
            ("hosts", self.extract_hosts),
        ]

        # Use tqdm for progress if text is large
        use_progress = len(text) > LARGE_TEXT_THRESHOLD

        extraction_iterable: Iterable[tuple[str, Callable[[str], list[str]]]]
        if use_progress:
            extraction_iterable = tqdm(
                extraction_methods,
                desc="Extracting IOCs",
                unit="type",
            )
        else:
            extraction_iterable = extraction_methods

        def _extract_single_type(
            ioc_type: str,
            method: Callable[[str], list[str]],
            text: str,
        ) -> list[str] | None:
            """Extract a single IOC type, handling errors safely."""
            try:
                results = method(text)
            except Exception as e:
                # Log error but continue with other extractions
                print(f"Error extracting {ioc_type}: {e!s}")
                return None
            else:
                return results if results else None

        for ioc_type, method in extraction_iterable:
            results = _extract_single_type(ioc_type, method, text)
            if results:
                iocs[ioc_type] = results

        return iocs
