#!/usr/bin/env python3

"""
Core helpers for extracting indicators of compromise (IOCs).

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

import binascii
import json
import sys
import urllib.parse
from pathlib import Path
from re import Pattern
from types import ModuleType
from typing import cast

from iocparser.modules.extractor_patterns import PATTERNS
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


class ExtractorBase:
    """Shared helper methods for IOC extraction."""

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
        self.patterns: dict[str, Pattern[str]] = PATTERNS.copy()

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
        tlds_file = self._get_data_dir() / "tlds.txt"
        if tlds_file.exists():
            try:
                with tlds_file.open(encoding="utf-8") as f:
                    return {line.strip().lower() for line in f if line.strip()}
            except (OSError, ValueError) as exc:
                logger.debug("Failed to load TLD list from file: %s", exc)

        return common_tlds

    def _load_legitimate_domains(self) -> None:
        """Load legitimate domains from JSON file."""
        domains_file = self._get_data_dir() / "legitimate_domains.json"
        if domains_file.exists():
            try:
                with domains_file.open(encoding="utf-8") as f:
                    data = cast("dict[str, list[str]]", json.load(f))
                    self.legitimate_domains = set(data.get("legitimate_domains", []))
                    self.legitimate_with_subdomains = set(
                        data.get("legitimate_with_subdomains", [])
                    )
                    return
            except (OSError, ValueError) as exc:
                logger.debug("Failed to load legitimate domains from file: %s", exc)

        # Fallback to empty sets - will use hardcoded values in _is_valid_domain
        self.legitimate_domains = set()
        self.legitimate_with_subdomains = set()

    def _get_data_dir(self) -> Path:
        """Return the data directory based on the extractor module location."""
        module: ModuleType | None = sys.modules.get(self.__class__.__module__)
        module_file = module.__file__ if module is not None else None
        if isinstance(module_file, str):
            return Path(module_file).parent / "data"
        return Path(__file__).parent / "data"

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
                for match_value in match:
                    if match_value:
                        clean_matches.append(match_value)
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

        if tld not in self.valid_tlds or tld in self.common_file_extensions:
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

        if any(part.lower() in programming_keywords for part in parts):
            return False

        domain_lower = domain.lower()

        # If it's a known legitimate domain, exclude it
        if (
            domain_lower in self.legitimate_domains
            or domain_lower in self.legitimate_with_subdomains
        ):
            return False

        # If it's a subdomain of a legitimate domain but looks suspicious, keep it
        for legit in self.legitimate_domains:
            if domain_lower.endswith("." + legit):
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
                return any(
                    keyword in subdomain.lower() for keyword in suspicious_subdomain_keywords
                )

        domain_length_valid = len(domain) <= MAX_DOMAIN_LENGTH
        parts_length_valid = all(len(part) <= MAX_DOMAIN_PART_LENGTH for part in parts)
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
            clean_url = url.replace("[.]", ".").replace("hxxp", "http")

            try:
                parsed = urllib.parse.urlparse(clean_url)
                if parsed.netloc:
                    domain = parsed.netloc.split(":")[0]
                    if self._is_valid_domain(domain):
                        domains.append(domain)
            except (ValueError, AttributeError) as exc:
                logger.debug("Failed to parse URL %s: %s", clean_url, exc)

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
        return [candidate for candidate in candidates if self._is_valid_hash_pattern(candidate)]
