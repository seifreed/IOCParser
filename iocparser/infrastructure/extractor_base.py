#!/usr/bin/env python3

"""
Core helpers for extracting indicators of compromise (IOCs).

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from re import Pattern

from tqdm import tqdm

from iocparser.infrastructure.extractor_base_runtime_support import (
    build_reference_data,
    clean_defanged,
    defang_dotted,
    defang_url,
)
from iocparser.infrastructure.extractor_patterns import PATTERNS
from iocparser.infrastructure.logger import get_logger
from iocparser.shared_utils import dedup_case_insensitive

logger = get_logger(__name__)

MIN_HASH_UNIQUE_CHARS = 4
MAX_DOMAIN_LENGTH = 253
MAX_DOMAIN_PART_LENGTH = 63
IPv4_PARTS_COUNT = 4
IPv4_MAX_OCTET = 255
MIN_HOSTNAME_LENGTH = 3
LARGE_TEXT_THRESHOLD = 10000

PROGRAMMING_KEYWORDS = {
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
    "innerHTML",
    "outerHTML",
    "appendChild",
    "removeChild",
    "createElement",
}
SUSPICIOUS_SUBDOMAIN_KEYWORDS = [
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


@dataclass(frozen=True)
class HashValidationPolicy:
    min_unique_chars: int
    forbidden_sequences: tuple[str, ...]

    def is_valid(self, hash_string: str) -> bool:
        # Hash regexes only match isolated, fixed-length hex tokens (md5/sha1/
        # sha256/sha512), so a cryptographic digest's pseudo-random bytes can never
        # be a hex-encoded file here. Decoding the digest and rejecting it on
        # file-magic prefixes or printable-byte ratio only produced false negatives,
        # silently dropping valid hashes whose first bytes happened to spell "MZ"/
        # "PK"/"7z" or that decoded to mostly-ASCII bytes.
        if len(set(hash_string.lower())) < self.min_unique_chars:
            return False
        return not any(pattern in hash_string.lower() for pattern in self.forbidden_sequences)


@dataclass(frozen=True)
class DomainValidationPolicy:
    programming_keywords: frozenset[str]
    suspicious_subdomain_keywords: tuple[str, ...]
    max_domain_length: int
    max_domain_part_length: int

    def is_valid(
        self,
        domain: str,
        *,
        valid_tlds: set[str],
        common_file_extensions: set[str],
        legitimate_domains: set[str],
        legitimate_with_subdomains: set[str],
    ) -> bool:
        if not domain or "." not in domain:
            return False
        parts = domain.lower().split(".")
        tld = parts[-1]
        if tld not in valid_tlds or tld in common_file_extensions:
            return False
        if any(part.lower() in self.programming_keywords for part in parts):
            return False
        domain_lower = domain.lower()
        if domain_lower in legitimate_domains or domain_lower in legitimate_with_subdomains:
            return False
        matching_suffixes = [
            legit for legit in legitimate_domains if domain_lower.endswith("." + legit)
        ]
        if matching_suffixes:
            longest_suffix = max(matching_suffixes, key=len)
            subdomain = domain_lower.removesuffix("." + longest_suffix)
            return any(keyword in subdomain for keyword in self.suspicious_subdomain_keywords)
        return (
            len(domain) <= self.max_domain_length
            and all(len(part) <= self.max_domain_part_length for part in parts)
            and len(parts) >= 2
            and all(part for part in parts)
        )


DEFAULT_HASH_VALIDATION_POLICY = HashValidationPolicy(
    min_unique_chars=MIN_HASH_UNIQUE_CHARS,
    forbidden_sequences=("0123456789abcdef", "abcdefabcdef", "fedcbafedcba", "9876543210fedcba"),
)

DEFAULT_DOMAIN_VALIDATION_POLICY = DomainValidationPolicy(
    programming_keywords=frozenset(PROGRAMMING_KEYWORDS),
    suspicious_subdomain_keywords=tuple(SUSPICIOUS_SUBDOMAIN_KEYWORDS),
    max_domain_length=MAX_DOMAIN_LENGTH,
    max_domain_part_length=MAX_DOMAIN_PART_LENGTH,
)


@dataclass(frozen=True)
class HashPatternRule:
    method_name: str
    pattern_name: str
    validate: bool = True

    def apply(self, extractor: ExtractorBase, text: str) -> list[str]:
        return extractor._extract_hash(text, self.pattern_name, validate=self.validate)


HASH_PATTERN_RULES: tuple[HashPatternRule, ...] = (
    HashPatternRule("extract_md5", "md5"),
    HashPatternRule("extract_imphash", "imphash", validate=False),
    HashPatternRule("extract_sha1", "sha1"),
    HashPatternRule("extract_sha256", "sha256"),
    HashPatternRule("extract_sha512", "sha512"),
    HashPatternRule("extract_ssdeep", "ssdeep", validate=False),
)
HASH_EXTRACTION_METHODS: tuple[str, ...] = tuple(rule.method_name for rule in HASH_PATTERN_RULES)


def _hash_rule_method(rule: HashPatternRule) -> Callable[[ExtractorBase, str], list[str]]:
    def extractor(self: ExtractorBase, text: str) -> list[str]:
        return rule.apply(self, text)

    extractor.__name__ = rule.method_name
    return extractor


# 32-hex IOC types that carry an explicit context label and would otherwise be
# double-reported as a generic md5 file hash. (jarm is 62 hex and ja4 contains
# underscores, so neither collides with the md5 pattern.)
_MD5_SHAPED_FINGERPRINT_TYPES = ("imphash", "ja3", "ja3s", "hassh", "hassh_server")


def _separate_fingerprints_from_md5(iocs: dict[str, list[str]]) -> None:
    """Drop explicitly-labelled 32-hex fingerprints from the generic md5 bucket.

    The md5 pattern matches any standalone 32-hex string, so a value introduced
    as ``imphash:``/``ja3:``/``hassh:`` (etc.) is also captured as an md5. Each is
    its own IOC type, so keep it only under that type rather than also emitting a
    spurious md5 file hash.
    """
    md5s = iocs.get("md5")
    if not md5s:
        return
    fingerprint_values = {
        value.lower()
        for type_name in _MD5_SHAPED_FINGERPRINT_TYPES
        for value in iocs.get(type_name) or ()
    }
    if not fingerprint_values:
        return
    remaining = [value for value in md5s if value.lower() not in fingerprint_values]
    if remaining:
        iocs["md5"] = remaining
    else:
        del iocs["md5"]


class ExtractorBase:
    """Shared helper methods for IOC extraction."""

    def __init__(self, defang: bool = True) -> None:
        """
        Initialize the extractor.

        Args:
            defang: If True, performs defanging on the results
        """
        self.defang = defang
        self.reference_data = build_reference_data(self.__class__.__module__)

        # Define regex patterns for all IOC types
        self.patterns: dict[str, Pattern[str]] = PATTERNS.copy()

    @property
    def valid_tlds(self) -> set[str]:
        return self.reference_data.valid_tlds

    @property
    def legitimate_domains(self) -> set[str]:
        return self.reference_data.legitimate_domains

    @property
    def legitimate_with_subdomains(self) -> set[str]:
        return self.reference_data.legitimate_with_subdomains

    @property
    def common_file_extensions(self) -> set[str]:
        return self.reference_data.common_file_extensions

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
        clean_matches: list[str] = []
        for match_obj in pattern.finditer(text):
            match_value = match_obj.group(0)
            # If the pattern has explicit capture groups, prefer the first non-empty group
            groups = match_obj.groups()
            if groups:
                for group in groups:
                    if group:
                        match_value = group
                        break
            if match_value:
                clean_matches.append(match_value)
        if pattern_name == "urls":
            # URL paths/queries are case-sensitive (RFC 3986); a case-insensitive
            # dedup here would drop distinct URLs. Dedup exact duplicates only and
            # let extracted_urls collapse host-case variants on the canonical value.
            return list(dict.fromkeys(clean_matches))
        return dedup_case_insensitive(clean_matches)

    def _is_valid_hash_pattern(self, hash_string: str) -> bool:
        """
        Check if a hash string has a valid pattern.

        Args:
            hash_string: Hash string to validate

        Returns:
            True if valid pattern, False otherwise
        """
        return DEFAULT_HASH_VALIDATION_POLICY.is_valid(hash_string)

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate if a string is a valid domain.

        Args:
            domain: Domain string to validate

        Returns:
            True if valid domain, False otherwise
        """
        return self.reference_data.is_valid_domain(domain)

    def _defang_dotted(self, value: str) -> str:
        """
        Defang a dotted value (domain or IP) by replacing dots with [.].

        Args:
            value: Domain or IP address to defang

        Returns:
            Defanged value
        """
        return defang_dotted(value)

    def _defang_url(self, url: str) -> str:
        """
        Defang a URL.

        Args:
            url: URL to defang

        Returns:
            Defanged URL
        """
        return defang_url(url)

    def _clean_defanged(self, value: str) -> str:
        """
        Clean defanged notation from a value (domain or IP).

        Args:
            value: Defanged value to clean

        Returns:
            Cleaned value with standard dots
        """
        return clean_defanged(value)

    def _extract_domains_from_urls(self, text: str) -> list[str]:
        """
        Extract domains from URLs in text.

        Args:
            text: Text to search in

        Returns:
            List of domains
        """
        return self.reference_data.extract_domains_from_text(
            text, extract_pattern=self._extract_pattern
        )

    def _extract_hash(self, text: str, hash_type: str, *, validate: bool = True) -> list[str]:
        """
        Extract hashes of a specific type from text.

        Args:
            text: Text to search in
            hash_type: Type of hash pattern to use (md5, sha1, sha256, sha512)

        Returns:
            List of valid hashes
        """
        candidates = self._extract_pattern(text, hash_type)
        if not validate:
            return candidates
        return [candidate for candidate in candidates if self._is_valid_hash_pattern(candidate)]


class ExtractionAggregateMixin:
    """Aggregate extraction methods into a single result."""

    def _extract_single_type(
        self,
        ioc_type: str,
        method: Callable[[str], list[str]],
        text: str,
    ) -> list[str] | None:
        try:
            results = method(text)
        except (OSError, ValueError) as exc:
            logger.warning("Error extracting %s: %s", ioc_type, exc)
            return None
        return results if results else None

    def _extraction_methods(self) -> list[tuple[str, Callable[[str], list[str]]]]:
        cached = getattr(self, "_cached_extraction_methods", None)
        if isinstance(cached, list):
            return cached
        from iocparser.infrastructure.extractor_artifacts import ARTIFACT_EXTRACTION_METHODS
        from iocparser.infrastructure.extractor_network import NETWORK_EXTRACTION_METHODS

        methods: list[tuple[str, Callable[[str], list[str]]]] = []
        for category_methods in (
            HASH_EXTRACTION_METHODS,
            NETWORK_EXTRACTION_METHODS,
            ARTIFACT_EXTRACTION_METHODS,
        ):
            for method_name in category_methods:
                methods.append((method_name.removeprefix("extract_"), getattr(self, method_name)))
        self._cached_extraction_methods = methods
        return methods

    def extract_all(self, text: str) -> dict[str, list[str]]:
        iocs: dict[str, list[str]] = {}
        extraction_methods = self._extraction_methods()
        use_progress = len(text) > LARGE_TEXT_THRESHOLD

        extraction_iterable: Iterable[tuple[str, Callable[[str], list[str]]]]
        if use_progress:
            extraction_iterable = tqdm(extraction_methods, desc="Extracting IOCs", unit="type")
        else:
            extraction_iterable = extraction_methods

        for ioc_type, method in extraction_iterable:
            results = self._extract_single_type(ioc_type, method, text)
            if results:
                iocs[ioc_type] = results

        _separate_fingerprints_from_md5(iocs)
        return iocs


for _rule in HASH_PATTERN_RULES:
    setattr(ExtractorBase, _rule.method_name, _hash_rule_method(_rule))
