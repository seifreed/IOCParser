#!/usr/bin/env python3

"""
Network-related extraction mixin for IOC extraction.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

import ipaddress as _ipaddress_module
import re
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from iocparser.infrastructure.extractor_base import ExtractorBase, IPv4_MAX_OCTET, IPv4_PARTS_COUNT

UNC_HOST_PATTERN = re.compile(r"\\\\([A-Z][A-Z0-9\-]{2,14})(?:\\|\s)", re.IGNORECASE)
NORMALIZED_DOT_PATTERN = re.compile(r"[\[\(\{]\.[\]\)\}]")


def _dedup_case_insensitive(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


@dataclass(frozen=True)
class NetworkHeuristicPolicy:
    file_sharing_sites: frozenset[str]
    suspicious_path_keywords: tuple[str, ...]
    documentation_domains: tuple[str, ...]
    filtered_url_suffixes: tuple[str, ...]
    suspicious_doc_terms: tuple[str, ...]
    host_false_positives: tuple[str, ...]

    def normalize_ip_candidate(self, value: str) -> str:
        return NORMALIZED_DOT_PATTERN.sub(".", value)

    def is_valid_ipv4(self, parts: Iterable[str], *, octet_count: int, max_octet: int) -> bool:
        normalized_parts = list(parts)
        if len(normalized_parts) != octet_count:
            return False
        for part in normalized_parts:
            if len(part) > 1 and part[0] == "0":
                return False
            try:
                num = int(part)
            except ValueError:
                return False
            if not 0 <= num <= max_octet:
                return False
        return True

    def parse_url_candidate(
        self, value: str, *, clean_defanged: Callable[[str], str]
    ) -> tuple[str, str] | None:
        try:
            from iocparser.shared_utils import refang_ioc

            clean_for_parse = refang_ioc(clean_defanged(value))
            parsed = urllib.parse.urlparse(clean_for_parse)
        except (ValueError, AttributeError):
            return None
        return parsed.netloc.lower(), parsed.path.lower()

    def is_file_sharing_url(self, domain: str) -> bool:
        return any(
            domain == site or domain.endswith(f".{site}") for site in self.file_sharing_sites
        )

    def is_suspicious_code_hosting_url(self, domain: str, path: str) -> bool:
        if not ("github.com" in domain or "gitlab.com" in domain or "bitbucket.org" in domain):
            return False
        return any(keyword in path for keyword in self.suspicious_path_keywords)

    def should_exclude_documentation_url(self, domain: str, path: str) -> bool:
        if not any(doc_domain in domain for doc_domain in self.documentation_domains):
            return False
        return not any(term in path for term in self.suspicious_doc_terms)

    def should_keep_url(self, domain: str, path: str) -> bool:
        if self.is_file_sharing_url(domain) or self.is_suspicious_code_hosting_url(domain, path):
            return True
        if (
            "github.com" in domain
            or "gitlab.com" in domain
            or "bitbucket.org" in domain
            or self.should_exclude_documentation_url(domain, path)
        ):
            return False
        return bool(domain) and not path.endswith(self.filtered_url_suffixes)

    def is_valid_host_candidate(self, domain: str) -> bool:
        if "." not in domain:
            return False
        domain_lower = domain.lower()
        parts = domain_lower.split(".")
        for fragment in self.host_false_positives:
            if fragment.startswith("."):
                if domain_lower.endswith(fragment):
                    return False
            elif fragment.endswith("."):
                if domain_lower.startswith(fragment):
                    return False
            elif fragment in parts:
                return False
        return True

    def unc_hosts(self, text: str) -> list[str]:
        return [
            match
            for match in UNC_HOST_PATTERN.findall(text)
            if match and len(match) >= 3 and match.lower() not in {"users", "windows", "program"}
        ]

    def extracted_urls(
        self,
        *,
        raw_urls: list[str],
        clean_defanged: Callable[[str], str],
        defang_url: Callable[[str], str],
        defang: bool,
    ) -> list[str]:
        clean_urls: list[str] = []
        for url in raw_urls:
            parsed = self.parse_url_candidate(url, clean_defanged=clean_defanged)
            if parsed is None:
                clean_urls.append(defang_url(url) if defang else url)
                continue
            domain, path = parsed
            if "." not in domain:
                continue
            if self.should_keep_url(domain, path):
                clean_urls.append(defang_url(url) if defang else url)
        return _dedup_case_insensitive(clean_urls)

    def extracted_emails(self, *, raw_emails: list[str], defang: bool) -> list[str]:
        if defang:
            raw_emails = [email.replace("@", "[@]").replace(".", "[.]") for email in raw_emails]
        return _dedup_case_insensitive(raw_emails)

    def extracted_hosts(self, *, domains: list[str], text: str) -> list[str]:
        valid_hosts = [domain for domain in domains if self.is_valid_host_candidate(domain)]
        valid_hosts.extend(self.unc_hosts(text))
        return _dedup_case_insensitive(valid_hosts)

    def extracted_domains(
        self,
        *,
        direct_domains: list[str],
        url_domains: list[str],
        clean_defanged: Callable[[str], str],
        is_valid_domain: Callable[[str], bool],
        defang_dotted: Callable[[str], str],
        defang: bool,
    ) -> list[str]:
        clean_domains: list[str] = []
        for domain in direct_domains + url_domains:
            clean_domain = clean_defanged(domain)
            if is_valid_domain(clean_domain):
                clean_domains.append(defang_dotted(clean_domain) if defang else clean_domain)
        return _dedup_case_insensitive(clean_domains)

    def extracted_ips(
        self,
        *,
        raw_ips: list[str],
        clean_defanged: Callable[[str], str],
        defang_dotted: Callable[[str], str],
        defang: bool,
        octet_count: int,
        max_octet: int,
    ) -> list[str]:
        clean_ips: list[str] = []
        for ip in raw_ips:
            clean_ip = self.normalize_ip_candidate(clean_defanged(ip))
            if not self.is_valid_ipv4(
                clean_ip.split("."), octet_count=octet_count, max_octet=max_octet
            ):
                continue
            clean_ips.append(defang_dotted(clean_ip) if defang else clean_ip)
        return _dedup_case_insensitive(clean_ips)


DEFAULT_NETWORK_POLICY = NetworkHeuristicPolicy(
    file_sharing_sites=frozenset(
        {
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
    ),
    suspicious_path_keywords=(
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
    ),
    documentation_domains=(
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
    ),
    filtered_url_suffixes=(".png", ".jpg", ".gif", ".css", ".js"),
    suspicious_doc_terms=("exploit", "vulnerability", "cve-", "poc", "bypass"),
    host_false_positives=(
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
    ),
)


def _extract_domains(self: ExtractorBase, text: str) -> list[str]:
    return DEFAULT_NETWORK_POLICY.extracted_domains(
        direct_domains=self._extract_pattern(text, "domains"),
        url_domains=self._extract_domains_from_urls(text),
        clean_defanged=self._clean_defanged,
        is_valid_domain=self.reference_data.is_valid_domain,
        defang_dotted=self._defang_dotted,
        defang=self.defang,
    )


def _extract_ips(self: ExtractorBase, text: str) -> list[str]:
    return DEFAULT_NETWORK_POLICY.extracted_ips(
        raw_ips=self._extract_pattern(text, "ips"),
        clean_defanged=self._clean_defanged,
        defang_dotted=self._defang_dotted,
        defang=self.defang,
        octet_count=IPv4_PARTS_COUNT,
        max_octet=IPv4_MAX_OCTET,
    )


def _extract_ipv6(self: ExtractorBase, text: str) -> list[str]:
    candidates = self._extract_pattern(text, "ipv6")
    validated: list[str] = []
    for candidate in candidates:
        try:
            _ipaddress_module.ip_address(candidate)
            validated.append(candidate)
        except ValueError:
            pass
    return validated


def _extract_urls(self: ExtractorBase, text: str) -> list[str]:
    return DEFAULT_NETWORK_POLICY.extracted_urls(
        raw_urls=self._extract_pattern(text, "urls"),
        clean_defanged=self._clean_defanged,
        defang_url=self._defang_url,
        defang=self.defang,
    )


def _extract_emails(self: ExtractorBase, text: str) -> list[str]:
    return DEFAULT_NETWORK_POLICY.extracted_emails(
        raw_emails=self._extract_pattern(text, "emails"), defang=self.defang
    )


NETWORK_EXTRACTION_METHODS: tuple[str, ...] = (
    "extract_domains",
    "extract_ips",
    "extract_ipv6",
    "extract_urls",
    "extract_emails",
    "extract_hosts",
)


class NetworkExtractionMixin(ExtractorBase):
    """Network IOC extraction methods."""

    def extract_domains(self, text: str) -> list[str]:
        """Extract domain names from text."""
        return _extract_domains(self, text)

    def extract_ips(self, text: str) -> list[str]:
        """Extract IPv4 addresses from text."""
        return _extract_ips(self, text)

    def extract_ipv6(self, text: str) -> list[str]:
        """Extract IPv6 addresses from text."""
        return _extract_ipv6(self, text)

    def extract_urls(self, text: str) -> list[str]:
        """Extract URLs from text, intelligently filtering based on context."""
        return _extract_urls(self, text)

    def extract_emails(self, text: str) -> list[str]:
        """Extract email addresses from text."""
        return _extract_emails(self, text)

    def _is_file_sharing_url(self, domain: str) -> bool:
        """Check if domain belongs to a file sharing service."""
        return DEFAULT_NETWORK_POLICY.is_file_sharing_url(domain)

    def _is_suspicious_url(self, domain: str, path: str) -> bool:
        """Check if URL path contains suspicious keywords for code hosting sites."""
        return DEFAULT_NETWORK_POLICY.is_suspicious_code_hosting_url(domain, path)

    def _should_exclude_url(self, domain: str, path: str) -> bool:
        """Determine if URL should be excluded from results."""
        return DEFAULT_NETWORK_POLICY.should_exclude_documentation_url(domain, path)

    def _append_url(self, clean_urls: list[str], url: str) -> None:
        """Append URL to list, applying defanging if enabled."""
        clean_urls.append(self._defang_url(url) if self.defang else url)

    def extract_hosts(self, text: str) -> list[str]:
        """
        Extract actual network hostnames and domains from text.
        Returns only valid domains and explicitly mentioned machine names.
        """
        return DEFAULT_NETWORK_POLICY.extracted_hosts(domains=self.extract_domains(text), text=text)
