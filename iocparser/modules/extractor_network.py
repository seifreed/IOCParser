#!/usr/bin/env python3

"""
Network-related extraction mixin for IOC extraction.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

import re
import urllib.parse
from re import Pattern
from typing import ClassVar

from iocparser.modules.extractor_base import ExtractorBase, IPv4_MAX_OCTET, IPv4_PARTS_COUNT


class NetworkExtractionMixin(ExtractorBase):
    """Network IOC extraction methods."""

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

            parts = clean_ip.split(".")
            if len(parts) != IPv4_PARTS_COUNT:
                continue

            try:
                valid = True
                for part in parts:
                    if len(part) > 1 and part[0] == "0":
                        valid = False
                        break
                    num = int(part)
                    if not 0 <= num <= IPv4_MAX_OCTET:
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
            except (ValueError, AttributeError):
                self._append_url(clean_urls, url)

        return list(set(clean_urls))

    def extract_emails(self, text: str) -> list[str]:
        """Extract email addresses from text."""
        emails = self._extract_pattern(text, "emails")

        if self.defang:
            emails = [email.replace("@", "[@]").replace(".", "[.]") for email in emails]

        return list(set(emails))

    def extract_hosts(self, text: str) -> list[str]:
        """
        Extract actual network hostnames and domains from text.
        Returns only valid domains and explicitly mentioned machine names.
        """
        all_domains: list[str] = self.extract_domains(text)

        valid_hosts = []
        for domain in all_domains:
            if "." not in domain:
                continue

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

            parts = domain.split(".")
            if len(parts) >= 2 and all(len(part) > 0 for part in parts):
                valid_hosts.append(domain)

        unc_pattern: Pattern[str] = re.compile(
            r"\\\\\\\\([A-Z][A-Z0-9\-]{2,14})(?:\\\\|\s)",
            re.IGNORECASE,
        )

        unc_matches: list[str] = unc_pattern.findall(text)
        for match in unc_matches:
            if match and len(match) > 3 and match.lower() not in ["users", "windows", "program"]:
                valid_hosts.append(match)

        return list(set(valid_hosts))
