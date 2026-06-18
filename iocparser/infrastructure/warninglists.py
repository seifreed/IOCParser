#!/usr/bin/env python3

"""Module for managing MISP warning lists to detect false positives."""

import ipaddress
import re
from pathlib import Path
from typing import ClassVar

import requests

from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.utils import DEFANG_REPLACEMENTS
from iocparser.infrastructure.warninglists_cache import WarningListCacheMixin
from iocparser.infrastructure.warninglists_diagnostics import WarningListDiagnosticsMixin
from iocparser.infrastructure.warninglists_matching import WarningListMatchingMixin
from iocparser.infrastructure.warninglists_preprocess import WarningListPreprocessMixin
from iocparser.infrastructure.warninglists_types import WarningListDict, WarningListLookups

logger = get_logger("iocparser.infrastructure.warninglists")

__all__ = ["MISPWarningLists", "WarningListLookups", "logger", "requests"]


class MISPWarningLists(
    WarningListCacheMixin,
    WarningListPreprocessMixin,
    WarningListMatchingMixin,
    WarningListDiagnosticsMixin,
):
    """Class for managing MISP warning lists to detect false positives"""

    # Type alias for warning response
    WarningInfo = dict[str, str]

    GITHUB_API_BASE: ClassVar[str] = (
        "https://api.github.com/repos/MISP/misp-warninglists/contents/lists"
    )
    GITHUB_RAW_BASE: ClassVar[str] = (
        "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"
    )

    # Consolidated IOC type mapping used across the class
    IOC_TYPE_MAPPING: ClassVar[dict[str, str]] = {
        "domain": "domains",
        "hostname": "domains",
        "hosts": "domains",
        "fqdn": "domains",
        "ip": "ips",
        "ipv4": "ips",
        "ipv6": "ipv6",
        "url": "urls",
        "uri": "urls",
        "email": "emails",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
        "cve": "cves",
    }

    # MISP attribute types for each IOC type
    MISP_TYPE_MAPPING: ClassVar[dict[str, list[str]]] = {
        "domains": ["hostname", "domain", "domain|ip", "fqdn"],
        "hosts": ["hostname", "domain", "domain|ip", "fqdn"],
        "urls": ["url", "uri", "link", "uri-path"],
        "emails": [
            "email",
            "email-src",
            "email-dst",
            "target-email",
            "email-address",
            "email-subject",
        ],
        "cves": ["vulnerability", "cve", "weakness"],
        "mitre_attack": ["mitre-attack-pattern", "attack-pattern", "technique"],
    }

    # Keywords for relevance checking by IOC type
    TYPE_KEYWORDS: ClassVar[dict[str, list[str]]] = {
        "ips": ["ip", "address", "ipv4", "ipv6", "cidr"],
        "domains": ["domain", "hostname", "fqdn", "dns"],
        "urls": ["url", "uri", "link"],
        "emails": ["email", "mail"],
        "cves": ["cve", "vulnerability"],
    }

    # Defanging cleaners for URL/domain normalization
    DEFANG_CLEANERS: ClassVar[list[tuple[str, str]]] = list(DEFANG_REPLACEMENTS)

    def __init__(self, cache_duration: int = 24, force_update: bool = False) -> None:
        """
        Initialize the warning lists manager.

        Args:
            cache_duration: Duration in hours to keep the local cache before updating
            force_update: If True, force update regardless of cache age
        """
        self.cache_duration: int = cache_duration  # hours
        self.force_update: bool = force_update
        self.warning_lists: dict[str, WarningListDict] = {}
        self.logger = logger

        # Fix: Use Path for better path handling
        self.data_dir: Path = Path(__file__).parent / "data"
        self.cache_file: Path = self.data_dir / "misp_warninglists_cache.json"
        self.cache_metadata_file: Path = self.data_dir / "misp_warninglists_metadata.json"

        # OPTIMIZATION: Pre-computed lookup structures
        self.lookup_data = WarningListLookups(
            string_lookups={},
            compiled_regex={},
            cidr_networks={},
            lists_by_ioc_type={},
        )
        self._clean_value_cache: dict[str, str] = {}
        self._warning_lookup_cache: dict[tuple[str, str], tuple[bool, dict[str, str] | None]] = {}

        # Create the data directory if it doesn't exist
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load or update the lists
        self._load_or_update_lists()

        # OPTIMIZATION: Pre-process lists for faster lookups
        self._preprocess_lists()

    @property
    def string_lookups(self) -> dict[str, set[str]]:
        return self.lookup_data.string_lookups

    @property
    def compiled_regex(self) -> dict[str, list[re.Pattern[str]]]:
        return self.lookup_data.compiled_regex

    @property
    def cidr_networks(self) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
        return self.lookup_data.cidr_networks

    @property
    def lists_by_ioc_type(self) -> dict[str, list[str]]:
        return self.lookup_data.lists_by_ioc_type
