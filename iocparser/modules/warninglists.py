#!/usr/bin/env python3

"""
Module for managing MISP warning lists to detect false positives

Author: Marc Rivero | @seifreed
"""

import ipaddress
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import ClassVar, Union, cast
from urllib.parse import urlparse

import requests
from tqdm import tqdm

from iocparser.modules.logger import get_logger
from iocparser.modules.warninglists_diagnostics import WarningListDiagnosticsMixin

# Type alias for cleaner code
WarningListEntry = Union[str, dict[str, str], int, bool, None]
WarningListValue = Union[str, list[WarningListEntry], int, bool]
WarningListDict = dict[str, WarningListValue]
IOCValue = Union[str, int, float, bool, None]
JSONValue = Union[str, int, bool, list[str], list[dict[str, str]], dict[str, str]]
JSONData = Union[dict[str, JSONValue], list[JSONValue]]

logger = get_logger(__name__)


@dataclass
class WarningListLookups:
    """Lookup containers for optimized warning list checks."""

    string_lookups: dict[str, set[str]]
    compiled_regex: dict[str, list[re.Pattern[str]]]
    cidr_networks: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]
    lists_by_ioc_type: dict[str, list[str]]


class MISPWarningLists(WarningListDiagnosticsMixin):
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
    DEFANG_CLEANERS: ClassVar[list[tuple[str, str]]] = [
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[:]", ":"),
        ("(:)", ":"),
        ("{:}", ":"),
        ("[@]", "@"),
        ("[@ ]", "@"),
        ("(@)", "@"),
        ("{@}", "@"),
        ("[//]", "//"),
        ("{//}", "//"),
        ("[/]", "/"),
        ("{/}", "/"),
        ("hxxp://", "http://"),
        ("hxxps://", "https://"),
        ("hXXp://", "http://"),
        ("hXXps://", "https://"),
        ("h__p://", "http://"),
        ("h__ps://", "https://"),
    ]

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

        # Create the data directory if it doesn't exist
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load or update the lists
        self._load_or_update_lists()

        # OPTIMIZATION: Pre-process lists for faster lookups
        self._preprocess_lists()

    @property
    def string_lookups(self) -> dict[str, set[str]]:
        """Backwards-compatible access to string lookups."""
        return self.lookup_data.string_lookups

    @property
    def compiled_regex(self) -> dict[str, list[re.Pattern[str]]]:
        """Backwards-compatible access to compiled regex patterns."""
        return self.lookup_data.compiled_regex

    @property
    def cidr_networks(
        self,
    ) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
        """Backwards-compatible access to CIDR networks."""
        return self.lookup_data.cidr_networks

    @property
    def lists_by_ioc_type(self) -> dict[str, list[str]]:
        """Backwards-compatible access to IOC type mapping."""
        return self.lookup_data.lists_by_ioc_type

    def _reset_cache_files(self) -> None:
        """Remove cache files when they are corrupted."""
        for cache_path in (self.cache_file, self.cache_metadata_file):
            self._safe_unlink(cache_path)

    def _safe_unlink(self, cache_path: Path) -> None:
        """Safely unlink a cache file."""
        try:
            cache_path.unlink(missing_ok=True)
        except (OSError, PermissionError) as cleanup_error:
            logger.debug("Could not remove cache file %s: %s", cache_path, cleanup_error)

    def _load_or_update_lists(self) -> None:
        """Load lists from cache or update them if necessary"""
        # Check if cache exists and its age
        if (
            not self.force_update
            and self.cache_duration > 0
            and self.cache_file.exists()
            and self.cache_metadata_file.exists()
        ):
            try:
                with self.cache_metadata_file.open() as f:
                    metadata: dict[str, float] = json.load(f)
                last_update_raw = metadata.get("last_update", 0.0)
                try:
                    last_update = float(last_update_raw)
                except (TypeError, ValueError):
                    last_update = 0.0
                current_time = time.time()

                # Check if the cache is up to date
                if current_time - last_update < self.cache_duration * 3600:
                    logger.info("Loading MISP warning lists from local cache...")
                    with self.cache_file.open() as f:
                        loaded_data: JSONData = json.load(f)
                        self.warning_lists = cast("dict[str, WarningListDict]", loaded_data)
                    logger.info(
                        "Loaded %s MISP warning lists from cache",
                        len(self.warning_lists),
                    )
                    return
            except json.JSONDecodeError as e:
                logger.warning(
                    "Cache is corrupted (JSON decode error): %s. Resetting cache.",
                    e,
                )
                self._reset_cache_files()
            except (OSError, ValueError) as e:
                logger.warning("Failed to load cache: %s", e)
                self._reset_cache_files()

        # If we get here, we need to update the lists
        self._update_warning_lists()

    def _fetch_list_directories(self) -> list[str]:
        """Fetch list directory names from the MISP warning lists repository."""
        response = requests.get(self.GITHUB_API_BASE, timeout=30)
        response.raise_for_status()
        response_data: JSONData = response.json()
        directories: list[dict[str, str]] = cast("list[dict[str, str]]", response_data)
        return [item["name"] for item in directories if item.get("type") == "dir"]

    def _download_single_list(self, directory: str) -> tuple[str, WarningListDict | None]:
        """Download a single warning list."""
        try:
            list_url = f"{self.GITHUB_RAW_BASE}/{directory}/list.json"
            list_response = requests.get(list_url, timeout=30)
            list_response.raise_for_status()
            response_json: JSONData = list_response.json()
            result: WarningListDict = cast("WarningListDict", response_json)
            return directory, result
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Error downloading warning list %s: %s", directory, exc)
            return directory, None

    def _download_warning_lists(
        self,
        list_directories: list[str],
    ) -> tuple[dict[str, WarningListDict], list[str]]:
        """Download all warning lists and return results plus failures."""
        warning_lists: dict[str, WarningListDict] = {}
        failed_downloads: list[str] = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self._download_single_list, d) for d in list_directories]
            for future in tqdm(
                as_completed(futures),
                total=len(list_directories),
                desc="Downloading warning lists",
            ):
                directory, warning_list = future.result()
                if warning_list is not None:
                    warning_lists[directory] = warning_list
                else:
                    failed_downloads.append(directory)
        return warning_lists, failed_downloads

    def _write_cache(self) -> None:
        """Write cache files for warning lists and metadata."""
        with self.cache_file.open("w") as f:
            json.dump(self.warning_lists, f)
        cache_data: dict[str, float] = {"last_update": time.time()}
        with self.cache_metadata_file.open("w") as f:
            json.dump(cache_data, f)

    def _log_failed_downloads(self, failed_downloads: list[str]) -> None:
        """Log summary of failed warning list downloads."""
        if not failed_downloads:
            return
        failed_head = ", ".join(failed_downloads[:10])
        suffix = " ..." if len(failed_downloads) > 10 else ""
        logger.warning(
            "Failed to download %s warning lists: %s%s",
            len(failed_downloads),
            failed_head,
            suffix,
        )

    def _update_warning_lists(self) -> None:
        """Update warning lists from the MISP GitHub repository"""
        try:
            logger.warning("Updating MISP warning lists from GitHub repository...")

            list_directories = self._fetch_list_directories()
            logger.info("Downloading %s MISP warning lists...", len(list_directories))

            warning_lists, failed_downloads = self._download_warning_lists(list_directories)
            self.warning_lists = warning_lists
            self._write_cache()
            self._log_failed_downloads(failed_downloads)

            logger.info("Successfully updated %s MISP warning lists", len(self.warning_lists))

        except (OSError, ValueError, requests.RequestException, json.JSONDecodeError):
            logger.exception("Could not update warning lists")

            # If a cache is available, try to use it despite the error
            if self.cache_file.exists():
                try:
                    with self.cache_file.open() as f:
                        loaded_data: JSONData = json.load(f)
                        self.warning_lists = cast("dict[str, WarningListDict]", loaded_data)
                    logger.warning("Using cached warning lists")
                except (OSError, ValueError, json.JSONDecodeError):
                    logger.exception("Could not load warning lists from cache")

    def _clear_preprocessed_data(self) -> None:
        """Clear all preprocessed data structures"""
        self.lookup_data.string_lookups.clear()
        self.lookup_data.compiled_regex.clear()
        self.lookup_data.cidr_networks.clear()
        self.lookup_data.lists_by_ioc_type.clear()

    def _add_string_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        """Add string values to fast lookup table."""
        for value in values_val:
            if value is None:
                continue
            value_lower = str(value).lower()
            if value_lower not in self.lookup_data.string_lookups:
                self.lookup_data.string_lookups[value_lower] = set()
            self.lookup_data.string_lookups[value_lower].add(list_id)

    def _add_regex_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        """Add regex values to compiled regex table."""
        compiled_patterns: list[re.Pattern[str]] = []
        for pattern in values_val:
            if pattern is None:
                continue
            try:
                compiled_patterns.append(re.compile(str(pattern), re.IGNORECASE))
            except (re.error, TypeError):
                logger.debug("Invalid regex pattern: %s", pattern)
        if compiled_patterns:
            self.lookup_data.compiled_regex[list_id] = compiled_patterns

    def _add_cidr_values(self, list_id: str, values_val: list[WarningListEntry]) -> None:
        """Add CIDR values to parsed network table."""
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr_value in values_val:
            if cidr_value is None:
                continue
            cidr_text = str(cidr_value)
            if "/" not in cidr_text:
                continue
            try:
                networks.append(ipaddress.ip_network(cidr_text, strict=False))
            except (ValueError, ipaddress.AddressValueError):
                logger.debug("Invalid CIDR entry: %s", cidr_text)
        if networks:
            self.lookup_data.cidr_networks[list_id] = networks

    def _index_matching_attributes(self, list_id: str, warning_list: WarningListDict) -> None:
        """Index lists by applicable IOC types."""
        matching_attrs = warning_list.get("matching_attributes", [])
        if not isinstance(matching_attrs, list):
            return
        for attr in matching_attrs:
            if isinstance(attr, str):
                attr_str = attr
            elif isinstance(attr, dict):
                attr_str = str(attr.get("name", ""))
            else:
                attr_str = str(attr)
            for keyword, ioc_type in self.IOC_TYPE_MAPPING.items():
                if keyword in attr_str.lower():
                    if ioc_type not in self.lookup_data.lists_by_ioc_type:
                        self.lookup_data.lists_by_ioc_type[ioc_type] = []
                    if list_id not in self.lookup_data.lists_by_ioc_type[ioc_type]:
                        self.lookup_data.lists_by_ioc_type[ioc_type].append(list_id)

    def _preprocess_lists(self) -> None:
        """Pre-process warning lists for optimized lookups"""
        logger.info("Pre-processing warning lists for optimized lookups...")

        # Clear existing preprocessed data first
        self._clear_preprocessed_data()

        for list_id, warning_list in self.warning_lists.items():
            list_type = str(warning_list.get("type", "string"))
            values_val = warning_list.get("list", [])

            if not isinstance(values_val, list):
                continue

            if list_type == "string":
                self._add_string_values(list_id, values_val)
            elif list_type == "regex":
                self._add_regex_values(list_id, values_val)
            elif list_type == "cidr":
                self._add_cidr_values(list_id, values_val)

            self._index_matching_attributes(list_id, warning_list)

        logger.info("Pre-processing complete")

    @lru_cache(maxsize=10000)  # type: ignore[misc]
    def _clean_defanged_value(self, value: str) -> str:
        """
        Remove common defanging patterns from a value.

        Args:
            value: The value to clean

        Returns:
            Cleaned value
        """
        clean_value: str = value
        for old, new in self.DEFANG_CLEANERS:
            clean_value = clean_value.replace(old, new)

        return clean_value

    def _extract_email_domain(self, value: str) -> str | None:
        """Extract domain from an email address."""
        cleaned = self._clean_defanged_value(value)
        if "@" not in cleaned:
            return None
        domain = cleaned.rsplit("@", 1)[1].strip()
        return domain or None

    def _email_domain_in_warning_list(self, value: str) -> bool:
        """Check if an email's domain is in warning lists."""
        domain = self._extract_email_domain(value)
        if not domain:
            return False
        in_warning_list, _ = self.check_value(domain, "domains")
        return in_warning_list

    def _build_warning_response(
        self,
        warning_list: WarningListDict,
        list_id: str,
    ) -> "MISPWarningLists.WarningInfo":
        """
        Build a standardized warning response dictionary.

        Args:
            warning_list: The warning list dictionary
            list_id: The list identifier

        Returns:
            Dictionary with 'name' and 'description' keys
        """
        return {
            "name": str(warning_list.get("name", list_id)),
            "description": str(warning_list.get("description", "")),
        }

    def _get_misp_types_for_ioc(self, ioc_type: str) -> list[str]:
        """Get MISP attribute types for a given IOC type."""
        # Special handling for IPs
        if ioc_type in ["ips", "ipv6"]:
            return [
                "ip-src",
                "ip-dst",
                "ip-src|port",
                "ip-dst|port",
                "domain|ip",
                "ip",
                "ip-range",
                "ipv4",
                "ipv6",
            ]

        # Special handling for hashes
        if ioc_type in ["md5", "sha1", "sha256", "sha512", "ssdeep", "imphash"]:
            return [
                ioc_type,
                f"filename|{ioc_type}",
                "hash",
                f"attachment|{ioc_type}",
                f"malware-sample|{ioc_type}",
            ]

        # Special handling for cryptocurrencies
        if ioc_type in ["bitcoin", "ethereum", "monero"]:
            return ["btc", "bitcoin", "cryptocurrency", ioc_type, "crypto-address", "xmr", "eth"]

        return self.MISP_TYPE_MAPPING.get(ioc_type, [ioc_type, "other", "text"])

    def _check_against_warning_list(
        self,
        clean_value: str,
        extracted_domain: str | None,
        warning_list: WarningListDict,
        list_id: str,
    ) -> dict[str, str] | None:
        """Check a value against a specific warning list."""
        type_val = warning_list.get("type", "string")
        list_type = str(type_val) if type_val is not None else "string"

        values_val = warning_list.get("list", [])
        if isinstance(values_val, list):
            values: list[IOCValue] = [str(v) if v is not None else None for v in values_val]
        else:
            values = []

        # Check with original value
        if self._check_value_in_list(clean_value, values, list_type):
            return self._build_warning_response(warning_list, list_id)

        # Also check the extracted domain for URLs
        if extracted_domain and self._check_value_in_list(extracted_domain, values, list_type):
            return self._build_warning_response(warning_list, list_id)

        return None

    def _get_relevant_list_ids(self, ioc_type: str) -> list[str]:
        """Return list IDs relevant to an IOC type."""
        relevant_list_ids = self.lookup_data.lists_by_ioc_type.get(ioc_type, [])
        if not relevant_list_ids:
            return list(self.warning_lists.keys())
        return relevant_list_ids

    def _check_string_lookups(
        self,
        clean_value_lower: str,
        extracted_domain: str | None,
        relevant_list_ids: list[str],
    ) -> dict[str, str] | None:
        """Check string lookup tables for a match."""
        string_lookups = self.lookup_data.string_lookups
        if clean_value_lower in string_lookups:
            for list_id in string_lookups[clean_value_lower]:
                if list_id in relevant_list_ids and list_id in self.warning_lists:
                    warning_list = self.warning_lists[list_id]
                    return self._build_warning_response(warning_list, list_id)

        if extracted_domain:
            domain_lower = extracted_domain.lower()
            if domain_lower in string_lookups:
                for list_id in string_lookups[domain_lower]:
                    if list_id in relevant_list_ids and list_id in self.warning_lists:
                        warning_list = self.warning_lists[list_id]
                        return self._build_warning_response(warning_list, list_id)
        return None

    def _check_regex_lookups(
        self,
        clean_value: str,
        extracted_domain: str | None,
        relevant_list_ids: list[str],
    ) -> dict[str, str] | None:
        """Check compiled regex lists for a match."""
        compiled_regex = self.lookup_data.compiled_regex
        for list_id in relevant_list_ids:
            if list_id not in compiled_regex or list_id not in self.warning_lists:
                continue
            for pattern in compiled_regex[list_id]:
                if pattern.search(clean_value):
                    warning_list = self.warning_lists[list_id]
                    return self._build_warning_response(warning_list, list_id)
                if extracted_domain and pattern.search(extracted_domain):
                    warning_list = self.warning_lists[list_id]
                    return self._build_warning_response(warning_list, list_id)
        return None

    def _check_cidr_lookups(
        self,
        clean_value: str,
        relevant_list_ids: list[str],
    ) -> dict[str, str] | None:
        """Check CIDR network lists for a match."""
        try:
            ip_obj = ipaddress.ip_address(clean_value)
        except (ValueError, ipaddress.AddressValueError):
            return None

        cidr_networks = self.lookup_data.cidr_networks
        for list_id in relevant_list_ids:
            if list_id not in cidr_networks or list_id not in self.warning_lists:
                continue
            for network in cidr_networks[list_id]:
                if ip_obj in network:
                    warning_list = self.warning_lists[list_id]
                    return self._build_warning_response(warning_list, list_id)
        return None

    def _check_substring_lists(
        self,
        clean_value: str,
        extracted_domain: str | None,
        relevant_list_ids: list[str],
        ioc_type: str,
    ) -> dict[str, str] | None:
        """Fallback checks for substring-based lists."""
        for list_id in relevant_list_ids:
            if list_id not in self.warning_lists:
                continue
            warning_list = self.warning_lists[list_id]
            if warning_list.get("type") != "substring":
                continue
            misp_types: list[str] = self._get_misp_types_for_ioc(ioc_type)
            if not self._is_list_applicable(warning_list, misp_types, ioc_type):
                continue
            result = self._check_against_warning_list(
                clean_value,
                extracted_domain,
                warning_list,
                list_id,
            )
            if result:
                return result
        return None

    @lru_cache(maxsize=5000)  # type: ignore[misc]
    def check_value(self, value: str, ioc_type: str) -> tuple[bool, dict[str, str] | None]:
        """
        Optimized check if a value is on any warning list.

        Args:
            value: The value to check
            ioc_type: The type of IOC (ip, domain, url, etc.)

        Returns:
            Tuple of (is_in_warning_list, warning_info_dict or None)
        """
        # Clean value for checking (remove defang markers)
        clean_value: str = self._clean_defanged_value(value)
        clean_value_lower = clean_value.lower()

        # Special handling for URLs - extract domain for checking
        extracted_domain: str | None = None
        if ioc_type == "urls":
            extracted_domain = self._extract_domain_from_url(clean_value)

        relevant_list_ids = self._get_relevant_list_ids(ioc_type)

        warning = self._check_string_lookups(
            clean_value_lower,
            extracted_domain,
            relevant_list_ids,
        )
        if warning:
            return True, warning

        warning = self._check_regex_lookups(
            clean_value,
            extracted_domain,
            relevant_list_ids,
        )
        if warning:
            return True, warning

        if ioc_type in ["ips", "ipv6"]:
            warning = self._check_cidr_lookups(clean_value, relevant_list_ids)
            if warning:
                return True, warning

        warning = self._check_substring_lists(
            clean_value,
            extracted_domain,
            relevant_list_ids,
            ioc_type,
        )
        return warning is not None, warning

    def _extract_domain_from_url(self, url: str) -> str | None:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
        except ValueError:
            logger.debug("Failed to parse URL for domain extraction: %s", url)
            return None
        if parsed.netloc:
            return parsed.netloc.split(":", 1)[0]  # Remove port
        return None

    def _is_list_applicable(
        self,
        warning_list: WarningListDict,
        misp_types: list[str],
        ioc_type: str,
    ) -> bool:
        """Check if a warning list is applicable for the given IOC type."""
        # Skip lists that don't have matching attributes
        matching_attrs = warning_list.get("matching_attributes")
        if not matching_attrs:
            return False

        # Ensure matching_attributes is a list of strings
        if not isinstance(matching_attrs, list):
            return False

        attrs_list: list[str] = []
        for attr in matching_attrs:
            if isinstance(attr, str):
                attrs_list.append(attr)
            elif isinstance(attr, dict) and "name" in attr:
                attrs_list.append(str(attr["name"]))

        if not attrs_list:
            return False

        # Check if any attribute type matches
        for misp_type in misp_types:
            for warning_attr in attrs_list:
                if (
                    misp_type.lower() in warning_attr.lower()
                    or warning_attr.lower() in misp_type.lower()
                ):
                    return True

        # Special case for CIDR lists with IPs
        list_type = warning_list.get("type")
        return ioc_type in ["ips", "ipv6"] and list_type == "cidr"

    def _check_string_type(self, value: str, values: list[IOCValue]) -> bool:
        """Check string type comparison."""
        return value.lower() in [str(v).lower() for v in values if v is not None]

    def _check_substring_type(self, value: str, values: list[IOCValue]) -> bool:
        """Check substring type comparison."""
        value_lower = value.lower()
        for list_value in values:
            if list_value is None:
                continue
            list_value_str = str(list_value).lower()
            # Check both directions
            if list_value_str in value_lower or value_lower in list_value_str:
                return True
        return False

    def _check_regex_type(self, value: str, values: list[IOCValue]) -> bool:
        """Check regex type comparison."""
        for regex_pattern in values:
            if regex_pattern is None:
                continue
            try:
                if re.search(str(regex_pattern), value, re.IGNORECASE):
                    return True
            except (re.error, TypeError):
                # Skip invalid regex patterns
                logger.debug("Invalid regex pattern: %s", regex_pattern)
                continue
        return False

    def _check_value_in_list(
        self,
        value: str,
        values: list[IOCValue],
        list_type: str,
    ) -> bool:
        """
        Check if a value is in a warning list.

        Args:
            value: The value to check
            values: The list of values to check against
            list_type: The type of comparison to perform (string, substring, regex, cidr)

        Returns:
            True if the value is in the list, False otherwise
        """
        if not values:
            return False

        check_methods = {
            "string": self._check_string_type,
            "substring": self._check_substring_type,
            "regex": self._check_regex_type,
            "cidr": self._check_cidr,
        }

        check_method = check_methods.get(list_type)
        if check_method:
            return check_method(value, values)

        return False

    def _check_cidr(self, ip_value: str, cidr_list: list[IOCValue]) -> bool:
        """
        Check if an IP address is in any CIDR range in the list.

        Args:
            ip_value: The IP address to check
            cidr_list: List of CIDR ranges or IP addresses

        Returns:
            True if the IP is in any range, False otherwise
        """
        try:
            # Parse the IP address
            ip_obj = ipaddress.ip_address(ip_value)

            for cidr_value in cidr_list:
                if cidr_value is None:
                    continue

                cidr_str = str(cidr_value)

                try:
                    # Check if it's a CIDR range
                    if "/" in cidr_str:
                        network = ipaddress.ip_network(cidr_str, strict=False)
                        if ip_obj in network:
                            return True
                    # Check exact match
                    elif ipaddress.ip_address(cidr_str) == ip_obj:
                        return True
                except (ValueError, ipaddress.AddressValueError):
                    # Skip invalid entries
                    logger.debug("Invalid CIDR/IP entry: %s", cidr_str)
                    continue

        except (ValueError, ipaddress.AddressValueError):
            # Not a valid IP address
            logger.debug("Invalid IP address: %s", ip_value)
            return False

        return False

    def get_warnings_for_iocs(
        self,
        iocs: dict[str, list[str | dict[str, str]]],
    ) -> dict[str, list[dict[str, str]]]:
        """
        Check all IOCs against warning lists and return warnings for any matches.

        Args:
            iocs: Dictionary with IOCs grouped by type

        Returns:
            Dictionary with warnings grouped by IOC type
        """
        warnings: dict[str, list[dict[str, str]]] = {}

        for ioc_type, ioc_list in iocs.items():
            type_warnings: list[dict[str, str]] = []

            for ioc in ioc_list:
                # If the IOC is a dictionary (like with hashes), use the 'value' key
                if isinstance(ioc, dict) and "value" in ioc:
                    value: str = str(ioc["value"])
                else:
                    value = str(ioc)

                in_warning_list, warning_info = self.check_value(value, ioc_type)
                if in_warning_list and warning_info:
                    warning_entry: dict[str, str] = {
                        "value": value,
                        "warning_list": warning_info["name"],
                        "description": warning_info["description"],
                    }
                    type_warnings.append(warning_entry)

            if type_warnings:
                warnings[ioc_type] = type_warnings

        return warnings

    def _extract_ioc_value(self, ioc: str | dict[str, str]) -> str:
        """Extract string value from IOC entry."""
        if isinstance(ioc, dict) and "value" in ioc:
            return str(ioc["value"])
        return str(ioc)

    def _build_warning_entry(
        self,
        value: str,
        warning_info: dict[str, str],
        ioc: str | dict[str, str],
    ) -> dict[str, str]:
        """Build warning entry preserving extra IOC metadata."""
        warning_entry: dict[str, str] = {
            "value": value,
            "warning_list": warning_info["name"],
            "description": warning_info["description"],
        }
        if isinstance(ioc, dict):
            for key, val in ioc.items():
                if key not in warning_entry:
                    warning_entry[key] = val
        return warning_entry

    def separate_iocs_by_warnings(
        self,
        iocs: dict[str, list[str | dict[str, str]]],
    ) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
        """
        Separate IOCs into normal IOCs and warning list IOCs.

        Args:
            iocs: Dictionary with IOCs grouped by type

        Returns:
            Tuple of (normal_iocs, warning_iocs) dictionaries
        """
        logger.info("Checking IOCs against MISP Warning Lists...")

        normal_iocs: dict[str, list[str | dict[str, str]]] = {}
        warning_iocs: dict[str, list[dict[str, str]]] = {}

        for ioc_type, ioc_list in iocs.items():
            normal_list: list[str | dict[str, str]] = []
            warning_list: list[dict[str, str]] = []

            for ioc in ioc_list:
                value = self._extract_ioc_value(ioc)

                if ioc_type == "emails" and self._email_domain_in_warning_list(value):
                    logger.info(
                        "Skipping email IOC due to warning-listed domain: %s",
                        value,
                    )
                    continue

                in_warning_list, warning_info = self.check_value(value, ioc_type)

                if in_warning_list and warning_info:
                    warning_list.append(self._build_warning_entry(value, warning_info, ioc))
                else:
                    # Add to normal list
                    normal_list.append(ioc)

            # Only add non-empty lists
            if normal_list:
                normal_iocs[ioc_type] = normal_list
            if warning_list:
                warning_iocs[ioc_type] = warning_list

        logger.info("IOCs verification against MISP Warning Lists completed")

        # Log statistics
        normal_count: int = sum(len(v) for v in normal_iocs.values())
        warning_count: int = sum(len(v) for v in warning_iocs.values())
        logger.info("Normal IOCs: %s, Warning IOCs: %s", normal_count, warning_count)

        return normal_iocs, warning_iocs
