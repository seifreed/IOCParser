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
from functools import lru_cache
from pathlib import Path
from typing import ClassVar, Union, cast
from urllib.parse import urlparse

import requests
from tqdm import tqdm

from iocparser.modules.logger import get_logger

# Type alias for cleaner code
WarningListValue = Union[str, list[str], list[dict[str, str]], int, bool]
WarningListDict = dict[str, WarningListValue]
IOCValue = Union[str, int, float, bool, None]
JSONValue = Union[str, int, bool, list[str], list[dict[str, str]], dict[str, str]]
JSONData = Union[dict[str, JSONValue], list[JSONValue]]

logger = get_logger(__name__)


class MISPWarningLists:
    """Class for managing MISP warning lists to detect false positives"""

    # Type alias for warning response
    WarningInfo = dict[str, str]

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

        self.github_api_base: str = (
            "https://api.github.com/repos/MISP/misp-warninglists/contents/lists"
        )
        self.github_raw_base: str = (
            "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"
        )

        # OPTIMIZATION: Pre-computed lookup structures
        self.string_lookups: dict[str, set[str]] = {}  # {value_lower: {list_ids}}
        self.compiled_regex: dict[str, list[re.Pattern[str]]] = {}  # {list_id: [compiled_patterns]}
        self.cidr_networks: dict[
            str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]
        ] = {}  # {list_id: [networks]}
        self.lists_by_ioc_type: dict[str, list[str]] = {}  # {ioc_type: [relevant_list_ids]}

        # Create the data directory if it doesn't exist
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load or update the lists
        self._load_or_update_lists()

        # OPTIMIZATION: Pre-process lists for faster lookups
        self._preprocess_lists()

    def _reset_cache_files(self) -> None:
        """Remove cache files when they are corrupted."""
        for cache_path in (self.cache_file, self.cache_metadata_file):
            try:
                cache_path.unlink(missing_ok=True)
            except Exception as cleanup_error:
                logger.debug(f"Could not remove cache file {cache_path}: {cleanup_error}")

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
                last_update: float = metadata.get("last_update", 0.0)
                current_time = time.time()

                # Check if the cache is up to date
                if current_time - last_update < self.cache_duration * 3600:
                    logger.info("Loading MISP warning lists from local cache...")
                    with self.cache_file.open() as f:
                        loaded_data: JSONData = json.load(f)
                        self.warning_lists = cast("dict[str, WarningListDict]", loaded_data)
                    logger.info(f"Loaded {len(self.warning_lists)} MISP warning lists from cache")
                    return
            except json.JSONDecodeError as e:
                logger.warning(f"Cache is corrupted (JSON decode error): {e}. Resetting cache.")
                self._reset_cache_files()
            except Exception as e:
                logger.warning(f"Failed to load cache: {e!s}")
                self._reset_cache_files()

        # If we get here, we need to update the lists
        self._update_warning_lists()

    def _update_warning_lists(self) -> None:
        """Update warning lists from the MISP GitHub repository"""
        try:
            logger.warning("Updating MISP warning lists from GitHub repository...")

            response = requests.get(self.github_api_base, timeout=30)
            response.raise_for_status()
            response_data: JSONData = response.json()
            directories: list[dict[str, str]] = cast("list[dict[str, str]]", response_data)

            # Get list of directories
            list_directories = [item["name"] for item in directories if item["type"] == "dir"]

            # Process each directory to get the warning list
            logger.info(f"Downloading {len(list_directories)} MISP warning lists...")
            failed_downloads: list[str] = []

            def _download_single_list(directory: str) -> tuple[str, WarningListDict | None]:
                """Download a single warning list."""
                try:
                    list_url = f"{self.github_raw_base}/{directory}/list.json"
                    list_response = requests.get(list_url, timeout=30)
                    list_response.raise_for_status()
                    response_json: JSONData = list_response.json()
                    result: WarningListDict = cast("WarningListDict", response_json)
                    return directory, result
                except Exception as e:
                    logger.warning(f"Error downloading warning list {directory}: {e}")
                    return directory, None

            # OPTIMIZATION: Use ThreadPoolExecutor for parallel downloads
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(_download_single_list, d) for d in list_directories]

                for future in tqdm(
                    as_completed(futures),
                    total=len(list_directories),
                    desc="Downloading warning lists",
                ):
                    directory, warning_list = future.result()
                    if warning_list is not None:
                        self.warning_lists[directory] = warning_list
                    else:
                        failed_downloads.append(directory)

            # Save lists to cache
            with self.cache_file.open("w") as f:
                json.dump(self.warning_lists, f)

            # Save cache metadata
            cache_data: dict[str, float] = {"last_update": time.time()}
            with self.cache_metadata_file.open("w") as f:
                json.dump(cache_data, f)

            # Report failed downloads
            if failed_downloads:
                logger.warning(
                    f"Failed to download {len(failed_downloads)} warning lists: "
                    f"{', '.join(failed_downloads[:10])}"
                    f"{' ...' if len(failed_downloads) > 10 else ''}"
                )

            logger.info(f"Successfully updated {len(self.warning_lists)} MISP warning lists")

        except Exception:
            logger.exception("Could not update warning lists")

            # If a cache is available, try to use it despite the error
            if self.cache_file.exists():
                try:
                    with self.cache_file.open() as f:
                        loaded_data: JSONData = json.load(f)
                        self.warning_lists = cast("dict[str, WarningListDict]", loaded_data)
                    logger.warning("Using cached warning lists")
                except Exception:
                    logger.exception("Could not load warning lists from cache")

    def _clear_preprocessed_data(self) -> None:
        """Clear all preprocessed data structures"""
        self.string_lookups.clear()
        self.compiled_regex.clear()
        self.cidr_networks.clear()
        self.lists_by_ioc_type.clear()

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

            # Pre-process based on list type
            if list_type == "string":
                # OPTIMIZATION: Create hash sets for O(1) lookups
                for value in values_val:
                    if value is not None:
                        value_lower = str(value).lower()
                        if value_lower not in self.string_lookups:
                            self.string_lookups[value_lower] = set()
                        self.string_lookups[value_lower].add(list_id)

            elif list_type == "regex":
                # OPTIMIZATION: Pre-compile regex patterns
                compiled_patterns: list[re.Pattern[str]] = []
                for pattern in values_val:
                    if pattern is not None:
                        try:
                            compiled_patterns.append(re.compile(str(pattern), re.IGNORECASE))
                        except (re.error, TypeError):
                            logger.debug(f"Invalid regex pattern: {pattern}")
                            continue
                if compiled_patterns:
                    self.compiled_regex[list_id] = compiled_patterns

            elif list_type == "cidr":
                # OPTIMIZATION: Pre-parse CIDR networks
                networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
                for cidr_value in values_val:
                    if cidr_value is not None and "/" in str(cidr_value):
                        try:
                            networks.append(ipaddress.ip_network(str(cidr_value), strict=False))
                        except (ValueError, ipaddress.AddressValueError):
                            logger.debug(f"Invalid CIDR entry: {cidr_value}")
                            continue
                if networks:
                    self.cidr_networks[list_id] = networks

            # OPTIMIZATION: Group lists by applicable IOC types
            matching_attrs = warning_list.get("matching_attributes", [])
            if isinstance(matching_attrs, list):
                for attr in matching_attrs:
                    attr_str = str(attr) if isinstance(attr, str) else str(attr.get("name", ""))

                    for keyword, ioc_type in self.IOC_TYPE_MAPPING.items():
                        if keyword in attr_str.lower():
                            if ioc_type not in self.lists_by_ioc_type:
                                self.lists_by_ioc_type[ioc_type] = []
                            if list_id not in self.lists_by_ioc_type[ioc_type]:
                                self.lists_by_ioc_type[ioc_type].append(list_id)

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

        # OPTIMIZATION: Only check relevant lists for this IOC type
        relevant_list_ids = self.lists_by_ioc_type.get(ioc_type, [])

        # Also check all lists if no specific mapping found
        if not relevant_list_ids:
            relevant_list_ids = list(self.warning_lists.keys())

        # Special handling for URLs - extract domain for checking
        extracted_domain: str | None = None
        if ioc_type == "urls":
            extracted_domain = self._extract_domain_from_url(clean_value)

        # OPTIMIZATION: Check string lookups first (fastest)
        if clean_value_lower in self.string_lookups:
            for list_id in self.string_lookups[clean_value_lower]:
                if list_id in relevant_list_ids and list_id in self.warning_lists:
                    warning_list = self.warning_lists[list_id]
                    return True, self._build_warning_response(warning_list, list_id)

        # Also check extracted domain for URLs
        if extracted_domain and extracted_domain.lower() in self.string_lookups:
            for list_id in self.string_lookups[extracted_domain.lower()]:
                if list_id in relevant_list_ids and list_id in self.warning_lists:
                    warning_list = self.warning_lists[list_id]
                    return True, self._build_warning_response(warning_list, list_id)

        # Check regex patterns (slower)
        for list_id in relevant_list_ids:
            if list_id in self.compiled_regex and list_id in self.warning_lists:
                for pattern in self.compiled_regex[list_id]:
                    if pattern.search(clean_value):
                        warning_list = self.warning_lists[list_id]
                        return True, self._build_warning_response(warning_list, list_id)
                    if extracted_domain and pattern.search(extracted_domain):
                        warning_list = self.warning_lists[list_id]
                        return True, self._build_warning_response(warning_list, list_id)

        # Check CIDR ranges for IPs
        if ioc_type in ["ips", "ipv6"]:
            try:
                ip_obj = ipaddress.ip_address(clean_value)
                for list_id in relevant_list_ids:
                    if list_id in self.cidr_networks and list_id in self.warning_lists:
                        for network in self.cidr_networks[list_id]:
                            if ip_obj in network:
                                warning_list = self.warning_lists[list_id]
                                return True, self._build_warning_response(warning_list, list_id)
            except (ValueError, ipaddress.AddressValueError):
                pass

        # Fallback to old method for any lists not preprocessed (substring type)
        for list_id in relevant_list_ids:
            if list_id not in self.warning_lists:
                continue
            warning_list = self.warning_lists[list_id]
            if warning_list.get("type") == "substring":
                misp_types: list[str] = self._get_misp_types_for_ioc(ioc_type)
                if self._is_list_applicable(warning_list, misp_types, ioc_type):
                    result = self._check_against_warning_list(
                        clean_value,
                        extracted_domain,
                        warning_list,
                        list_id,
                    )
                    if result:
                        return True, result

        return False, None

    def _extract_domain_from_url(self, url: str) -> str | None:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                return parsed.netloc.split(":")[0]  # Remove port
        except Exception:
            logger.debug("Failed to parse URL for domain extraction")
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
                logger.debug(f"Invalid regex pattern: {regex_pattern}")
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
                    logger.debug(f"Invalid CIDR/IP entry: {cidr_str}")
                    continue

        except (ValueError, ipaddress.AddressValueError):
            # Not a valid IP address
            logger.debug(f"Invalid IP address: {ip_value}")
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
                # Handle dictionary IOCs
                value: str = ioc["value"] if isinstance(ioc, dict) and "value" in ioc else str(ioc)

                in_warning_list, warning_info = self.check_value(value, ioc_type)

                if in_warning_list and warning_info:
                    # Add to warning list
                    warning_entry: dict[str, str] = {
                        "value": value,
                        "warning_list": warning_info["name"],
                        "description": warning_info["description"],
                    }

                    # Preserve additional fields if IOC is a dict
                    if isinstance(ioc, dict):
                        for key in ioc:
                            if key not in warning_entry:
                                warning_entry[key] = ioc[key]

                    warning_list.append(warning_entry)
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
        logger.info(f"Normal IOCs: {normal_count}, Warning IOCs: {warning_count}")

        return normal_iocs, warning_iocs

    def _is_list_relevant_for_expected(
        self,
        name: str,
        description: str,
        expected_lists: list[str] | None,
    ) -> bool:
        """Check if list is relevant based on expected lists."""
        if not expected_lists:
            return False
        return any(
            expected.lower() in name.lower() or expected.lower() in description.lower()
            for expected in expected_lists
        )

    def _is_list_relevant_for_type(
        self,
        name: str,
        description: str,
        ioc_type: str,
    ) -> bool:
        """Check if list is relevant based on IOC type."""
        if ioc_type not in self.TYPE_KEYWORDS:
            return False

        name_lower = name.lower()
        desc_lower = description.lower()
        return any(
            keyword in name_lower or keyword in desc_lower
            for keyword in self.TYPE_KEYWORDS[ioc_type]
        )

    def diagnose_value_detection(
        self,
        value: str,
        ioc_type: str,
        expected_lists: list[str] | None = None,
    ) -> None:
        """
        Diagnostic tool to understand why a value is or isn't detected in MISP lists.

        Args:
            value: The value to diagnose
            ioc_type: The type of IOC
            expected_lists: Optional list of expected warning list names
        """

        # Internal diagnostic helper functions (only used within this method)
        def log_matched_value(clean_val: str, vals: list[IOCValue]) -> None:
            """Log which specific entry matched."""
            for v in vals:
                if str(v).lower() == clean_val.lower():
                    logger.info(f"    Matched: {v}")
                    break

        def log_list_check_result(
            clean_val: str,
            warning_list: WarningListDict,
            list_id: str,
            vals: list[IOCValue],
        ) -> None:
            """Log the result of checking a value against a warning list."""
            name = warning_list.get("name", list_id)
            list_type = warning_list.get("type", "string")
            matching_attrs = warning_list.get("matching_attributes", [])

            logger.info(f"\nChecking list: {name}")
            logger.info(f"  Type: {list_type}")
            logger.info(f"  Matching attributes: {matching_attrs}")
            logger.info(f"  Number of values: {len(vals)}")

            list_type_str = str(list_type) if list_type is not None else "string"
            if self._check_value_in_list(clean_val, vals, list_type_str):
                logger.info("  ✓ VALUE FOUND IN THIS LIST")
                if list_type == "string":
                    log_matched_value(clean_val, vals)
            else:
                logger.info("  ✗ Value not in this list")
                if vals:
                    logger.info(f"    Sample values: {vals[:3]}")

        logger.info(f"Diagnosing detection for {value} (type: {ioc_type})")

        clean_value = self._clean_defanged_value(value)
        logger.info(f"Cleaned value: {clean_value}")

        # Find relevant lists
        relevant_lists: list[tuple[str, WarningListDict]] = []
        for list_id, warning_list in self.warning_lists.items():
            name_val = warning_list.get("name", "")
            desc_val = warning_list.get("description", "")
            name = str(name_val) if name_val is not None else ""
            description = str(desc_val) if desc_val is not None else ""

            is_relevant = self._is_list_relevant_for_expected(
                name, description, expected_lists
            ) or self._is_list_relevant_for_type(name, description, ioc_type)

            if is_relevant:
                relevant_lists.append((list_id, warning_list))

        logger.info(f"Found {len(relevant_lists)} potentially relevant lists")

        # Check each relevant list
        for list_id, warning_list in relevant_lists:
            values_raw = warning_list.get("list", [])
            # Convert values to proper type, handling None values
            if isinstance(values_raw, list):
                values: list[IOCValue] = [str(v) if v is not None else None for v in values_raw]
            else:
                values = []
            log_list_check_result(clean_value, warning_list, list_id, values)

        # Final check using the main method
        in_warning_list, warning_info = self.check_value(value, ioc_type)
        if in_warning_list and warning_info:
            logger.info(f"\n✓ FINAL RESULT: Value IS in warning list: {warning_info['name']}")
        else:
            logger.info("\n✗ FINAL RESULT: Value is NOT in any warning list")
