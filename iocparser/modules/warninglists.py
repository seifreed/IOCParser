#!/usr/bin/env python3

"""
Module for managing MISP warning lists to detect false positives

Author: Marc Rivero | @seifreed
"""

import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, cast
from urllib.parse import urlparse

import requests
from tqdm import tqdm

from iocparser.modules.logger import get_logger

# Type alias for cleaner code
WarningListValue = Union[str, List[str], List[Dict[str, str]], int, bool]
WarningListDict = Dict[str, WarningListValue]
IOCValue = Union[str, int, float, bool, None]
JSONValue = Union[str, int, bool, List[str], List[Dict[str, str]], Dict[str, str]]
JSONData = Union[Dict[str, JSONValue], List[JSONValue]]

logger = get_logger(__name__)


class MISPWarningLists:
    """Class for managing MISP warning lists to detect false positives"""

    def __init__(self, cache_duration: int = 24, force_update: bool = False) -> None:
        """
        Initialize the warning lists manager.

        Args:
            cache_duration: Duration in hours to keep the local cache before updating
            force_update: If True, force update regardless of cache age
        """
        self.cache_duration: int = cache_duration  # hours
        self.force_update: bool = force_update
        self.warning_lists: Dict[str, WarningListDict] = {}

        # Fix: Use Path for better path handling
        self.data_dir: Path = Path(__file__).parent / 'data'
        self.cache_file: Path = self.data_dir / 'misp_warninglists_cache.json'
        self.cache_metadata_file: Path = self.data_dir / 'misp_warninglists_metadata.json'

        self.github_api_base: str = "https://api.github.com/repos/MISP/misp-warninglists/contents/lists"
        self.github_raw_base: str = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"

        # Create the data directory if it doesn't exist
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load or update the lists
        self._load_or_update_lists()

    def _load_or_update_lists(self) -> None:
        """Load lists from cache or update them if necessary"""
        # Check if cache exists and its age
        if (not self.force_update and
            self.cache_duration > 0 and
            self.cache_file.exists() and
            self.cache_metadata_file.exists()):
            try:
                with self.cache_metadata_file.open() as f:
                    metadata: Dict[str, float] = json.load(f)
                last_update: float = metadata.get('last_update', 0.0)
                current_time = time.time()

                # Check if the cache is up to date
                if current_time - last_update < self.cache_duration * 3600:
                    logger.info("Loading MISP warning lists from local cache...")
                    with self.cache_file.open() as f:
                        loaded_data: JSONData = json.load(f)
                        self.warning_lists = cast('Dict[str, WarningListDict]', loaded_data)
                    logger.info(f"Loaded {len(self.warning_lists)} MISP warning lists from cache")
                    return
            except Exception as e:
                logger.warning(f"Failed to load cache: {e!s}")

        # If we get here, we need to update the lists
        self._update_warning_lists()

    def _update_warning_lists(self) -> None:
        """Update warning lists from the MISP GitHub repository"""
        try:
            logger.warning("Updating MISP warning lists from GitHub repository...")

            response = requests.get(self.github_api_base, timeout=30)
            response.raise_for_status()
            response_data: JSONData = response.json()
            directories: List[Dict[str, str]] = cast('List[Dict[str, str]]', response_data)

            # Get list of directories
            list_directories = [item['name'] for item in directories if item['type'] == 'dir']

            # Process each directory to get the warning list
            logger.info(f"Downloading {len(list_directories)} MISP warning lists...")
            failed_downloads: List[str] = []

            def _download_single_list(directory: str) -> Optional[WarningListDict]:
                """Download a single warning list."""
                try:
                    list_url = f"{self.github_raw_base}/{directory}/list.json"
                    list_response = requests.get(list_url, timeout=30)
                    list_response.raise_for_status()
                except Exception as e:
                    logger.warning(f"Error downloading warning list {directory}: {e}")
                    return None
                else:
                    response_json: JSONData = list_response.json()
                    result: WarningListDict = cast('WarningListDict', response_json)
                    return result

            directory_progress: tqdm[str] = tqdm(
                list_directories, desc="Downloading warning lists", unit="list",
            )
            for directory in directory_progress:
                warning_list = _download_single_list(directory)
                if warning_list is not None:
                    self.warning_lists[directory] = warning_list
                else:
                    failed_downloads.append(directory)

            # Save lists to cache
            with self.cache_file.open('w') as f:
                json.dump(self.warning_lists, f)

            # Save cache metadata
            cache_data: Dict[str, float] = {'last_update': time.time()}
            with self.cache_metadata_file.open('w') as f:
                json.dump(cache_data, f)

            logger.info(f"Successfully updated {len(self.warning_lists)} MISP warning lists")

        except Exception:
            logger.exception("Could not update warning lists")

            # If a cache is available, try to use it despite the error
            if self.cache_file.exists():
                try:
                    with self.cache_file.open() as f:
                        loaded_data: JSONData = json.load(f)
                        self.warning_lists = cast('Dict[str, WarningListDict]', loaded_data)
                    logger.warning("Using cached warning lists")
                except Exception:
                    logger.exception("Could not load warning lists from cache")

    def _clean_defanged_value(self, value: str) -> str:
        """
        Remove common defanging patterns from a value.

        Args:
            value: The value to clean

        Returns:
            Cleaned value
        """
        cleaners: List[Tuple[str, str]] = [
            ('[.]', '.'), ('(.)', '.'), ('{.}', '.'),
            ('[:]', ':'), ('(:)', ':'), ('{:}', ':'),
            ('[@ ]', '@'), ('(@)', '@'), ('{@}', '@'),
            ('[//]', '//'), ('{//}', '//'),
            ('[/]', '/'), ('{/}', '/'),
            ('hxxp://', 'http://'), ('hxxps://', 'https://'),
            ('hXXp://', 'http://'), ('hXXps://', 'https://'),
            ('h__p://', 'http://'), ('h__ps://', 'https://'),
        ]

        clean_value: str = value
        for old, new in cleaners:
            clean_value = clean_value.replace(old, new)

        return clean_value

    def _get_misp_types_for_ioc(self, ioc_type: str) -> List[str]:
        """Get MISP attribute types for a given IOC type."""
        type_mapping = {
            'domains': ['hostname', 'domain', 'domain|ip', 'fqdn'],
            'urls': ['url', 'uri', 'link', 'uri-path'],
            'emails': ['email', 'email-src', 'email-dst', 'target-email',
                      'email-address', 'email-subject'],
            'cves': ['vulnerability', 'cve', 'weakness'],
            'mitre_attack': ['mitre-attack-pattern', 'attack-pattern', 'technique'],
        }

        # Special handling for IPs
        if ioc_type in ['ips', 'ipv6']:
            return ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port',
                   'domain|ip', 'ip', 'ip-range', 'ipv4', 'ipv6']

        # Special handling for hashes
        if ioc_type in ['md5', 'sha1', 'sha256', 'sha512', 'ssdeep', 'imphash']:
            return [ioc_type, f'filename|{ioc_type}', 'hash',
                   f'attachment|{ioc_type}', f'malware-sample|{ioc_type}']

        # Special handling for cryptocurrencies
        if ioc_type in ['bitcoin', 'ethereum', 'monero']:
            return ['btc', 'bitcoin', 'cryptocurrency', ioc_type,
                   'crypto-address', 'xmr', 'eth']

        return type_mapping.get(ioc_type, [ioc_type, 'other', 'text'])

    def _check_against_warning_list(
        self,
        clean_value: str,
        extracted_domain: Optional[str],
        warning_list: WarningListDict,
        list_id: str,
    ) -> Optional[Dict[str, str]]:
        """Check a value against a specific warning list."""
        name_val = warning_list.get('name', list_id)
        name = str(name_val) if name_val is not None else list_id

        desc_val = warning_list.get('description', '')
        description = str(desc_val) if desc_val is not None else ''

        type_val = warning_list.get('type', 'string')
        list_type = str(type_val) if type_val is not None else 'string'

        values_val = warning_list.get('list', [])
        if isinstance(values_val, list):
            values: List[IOCValue] = [str(v) if v is not None else None for v in values_val]
        else:
            values = []

        # Check with original value
        if self._check_value_in_list(clean_value, values, list_type):
            return {'name': name, 'description': description}

        # Also check the extracted domain for URLs
        if extracted_domain and self._check_value_in_list(extracted_domain, values, list_type):
            return {'name': name, 'description': description}

        return None

    def check_value(self, value: str, ioc_type: str) -> Tuple[bool, Optional[Dict[str, str]]]:
        """
        Check if a value is on any warning list.

        Args:
            value: The value to check
            ioc_type: The type of IOC (ip, domain, url, etc.)

        Returns:
            Tuple of (is_in_warning_list, warning_info_dict or None)
        """
        misp_types: List[str] = self._get_misp_types_for_ioc(ioc_type)

        # Clean value for checking (remove defang markers)
        clean_value: str = self._clean_defanged_value(value)

        # Special handling for URLs - extract domain for checking
        extracted_domain: Optional[str] = None
        if ioc_type == 'urls':
            extracted_domain = self._extract_domain_from_url(clean_value)

        # Check each MISP list
        for list_id, warning_list in self.warning_lists.items():
            if not self._is_list_applicable(warning_list, misp_types, ioc_type):
                continue

            result = self._check_against_warning_list(
                clean_value, extracted_domain, warning_list, list_id,
            )
            if result:
                return True, result

        return False, None

    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                return parsed.netloc.split(':')[0]  # Remove port
        except Exception:
            logger.debug("Failed to parse URL for domain extraction")
        return None

    def _is_list_applicable(
        self, warning_list: WarningListDict, misp_types: List[str], ioc_type: str,
    ) -> bool:
        """Check if a warning list is applicable for the given IOC type."""
        # Skip lists that don't have matching attributes
        matching_attrs = warning_list.get('matching_attributes')
        if not matching_attrs:
            return False

        # Ensure matching_attributes is a list of strings
        if not isinstance(matching_attrs, list):
            return False

        attrs_list: List[str] = []
        for attr in matching_attrs:
            if isinstance(attr, str):
                attrs_list.append(attr)
            elif isinstance(attr, dict) and 'name' in attr:
                attrs_list.append(str(attr['name']))

        if not attrs_list:
            return False

        # Check if any attribute type matches
        for misp_type in misp_types:
            for warning_attr in attrs_list:
                if (misp_type.lower() in warning_attr.lower() or
                    warning_attr.lower() in misp_type.lower()):
                    return True

        # Special case for CIDR lists with IPs
        list_type = warning_list.get('type')
        return ioc_type in ['ips', 'ipv6'] and list_type == 'cidr'

    def _check_string_type(self, value: str, values: List[IOCValue]) -> bool:
        """Check string type comparison."""
        return value.lower() in [str(v).lower() for v in values if v is not None]

    def _check_substring_type(self, value: str, values: List[IOCValue]) -> bool:
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

    def _check_regex_type(self, value: str, values: List[IOCValue]) -> bool:
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
        self, value: str, values: List[IOCValue], list_type: str,
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
            'string': self._check_string_type,
            'substring': self._check_substring_type,
            'regex': self._check_regex_type,
            'cidr': self._check_cidr,
        }

        check_method = check_methods.get(list_type)
        if check_method:
            return check_method(value, values)

        return False

    def _check_cidr(self, ip_value: str, cidr_list: List[IOCValue]) -> bool:
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
                    if '/' in cidr_str:
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
        self, iocs: Dict[str, List[Union[str, Dict[str, str]]]],
    ) -> Dict[str, List[Dict[str, str]]]:
        """
        Check all IOCs against warning lists and return warnings for any matches.

        Args:
            iocs: Dictionary with IOCs grouped by type

        Returns:
            Dictionary with warnings grouped by IOC type
        """
        warnings: Dict[str, List[Dict[str, str]]] = {}

        for ioc_type, ioc_list in iocs.items():
            type_warnings: List[Dict[str, str]] = []

            for ioc in ioc_list:
                # If the IOC is a dictionary (like with hashes), use the 'value' key
                if isinstance(ioc, dict) and 'value' in ioc:
                    value: str = str(ioc['value'])
                else:
                    value = str(ioc)

                in_warning_list, warning_info = self.check_value(value, ioc_type)
                if in_warning_list and warning_info:
                    warning_entry: Dict[str, str] = {
                        'value': value,
                        'warning_list': warning_info['name'],
                        'description': warning_info['description'],
                    }
                    type_warnings.append(warning_entry)

            if type_warnings:
                warnings[ioc_type] = type_warnings

        return warnings

    def separate_iocs_by_warnings(
        self,
        iocs: Dict[str, List[Union[str, Dict[str, str]]]],
    ) -> Tuple[Dict[str, List[Union[str, Dict[str, str]]]], Dict[str, List[Dict[str, str]]]]:
        """
        Separate IOCs into normal IOCs and warning list IOCs.

        Args:
            iocs: Dictionary with IOCs grouped by type

        Returns:
            Tuple of (normal_iocs, warning_iocs) dictionaries
        """
        logger.info("Checking IOCs against MISP Warning Lists...")

        normal_iocs: Dict[str, List[Union[str, Dict[str, str]]]] = {}
        warning_iocs: Dict[str, List[Dict[str, str]]] = {}

        for ioc_type, ioc_list in iocs.items():
            normal_list: List[Union[str, Dict[str, str]]] = []
            warning_list: List[Dict[str, str]] = []

            for ioc in ioc_list:
                # Handle dictionary IOCs
                value: str = ioc['value'] if isinstance(ioc, dict) and 'value' in ioc else str(ioc)

                in_warning_list, warning_info = self.check_value(value, ioc_type)

                if in_warning_list and warning_info:
                    # Add to warning list
                    warning_entry: Dict[str, str] = {
                        'value': value,
                        'warning_list': warning_info['name'],
                        'description': warning_info['description'],
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
        self, name: str, description: str, expected_lists: Optional[List[str]],
    ) -> bool:
        """Check if list is relevant based on expected lists."""
        if not expected_lists:
            return False
        return any(
            expected.lower() in name.lower() or expected.lower() in description.lower()
            for expected in expected_lists
        )

    def _is_list_relevant_for_type(
        self, name: str, description: str, ioc_type: str,
    ) -> bool:
        """Check if list is relevant based on IOC type."""
        type_keywords: Dict[str, List[str]] = {
            'ips': ['ip', 'address', 'ipv4', 'ipv6', 'cidr'],
            'domains': ['domain', 'hostname', 'fqdn', 'dns'],
            'urls': ['url', 'uri', 'link'],
            'emails': ['email', 'mail'],
            'cves': ['cve', 'vulnerability'],
        }

        if ioc_type not in type_keywords:
            return False

        name_lower = name.lower()
        desc_lower = description.lower()
        return any(
            keyword in name_lower or keyword in desc_lower
            for keyword in type_keywords[ioc_type]
        )

    def _log_list_check_result(
        self,
        clean_value: str,
        warning_list: WarningListDict,
        list_id: str,
        values: List[IOCValue],
    ) -> None:
        """Log the result of checking a value against a warning list."""
        name = warning_list.get('name', list_id)
        list_type = warning_list.get('type', 'string')
        matching_attrs = warning_list.get('matching_attributes', [])

        logger.info(f"\nChecking list: {name}")
        logger.info(f"  Type: {list_type}")
        logger.info(f"  Matching attributes: {matching_attrs}")
        logger.info(f"  Number of values: {len(values)}")

        list_type_str = str(list_type) if list_type is not None else 'string'
        if self._check_value_in_list(clean_value, values, list_type_str):
            logger.info("  ✓ VALUE FOUND IN THIS LIST")
            if list_type == 'string':
                self._log_matched_value(clean_value, values)
        else:
            logger.info("  ✗ Value not in this list")
            if values:
                logger.info(f"    Sample values: {values[:3]}")

    def _log_matched_value(self, clean_value: str, values: List[IOCValue]) -> None:
        """Log which specific entry matched."""
        for v in values:
            if str(v).lower() == clean_value.lower():
                logger.info(f"    Matched: {v}")
                break

    def diagnose_value_detection(
        self,
        value: str,
        ioc_type: str,
        expected_lists: Optional[List[str]] = None,
    ) -> None:
        """
        Diagnostic tool to understand why a value is or isn't detected in MISP lists.

        Args:
            value: The value to diagnose
            ioc_type: The type of IOC
            expected_lists: Optional list of expected warning list names
        """
        logger.info(f"Diagnosing detection for {value} (type: {ioc_type})")

        clean_value = self._clean_defanged_value(value)
        logger.info(f"Cleaned value: {clean_value}")

        # Find relevant lists
        relevant_lists: List[Tuple[str, WarningListDict]] = []
        for list_id, warning_list in self.warning_lists.items():
            name_val = warning_list.get('name', '')
            desc_val = warning_list.get('description', '')
            name = str(name_val) if name_val is not None else ''
            description = str(desc_val) if desc_val is not None else ''

            is_relevant = (
                self._is_list_relevant_for_expected(name, description, expected_lists) or
                self._is_list_relevant_for_type(name, description, ioc_type)
            )

            if is_relevant:
                relevant_lists.append((list_id, warning_list))

        logger.info(f"Found {len(relevant_lists)} potentially relevant lists")

        # Check each relevant list
        for list_id, warning_list in relevant_lists:
            values_raw = warning_list.get('list', [])
            # Convert values to proper type, handling None values
            if isinstance(values_raw, list):
                values: List[IOCValue] = [str(v) if v is not None else None for v in values_raw]
            else:
                values = []
            self._log_list_check_result(clean_value, warning_list, list_id, values)

        # Final check using the main method
        in_warning_list, warning_info = self.check_value(value, ioc_type)
        if in_warning_list and warning_info:
            logger.info(f"\n✓ FINAL RESULT: Value IS in warning list: {warning_info['name']}")
        else:
            logger.info("\n✗ FINAL RESULT: Value is NOT in any warning list")
