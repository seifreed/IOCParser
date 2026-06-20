from __future__ import annotations

import ipaddress
from abc import abstractmethod
from logging import Logger
from typing import ClassVar
from urllib.parse import urlparse

from iocparser.domain.enums import IOCType, ioc_type_name
from iocparser.infrastructure.logger import get_logger
from iocparser.infrastructure.warninglists_match_checks import (
    check_cidr as _check_cidr_value,
)
from iocparser.infrastructure.warninglists_match_checks import (
    check_regex_type as _check_regex_value_type,
)
from iocparser.infrastructure.warninglists_match_checks import (
    check_string_type as _check_string_value_type,
)
from iocparser.infrastructure.warninglists_match_checks import (
    check_substring_type as _check_substring_value_type,
)
from iocparser.infrastructure.warninglists_match_checks import (
    check_value_in_list as _check_value_against_list_type,
)
from iocparser.infrastructure.warninglists_match_separation import (
    extract_ioc_value,
)
from iocparser.infrastructure.warninglists_match_separation import (
    get_warnings_for_iocs as _get_warnings_for_iocs,
)
from iocparser.infrastructure.warninglists_match_separation import (
    separate_iocs_by_warnings as _separate_iocs_by_warnings,
)
from iocparser.infrastructure.warninglists_types import (
    IOCValue,
    WarningListDict,
    WarningListLookups,
    get_mixin_logger,
    matching_attribute_name,
)

logger = get_logger("iocparser.infrastructure.warninglists")


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Expected {field} to be string, got {type(value).__name__}")
    return value


class WarningListMatchingMixin:
    """Value matching and IOC separation support for warning lists."""

    logger: Logger
    warning_lists: dict[str, WarningListDict]
    lookup_data: WarningListLookups
    IOC_TYPE_MAPPING: ClassVar[dict[str, str]]
    MISP_TYPE_MAPPING: ClassVar[dict[str, list[str]]]
    _warning_lookup_cache: dict[tuple[str, str], tuple[bool, dict[str, str] | None]]

    @abstractmethod
    def _clean_defanged_value(self, value: str) -> str:
        raise NotImplementedError

    def _get_logger(self) -> Logger:
        return get_mixin_logger(self, logger)

    def _ensure_warning_lookup_cache(
        self,
    ) -> dict[tuple[str, str], tuple[bool, dict[str, str] | None]]:
        try:
            return self._warning_lookup_cache
        except AttributeError:
            cache: dict[tuple[str, str], tuple[bool, dict[str, str] | None]] = {}
            self._warning_lookup_cache = cache
            return cache

    def _extract_email_domain(self, value: str) -> str | None:
        cleaned = self._clean_defanged_value(value)
        if "@" not in cleaned:
            return None
        domain = cleaned.rsplit("@", 1)[1].strip()
        return domain or None

    def _email_domain_in_warning_list(self, value: str) -> tuple[bool, dict[str, str] | None]:
        domain = self._extract_email_domain(value)
        if not domain:
            return False, None
        return self.check_value(domain, "domains")

    def _build_warning_response(
        self,
        warning_list: WarningListDict,
        list_id: str,
    ) -> dict[str, str]:
        return {
            "name": _require_str(warning_list.get("name", list_id), field="name"),
            "description": _require_str(warning_list.get("description", ""), field="description"),
        }

    def _get_misp_types_for_ioc(self, ioc_type: str) -> list[str]:
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
        if ioc_type in ["md5", "sha1", "sha256", "sha512", "ssdeep", "imphash"]:
            return [
                ioc_type,
                f"filename|{ioc_type}",
                "hash",
                f"attachment|{ioc_type}",
                f"malware-sample|{ioc_type}",
            ]
        if ioc_type in ["bitcoin", "ethereum", "monero"]:
            return ["btc", "bitcoin", "cryptocurrency", ioc_type, "crypto-address", "xmr", "eth"]
        mapped = self.MISP_TYPE_MAPPING.get(ioc_type)
        return mapped if mapped is not None else [ioc_type, "other", "text"]

    def _check_against_warning_list(
        self,
        clean_value: str,
        extracted_domain: str | None,
        warning_list: WarningListDict,
        list_id: str,
    ) -> dict[str, str] | None:
        list_type = _require_str(warning_list.get("type", "string"), field="type")
        values_val = warning_list.get("list", [])
        if isinstance(values_val, list):
            values: list[IOCValue] = [
                _require_str(v, field="warning list entry") if v is not None else None
                for v in values_val
            ]
        else:
            values = []
        if self._check_value_in_list(clean_value, values, list_type):
            return self._build_warning_response(warning_list, list_id)
        if extracted_domain and self._check_value_in_list(extracted_domain, values, list_type):
            return self._build_warning_response(warning_list, list_id)
        return None

    def _get_relevant_list_ids(self, ioc_type: str) -> list[str]:
        return self.lookup_data.lists_by_ioc_type.get(ioc_type, [])

    def _get_all_list_ids(self) -> list[str]:
        return list(self.warning_lists.keys())

    def _matching_attribute_names(self, warning_list: WarningListDict) -> list[str]:
        matching_attrs = warning_list.get("matching_attributes")
        if not isinstance(matching_attrs, list):
            return []
        def _names() -> list[str]:
            names: list[str] = []
            for attr in matching_attrs:
                try:
                    names.append(matching_attribute_name(attr))
                except TypeError:
                    continue
            return names

        names = _names()
        return [name for name in names if name.strip()]

    def _get_unscoped_list_ids(self) -> list[str]:
        # A scoped list is only reachable if it was indexed under some IOC type by
        # its matching_attributes. Attributes that map to no known IOC type (e.g.
        # azure-application-id) would otherwise leave the list dead — never a
        # candidate for any value. Fall back to checking such lists globally, the
        # same way truly unscoped lists are checked.
        indexed_list_ids = {
            list_id
            for list_ids in self.lookup_data.lists_by_ioc_type.values()
            for list_id in list_ids
        }
        return [
            list_id
            for list_id, warning_list in self.warning_lists.items()
            if not self._matching_attribute_names(warning_list)
            or list_id not in indexed_list_ids
        ]

    def _is_known_ioc_type(self, ioc_type: str) -> bool:
        known_types = {known_type.value for known_type in IOCType}
        known_types.update(self.IOC_TYPE_MAPPING.values())
        known_types.update(self.MISP_TYPE_MAPPING)
        return ioc_type in known_types

    def _get_candidate_list_ids(self, ioc_type: str) -> list[str]:
        try:
            ioc_type = ioc_type_name(IOCType.from_name(ioc_type))
        except ValueError:
            ioc_type = ioc_type.strip().lower()
        related_types = [ioc_type]
        if ioc_type == "hosts":
            related_types.append("domains")
        if ioc_type in {"urls", "emails"}:
            related_types.append("domains")
        elif ioc_type == "ips":
            related_types.append("ipv6")
        elif ioc_type == "ipv6":
            # MISP ip-src/ip-dst lists are indexed under "ips" but apply to IPv6 too;
            # the CIDR/string match is address-family-safe, so this cannot false-match.
            related_types.append("ips")
        relevant_list_ids = [
            list_id
            for related_type in related_types
            for list_id in self._get_relevant_list_ids(related_type)
        ]
        if not self._is_known_ioc_type(ioc_type):
            return relevant_list_ids if relevant_list_ids else self._get_all_list_ids()
        return list(dict.fromkeys([*relevant_list_ids, *self._get_unscoped_list_ids()]))

    def _check_string_lookups(
        self,
        clean_value_lower: str,
        extracted_domain: str | None,
        relevant_list_ids: list[str],
    ) -> dict[str, str] | None:
        string_lookups = self.lookup_data.string_lookups
        domain_lower = extracted_domain.lower() if extracted_domain else None
        for candidate in (clean_value_lower, domain_lower):
            if candidate is None or candidate not in string_lookups:
                continue
            matching = string_lookups[candidate]
            # Iterate relevant_list_ids (ordered) rather than the lookup's set so the
            # chosen list is deterministic across runs when a value is in several
            # lists -- a set's iteration order varies under hash randomization and
            # produced unstable warning-source output (spurious diff churn).
            for list_id in relevant_list_ids:
                if list_id in matching and list_id in self.warning_lists:
                    return self._build_warning_response(self.warning_lists[list_id], list_id)
        return self._check_suffix_lookups((clean_value_lower, domain_lower), relevant_list_ids)

    def _check_suffix_lookups(
        self,
        candidates: tuple[str | None, str | None],
        relevant_list_ids: list[str],
    ) -> dict[str, str] | None:
        """Match leading-dot hostname entries (apex + every subdomain) by parent suffix."""
        suffix_lookups = self.lookup_data.suffix_lookups
        if not suffix_lookups:
            return None
        for candidate in candidates:
            if candidate is None:
                continue
            labels = candidate.split(".")
            for index in range(len(labels) - 1):
                suffix = ".".join(labels[index:])
                matching = suffix_lookups.get(suffix)
                if not matching:
                    continue
                for list_id in relevant_list_ids:
                    if list_id in matching and list_id in self.warning_lists:
                        return self._build_warning_response(self.warning_lists[list_id], list_id)
        return None

    def _check_regex_lookups(
        self,
        clean_value: str,
        extracted_domain: str | None,
        relevant_list_ids: list[str],
    ) -> dict[str, str] | None:
        compiled_regex = self.lookup_data.compiled_regex
        for list_id in relevant_list_ids:
            if list_id not in compiled_regex or list_id not in self.warning_lists:
                continue
            for pattern in compiled_regex[list_id]:
                if pattern.search(clean_value) or (
                    extracted_domain and pattern.search(extracted_domain)
                ):
                    return self._build_warning_response(self.warning_lists[list_id], list_id)
        return None

    def _check_cidr_lookups(
        self,
        clean_value: str,
        relevant_list_ids: list[str],
    ) -> dict[str, str] | None:
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
                    return self._build_warning_response(self.warning_lists[list_id], list_id)
        return None

    def _check_substring_lists(
        self,
        clean_value: str,
        extracted_domain: str | None,
        relevant_list_ids: list[str],
        ioc_type: str,
    ) -> dict[str, str] | None:
        for list_id in relevant_list_ids:
            if list_id not in self.warning_lists:
                continue
            warning_list = self.warning_lists[list_id]
            if warning_list.get("type") != "substring":
                continue
            misp_types = self._get_misp_types_for_ioc(ioc_type)
            if extracted_domain:
                # A URL also carries a domain, so domain-scoped substring lists are
                # applicable to it -- mirroring _check_against_warning_list (which
                # tests extracted_domain) and the ungated string/regex/cidr paths.
                misp_types = misp_types + self._get_misp_types_for_ioc("domains")
            if self._matching_attribute_names(warning_list) and not self._is_list_applicable(
                warning_list, misp_types, ioc_type
            ):
                continue
            result = self._check_against_warning_list(
                clean_value, extracted_domain, warning_list, list_id
            )
            if result:
                return result
        return None

    def check_value(self, value: str, ioc_type: str) -> tuple[bool, dict[str, str] | None]:
        try:
            ioc_type = ioc_type_name(IOCType.from_name(ioc_type))
        except ValueError:
            ioc_type = ioc_type.strip().lower()
        cache_key = (value, ioc_type)
        cached = self._ensure_warning_lookup_cache().get(cache_key)
        if cached is not None:
            return cached
        clean_value = self._clean_defanged_value(value)
        clean_value_lower = clean_value.lower()
        extracted_domain: str | None = None
        if ioc_type == "urls":
            extracted_domain = self._extract_domain_from_url(clean_value)
        elif ioc_type == "emails":
            extracted_domain = self._extract_email_domain(clean_value)
        candidate_list_ids = self._get_candidate_list_ids(ioc_type)
        warning = self._check_string_lookups(
            clean_value_lower, extracted_domain, candidate_list_ids
        )
        if warning:
            string_result: tuple[bool, dict[str, str] | None] = (True, warning)
            self._cache_check_value(cache_key, string_result)
            return string_result
        warning = self._check_regex_lookups(clean_value, extracted_domain, candidate_list_ids)
        if warning:
            regex_result: tuple[bool, dict[str, str] | None] = (True, warning)
            self._cache_check_value(cache_key, regex_result)
            return regex_result
        if ioc_type in ["ips", "ipv6"]:
            warning = self._check_cidr_lookups(clean_value, candidate_list_ids)
            if warning:
                cidr_result: tuple[bool, dict[str, str] | None] = (True, warning)
                self._cache_check_value(cache_key, cidr_result)
                return cidr_result
        warning = self._check_substring_lists(
            clean_value, extracted_domain, candidate_list_ids, ioc_type
        )
        result: tuple[bool, dict[str, str] | None] = (warning is not None, warning)
        self._cache_check_value(cache_key, result)
        return result

    def _cache_check_value(
        self,
        cache_key: tuple[str, str],
        result: tuple[bool, dict[str, str] | None],
    ) -> None:
        cache = self._ensure_warning_lookup_cache()
        if len(cache) >= 5000:
            cache.clear()
        cache[cache_key] = result

    def _extract_domain_from_url(self, url: str) -> str | None:
        try:
            parsed = urlparse(url)
        except ValueError:
            self._get_logger().debug("Failed to parse URL for domain extraction: %s", url)
            return None
        return parsed.hostname

    def _is_list_applicable(
        self,
        warning_list: WarningListDict,
        misp_types: list[str],
        ioc_type: str,
    ) -> bool:
        matching_attrs = warning_list.get("matching_attributes")
        if not matching_attrs or not isinstance(matching_attrs, list):
            return False
        attrs_list = self._matching_attribute_names(warning_list)
        if not attrs_list:
            return False
        for misp_type in misp_types:
            for warning_attr in attrs_list:
                if (
                    misp_type.lower() == warning_attr.lower()
                    or misp_type.lower() in warning_attr.lower().split("|")
                ):
                    return True
        return ioc_type in ["ips", "ipv6"] and warning_list.get("type") == "cidr"

    def _check_string_type(self, value: str, values: list[IOCValue]) -> bool:
        return _check_string_value_type(value, values)

    def _check_substring_type(self, value: str, values: list[IOCValue]) -> bool:
        return _check_substring_value_type(value, values)

    def _check_regex_type(self, value: str, values: list[IOCValue]) -> bool:
        return _check_regex_value_type(self._get_logger, value, values)

    def _check_value_in_list(self, value: str, values: list[IOCValue], list_type: str) -> bool:
        return _check_value_against_list_type(self._get_logger, value, values, list_type)

    def _check_cidr(self, ip_value: str, cidr_list: list[IOCValue]) -> bool:
        return _check_cidr_value(self._get_logger, ip_value, cidr_list)

    def get_warnings_for_iocs(
        self,
        iocs: dict[str, list[str | dict[str, str]]],
    ) -> dict[str, list[dict[str, str]]]:
        return _get_warnings_for_iocs(self.check_value, iocs)

    def _build_warning_entry(
        self,
        value: str,
        warning_info: dict[str, str],
        ioc: str | dict[str, str],
    ) -> dict[str, str]:
        warning_entry = {
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
        return _separate_iocs_by_warnings(
            get_logger=self._get_logger,
            extract_ioc_value=extract_ioc_value,
            check_value=self.check_value,
            build_warning_entry=self._build_warning_entry,
            iocs=iocs,
        )
