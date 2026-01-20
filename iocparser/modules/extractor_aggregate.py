#!/usr/bin/env python3

"""
Aggregation mixin for IOC extraction.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, cast

from tqdm import tqdm

from iocparser.modules.extractor_base import LARGE_TEXT_THRESHOLD
from iocparser.modules.logger import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from iocparser.modules.extractor import IOCExtractor


class ExtractionAggregateMixin:
    """Aggregate extraction methods into a single result."""

    def _extract_single_type(
        self,
        ioc_type: str,
        method: Callable[[str], list[str]],
        text: str,
    ) -> list[str] | None:
        """Extract a single IOC type, handling errors safely."""
        try:
            results = method(text)
        except (OSError, ValueError) as exc:
            logger.warning("Error extracting %s: %s", ioc_type, exc)
            return None
        return results if results else None

    def extract_all(self, text: str) -> dict[str, list[str]]:
        """
        Extract all types of IOCs from text.

        Args:
            text: Text to extract IOCs from

        Returns:
            Dictionary with IOC types as keys and lists of IOCs as values
        """
        iocs: dict[str, list[str]] = {}

        extractor = cast("IOCExtractor", self)
        extraction_methods: list[tuple[str, Callable[[str], list[str]]]] = [
            ("md5", extractor.extract_md5),
            ("sha1", extractor.extract_sha1),
            ("sha256", extractor.extract_sha256),
            ("sha512", extractor.extract_sha512),
            ("ssdeep", extractor.extract_ssdeep),
            ("domains", extractor.extract_domains),
            ("ips", extractor.extract_ips),
            ("ipv6", extractor.extract_ipv6),
            ("urls", extractor.extract_urls),
            ("emails", extractor.extract_emails),
            ("bitcoin", extractor.extract_bitcoin),
            ("ethereum", extractor.extract_ethereum),
            ("monero", extractor.extract_monero),
            ("cves", extractor.extract_cves),
            ("mitre_attack", extractor.extract_mitre_attack),
            ("registry", extractor.extract_registry),
            ("mutex", extractor.extract_mutex),
            ("service_names", extractor.extract_service_names),
            ("named_pipes", extractor.extract_named_pipes),
            ("filenames", extractor.extract_filenames),
            ("filepaths", extractor.extract_filepaths),
            ("mac_addresses", extractor.extract_mac_addresses),
            ("user_agents", extractor.extract_user_agents),
            ("yara", extractor.extract_yara_rules),
            ("asn", extractor.extract_asn),
            ("jwt", extractor.extract_jwt),
            ("cert_serials", extractor.extract_cert_serials),
            ("hosts", extractor.extract_hosts),
        ]

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

        for ioc_type, method in extraction_iterable:
            results = self._extract_single_type(ioc_type, method, text)
            if results:
                iocs[ioc_type] = results

        return iocs
