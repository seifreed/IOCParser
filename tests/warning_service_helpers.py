from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import iocparser.api_extraction as api_extraction_module
from iocparser.domain.models import IOC, ExtractionResult
from tests.test_warninglists_offline import OfflineWarningLists

DEFAULT_WARNING_LISTS = {
    "common-domains": {
        "name": "Common Domains",
        "description": "Legitimate common domains",
        "type": "string",
        "matching_attributes": ["domain", "hostname"],
        "list": ["google.com", "cloudflare.com", "microsoft.com", "example.com"],
    },
    "public-dns": {
        "name": "Public DNS",
        "description": "Common public DNS addresses",
        "type": "string",
        "matching_attributes": ["ip-src", "ip-dst", "ip"],
        "list": ["8.8.8.8", "1.1.1.1"],
    },
}


class StaticWarningListService:
    """Small offline warning-list service for functional tests."""

    def __init__(self, warning_lists: dict[str, dict[str, object]] | None = None) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self._warning_lists = OfflineWarningLists(Path(self._tempdir.name), cache_duration=24)
        self._warning_lists.warning_lists = warning_lists or DEFAULT_WARNING_LISTS
        self._warning_lists._preprocess_lists()
        self.force_update_calls: list[bool] = []

    def separate(
        self,
        iocs: tuple[IOC, ...],
        *,
        force_update: bool = False,
    ) -> ExtractionResult:
        self.force_update_calls.append(force_update)
        grouped_iocs: dict[str, list[str | dict[str, str]]] = {}
        for ioc in iocs:
            grouped_iocs.setdefault(ioc.ioc_type.value, []).append(ioc.value.raw)
        normal_iocs, warning_iocs = self._warning_lists.separate_iocs_by_warnings(grouped_iocs)
        return ExtractionResult.from_grouped_payload(normal_iocs, warning_iocs)

    def close(self) -> None:
        self._tempdir.cleanup()


@contextmanager
def swap_warning_service(module: object, service: StaticWarningListService) -> Iterator[StaticWarningListService]:
    """Temporarily replace a module-level warning service."""
    original_holder = list(api_extraction_module._warning_service_holder)
    had_module_service = hasattr(module, "_warning_service")
    original = getattr(module, "_warning_service", None)
    api_extraction_module._warning_service_holder[:] = [service]
    if had_module_service:
        module._warning_service = service
    try:
        yield service
    finally:
        api_extraction_module._warning_service_holder[:] = original_holder
        if had_module_service:
            module._warning_service = original
        service.close()
