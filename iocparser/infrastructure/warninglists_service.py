from __future__ import annotations

from collections import defaultdict

from iocparser.domain.enums import ioc_type_name
from iocparser.domain.models import IOC, ExtractionResult, WarningMatch, classify_ioc
from iocparser.infrastructure.warninglists import MISPWarningLists
from iocparser.interfaces.ports import WarningListService


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Expected {field} to be string-like, got {type(value).__name__}")
    return value


class MISPWarningListService(WarningListService):
    """Warning-list adapter backed by MISP warning lists."""

    def __init__(self) -> None:
        self._cached_lists: MISPWarningLists | None = None

    def _get_lists(self, *, force_update: bool) -> MISPWarningLists:
        if force_update or self._cached_lists is None:
            self._cached_lists = MISPWarningLists(force_update=force_update)
        return self._cached_lists

    def separate(
        self,
        iocs: tuple[IOC, ...],
        *,
        force_update: bool = False,
    ) -> ExtractionResult:
        """Separate normal IOCs from warning list matches."""
        grouped_iocs: dict[str, list[str | dict[str, str]]] = {}
        by_key: dict[tuple[str, str], list[IOC]] = defaultdict(list)
        for ioc in iocs:
            ioc_type = ioc_type_name(ioc.ioc_type)
            raw_value = _require_str(ioc.value.raw, field="raw")
            grouped_iocs.setdefault(ioc_type, []).append(raw_value)
            by_key[(ioc_type, raw_value)].append(ioc)

        normal_iocs, warning_iocs = self._get_lists(
            force_update=force_update
        ).separate_iocs_by_warnings(
            grouped_iocs,
        )

        normal_records: list[IOC] = []
        warnings: list[WarningMatch] = []

        for ioc_type, values in normal_iocs.items():
            for value in values:
                key = (ioc_type, str(value))
                if by_key[key]:
                    normal_records.append(by_key[key].pop(0))
                else:
                    normal_records.append(IOC.from_raw(ioc_type, str(value)))

        for ioc_type, warning_values in warning_iocs.items():
            for warning in warning_values:
                value = warning.get("value", "")
                if not value:
                    continue
                key = (ioc_type, value)
                if by_key[key]:
                    matched_ioc = by_key[key].pop(0)
                    severity, tags = classify_ioc(matched_ioc.ioc_type, is_warning=True)
                    matched_ioc = IOC(
                        ioc_type=matched_ioc.ioc_type,
                        value=matched_ioc.value,
                        evidence=matched_ioc.evidence,
                        severity=severity,
                        tags=tags,
                    )
                else:
                    severity, tags = classify_ioc(
                        IOC.from_raw(ioc_type, value).ioc_type, is_warning=True
                    )
                    matched_ioc = IOC.from_raw(ioc_type, value, severity=severity, tags=tags)
                warnings.append(
                    WarningMatch(
                        ioc=matched_ioc,
                        warning_list=warning.get("warning_list", "") or "",
                        description=warning.get("description", "") or "",
                    ),
                )
        return ExtractionResult(iocs=tuple(normal_records), warnings=tuple(warnings))


class CompositeWarningListService(WarningListService):
    """Compose multiple warning-list enrichers into one pipeline."""

    def __init__(self, services: tuple[WarningListService, ...]) -> None:
        self.services = services

    def separate(
        self,
        iocs: tuple[IOC, ...],
        *,
        force_update: bool = False,
    ) -> ExtractionResult:
        """Apply each warning-list service in order, keeping cumulative warnings."""
        remaining = iocs
        warnings: list[WarningMatch] = []
        for service in self.services:
            separated = service.separate(remaining, force_update=force_update)
            remaining = separated.iocs
            warnings.extend(separated.warnings)
        return ExtractionResult(iocs=remaining, warnings=tuple(warnings))
