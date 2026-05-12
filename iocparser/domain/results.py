from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

from iocparser.domain.enums import IOCType, IOCTypeName, get_custom_ioc_type, ioc_type_name
from iocparser.domain.values import IndicatorValue, indicator_value_for
from iocparser.shared_utils import deduplicate_iocs

INVALID_ANALYST_SORT_BY_ERROR = "Invalid sort_by: {value}"
VALID_ANALYST_SORT_VALUES = {"severity", "type", "value"}


def classify_ioc(
    ioc_type: IOCType | IOCTypeName | str, *, is_warning: bool = False
) -> tuple[str, tuple[str, ...]]:
    """Classify an IOC with a simple severity and tags."""
    custom_type = get_custom_ioc_type(ioc_type)
    if custom_type is not None:
        severity = custom_type.severity or classify_ioc(custom_type.base_type, is_warning=False)[0]
        tags = list(custom_type.tags or classify_ioc(custom_type.base_type, is_warning=False)[1])
        if custom_type.name not in tags:
            tags.insert(0, custom_type.name)
        if is_warning:
            severity = "informational"
            if "warning-list-match" not in tags:
                tags.append("warning-list-match")
        return severity, tuple(tags)
    tags = [ioc_type_name(ioc_type)]
    if ioc_type in {
        IOCType.CVE,
        IOCType.MITRE_ATTACK,
        IOCType.YARA,
        IOCType.REGISTRY,
        IOCType.MUTEX,
    }:
        severity = "high"
        tags.append("behavioral")
    elif ioc_type in {
        IOCType.URL,
        IOCType.DOMAIN,
        IOCType.HOST,
        IOCType.IP,
        IOCType.IPV6,
        IOCType.EMAIL,
    }:
        severity = "medium"
        tags.append("network")
    elif ioc_type in {
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.SHA512,
        IOCType.SSDEEP,
        IOCType.IMPHASH,
    }:
        severity = "medium"
        tags.append("artifact")
    else:
        severity = "low"
        tags.append("contextual")
    if is_warning:
        severity = "informational"
        tags.append("warning-list-match")
    return severity, tuple(tags)


@dataclass(frozen=True)
class IOCEvidence:
    """Context snippet showing where an IOC was found."""

    excerpt: str
    line_number: int | None = None
    source: str = ""


@dataclass(frozen=True)
class IOC:
    """Normalized IOC value object."""

    ioc_type: IOCType | IOCTypeName
    value: IndicatorValue
    evidence: tuple[IOCEvidence, ...] = ()
    severity: str = "medium"
    tags: tuple[str, ...] = ()

    @classmethod
    def from_raw(
        cls,
        ioc_type: str,
        value: str,
        *,
        evidence: tuple[IOCEvidence, ...] = (),
        severity: str | None = None,
        tags: tuple[str, ...] = (),
    ) -> IOC:
        """Build a domain IOC from raw string inputs."""
        canonical_type = IOCType.from_name(ioc_type)
        derived_severity, derived_tags = classify_ioc(canonical_type)
        return cls(
            ioc_type=canonical_type,
            value=indicator_value_for(canonical_type, value),
            evidence=evidence,
            severity=severity or derived_severity,
            tags=tags or derived_tags,
        )

    def canonical_value(self) -> str:
        """Canonical IOC representation for rendering and comparisons."""
        return self.value.canonical()

    def to_record(self) -> dict[str, object]:
        """Serialize the IOC into a structured record."""
        return {
            "type": ioc_type_name(self.ioc_type),
            "value": self.canonical_value(),
            "raw_value": self.value.raw,
            "severity": self.severity,
            "tags": list(self.tags),
            "evidence": [
                {
                    "excerpt": evidence.excerpt,
                    "line_number": evidence.line_number,
                    "source": evidence.source,
                }
                for evidence in self.evidence
            ],
        }


@dataclass(frozen=True)
class WarningMatch:
    """IOC entry associated with a warning list."""

    ioc: IOC
    warning_list: str
    description: str = ""

    def to_record(self) -> dict[str, object]:
        """Serialize the warning into a structured record."""
        record = self.ioc.to_record()
        record["warning_list"] = self.warning_list
        record["description"] = self.description
        return record


@dataclass(frozen=True)
class ExtractionResult:
    """Normalized extraction output shared by application and adapters."""

    iocs: tuple[IOC, ...] = ()
    warnings: tuple[WarningMatch, ...] = ()

    @classmethod
    def from_grouped_payload(
        cls,
        normal_iocs: dict[str, list[str | dict[str, str]]],
        warning_iocs: dict[str, list[dict[str, str]]],
    ) -> ExtractionResult:
        """Build a normalized result from grouped IOC payloads."""
        iocs: list[IOC] = []
        warnings: list[WarningMatch] = []

        for ioc_type, values in normal_iocs.items():
            for value in values:
                normalized = value.get("value") if isinstance(value, dict) else str(value)
                if normalized:
                    iocs.append(IOC.from_raw(ioc_type, normalized))

        for ioc_type, warning_values in warning_iocs.items():
            for warning in warning_values:
                warning_value = warning.get("value")
                if not warning_value:
                    continue
                value_str = str(warning_value)
                severity, tags = classify_ioc(IOCType.from_name(ioc_type), is_warning=True)
                warnings.append(
                    WarningMatch(
                        ioc=IOC.from_raw(ioc_type, value_str, severity=severity, tags=tags),
                        warning_list=warning.get("warning_list", "") or "",
                        description=warning.get("description", "") or "",
                    ),
                )
        return cls(iocs=tuple(iocs), warnings=tuple(warnings))

    def grouped_iocs(self) -> dict[str, list[str | dict[str, str]]]:
        """Group normal IOCs by type using the canonical grouped shape."""
        grouped: dict[str, list[str | dict[str, str]]] = {}
        for ioc in self.iocs:
            grouped.setdefault(ioc_type_name(ioc.ioc_type), []).append(ioc.value.raw)
        return deduplicate_iocs(grouped)

    def grouped_warnings(self) -> dict[str, list[dict[str, str]]]:
        """Group warning matches by type using the canonical grouped shape."""
        grouped: dict[str, list[dict[str, str]]] = {}
        seen: dict[str, set[tuple[str, str, str]]] = {}
        for warning in self.warnings:
            key = (
                warning.ioc.value.raw,
                warning.warning_list,
                warning.description,
            )
            group_name = ioc_type_name(warning.ioc.ioc_type)
            seen.setdefault(group_name, set())
            if key in seen[group_name]:
                continue
            seen[group_name].add(key)
            grouped.setdefault(group_name, []).append(
                {
                    "value": warning.ioc.value.raw,
                    "warning_list": warning.warning_list,
                    "description": warning.description,
                },
            )
        return grouped

    def canonical_by_type(self) -> dict[IOCType | IOCTypeName, tuple[str, ...]]:
        """Return canonical values grouped by canonical IOC type."""
        grouped: dict[IOCType | IOCTypeName, list[str]] = {}
        seen: dict[IOCType | IOCTypeName, set[str]] = {}
        for result_set in (self.iocs, tuple(warning.ioc for warning in self.warnings)):
            for ioc in result_set:
                seen.setdefault(ioc.ioc_type, set())
                canonical = ioc.canonical_value()
                if canonical not in seen[ioc.ioc_type]:
                    grouped.setdefault(ioc.ioc_type, []).append(canonical)
                    seen[ioc.ioc_type].add(canonical)
        return {ioc_type: tuple(values) for ioc_type, values in grouped.items()}

    def filter_types(
        self,
        include_types: tuple[IOCType | IOCTypeName, ...] = (),
        exclude_types: tuple[IOCType | IOCTypeName, ...] = (),
    ) -> ExtractionResult:
        """Return a new result filtered by IOC type."""
        include_names = {ioc_type_name(ioc_type) for ioc_type in include_types}
        exclude_names = {ioc_type_name(ioc_type) for ioc_type in exclude_types}

        def allowed(ioc_type: IOCType | IOCTypeName) -> bool:
            name = ioc_type_name(ioc_type)
            if include_names and name not in include_names:
                return False
            return name not in exclude_names

        return ExtractionResult(
            iocs=tuple(ioc for ioc in self.iocs if allowed(ioc.ioc_type)),
            warnings=tuple(warning for warning in self.warnings if allowed(warning.ioc.ioc_type)),
        )

    def filter_analyst_view(
        self,
        *,
        severities: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
        include_normal: bool = True,
        include_warnings: bool = True,
        max_evidence: int | None = None,
        sort_by: str = "type",
    ) -> ExtractionResult:
        """Filter and sort the result for analyst-facing outputs."""

        normalized_sort_by = sort_by.strip().lower()
        if normalized_sort_by not in VALID_ANALYST_SORT_VALUES:
            raise ValueError(INVALID_ANALYST_SORT_BY_ERROR.format(value=sort_by))
        normalized_severities = {
            severity.strip().lower() for severity in severities if severity.strip()
        }
        normalized_tags = {tag.strip().lower() for tag in tags if tag.strip()}

        def matches(ioc: IOC) -> bool:
            if normalized_severities and ioc.severity.lower() not in normalized_severities:
                return False
            ioc_tags: set[str] = {str(tag).lower() for tag in ioc.tags}
            if normalized_tags and not normalized_tags.issubset(ioc_tags):
                return False
            return True

        def trim(ioc: IOC) -> IOC:
            if max_evidence is None:
                return ioc
            return replace(ioc, evidence=ioc.evidence[: max(0, max_evidence)])

        def order_key(item: IOC | WarningMatch) -> tuple[str, str, str]:
            ioc = item if isinstance(item, IOC) else item.ioc
            if normalized_sort_by == "severity":
                rank = {"high": "0", "medium": "1", "low": "2", "informational": "3"}.get(
                    ioc.severity.lower(),
                    "9",
                )
                return (rank, ioc_type_name(ioc.ioc_type), ioc.canonical_value())
            if normalized_sort_by == "value":
                return (ioc.canonical_value(), ioc_type_name(ioc.ioc_type), ioc.severity)
            return (ioc_type_name(ioc.ioc_type), ioc.canonical_value(), ioc.severity)

        filtered_iocs = tuple(trim(ioc) for ioc in self.iocs if include_normal and matches(ioc))
        filtered_warnings = tuple(
            replace(warning, ioc=trim(warning.ioc))
            for warning in self.warnings
            if include_warnings and matches(warning.ioc)
        )
        return ExtractionResult(
            iocs=tuple(sorted(filtered_iocs, key=order_key)),
            warnings=tuple(sorted(filtered_warnings, key=order_key)),
        )

    def to_records(self) -> list[dict[str, object]]:
        """Return structured IOC records for rich outputs."""
        records = [ioc.to_record() for ioc in self.iocs]
        records.extend(warning.to_record() for warning in self.warnings)
        return records

    def counts_by_type(self, *, include_warnings: bool = True) -> dict[str, int]:
        """Return IOC counts grouped by type."""
        counter: Counter[str] = Counter(ioc_type_name(ioc.ioc_type) for ioc in self.iocs)
        if include_warnings:
            warning_counts = Counter(
                ioc_type_name(warning.ioc.ioc_type) for warning in self.warnings
            )
            counter.update(warning_counts)
        return dict(sorted(counter.items()))

    def total_count(self, *, include_warnings: bool = True) -> int:
        """Return the total number of records."""
        total = len(self.iocs)
        if include_warnings:
            total += len(self.warnings)
        return total
