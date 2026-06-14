from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence

from stix2 import Bundle, Indicator

from iocparser.domain.models import ExtractionResult, ioc_type_name

SectionValue = str | dict[str, str]
WarningValue = dict[str, str] | str
ContextMap = Mapping[tuple[str, str], Sequence[str]]

SECTION_ORDER: list[tuple[str, str]] = [
    ("md5", "MD5 Hashes"),
    ("sha1", "SHA1 Hashes"),
    ("sha256", "SHA256 Hashes"),
    ("sha512", "SHA512 Hashes"),
    ("ssdeep", "SSDEEP Hashes"),
    ("imphash", "Import Hashes"),
    ("domains", "Domains"),
    ("hosts", "Hosts"),
    ("ips", "IP Addresses"),
    ("ipv6", "IPv6 Addresses"),
    ("urls", "URLs"),
    ("emails", "Email Addresses"),
    ("cves", "Vulnerabilities (CVEs)"),
    ("mitre_attack", "MITRE ATT&CK Techniques"),
    ("registry", "Windows Registry Keys"),
    ("mutex", "Mutex Names"),
    ("service_names", "Service Names"),
    ("named_pipes", "Named Pipes"),
    ("filenames", "Filenames"),
    ("filepaths", "Filepaths"),
    ("bitcoin", "Bitcoin Addresses"),
    ("ethereum", "Ethereum Addresses"),
    ("monero", "Monero Addresses"),
    ("mac_addresses", "MAC Addresses"),
    ("user_agents", "User Agents"),
    ("yara", "YARA Rules"),
    ("asn", "AS Numbers"),
    ("jwt", "JWT Tokens"),
    ("cert_serials", "Certificate Serial Numbers"),
]


def group_canonical_by_type(result: ExtractionResult) -> dict[str, list[str]]:
    """Group an extraction result's canonical values by display type name."""
    return {
        ioc_type_name(ioc_type): list(values)
        for ioc_type, values in result.canonical_by_type().items()
    }


def evidence_excerpts(evidence_items: Sequence[object]) -> list[str]:
    """Collect non-empty excerpt strings from a record's evidence entries."""
    return [
        str(entry["excerpt"])
        for entry in evidence_items
        if isinstance(entry, dict) and entry.get("excerpt")
    ]


def render_text_output(
    grouped: Mapping[str, Sequence[SectionValue]],
    warning_grouped: Mapping[str, Sequence[WarningValue]],
    *,
    format_section: Callable[[str, Sequence[SectionValue]], list[str]],
    format_warning: Callable[[WarningValue], list[str]],
    context_map: ContextMap | None = None,
    context_lookup: Callable[[str, str], Iterable[str]] | None = None,
) -> str:
    output: list[str] = ["# Indicators of Compromise (IOCs) Extracted\n"]
    append_text_sections(
        output,
        grouped=grouped,
        format_section=format_section,
        context_map=context_map,
        context_lookup=context_lookup,
    )
    if warning_grouped:
        output.append("\n# Warning List Matches\n")
        output.append(
            "The following indicators were found in warning lists and might be false positives:\n"
        )
        append_warning_sections(
            output,
            warning_grouped=warning_grouped,
            format_warning=format_warning,
        )
    return "\n".join(output)


def append_text_sections(
    output: list[str],
    *,
    grouped: Mapping[str, Sequence[SectionValue]],
    format_section: Callable[[str, Sequence[SectionValue]], list[str]],
    context_map: ContextMap | None,
    context_lookup: Callable[[str, str], Iterable[str]] | None,
) -> None:
    rendered_sections: set[str] = set()
    for section_key, section_title in SECTION_ORDER:
        if append_text_section(
            output,
            section_key,
            section_title,
            grouped=grouped,
            format_section=format_section,
            context_map=context_map,
            context_lookup=context_lookup,
        ):
            rendered_sections.add(section_key)
    for section_key in sorted(grouped):
        if section_key not in rendered_sections and append_text_section(
            output,
            section_key,
            fallback_section_title(section_key),
            grouped=grouped,
            format_section=format_section,
            context_map=context_map,
            context_lookup=context_lookup,
        ):
            rendered_sections.add(section_key)


def append_text_section(
    output: list[str],
    section_key: str,
    section_title: str,
    *,
    grouped: Mapping[str, Sequence[SectionValue]],
    format_section: Callable[[str, Sequence[SectionValue]], list[str]],
    context_map: ContextMap | None,
    context_lookup: Callable[[str, str], Iterable[str]] | None,
) -> bool:
    section_data = grouped.get(section_key)
    if not section_data:
        return False
    output.append(f"\n## {section_title}\n")
    lines = format_section(section_key, section_data)
    output.extend(lines)
    if context_map is not None and context_lookup is not None:
        for line in lines:
            for excerpt in context_lookup(section_key, line):
                output.append(f"  Context: {excerpt}")
    return True


def append_warning_sections(
    output: list[str],
    *,
    warning_grouped: Mapping[str, Sequence[WarningValue]],
    format_warning: Callable[[WarningValue], list[str]],
) -> None:
    rendered_warning_sections: set[str] = set()
    for section_key, section_title in SECTION_ORDER:
        if append_warning_section(
            output,
            section_key,
            section_title,
            warning_grouped=warning_grouped,
            format_warning=format_warning,
        ):
            rendered_warning_sections.add(section_key)
    for section_key in sorted(warning_grouped):
        if section_key not in rendered_warning_sections and append_warning_section(
            output,
            section_key,
            fallback_section_title(section_key),
            warning_grouped=warning_grouped,
            format_warning=format_warning,
        ):
            rendered_warning_sections.add(section_key)


def append_warning_section(
    output: list[str],
    section_key: str,
    section_title: str,
    *,
    warning_grouped: Mapping[str, Sequence[WarningValue]],
    format_warning: Callable[[WarningValue], list[str]],
) -> bool:
    warnings = warning_grouped.get(section_key)
    if not warnings:
        return False
    output.append(f"\n## {section_title} in Warning Lists\n")
    for warning in warnings:
        output.extend(format_warning(warning))
    return True


def fallback_section_title(section_key: str) -> str:
    return section_key.replace("_", " ").title()


def prepare_json_payload(
    data: Mapping[str, Sequence[SectionValue]],
    warning_iocs: Mapping[str, Sequence[dict[str, str]]],
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in data.items():
        if key != "hashes":
            str_values = [item for item in value if isinstance(item, str)]
            dict_values = [item for item in value if isinstance(item, dict)]
            if str_values and not dict_values:
                payload[key] = sorted(str_values)
                continue
        payload[key] = list(value)
    if warning_iocs:
        payload["warning_list_matches"] = {
            key: list(values) for key, values in warning_iocs.items()
        }
    return payload


def serialize_pretty_json(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, indent=4, sort_keys=True)


def build_stix_bundle[T](
    entries: Iterable[T],
    *,
    build_indicator: Callable[[T], Indicator | None],
    bundle_mutator: Callable[[dict[str, object]], dict[str, object]] | None = None,
) -> str:
    indicators: list[Indicator] = []
    seen_patterns: set[str] = set()
    for entry in entries:
        indicator = build_indicator(entry)
        if indicator and indicator.pattern not in seen_patterns:
            indicators.append(indicator)
            seen_patterns.add(indicator.pattern)
    payload = json.loads(Bundle(objects=indicators, allow_custom=True).serialize(pretty=True))
    if not isinstance(payload, dict):
        payload = {}
    mutated = bundle_mutator(payload) if bundle_mutator else payload
    return json.dumps(mutated, indent=4, sort_keys=True)
