from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import TypeVar

from stix2 import Bundle, Indicator

SectionValue = str | dict[str, str]
WarningValue = dict[str, str] | str
ContextMap = Mapping[tuple[str, str], Sequence[str]]
T = TypeVar("T")

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
    for section_key, section_title in SECTION_ORDER:
        section_data = grouped.get(section_key)
        if not section_data:
            continue
        output.append(f"\n## {section_title}\n")
        lines = format_section(section_key, section_data)
        output.extend(lines)
        if context_map is not None and context_lookup is not None:
            for line in lines:
                for excerpt in context_lookup(section_key, line):
                    output.append(f"  Context: {excerpt}")
    if warning_grouped:
        output.append("\n# Warning List Matches\n")
        output.append("The following indicators were found in warning lists and might be false positives:\n")
        for section_key, section_title in SECTION_ORDER:
            warnings = warning_grouped.get(section_key)
            if not warnings:
                continue
            output.append(f"\n## {section_title} in Warning Lists\n")
            for warning in warnings:
                output.extend(format_warning(warning))
    return "\n".join(output)


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
        payload["warning_list_matches"] = {key: list(values) for key, values in warning_iocs.items()}
    return payload


def serialize_pretty_json(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, indent=4, sort_keys=True)


def build_stix_bundle(
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
