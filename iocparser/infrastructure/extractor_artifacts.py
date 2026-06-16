#!/usr/bin/env python3

"""
Artifact extraction mixin for IOC extraction.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from iocparser.infrastructure.extractor_base import ExtractorBase, IPv4_MAX_OCTET, IPv4_PARTS_COUNT
from iocparser.infrastructure.extractor_network import DEFAULT_NETWORK_POLICY
from iocparser.shared_utils import dedup_case_insensitive

LEGITIMATE_PROCESS_NAMES = {
    "svchost.exe",
    "explorer.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "lsass.exe",
    "services.exe",
    "spoolsv.exe",
    "taskhost.exe",
    "dwm.exe",
    "userinit.exe",
    "logonui.exe",
    "wininit.exe",
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "notepad.exe",
    "calc.exe",
    "cmd.exe",
    "powershell.exe",
    "conhost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "chrome.exe",
    "firefox.exe",
    "iexplore.exe",
    "msiexec.exe",
}

INVALID_PATH_FRAGMENTS = (
    "folder on the",
    "uploaded to",
    "artifacts were",
)


@dataclass(frozen=True)
class ArtifactHeuristicPolicy:
    legitimate_process_names: frozenset[str]
    invalid_path_fragments: tuple[str, ...]

    def bitcoin_addresses(self, candidates: list[str]) -> list[str]:
        validated: list[str] = []
        for addr in candidates:
            if len(addr) == 32 and all(char in "0123456789abcdefABCDEF" for char in addr):
                continue
            if len(addr) >= 25 and not all(char in "0123456789abcdefABCDEF" for char in addr):
                validated.append(addr)
        return validated

    def real_filenames(self, matches: list[str]) -> list[str]:
        filenames = [
            match for match in matches if isinstance(match, str) and "." in match and len(match) > 4
        ]
        return dedup_case_insensitive(
            [match for match in filenames if match.lower() not in self.legitimate_process_names]
        )

    def valid_filepaths(self, raw_paths: list[str]) -> list[str]:
        valid_paths: list[str] = []
        for path in raw_paths:
            clean_path = path.strip()
            if (
                len(clean_path) >= 10
                and len(clean_path) < 300
                and ("\\" in clean_path or "/" in clean_path)
                and not any(word in clean_path.lower() for word in self.invalid_path_fragments)
            ):
                clean_part = clean_path.rstrip('",;\'"').strip()
                if (":\\" in clean_part or clean_part.startswith("%")) or (
                    clean_part.startswith("/") and len(clean_part) > 5
                ):
                    valid_paths.append(clean_part)
        return dedup_case_insensitive(valid_paths)

    def valid_mac_addresses(self, candidates: list[str]) -> list[str]:
        valid_macs: list[str] = []
        for mac in candidates:
            if "." in mac and len(mac.replace(".", "")) == 12:
                hex_only = mac.replace(".", "")
                if all(char in "0123456789abcdefABCDEF" for char in hex_only):
                    # Lowercase to match the dash/colon branches; a MAC's canonical
                    # form must be case-insensitive-stable (so the same address in
                    # dotted vs colon notation dedups) and STIX mac-addr:value
                    # requires lowercase EUI-48.
                    canonical = hex_only.lower()
                    valid_macs.append(
                        ":".join(canonical[index : index + 2] for index in range(0, 12, 2))
                    )
                continue
            normalized = mac.replace("-", ":").lower()
            hex_only = normalized.replace(":", "")
            if len(hex_only) != 12:
                continue
            if ":" in normalized:
                parts = normalized.split(":")
                if len(parts) == 6 and all(
                    len(part) == 2 and all(char in "0123456789abcdef" for char in part)
                    for part in parts
                ):
                    valid_macs.append(normalized)
        return dedup_case_insensitive(valid_macs)

    def valid_yara_rules(self, raw_rules: list[str]) -> list[str]:
        valid_rules: list[str] = []
        for rule in raw_rules:
            if len(rule) < 3000 and "rule " in rule and "{" in rule:
                if any(keyword in rule for keyword in ["strings:", "condition:", "meta:"]):
                    clean_rule = rule.strip()
                    if not clean_rule.endswith("}"):
                        clean_rule += "\n}"
                    valid_rules.append(clean_rule)
        return valid_rules

    def valid_cidr(self, candidates: list[str]) -> list[str]:
        valid: list[str] = []
        for candidate in candidates:
            if "/" not in candidate:
                continue
            addr, prefix = candidate.rsplit("/", 1)
            try:
                prefix_len = int(prefix)
            except ValueError:
                continue
            if prefix_len < 0 or prefix_len > 32:
                continue
            octets = addr.split(".")
            if len(octets) != 4:
                continue
            if DEFAULT_NETWORK_POLICY.is_valid_ipv4(
                octets, octet_count=IPv4_PARTS_COUNT, max_octet=IPv4_MAX_OCTET
            ):
                valid.append(candidate)
        return dedup_case_insensitive(valid)

    def valid_snort_rules(self, candidates: list[str]) -> list[str]:
        valid_rules: list[str] = []
        for rule in candidates:
            if "sid:" in rule and "msg:" in rule:
                valid_rules.append(rule.strip())
        return valid_rules

    def valid_sigma_rules(self, candidates: list[str]) -> list[str]:
        valid_rules: list[str] = []
        for rule in candidates:
            if all(keyword in rule for keyword in ["title:", "detection:", "condition:"]):
                valid_rules.append(rule.strip())
        return valid_rules

    def valid_cert_serials(self, candidates: list[str]) -> list[str]:
        valid_serials: list[str] = []
        for candidate in candidates:
            if ":" not in candidate and len(candidate) >= 16:
                normalized = ":".join(
                    candidate[index : index + 2] for index in range(0, len(candidate), 2)
                )
            else:
                normalized = candidate
            if ":" in normalized:
                parts = normalized.split(":")
                if 8 <= len(parts) <= 32 and all(
                    len(part) == 2 and all(char in "0123456789abcdefABCDEF" for char in part)
                    for part in parts
                ):
                    if len(parts) != 6 and all(
                        char in "0123456789abcdefABCDEF" for char in normalized.replace(":", "")
                    ):
                        valid_serials.append(normalized.lower())
        return dedup_case_insensitive(valid_serials)


DEFAULT_ARTIFACT_POLICY = ArtifactHeuristicPolicy(
    legitimate_process_names=frozenset(LEGITIMATE_PROCESS_NAMES),
    invalid_path_fragments=INVALID_PATH_FRAGMENTS,
)


@dataclass(frozen=True)
class ArtifactPatternRule:
    method_name: str
    pattern_name: str
    docstring: str
    postprocess: Callable[[list[str]], list[str]] | None = None
    unique: bool = False

    def apply(self, matches: list[str]) -> list[str]:
        if self.postprocess is not None:
            return self.postprocess(matches)
        if self.unique:
            return dedup_case_insensitive(matches)
        return matches


ARTIFACT_PATTERN_RULES: tuple[ArtifactPatternRule, ...] = (
    ArtifactPatternRule(
        "extract_bitcoin",
        "bitcoin",
        "Extract Bitcoin addresses from text.",
        DEFAULT_ARTIFACT_POLICY.bitcoin_addresses,
    ),
    ArtifactPatternRule("extract_ethereum", "ethereum", "Extract Ethereum addresses from text."),
    ArtifactPatternRule("extract_monero", "monero", "Extract Monero addresses from text."),
    ArtifactPatternRule("extract_cves", "cves", "Extract CVE identifiers from text."),
    ArtifactPatternRule(
        "extract_mitre_attack", "mitre_attack", "Extract MITRE ATT&CK technique IDs from text."
    ),
    ArtifactPatternRule("extract_registry", "registry", "Extract Windows registry keys from text."),
    ArtifactPatternRule("extract_mutex", "mutex", "Extract mutex names from text."),
    ArtifactPatternRule(
        "extract_service_names",
        "service_names",
        "Extract Windows service names from text.",
        unique=True,
    ),
    ArtifactPatternRule(
        "extract_named_pipes", "named_pipes", "Extract Windows named pipes from text."
    ),
    ArtifactPatternRule(
        "extract_filenames",
        "filenames",
        "Extract filenames from text, only real files with extensions.",
        DEFAULT_ARTIFACT_POLICY.real_filenames,
    ),
    ArtifactPatternRule(
        "extract_filepaths",
        "filepaths",
        "Extract file paths from text with validation.",
        DEFAULT_ARTIFACT_POLICY.valid_filepaths,
    ),
    ArtifactPatternRule(
        "extract_mac_addresses",
        "mac_addresses",
        "Extract MAC addresses from text.",
        DEFAULT_ARTIFACT_POLICY.valid_mac_addresses,
    ),
    ArtifactPatternRule(
        "extract_user_agents", "user_agents", "Extract user agent strings from text."
    ),
    ArtifactPatternRule(
        "extract_yara_rules",
        "yara",
        "Extract YARA rules from text with better validation.",
        DEFAULT_ARTIFACT_POLICY.valid_yara_rules,
    ),
    ArtifactPatternRule("extract_asn", "asn", "Extract AS numbers from text."),
    ArtifactPatternRule("extract_jwt", "jwt", "Extract JWT tokens from text."),
    ArtifactPatternRule(
        "extract_cert_serials",
        "cert_serials",
        "Extract certificate serial numbers from text.",
        DEFAULT_ARTIFACT_POLICY.valid_cert_serials,
    ),
    ArtifactPatternRule(
        "extract_cidr",
        "cidr",
        "Extract CIDR ranges from text.",
        DEFAULT_ARTIFACT_POLICY.valid_cidr,
    ),
    ArtifactPatternRule(
        "extract_mitre_software", "mitre_software", "Extract MITRE ATT&CK software IDs from text."
    ),
    ArtifactPatternRule(
        "extract_mitre_groups", "mitre_groups", "Extract MITRE ATT&CK group IDs from text."
    ),
    ArtifactPatternRule(
        "extract_mitre_mitigations",
        "mitre_mitigations",
        "Extract MITRE ATT&CK mitigation IDs from text.",
    ),
    ArtifactPatternRule(
        "extract_mitre_datasources",
        "mitre_datasources",
        "Extract MITRE ATT&CK data source IDs from text.",
    ),
    ArtifactPatternRule(
        "extract_onion_addresses", "onion_addresses", "Extract Tor .onion addresses from text."
    ),
    ArtifactPatternRule(
        "extract_aws_access_keys", "aws_access_keys", "Extract AWS access key IDs from text."
    ),
    ArtifactPatternRule("extract_pdb_paths", "pdb_paths", "Extract PDB debug paths from text."),
    ArtifactPatternRule("extract_ja3", "ja3", "Extract JA3 TLS client fingerprints from text."),
    ArtifactPatternRule("extract_ja3s", "ja3s", "Extract JA3S TLS server fingerprints from text."),
    ArtifactPatternRule("extract_ja4", "ja4", "Extract JA4+ TLS fingerprints from text."),
    ArtifactPatternRule(
        "extract_hassh", "hassh", "Extract HASSH SSH client fingerprints from text."
    ),
    ArtifactPatternRule(
        "extract_hassh_server", "hassh_server", "Extract HASSH server SSH fingerprints from text."
    ),
    ArtifactPatternRule("extract_jarm", "jarm", "Extract JARM TLS fingerprints from text."),
    ArtifactPatternRule("extract_aws_arns", "aws_arns", "Extract AWS ARNs from text."),
    ArtifactPatternRule(
        "extract_gcp_service_accounts",
        "gcp_service_accounts",
        "Extract GCP service account emails from text.",
    ),
    ArtifactPatternRule(
        "extract_azure_app_ids", "azure_app_ids", "Extract Azure AD app/tenant IDs from text."
    ),
    ArtifactPatternRule(
        "extract_docker_images",
        "docker_images",
        "Extract Docker image references with digest from text.",
    ),
    ArtifactPatternRule("extract_tlsh", "tlsh", "Extract TLSH hashes from text."),
    ArtifactPatternRule(
        "extract_sigma_rule_ids", "sigma_rule_ids", "Extract Sigma detection rule UUIDs from text."
    ),
    ArtifactPatternRule(
        "extract_suricata_sids", "suricata_sids", "Extract Suricata/Snort rule SIDs from text."
    ),
    ArtifactPatternRule(
        "extract_snort_rules",
        "snort_rules",
        "Extract Snort/Suricata rules from text.",
        DEFAULT_ARTIFACT_POLICY.valid_snort_rules,
    ),
    ArtifactPatternRule(
        "extract_sigma_rules",
        "sigma_rules",
        "Extract Sigma YAML rule blocks from text.",
        DEFAULT_ARTIFACT_POLICY.valid_sigma_rules,
    ),
)
ARTIFACT_EXTRACTION_METHODS: tuple[str, ...] = tuple(
    rule.method_name for rule in ARTIFACT_PATTERN_RULES
)


def _pattern_rule_method(rule: ArtifactPatternRule) -> Callable[[ExtractorBase, str], list[str]]:
    def extractor(self: ExtractorBase, text: str) -> list[str]:
        return rule.apply(self._extract_pattern(text, rule.pattern_name))

    extractor.__name__ = rule.method_name
    extractor.__doc__ = rule.docstring
    return extractor


class ArtifactExtractionMixin(ExtractorBase):
    """Artifact IOC extraction methods."""


for _rule in ARTIFACT_PATTERN_RULES:
    setattr(ArtifactExtractionMixin, _rule.method_name, _pattern_rule_method(_rule))
