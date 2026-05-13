#!/usr/bin/env python3

"""
Regex patterns for IOC extraction.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

import re
from re import Pattern

PATTERNS: dict[str, Pattern[str]] = {
    # Hash patterns - more flexible to catch hashes in various contexts
    "md5": re.compile(
        r"(?:MD5|md5)\s*:?\s*([a-fA-F0-9]{32})(?![a-fA-F0-9])"
        r"|\b([a-fA-F0-9]{32})\b(?![a-fA-F0-9])",
    ),
    "sha1": re.compile(
        r"(?:SHA-1|SHA1|sha1)\s*:?\s*([a-fA-F0-9]{40})(?![a-fA-F0-9])"
        r"|\b([a-fA-F0-9]{40})\b(?![a-fA-F0-9])",
    ),
    "sha256": re.compile(
        r"(?:SHA-256|SHA256|sha256)\s*:?\s*([a-fA-F0-9]{64})(?![a-fA-F0-9])"
        r"|\b([a-fA-F0-9]{64})\b(?![a-fA-F0-9])",
    ),
    "sha512": re.compile(
        r"(?:SHA-512|SHA512|sha512)\s*:?\s*([a-fA-F0-9]{128})(?![a-fA-F0-9])"
        r"|\b([a-fA-F0-9]{128})\b(?![a-fA-F0-9])",
    ),
    "ssdeep": re.compile(r"\b\d+:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\b"),
    "imphash": re.compile(
        r"(?:imphash|import\s*hash)[\s:=]+([a-fA-F0-9]{32})\b",
        re.IGNORECASE,
    ),  # Context-dependent: requires 'imphash' or 'import hash' prefix
    # Network indicators
    "domains": re.compile(
        r"\b((?:[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.){1,10}"
        r"[a-zA-Z]{2,63})\b|"
        r"\b((?:[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?"
        r"(?:\[\.\]|\(\.\)|\{\.\}|\.)){1,10}[a-zA-Z]{2,63})\b",
    ),
    "ips": re.compile(
        # Match potential IPs - we'll validate octets later
        # Handles both normal and defanged formats
        r"\b\d{1,3}(?:[\[\(\{]?\.[\]\)\}]?\d{1,3}){3}\b",
    ),
    "ipv6": re.compile(
        # IPv4-mapped must come before generic compressed forms;
        # otherwise ::ffff:192.168.1.1 is truncated at ::ffff:192.
        r"(?<![0-9a-zA-Z])::ffff:"
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9a-zA-Z])|"
        # Full format
        r"(?<![0-9a-zA-Z])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![0-9a-zA-Z])|"
        # Compressed
        r"(?<![0-9a-zA-Z])(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,6}"
        r"[0-9a-fA-F]{1,4}(?![0-9a-zA-Z])|"
        # xxxx::xxxx
        r"(?<![0-9a-zA-Z])(?:[0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{1,4}(?![0-9a-zA-Z])|"
        # xxxx:: (ending)
        r"(?<![0-9a-zA-Z])(?:[0-9a-fA-F]{1,4}:)+::(?![0-9a-zA-Z])|"
        # ::xxxx
        r"(?<![0-9a-zA-Z])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?![0-9a-zA-Z])|"
        # Special cases ::1 and ::
        r"(?<![0-9a-zA-Z])::1(?![0-9a-zA-Z])|(?<![0-9a-zA-Z])::(?![0-9a-zA-Z])",
    ),
    "urls": re.compile(
        r"\b(?:https?|hxxps?|h\[\.\]ttps?|s?ftp)://"
        r"(?!DOMAIN_NAME|IP:|\*\.|localhost|example\.)"
        r"[a-zA-Z0-9](?:[-a-zA-Z0-9]|(?:\.|\[\.\]|\(\.\)|\{\.\}))*[a-zA-Z0-9]"
        r"(?:\.[a-zA-Z]{2,63})?(?::[0-9]{1,5})?"
        r"(?:/[-a-zA-Z0-9()@:%_\+.~#?&/=]{0,2048})?",
        re.IGNORECASE,
    ),
    "mac_addresses": re.compile(
        r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|"
        r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b",
    ),
    # Cryptocurrency
    "bitcoin": re.compile(r"\b(bc1[a-zA-HJ-NP-Z0-9]{39,59}|[13][a-zA-HJ-NP-Z0-9]{25,34})\b"),
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "monero": re.compile(r"\b4[0-9AB][a-zA-Z0-9]{93}\b"),
    # Email and communication
    "emails": re.compile(
        r"\b[a-zA-Z0-9][a-zA-Z0-9._+-]*@"
        r"[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,63}\b",
    ),
    # Vulnerabilities and threats
    "cves": re.compile(r"\b(CVE-[0-9]{4}-[0-9]{1,7})\b", re.IGNORECASE),
    "mitre_attack": re.compile(r"\b(T1[0-9]{3}(?:\.[0-9]{1,3})?)\b"),
    # Windows artifacts
    "registry": re.compile(
        r"\b((?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|"
        r"HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|"
        r"HKEY_CURRENT_CONFIG|HKCC)\\[\\A-Za-z0-9-_\s]+?)(?=\s|$)",
    ),
    "mutex": re.compile(
        r"\b(?:Global\\|Local\\)?[A-Za-z0-9][A-Za-z0-9_\-]{2,}(?:Mutex|MUTEX)\b|"
        r"\bMutex:[A-Za-z0-9_\-]+\b",
    ),
    "service_names": re.compile(
        r"\b(?:Service|SERVICE):\s*([A-Za-z0-9][A-Za-z0-9_\-]{2,})\b|"
        r"\b([A-Za-z0-9][A-Za-z0-9_\-]{2,})(?:Service|Svc)\b",
    ),
    "named_pipes": re.compile(r"\\\\\.\\pipe\\[A-Za-z0-9_\-]+"),
    # File indicators
    "filenames": re.compile(
        r"\b([A-Za-z0-9][A-Za-z0-9-_\.]{2,}\."
        r"(?:exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|"
        r"zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif|"
        r"ps1|vbs|wsf|hta|cmd|com|lnk|ini|inf|reg))\b",
        re.IGNORECASE,
    ),
    "filepaths": re.compile(
        r"(?:"
        r'(?:%[A-Z_]+%\\|[A-Za-z]:\\)(?:[^\s<>:"/|?*\r\n\\]+\\){0,20}'
        r'[^\s<>:"/|?*\r\n\\]+(?:\.[A-Za-z0-9]{1,10})?(?=[\s"\u201c\u201d,;)>]|$)|'
        r"/(?:usr|bin|etc|var|tmp|home|opt|proc|sys|lib|dev)/(?:[A-Za-z0-9-_\\.]+/){0,20}"
        r'[A-Za-z0-9-_\.]+(?=[\s"\u201c\u201d,;]|$)'
        r")",
        re.IGNORECASE,
    ),
    # User agents
    "user_agents": re.compile(
        r"User-Agent:\s*([^\r\n]+)|(Mozilla/[0-9\.]+\s+\([^)]+\)[^\r\n]*)",
    ),
    # YARA rules - bounded to avoid ReDoS on deeply nested/unmatched braces
    "yara": re.compile(
        r"rule\s+\w+\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*){0,50}\}",
        re.DOTALL,
    ),
    "asn": re.compile(r"\bAS[1-9][0-9]{0,9}\b"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "cert_serials": re.compile(
        # Colon-separated (8-32 bytes)
        r"\b([a-fA-F0-9]{2}(?::[a-fA-F0-9]{2}){7,31})\b|"
        # Hex with context
        r"(?:serial|certificate|cert|thumbprint)[\s:]+([a-fA-F0-9]{16,64})\b",
    ),
    "cidr": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b"),
    "mitre_software": re.compile(r"\bS[0-9]{4}\b"),
    "mitre_groups": re.compile(r"\bG[0-9]{4}\b"),
    "mitre_mitigations": re.compile(r"\bM1[0-9]{3}\b"),
    "mitre_datasources": re.compile(r"\bDS[0-9]{4}\b"),
    "onion_addresses": re.compile(r"\b(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion\b"),
    "aws_access_keys": re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    "pdb_paths": re.compile(
        r"[A-Za-z]:\\(?:[^\s<>:\"/|?*\\]+\\){0,20}[^\s<>:\"/|?*\\]+\.pdb",
        re.IGNORECASE,
    ),
    "ja3": re.compile(r"(?:ja3|JA3)[\s:=]+([a-fA-F0-9]{32})\b"),
    "ja3s": re.compile(r"(?:ja3s|JA3S|JA3-S)[\s:=]+([a-fA-F0-9]{32})\b"),
    "ja4": re.compile(r"\b[qtd][0-9]{2}[dsi][0-9]{2,4}[a-z][0-9]{1,2}_[a-f0-9]{12}_[a-f0-9]{12}\b"),
    "hassh": re.compile(r"(?:hassh|HASSH)[\s:=]+([a-fA-F0-9]{32})\b"),
    "hassh_server": re.compile(r"(?:hassh[_-]?server|HASSHServer)[\s:=]+([a-fA-F0-9]{32})\b"),
    "jarm": re.compile(r"(?:jarm|JARM)[\s:=]+([a-fA-F0-9]{62})\b"),
    "aws_arns": re.compile(
        r"\barn:aws(?:-[a-z]+)?:[a-z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:[a-zA-Z0-9-_/:.]+\b",
    ),
    "gcp_service_accounts": re.compile(
        r"\b[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z0-9-]+\.iam\.gserviceaccount\.com\b",
    ),
    "azure_app_ids": re.compile(
        r"(?:tenant[_-]?id|app[_-]?id|client[_-]?id|directory[_-]?id|object[_-]?id)"
        r'[\s:="\']+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b',
        re.IGNORECASE,
    ),
    "docker_images": re.compile(
        r"\b(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)?[a-z0-9]+(?:[._-][a-z0-9]+)*"
        r"(?::[a-zA-Z0-9._-]+)?@sha256:[a-fA-F0-9]{64}\b",
    ),
    "tlsh": re.compile(
        r"(?:tlsh|TLSH)[\s:=]+T?1?([0-9A-Fa-f]{70,72})\b|"
        r"\b(T1[0-9A-F]{68,70})\b",
    ),
    "sigma_rule_ids": re.compile(
        r"(?:id|sigma[-_]?id|rule[-_]?id|detection[-_]?id)"
        r"[\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
        re.IGNORECASE,
    ),
    "suricata_sids": re.compile(r"\bsid\s*:\s*([0-9]{1,10})\s*;"),
    # Snort/Suricata rules - bounded line length to avoid ReDoS
    "snort_rules": re.compile(
        r"\b((?:alert|drop|reject|pass)\s+(?:tcp|udp|icmp|ip|http|dns|tls|ssh|ftp|smtp)"
        r"\s.{0,512};\s*(?:.{0,256}?\bsid\s*:\s*[0-9]+\s*;.{0,256}))",
    ),
    # Sigma rules - bounded block length to avoid ReDoS
    "sigma_rules": re.compile(
        r"(?:^|\n)(title:\s*[^\n]{0,256}\n(?:[^\n]{0,256}\n){0,50}?detection:\s*\n(?:\s+[^\n]{0,256}\n){0,50})",
        re.MULTILINE,
    ),
}
