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
    "md5": re.compile(r"(?:MD5|md5)\s*:?\s*([a-fA-F0-9]{32})|\b([a-fA-F0-9]{32})\b"),
    "sha1": re.compile(
        r"(?:SHA-1|SHA1|sha1)\s*:?\s*([a-fA-F0-9]{40})|\b([a-fA-F0-9]{40})\b",
    ),
    "sha256": re.compile(
        r"(?:SHA-256|SHA256|sha256)\s*:?\s*([a-fA-F0-9]{64})|\b([a-fA-F0-9]{64})\b",
    ),
    "sha512": re.compile(
        r"(?:SHA-512|SHA512|sha512)\s*:?\s*([a-fA-F0-9]{128})|"
        r"(?:^|\s)([a-fA-F0-9]{128})(?:\s|$)",
    ),
    "ssdeep": re.compile(r"\b\d{2,}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\b"),
    "imphash": re.compile(r"\b[a-fA-F0-9]{32}\b"),  # Same as MD5 but context-dependent
    # Network indicators
    "domains": re.compile(
        r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63})\b|"
        r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\[\.\]|\(\.\)|\{\.\}|\.)){1,}[a-zA-Z]{2,63})\b",
    ),
    "ips": re.compile(
        # Match potential IPs - we'll validate octets later
        # Handles both normal and defanged formats
        r"\b\d{1,3}(?:[\[\(\{]?\.[\]\)\}]?\d{1,3}){3}\b",
    ),
    "ipv6": re.compile(
        # Full format
        r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?=\s|$)|"
        # Compressed
        r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,6}"
        r"[0-9a-fA-F]{1,4}(?=\s|$)|"
        # xxxx::xxxx
        r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:){1,6}::[0-9a-fA-F]{1,4}(?=\s|$)|"
        # xxxx:: (ending)
        r"(?:^|(?<=\s))(?:[0-9a-fA-F]{1,4}:)+::(?=\s|$)|"
        # ::xxxx
        r"(?:^|(?<=\s))::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?=\s|$)|"
        # Special cases ::1 and ::
        r"(?:^|(?<=\s))::1(?=\s|$)|(?:^|(?<=\s))::(?=\s|$)|"
        # IPv4-mapped
        r"(?:^|(?<=\s))::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?=\s|$)",
    ),
    "urls": re.compile(
        r"\b(?:https?|hxxps?|h\[\.\]ttps?|s?ftp)://"
        r"(?!DOMAIN_NAME|IP:|\*\.|localhost|example\.)"
        r"[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]"
        r"(?:\.[a-zA-Z]{2,63})?(?::[0-9]{1,5})?"
        r"(?:/[-a-zA-Z0-9()@:%_\+.~#?&/=]*)?",
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
        r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*@"
        r"[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,63}\b",
    ),
    # Vulnerabilities and threats
    "cves": re.compile(r"\b(CVE-[0-9]{4}-[0-9]{4,7})\b", re.IGNORECASE),
    "mitre_attack": re.compile(r"\b(T[0-9]{4}(?:\.[0-9]{3})?)\b"),
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
        r'(?:%[A-Z_]+%\\|[A-Za-z]:\\)(?:[^\s<>:"/|?*\r\n\\]+\\)*'
        r'[^\s<>:"/|?*\r\n\\]+(?:\.[A-Za-z0-9]{1,10})?(?=[\s"\u201c\u201d,;]|$)|'
        r"/(?:usr|bin|etc|var|tmp|home|opt|proc|sys|lib|dev)/(?:[A-Za-z0-9-_\.]+/)*"
        r'[A-Za-z0-9-_\.]+(?=[\s"\u201c\u201d,;]|$)'
        r")",
        re.IGNORECASE,
    ),
    # User agents
    "user_agents": re.compile(
        r"User-Agent:\s*([^\r\n]+)|" + r"Mozilla/[0-9\.]+\s+\([^)]+\)[^\r\n]*",
    ),
    "yara": re.compile(r"rule\s+\w+\s*\{(?:[^{}]|\{[^}]*\})*\}", re.DOTALL),
    "asn": re.compile(r"\bAS[0-9]{1,10}\b"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "cert_serials": re.compile(
        # Colon-separated (8-32 bytes)
        r"\b([a-fA-F0-9]{2}(?::[a-fA-F0-9]{2}){7,31})\b|"
        # Hex with context
        r"(?:serial|certificate|cert|thumbprint)[\s:]+([a-fA-F0-9]{16,64})\b",
    ),
}
