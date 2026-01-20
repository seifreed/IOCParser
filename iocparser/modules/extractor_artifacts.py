#!/usr/bin/env python3

"""
Artifact extraction mixin for IOC extraction.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

from iocparser.modules.extractor_base import ExtractorBase


class ArtifactExtractionMixin(ExtractorBase):
    """Artifact IOC extraction methods."""

    def extract_bitcoin(self, text: str) -> list[str]:
        """Extract Bitcoin addresses from text."""
        potential_addresses = self._extract_pattern(text, "bitcoin")
        validated_addresses = []

        for addr in potential_addresses:
            # Skip if it's clearly a hex-only MD5 (32 chars, all hex)
            if len(addr) == 32 and all(c in "0123456789abcdefABCDEF" for c in addr):
                continue
            # Bitcoin addresses should have mixed case or contain non-hex chars
            if len(addr) >= 26 and (not all(c in "0123456789abcdefABCDEF" for c in addr)):
                validated_addresses.append(addr)

        return validated_addresses

    def extract_ethereum(self, text: str) -> list[str]:
        """Extract Ethereum addresses from text."""
        return self._extract_pattern(text, "ethereum")

    def extract_monero(self, text: str) -> list[str]:
        """Extract Monero addresses from text."""
        return self._extract_pattern(text, "monero")

    def extract_cves(self, text: str) -> list[str]:
        """Extract CVE identifiers from text."""
        return self._extract_pattern(text, "cves")

    def extract_mitre_attack(self, text: str) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from text."""
        return self._extract_pattern(text, "mitre_attack")

    def extract_registry(self, text: str) -> list[str]:
        """Extract Windows registry keys from text."""
        return self._extract_pattern(text, "registry")

    def extract_mutex(self, text: str) -> list[str]:
        """Extract mutex names from text."""
        return self._extract_pattern(text, "mutex")

    def extract_service_names(self, text: str) -> list[str]:
        """Extract Windows service names from text."""
        matches = self._extract_pattern(text, "service_names")
        return list(set(matches))

    def extract_named_pipes(self, text: str) -> list[str]:
        """Extract Windows named pipes from text."""
        return self._extract_pattern(text, "named_pipes")

    def extract_filenames(self, text: str) -> list[str]:
        """Extract filenames from text, only real files with extensions."""
        matches = self._extract_pattern(text, "filenames")

        real_filenames = []
        for match in matches:
            if isinstance(match, str) and "." in match and len(match) > 4:
                real_filenames.append(match)

        legitimate_processes = {
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

        filtered_matches = [
            match for match in real_filenames if match.lower() not in legitimate_processes
        ]

        return list(set(filtered_matches))

    def extract_filepaths(self, text: str) -> list[str]:
        """Extract file paths from text with validation."""
        raw_paths = self._extract_pattern(text, "filepaths")

        valid_paths = []
        for path in raw_paths:
            clean_path = path.strip()

            if (
                len(clean_path) >= 10
                and len(clean_path) < 300
                and ("\\" in clean_path or "/" in clean_path)
                and not any(
                    word in clean_path.lower()
                    for word in [
                        "folder on the",
                        "uploaded to",
                        "artifacts were",
                        "initially",
                    ]
                )
            ):
                clean_part = clean_path.rstrip('",;\'"').strip()

                if (":\\" in clean_part or clean_part.startswith("%")) or (
                    clean_part.startswith("/") and len(clean_part) > 5
                ):
                    valid_paths.append(clean_part)

        return list(set(valid_paths))

    def extract_mac_addresses(self, text: str) -> list[str]:
        """Extract MAC addresses from text."""
        candidates = self._extract_pattern(text, "mac_addresses")
        valid_macs = []

        for mac in candidates:
            if "." in mac and len(mac.replace(".", "")) == 12:
                hex_only = mac.replace(".", "")
                if all(c in "0123456789abcdefABCDEF" for c in hex_only):
                    formatted = ":".join([hex_only[i : i + 2] for i in range(0, 12, 2)])
                    valid_macs.append(formatted)
                continue

            normalized = mac.replace("-", ":").lower()
            hex_only = normalized.replace(":", "")
            if len(hex_only) != 12:
                continue

            if ":" in normalized:
                parts = normalized.split(":")
                if len(parts) == 6 and all(
                    len(part) == 2 and all(c in "0123456789abcdef" for c in part) for part in parts
                ):
                    valid_macs.append(mac)

        return list(set(valid_macs))

    def extract_user_agents(self, text: str) -> list[str]:
        """Extract user agent strings from text."""
        return self._extract_pattern(text, "user_agents")

    def extract_yara_rules(self, text: str) -> list[str]:
        """Extract YARA rules from text with better validation."""
        raw_rules = self._extract_pattern(text, "yara")

        valid_rules = []
        for rule in raw_rules:
            if len(rule) < 3000 and "rule " in rule and "{" in rule:
                if any(keyword in rule for keyword in ["strings:", "condition:", "meta:"]):
                    clean_rule = rule.strip()
                    if not clean_rule.endswith("}"):
                        clean_rule += "\n}"
                    valid_rules.append(clean_rule)

        return valid_rules

    def extract_asn(self, text: str) -> list[str]:
        """Extract AS numbers from text."""
        return self._extract_pattern(text, "asn")

    def extract_jwt(self, text: str) -> list[str]:
        """Extract JWT tokens from text."""
        return self._extract_pattern(text, "jwt")

    def extract_cert_serials(self, text: str) -> list[str]:
        """Extract certificate serial numbers from text."""
        candidates = self._extract_pattern(text, "cert_serials")
        valid_serials = []

        for candidate in candidates:
            if ":" not in candidate and len(candidate) >= 16:
                normalized = ":".join([candidate[i : i + 2] for i in range(0, len(candidate), 2)])
            else:
                normalized = candidate

            if ":" in normalized:
                parts = normalized.split(":")
                if 8 <= len(parts) <= 32 and all(
                    len(part) == 2 and part.isalnum() for part in parts
                ):
                    if len(parts) != 6 and all(
                        c in "0123456789abcdefABCDEF" for c in normalized.replace(":", "")
                    ):
                        valid_serials.append(normalized.lower())

        return list(set(valid_serials))
