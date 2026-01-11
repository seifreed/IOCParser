#!/usr/bin/env python3

"""
Module for formatting IOCs output in different formats

Author: Marc Rivero | @seifreed
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, Union

# Type aliases for complex return types
JSONValue = Union[list[str | dict[str, str]], dict[str, list[dict[str, str]]], list[str]]


class OutputFormatter(ABC):
    """Abstract base class for all output formatters."""

    def __init__(
        self,
        data: dict[str, list[str | dict[str, str]]],
        warning_iocs: dict[str, list[dict[str, str]]] | None = None,
    ) -> None:
        """
        Initialize the output formatter.

        Args:
            data: Data to format
            warning_iocs: IOCs found in warning lists
        """
        self.data: dict[str, list[str | dict[str, str]]] = data
        self.warning_iocs: dict[str, list[dict[str, str]]] = warning_iocs or {}

    def _ensure_directory(self, output_file: str) -> None:
        """Create parent directory if it doesn't exist."""
        Path(output_file).resolve().parent.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def format(self) -> str:
        """
        Format the data.

        Returns:
            The formatted data
        """

    @abstractmethod
    def save(self, output_file: str) -> None:
        """
        Save the formatted data to a file.

        Args:
            output_file: Path to the output file
        """


class JSONFormatter(OutputFormatter):
    """Class for formatting output in JSON."""

    def _prepare_data_for_json(self) -> dict[str, JSONValue]:
        """Prepare data for JSON serialization."""
        result: dict[str, JSONValue] = {}

        # Copy and sort regular data
        for key, value in self.data.items():
            if key != "hashes" and isinstance(value, list):
                # Sort only string values, preserve dict values as-is
                str_values = [item for item in value if isinstance(item, str)]
                dict_values = [item for item in value if isinstance(item, dict)]
                if str_values and not dict_values:
                    sorted_values: list[str] = sorted(str_values)
                    result[key] = sorted_values
                else:
                    result[key] = value
            else:
                result[key] = value

        # Add warning IOCs if available
        if self.warning_iocs:
            # Type assertion for warning_iocs
            warning_data: dict[str, list[dict[str, str]]] = self.warning_iocs
            result["warning_list_matches"] = warning_data

        return result

    def format(self) -> str:
        """
        Format the data in JSON.

        Returns:
            The data formatted in JSON
        """
        data_to_serialize = self._prepare_data_for_json()
        # Use type: ignore for json.dumps since it accepts complex types
        return json.dumps(data_to_serialize, indent=4, sort_keys=True)

    def save(self, output_file: str) -> None:
        """
        Save the formatted data to a JSON file.

        Args:
            output_file: Path to the output file
        """
        self._ensure_directory(output_file)
        data_to_serialize = self._prepare_data_for_json()

        with Path(output_file).open("w", encoding="utf-8") as f:
            json.dump(data_to_serialize, f, indent=4, ensure_ascii=False, sort_keys=True)


class TextFormatter(OutputFormatter):
    """Class for formatting output in plain text."""

    SECTION_ORDER: ClassVar[list[tuple[str, str]]] = [
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

    def _format_hashes_section(self, data: list[str | dict[str, str]]) -> list[str]:
        """Format hash entries grouped by type."""
        hashes_by_type: dict[str, list[str]] = {}
        for hash_obj in data:
            if isinstance(hash_obj, dict):
                hash_type = hash_obj.get("type", "unknown")
                if hash_type not in hashes_by_type:
                    hashes_by_type[hash_type] = []
                hashes_by_type[hash_type].append(hash_obj.get("value", ""))
            else:
                # If it's a string, group as unknown
                if "unknown" not in hashes_by_type:
                    hashes_by_type["unknown"] = []
                hashes_by_type["unknown"].append(str(hash_obj))

        result = []
        for hash_type in sorted(hashes_by_type.keys()):
            result.extend(sorted(hashes_by_type[hash_type]))
        return result

    def _format_yara_section(self, data: list[str]) -> list[str]:
        """Format YARA rules section."""
        return [f"```\n{rule}\n```\n" for rule in data]

    def _format_section(
        self,
        section_key: str,
        data: list[str | dict[str, str]],
    ) -> list[str]:
        """Format a section based on its type."""
        if section_key == "hashes":
            return self._format_hashes_section(data)
        if section_key == "yara":
            # For YARA, data should be strings only
            yara_data = [str(item) for item in data if isinstance(item, str)]
            return self._format_yara_section(yara_data)
        # For hash sections (md5, sha1, sha256, etc.) and other sections
        # Filter to strings and return without extra line breaks
        str_data = [str(item) for item in data]
        # Return sorted list without extra newlines
        return sorted(str_data)

    def _format_warning_ioc(self, ioc: dict[str, str] | str) -> list[str]:
        """Format a single warning IOC entry."""
        result = []
        if isinstance(ioc, dict):
            value = ioc.get("value", "")
            warning_list = ioc.get("warning_list", "Unknown list")
            description = ioc.get("description", "")
            result.append(f"{value} - *{warning_list}*")
            if description:
                result.append(f"  Description: {description}")
        else:
            result.append(str(ioc))
        return result

    def format(self) -> str:
        """
        Format the data in plain text.

        Returns:
            str: The data formatted in plain text
        """
        output: list[str] = ["# Indicators of Compromise (IOCs) Extracted\n"]

        # Process each section in the specified order
        for section_key, section_title in self.SECTION_ORDER:
            section_data = self.data.get(section_key)
            if section_data:
                output.append(f"\n## {section_title}\n")
                # Convert to Union type for _format_section
                union_data: list[str | dict[str, str]] = []
                for item in section_data:
                    if isinstance(item, dict):
                        union_data.append(item)
                    else:
                        union_data.append(str(item))
                output.extend(self._format_section(section_key, union_data))

        # Add warning list IOCs if available
        if self.warning_iocs:
            output.append("\n# Warning List Matches\n")
            output.append(
                "The following indicators were found in warning lists "
                "and might be false positives:\n",
            )

            for section_key, section_title in self.SECTION_ORDER:
                if self.warning_iocs.get(section_key):
                    output.append(f"\n## {section_title} in Warning Lists\n")
                    for ioc in self.warning_iocs[section_key]:
                        output.extend(self._format_warning_ioc(ioc))

        # Remove extra blank lines
        return "\n".join(output)

    def save(self, output_file: str) -> None:
        """
        Save the formatted data to a text file.

        Args:
            output_file: Path to the output file
        """
        try:
            self._ensure_directory(output_file)
            with Path(output_file).open("w", encoding="utf-8") as f:
                f.write(self.format())
        except Exception as e:
            print(f"Error saving text file: {e!s}")
