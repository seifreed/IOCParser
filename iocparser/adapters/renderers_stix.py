from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import ClassVar

from stix2 import Indicator

from iocparser.domain.enums import IOCTypeName, get_custom_ioc_type
from iocparser.domain.models import ExtractionResult, IOCType, WarningMatch, ioc_type_name
from iocparser.domain.pipeline import RESULT_SCHEMA_VERSION
from iocparser.interfaces.ports import OutputRenderer
from iocparser.rendering_support import build_stix_bundle
from iocparser.shared_utils import refang_ioc


class STIXOutputRenderer(OutputRenderer):
    """Render normalized extraction results as a STIX 2.1 bundle."""

    PATTERN_BUILDERS: ClassVar[dict[IOCType, Callable[[str], str]]] = {}

    def __init__(self, *, allowed_types: set[IOCType | IOCTypeName] | None = None) -> None:
        self.now = datetime.now(UTC)
        self.allowed_types = allowed_types
        if not self.PATTERN_BUILDERS:
            self._init_pattern_builders()

    @classmethod
    def _init_pattern_builders(cls) -> None:
        def _escape(value: str) -> str:
            return value.replace("\\", "\\\\").replace("'", "\\'")

        def _builder(pattern: str) -> Callable[[str], str]:
            return lambda value: pattern.format(value=_escape(refang_ioc(value)))

        cls.PATTERN_BUILDERS = {
            IOCType.DOMAIN: _builder("[domain-name:value = '{value}']"),
            IOCType.HOST: _builder("[domain-name:value = '{value}']"),
            IOCType.IP: _builder("[ipv4-addr:value = '{value}']"),
            IOCType.IPV6: _builder("[ipv6-addr:value = '{value}']"),
            IOCType.URL: _builder("[url:value = '{value}']"),
            IOCType.EMAIL: _builder("[email-addr:value = '{value}']"),
            IOCType.MD5: _builder("[file:hashes.'MD5' = '{value}']"),
            IOCType.SHA1: _builder("[file:hashes.'SHA-1' = '{value}']"),
            IOCType.SHA256: _builder("[file:hashes.'SHA-256' = '{value}']"),
            IOCType.SHA512: _builder("[file:hashes.'SHA-512' = '{value}']"),
            IOCType.FILENAME: _builder("[file:name = '{value}']"),
            IOCType.FILEPATH: _builder("[file:path = '{value}']"),
            # CVE omitted: STIX 2.1 models vulnerabilities as SDOs, not indicator patterns
            IOCType.REGISTRY: _builder("[windows-registry-key:key = '{value}']"),
            IOCType.MUTEX: _builder("[mutex:name = '{value}']"),
            IOCType.MAC_ADDRESS: _builder("[mac-addr:value = '{value}']"),
            IOCType.ASN: _builder("[autonomous-system:number = '{value}']"),
            IOCType.CIDR: _builder("[ipv4-addr:value = '{value}']"),
            IOCType.ONION_ADDRESS: _builder("[domain-name:value = '{value}']"),
            IOCType.AWS_ARN: _builder("[x-cloud-resource:value = '{value}']"),
            IOCType.GCP_SERVICE_ACCOUNT: _builder("[email-addr:value = '{value}']"),
            IOCType.AZURE_APP_ID: _builder("[x-cloud-resource:value = '{value}']"),
            IOCType.DOCKER_IMAGE: _builder("[software:name = '{value}']"),
            IOCType.TLSH: _builder("[file:hashes.'TLSH' = '{value}']"),
        }

    def _build_indicator(self, ioc_type: IOCType | str, value: str, warning: WarningMatch | None) -> Indicator | None:
        if self.allowed_types is not None and ioc_type not in self.allowed_types:
            return None
        lookup_type = get_custom_ioc_type(ioc_type) if isinstance(ioc_type, str) else None
        base_lookup_type = lookup_type.base_type if lookup_type is not None else ioc_type if isinstance(ioc_type, IOCType) else None
        builder = self.PATTERN_BUILDERS.get(base_lookup_type) if isinstance(base_lookup_type, IOCType) else None
        if builder is None and lookup_type is not None and lookup_type.stix_pattern:
            captured_pattern = str(lookup_type.stix_pattern)

            def custom_builder(current_value: str) -> str:
                escaped = refang_ioc(current_value).replace("\\", "\\\\").replace("'", "\\'")
                return captured_pattern.format(value=escaped)

            builder = custom_builder
        if not builder:
            return None
        custom_props: dict[str, str] = {}
        if warning:
            custom_props["x_warning_list"] = warning.warning_list
            if warning.description:
                custom_props["x_warning_description"] = warning.description
        return Indicator(
            name=f"{ioc_type_name(ioc_type)} indicator",
            pattern=builder(value),
            pattern_type="stix",
            pattern_version="2.1",
            valid_from=self.now,
            description=None,
            indicator_types=["malicious-activity"],
            allow_custom=True,
            **custom_props,  # type: ignore[arg-type]
        )

    def render(self, result: ExtractionResult) -> str:
        entries = [("ioc", ioc) for ioc in result.iocs] + [("warning", warning) for warning in result.warnings]
        return build_stix_bundle(
            entries,
            build_indicator=lambda entry: build_entry_indicator(self, entry),
            bundle_mutator=augment_stix_payload,
        )


def build_entry_indicator(renderer: STIXOutputRenderer, entry: tuple[str, object]) -> Indicator | None:
    entry_kind, payload = entry
    if entry_kind == "ioc" and hasattr(payload, "ioc_type") and hasattr(payload, "canonical_value"):
        return renderer._build_indicator(payload.ioc_type, payload.canonical_value(), None)
    if entry_kind == "warning" and hasattr(payload, "ioc"):
        return renderer._build_indicator(payload.ioc.ioc_type, payload.ioc.canonical_value(), payload)  # type: ignore[arg-type]
    return None


def augment_stix_payload(payload: dict[str, object]) -> dict[str, object]:
    payload["x_iocparser_schema_version"] = RESULT_SCHEMA_VERSION
    payload["x_iocparser_format"] = "stix"
    return payload
