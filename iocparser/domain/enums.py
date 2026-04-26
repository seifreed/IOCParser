from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RunStatus(StrEnum):
    """Canonical run status values."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


EMPTY_CUSTOM_IOC_TYPE = "Custom IOC type name cannot be empty"
INVALID_CUSTOM_BASE_TYPE = "Custom IOC types must derive from a built-in base IOC type"


class SourceKind(StrEnum):
    """Supported source kinds."""

    FILE = "file"
    URL = "url"
    TEXT = "text"

    @classmethod
    def from_name(cls, value: str) -> SourceKind:
        """Resolve a source kind from its wire value."""
        return cls(value)


class IOCType(StrEnum):
    """Canonical IOC type names used inside the domain."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SSDEEP = "ssdeep"
    IMPHASH = "imphash"
    DOMAIN = "domains"
    HOST = "hosts"
    IP = "ips"
    IPV6 = "ipv6"
    URL = "urls"
    EMAIL = "emails"
    CVE = "cves"
    MITRE_ATTACK = "mitre_attack"
    REGISTRY = "registry"
    MUTEX = "mutex"
    SERVICE_NAME = "service_names"
    NAMED_PIPE = "named_pipes"
    FILENAME = "filenames"
    FILEPATH = "filepaths"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    MONERO = "monero"
    MAC_ADDRESS = "mac_addresses"
    USER_AGENT = "user_agents"
    YARA = "yara"
    ASN = "asn"
    JWT = "jwt"
    CERT_SERIAL = "cert_serials"
    CIDR = "cidr"
    MITRE_ATTACK_SOFTWARE = "mitre_software"
    MITRE_ATTACK_GROUP = "mitre_groups"
    MITRE_ATTACK_MITIGATION = "mitre_mitigations"
    MITRE_ATTACK_DATASOURCE = "mitre_datasources"
    ONION_ADDRESS = "onion_addresses"
    AWS_ACCESS_KEY = "aws_access_keys"
    PDB_PATH = "pdb_paths"
    JA3 = "ja3"
    JA3S = "ja3s"
    JA4 = "ja4"
    HASSH = "hassh"
    HASSH_SERVER = "hassh_server"
    JARM = "jarm"
    AWS_ARN = "aws_arns"
    GCP_SERVICE_ACCOUNT = "gcp_service_accounts"
    AZURE_APP_ID = "azure_app_ids"
    DOCKER_IMAGE = "docker_images"
    TLSH = "tlsh"
    SIGMA_RULE_ID = "sigma_rule_ids"
    SURICATA_SID = "suricata_sids"
    SNORT_RULE = "snort_rules"
    SIGMA_RULE = "sigma_rules"

    @classmethod
    def from_name(cls, value: str) -> IOCType | IOCTypeName:
        """Resolve a canonical IOC type from wire names or aliases."""
        aliases = {
            "domain": cls.DOMAIN,
            "domains": cls.DOMAIN,
            "host": cls.HOST,
            "hosts": cls.HOST,
            "ip": cls.IP,
            "ips": cls.IP,
            "ipv4": cls.IP,
            "ipv6": cls.IPV6,
            "url": cls.URL,
            "urls": cls.URL,
            "email": cls.EMAIL,
            "emails": cls.EMAIL,
            "hashes": cls.SHA256,
            "cidr": cls.CIDR,
            "onion": cls.ONION_ADDRESS,
            "onion_address": cls.ONION_ADDRESS,
            "aws_key": cls.AWS_ACCESS_KEY,
            "pdb": cls.PDB_PATH,
            "arn": cls.AWS_ARN,
            "gcp": cls.GCP_SERVICE_ACCOUNT,
            "azure": cls.AZURE_APP_ID,
            "docker": cls.DOCKER_IMAGE,
            "suricata": cls.SURICATA_SID,
            "snort": cls.SNORT_RULE,
            "sigma": cls.SIGMA_RULE,
        }
        normalized = value.lower()
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return resolve_custom_ioc_type(normalized)


class IOCTypeName(str):
    """String IOC type compatible with built-in enum access patterns."""

    __slots__ = ()

    @property
    def value(self) -> str:
        return str(self)


@dataclass(frozen=True)
class CustomIOCTypeDefinition:
    """Registered custom IOC type metadata."""

    name: str
    base_type: IOCType
    aliases: tuple[str, ...] = ()
    severity: str | None = None
    tags: tuple[str, ...] = ()
    stix_pattern: str | None = None


_custom_ioc_types: dict[str, CustomIOCTypeDefinition] = {}
_custom_ioc_aliases: dict[str, str] = {}


def register_custom_ioc_type(
    name: str,
    *,
    base_type: IOCType | str = IOCType.URL,
    aliases: tuple[str, ...] = (),
    severity: str | None = None,
    tags: tuple[str, ...] = (),
    stix_pattern: str | None = None,
) -> IOCTypeName:
    """Register a custom IOC type that behaves like a first-class domain type."""
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError(EMPTY_CUSTOM_IOC_TYPE)
    base = base_type if isinstance(base_type, IOCType) else IOCType.from_name(str(base_type))
    if not isinstance(base, IOCType):
        raise TypeError(INVALID_CUSTOM_BASE_TYPE)
    definition = CustomIOCTypeDefinition(
        name=normalized,
        base_type=base,
        aliases=tuple(alias.strip().lower() for alias in aliases if alias.strip()),
        severity=severity.lower().strip() if severity else None,
        tags=tuple(tag.strip().lower() for tag in tags if tag.strip()),
        stix_pattern=stix_pattern,
    )
    _custom_ioc_types[normalized] = definition
    for alias in definition.aliases:
        _custom_ioc_aliases[alias] = normalized
    return IOCTypeName(normalized)


def resolve_custom_ioc_type(value: str) -> IOCTypeName:
    """Resolve a registered custom IOC type name."""
    normalized = value.strip().lower()
    canonical = _custom_ioc_aliases.get(normalized, normalized)
    if canonical not in _custom_ioc_types:
        raise ValueError(normalized)
    return IOCTypeName(canonical)


def get_custom_ioc_type(name: IOCType | IOCTypeName | str) -> CustomIOCTypeDefinition | None:
    """Return the custom IOC type metadata if the type is registered."""
    key = ioc_type_name(name)
    return _custom_ioc_types.get(key)


def custom_ioc_type_names() -> tuple[str, ...]:
    """List registered custom IOC type names."""
    return tuple(sorted(_custom_ioc_types))


def ioc_type_name(value: IOCType | IOCTypeName | str) -> str:
    """Return the canonical string name for any IOC type reference."""
    if isinstance(value, IOCType):
        return value.value
    return str(value)
