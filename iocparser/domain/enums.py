from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum

from iocparser.shared_utils import VALID_SEVERITIES, normalize_tokens


class RunStatus(StrEnum):
    """Canonical run status values."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


EMPTY_CUSTOM_IOC_TYPE = "Custom IOC type name cannot be empty"
INVALID_CUSTOM_BASE_TYPE = "Custom IOC types must derive from a built-in base IOC type"
SHADOWS_BUILTIN_IOC_TYPE = (
    "Custom IOC type name {name!r} shadows a built-in IOC type or alias and would never resolve"
)
ALIAS_SHADOWS_BUILTIN_IOC_TYPE = (
    "Alias {alias!r} for custom IOC type {name!r} shadows a built-in IOC type or alias "
    "and would never resolve"
)
ALIAS_COLLIDES_WITH_CUSTOM_TYPE = (
    "Alias {alias!r} for custom IOC type {name!r} already maps to custom type {owner!r}"
)
RESERVES_JSON_OUTPUT_KEY = (
    "Custom IOC type name {name!r} collides with a reserved JSON output key and would "
    "corrupt the rendered document"
)
RESERVES_CATEGORY_FILTER_NAME = (
    "Custom IOC type name {name!r} collides with a category filter word; --only/--exclude "
    "expands it to a family of types, so the custom type would never resolve"
)
INVALID_CUSTOM_SEVERITY = "Custom IOC type severity {severity!r} is not a recognized severity"
# Category words that --only/--exclude expand to a whole family of types before resolving
# any individual type. A custom type named after one can never be selected, so registration
# rejects it. Keep in sync with type_filters._CATEGORY_ALIASES (a guard there asserts it).
CATEGORY_FILTER_NAMES: frozenset[str] = frozenset({"hashes"})
# Structural keys the JSON renderer puts at the top level of its document. A custom IOC
# type whose name equals one of these would, when grouped into the payload, overwrite the
# metadata key with a flat list and corrupt the output. Keep in sync with
# adapters/renderers_json.py (a test asserts the renderer's metadata keys stay a subset).
RESERVED_JSON_OUTPUT_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "format",
        "records",
        "counts_by_type",
        "total_count",
        "warning_list_matches",
    }
)
ALIAS_COLLIDES_WITH_CUSTOM_TYPE_NAME = (
    "Alias {alias!r} for custom IOC type {name!r} shadows the canonical name of custom "
    "type {owner!r} and would make it unresolvable"
)


class SourceKind(StrEnum):
    """Supported source kinds."""

    FILE = "file"
    URL = "url"
    TEXT = "text"

    @classmethod
    def from_name(cls, value: str) -> SourceKind:
        """Resolve a source kind from its wire value."""
        if not isinstance(value, str):
            raise TypeError(f"Expected value to be string-like, got {type(value).__name__}")
        return cls(value.strip().lower())


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
        if not isinstance(value, str):
            raise TypeError(f"Expected value to be string-like, got {type(value).__name__}")
        aliases = {
            "domain": cls.DOMAIN,
            "domains": cls.DOMAIN,
            "host": cls.HOST,
            "hostname": cls.HOST,
            "hostnames": cls.HOST,
            "hosts": cls.HOST,
            "ip": cls.IP,
            "ips": cls.IP,
            "ipv4": cls.IP,
            "ipv6": cls.IPV6,
            "url": cls.URL,
            "uri": cls.URL,
            "urls": cls.URL,
            "email": cls.EMAIL,
            "emails": cls.EMAIL,
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
            # The artifact extractor's method is extract_yara_rules, so extract_all
            # emits the key "yara_rules" while the canonical enum value is "yara".
            "yara_rules": cls.YARA,
        }
        normalized = value.strip().lower()
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return resolve_custom_ioc_type(normalized)


HASH_IOC_TYPES = frozenset(
    {
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.SHA512,
        IOCType.SSDEEP,
        IOCType.IMPHASH,
    }
)


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
# Serializes mutation/iteration of the registry dicts. Plugin discovery can run from
# several threads on first use; without this, register_custom_ioc_type iterated
# _custom_ioc_aliases while another thread mutated it ("dict changed size during
# iteration") and lost updates.
_registry_lock = threading.Lock()


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
    # A name equal to a built-in IOC type/alias can never resolve to this custom
    # type (IOCType.from_name checks built-ins first), so the registration would be
    # silently inert. Reject it instead of accepting a dead definition.
    if normalized not in _custom_ioc_types and _is_builtin_ioc_type(normalized):
        raise ValueError(SHADOWS_BUILTIN_IOC_TYPE.format(name=name))
    # A name equal to a reserved JSON output key would clobber that metadata field with the
    # type's value list when rendered, silently corrupting the document. Reject up front.
    if normalized in RESERVED_JSON_OUTPUT_KEYS:
        raise ValueError(RESERVES_JSON_OUTPUT_KEY.format(name=name))
    # A name equal to a category filter word ("hashes") is expanded by parse_ioc_types
    # before any per-type resolution, so --only/--exclude could never select it.
    if normalized in CATEGORY_FILTER_NAMES:
        raise ValueError(RESERVES_CATEGORY_FILTER_NAME.format(name=name))
    if isinstance(base_type, IOCType):
        base: IOCType | IOCTypeName = base_type
    else:
        try:
            base = IOCType.from_name(str(base_type))
        except ValueError as exc:
            # from_name raises a bare ValueError(<name>) for an unknown type; surface the
            # same clear "must derive from a built-in base IOC type" message the custom-type
            # base case already raises, instead of a cryptic bare value.
            raise TypeError(INVALID_CUSTOM_BASE_TYPE) from exc
    if not isinstance(base, IOCType):
        raise TypeError(INVALID_CUSTOM_BASE_TYPE)
    normalized_aliases = _validated_custom_aliases(normalize_tokens(aliases), owner=normalized)
    definition = CustomIOCTypeDefinition(
        name=normalized,
        base_type=base,
        aliases=normalized_aliases,
        severity=_validated_custom_severity(severity),
        tags=normalize_tokens(tags),
        stix_pattern=stix_pattern,
    )
    # Drop aliases this type owned in a prior registration; otherwise an alias removed
    # in a re-registration (e.g. a reloaded plugin) keeps resolving and can falsely
    # block a different type from claiming it. Serialized so concurrent registrations
    # don't iterate the alias dict while another thread mutates it.
    with _registry_lock:
        for stale_alias in [
            alias for alias, owner in _custom_ioc_aliases.items() if owner == normalized
        ]:
            del _custom_ioc_aliases[stale_alias]
        _custom_ioc_types[normalized] = definition
        for alias in definition.aliases:
            _custom_ioc_aliases[alias] = normalized
    return IOCTypeName(normalized)


def _validated_custom_severity(severity: str | None) -> str | None:
    # Reject an unrecognized severity (e.g. "critical"): it would be stored but ranked
    # below informational by min_severity (silent drop) and rejected by the exact filter.
    normalized = severity.lower().strip() if severity else None
    if normalized is not None and normalized not in VALID_SEVERITIES:
        raise ValueError(INVALID_CUSTOM_SEVERITY.format(severity=severity))
    return normalized


def _is_builtin_ioc_type(name: str) -> bool:
    """Whether a name resolves to a built-in IOCType (not a custom type)."""
    try:
        return isinstance(IOCType.from_name(name), IOCType)
    except ValueError:
        return False


def _validated_custom_aliases(aliases: tuple[str, ...], *, owner: str) -> tuple[str, ...]:
    """Reject aliases that would be dead or that silently steal another type's alias.

    An alias equal to a built-in type/alias never resolves to the custom type
    (IOCType.from_name checks built-ins first), and an alias already owned by a
    different custom type would be silently overwritten -- both are rejected so the
    registration fails loudly instead of producing an inert or surprising mapping.
    """
    for alias in aliases:
        if alias == owner:
            continue
        if _is_builtin_ioc_type(alias):
            raise ValueError(ALIAS_SHADOWS_BUILTIN_IOC_TYPE.format(alias=alias, name=owner))
        if alias in _custom_ioc_types and alias != owner:
            raise ValueError(
                ALIAS_COLLIDES_WITH_CUSTOM_TYPE_NAME.format(alias=alias, name=owner, owner=alias)
            )
        existing_owner = _custom_ioc_aliases.get(alias)
        if existing_owner is not None and existing_owner != owner:
            raise ValueError(
                ALIAS_COLLIDES_WITH_CUSTOM_TYPE.format(
                    alias=alias, name=owner, owner=existing_owner
                )
            )
    return aliases


def resolve_custom_ioc_type(value: str) -> IOCTypeName:
    """Resolve a registered custom IOC type name."""
    normalized = value.strip().lower()
    canonical = _custom_ioc_aliases.get(normalized, normalized)
    if canonical not in _custom_ioc_types:
        raise ValueError(normalized)
    return IOCTypeName(canonical)


def get_custom_ioc_type(name: IOCType | IOCTypeName | str) -> CustomIOCTypeDefinition | None:
    """Return the custom IOC type metadata if the type is registered."""
    key = ioc_type_name(name).strip().lower()
    key = _custom_ioc_aliases.get(key, key)
    return _custom_ioc_types.get(key)


def custom_ioc_type_names() -> tuple[str, ...]:
    """List registered custom IOC type names."""
    with _registry_lock:
        return tuple(sorted(_custom_ioc_types))


def ioc_type_name(value: IOCType | IOCTypeName | str) -> str:
    """Return the canonical string name for any IOC type reference."""
    if isinstance(value, IOCType):
        return value.value
    return str(value)
