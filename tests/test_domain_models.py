from __future__ import annotations

from iocparser.domain.models import (
    IOC,
    DomainValue,
    EmailValue,
    ExtractionOptions,
    ExtractionResult,
    IOCType,
    IpValue,
    PersistOptions,
    Source,
    SourceKind,
    UrlValue,
    classify_ioc,
    indicator_value_for,
    register_custom_ioc_type,
)
from iocparser.domain.sources import normalize_url_value
from iocparser.domain.type_filters import parse_ioc_types


def test_source_kind_and_ioc_type_resolve_aliases() -> None:
    assert SourceKind.from_name("file") is SourceKind.FILE
    assert SourceKind.from_name(" URL ") is SourceKind.URL
    assert IOCType.from_name("domain") is IOCType.DOMAIN
    assert IOCType.from_name("host") is IOCType.HOST
    assert IOCType.from_name("ip") is IOCType.IP
    assert IOCType.from_name("ipv4") is IOCType.IP
    assert IOCType.from_name("url") is IOCType.URL
    assert IOCType.from_name("email") is IOCType.EMAIL
    assert IOCType.from_name(" domains ") is IOCType.DOMAIN


def test_yara_rules_extraction_key_resolves_to_yara_type() -> None:
    """Regression: extract_all emits the key "yara_rules" (from the method name
    extract_yara_rules), which must resolve to IOCType.YARA. It previously raised
    ValueError, crashing every extraction of a report containing a YARA rule."""
    assert IOCType.from_name("yara_rules") is IOCType.YARA

    from iocparser.infrastructure.extraction import IOCExtractor

    yara_rule = (
        "rule MalwareDetection {\n"
        '    meta:\n        description = "test"\n'
        '    strings:\n        $a = "SystemUpdateMutex"\n'
        "    condition:\n        any of them\n}"
    )
    extracted = IOCExtractor().extract_all(yara_rule)
    assert "yara_rules" in extracted
    assert all(isinstance(IOCType.from_name(key), IOCType) for key in extracted)


def test_hashes_category_filter_selects_whole_hash_family() -> None:
    """--only/--exclude hashes must cover every hash type, not just sha256.

    Regression: "hashes" was aliased to IOCType.SHA256, so --only hashes dropped
    md5/sha1/sha512/ssdeep/imphash and --exclude hashes left them behind.
    """
    expanded = {str(ioc_type) for ioc_type in parse_ioc_types("hashes")}
    assert expanded == {"md5", "sha1", "sha256", "sha512", "ssdeep", "imphash"}
    # Blank segments are skipped; a single category still expands fully.
    assert {str(t) for t in parse_ioc_types("hashes, ,domain")} == {
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "ssdeep",
        "imphash",
        "domains",
    }

    result = ExtractionResult.from_grouped_payload(
        {
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "domains": ["evil.example.com"],
        },
        {},
    )
    only_hashes = result.filter_types(include_types=parse_ioc_types("hashes"))
    grouped = only_hashes.grouped_iocs()
    assert set(grouped) == {"md5", "sha256"}
    assert "domains" not in grouped


def test_base_type_filter_selects_custom_ioc_types() -> None:
    """A custom URL-derived IOC should match include/exclude filters for urls."""
    import iocparser.domain.enums as enums_module

    name = "domain_model_custom_url"
    enums_module._custom_ioc_types.pop(name, None)
    try:
        register_custom_ioc_type(name, base_type="urls")
        result = ExtractionResult(iocs=(IOC.from_raw(name, "hxxps://example.com/a"),))

        assert result.filter_types(include_types=parse_ioc_types("urls")).total_count() == 1
        assert result.filter_types(exclude_types=parse_ioc_types("urls")).total_count() == 0
    finally:
        enums_module._custom_ioc_types.pop(name, None)


def test_extraction_options_base_type_allows_custom_ioc_types() -> None:
    import iocparser.domain.enums as enums_module

    name = "options_custom_url"
    enums_module._custom_ioc_types.pop(name, None)
    try:
        custom_name = register_custom_ioc_type(name, base_type="urls")

        assert ExtractionOptions(include_types=parse_ioc_types("urls")).allows(custom_name)
        assert not ExtractionOptions(exclude_types=parse_ioc_types("urls")).allows(custom_name)
        assert not ExtractionOptions(include_types=(custom_name,)).allows(IOCType.URL)
    finally:
        enums_module._custom_ioc_types.pop(name, None)


def test_grouped_iocs_keeps_case_distinct_urls_but_collapses_domains() -> None:
    """grouped_iocs must dedup on the canonical value, not a blanket lowercase.

    Regression: lowercasing every value merged case-distinct URLs (paths are
    case-sensitive per RFC 3986), silently dropping a distinct IOC from the public
    API and the persistence path, while case-insensitive domains must still merge.
    """
    result = ExtractionResult.from_grouped_payload(
        {
            "urls": ["http://x.com/AAAA", "http://x.com/aaaa"],
            "domains": ["Example.com", "example.com"],
        },
        {},
    )
    grouped = result.grouped_iocs()
    assert sorted(grouped["urls"]) == ["http://x.com/AAAA", "http://x.com/aaaa"]
    assert grouped["domains"] == ["Example.com"]


def test_value_objects_canonicalize_expected_values() -> None:
    assert DomainValue(" Example[.]COM ").canonical() == "example.com"
    assert UrlValue("hxxps://Example[.]COM/path").canonical() == "https://example.com/path"
    assert UrlValue("not really a url").canonical() == "not really a url"
    assert UrlValue("http://[::1").canonical() == "http://[::1"
    assert IpValue("2001:0db8::1").canonical() == "2001:db8::1"
    assert IpValue("not-an-ip").canonical() == "not-an-ip"
    assert EmailValue(" USER@Example[.]COM ").canonical() == "user@example.com"
    # ssdeep base64 is case-sensitive: strip only, never lowercase (would corrupt the digest).
    mixed_ssdeep = "768:C7tsNKI7aU8Y1O5wjNHDwLxQJidNG3qGqDRT:CtsI7aUwjNQidNG3GqDRT"
    assert indicator_value_for(IOCType.SSDEEP, f"  {mixed_ssdeep}  ").canonical() == mixed_ssdeep


def test_indicator_value_for_selects_specialized_types() -> None:
    assert type(indicator_value_for(IOCType.DOMAIN, "example.com")).__name__ == "DomainValue"
    assert type(indicator_value_for(IOCType.URL, "https://example.com")).__name__ == "UrlValue"
    assert type(indicator_value_for(IOCType.SHA256, "ABCD")).__name__ == "HashValue"
    assert type(indicator_value_for(IOCType.SSDEEP, "3:AbC:dE")).__name__ == "FuzzyHashValue"
    assert type(indicator_value_for(IOCType.IP, "198.51.100.7")).__name__ == "IpValue"
    assert type(indicator_value_for(IOCType.EMAIL, "a@b.test")).__name__ == "EmailValue"
    assert type(indicator_value_for("urls", "hxxps://example[.]com")).__name__ == "UrlValue"
    assert indicator_value_for("urls", "hxxps://example[.]com").canonical() == (
        "https://example.com/"
    )


def test_ioc_and_source_build_from_raw_inputs() -> None:
    source = Source.from_raw("text", "sample")
    ioc = IOC.from_raw("domains", "Example[.]COM")

    assert source == Source(kind=SourceKind.TEXT, value="sample")
    assert ioc.ioc_type is IOCType.DOMAIN
    assert ioc.canonical_value() == "example.com"


def test_classify_ioc_normalizes_string_type_names() -> None:
    severity, tags = classify_ioc("urls")

    assert severity == "medium"
    assert tags == ("urls", "network")


def test_custom_ioc_aliases_use_registered_metadata_for_direct_helpers() -> None:
    register_custom_ioc_type(
        "alias_url_type",
        base_type="urls",
        aliases=("alias-url",),
        severity="high",
        tags=("custom-tag",),
    )

    severity, tags = classify_ioc("alias-url")
    value = indicator_value_for("alias-url", "hxxps://Example[.]COM/path")

    assert severity == "high"
    assert tags == ("alias_url_type", "custom-tag")
    assert isinstance(value, UrlValue)
    assert value.canonical() == "https://example.com/path"


def test_register_custom_ioc_type_rejects_builtin_shadow() -> None:
    """A custom type named like a built-in/alias can never resolve, so registration
    must reject it instead of silently storing a dead definition."""
    import pytest

    for shadow in ("urls", "ip", "md5", "azure"):
        with pytest.raises(ValueError, match="shadows a built-in"):
            register_custom_ioc_type(shadow, base_type="urls")


def test_register_custom_ioc_type_rejects_reserved_json_output_key() -> None:
    """A custom type named like a reserved JSON output key would clobber that metadata
    field with its value list when rendered, corrupting the document. Reject it."""
    import pytest

    from iocparser.domain.enums import RESERVED_JSON_OUTPUT_KEYS

    for reserved in RESERVED_JSON_OUTPUT_KEYS:
        with pytest.raises(ValueError, match="reserved JSON output key"):
            register_custom_ioc_type(reserved, base_type="urls")


def test_json_renderer_metadata_keys_stay_within_reserved_set() -> None:
    """Drift guard: every top-level metadata key the JSON renderer emits must be declared
    in RESERVED_JSON_OUTPUT_KEYS, so the registration guard can never fall out of sync."""
    import json

    from iocparser.adapters.renderers_json import JSONOutputRenderer
    from iocparser.domain.enums import RESERVED_JSON_OUTPUT_KEYS
    from iocparser.domain.models import WarningMatch

    # A result with one IOC and one warning so every metadata key (incl. warning_list_matches)
    # is present; the single domain group key ("domains") is not a metadata key.
    result = ExtractionResult(
        iocs=(IOC.from_raw("domains", "evil.com"),),
        warnings=(
            WarningMatch(ioc=IOC.from_raw("ips", "8.8.8.8"), warning_list="L", description="d"),
        ),
    )
    rendered = json.loads(JSONOutputRenderer().render(result))
    metadata_keys = set(rendered) - {"domains", "ips"}
    assert metadata_keys <= RESERVED_JSON_OUTPUT_KEYS, (
        f"JSON renderer emits metadata keys not declared reserved: "
        f"{metadata_keys - RESERVED_JSON_OUTPUT_KEYS}"
    )


def test_register_custom_ioc_type_rejects_builtin_shadowing_alias() -> None:
    """An alias equal to a built-in type/alias never resolves to the custom type
    (built-ins win in from_name), so it must be rejected rather than stored dead."""
    import pytest

    with pytest.raises(ValueError, match="shadows a built-in"):
        register_custom_ioc_type("threatfeed_a", base_type="urls", aliases=("md5",))


def test_register_custom_ioc_type_rejects_alias_collision() -> None:
    """An alias already owned by a different custom type must not be silently stolen."""
    import pytest

    register_custom_ioc_type("collide_owner", base_type="urls", aliases=("shared_handle",))
    # Re-registering the same type with its own alias is idempotent, not a collision.
    register_custom_ioc_type("collide_owner", base_type="urls", aliases=("shared_handle",))
    with pytest.raises(ValueError, match="already maps to custom type"):
        register_custom_ioc_type("collide_thief", base_type="urls", aliases=("shared_handle",))


def test_register_custom_ioc_type_allows_alias_equal_to_own_name() -> None:
    """An alias identical to the type's own name is harmless and must be accepted."""
    name = register_custom_ioc_type("self_named", base_type="urls", aliases=("self_named",))
    assert str(name) == "self_named"


def test_re_registration_purges_dropped_aliases() -> None:
    """Regression: an alias dropped on re-registration must stop resolving (and free
    up for another type), instead of lingering in the alias map forever."""
    import pytest

    from iocparser.domain.enums import resolve_custom_ioc_type

    register_custom_ioc_type("reg_purge", base_type="urls", aliases=("rp_a", "rp_b"))
    register_custom_ioc_type("reg_purge", base_type="urls", aliases=("rp_a",))
    assert str(resolve_custom_ioc_type("rp_a")) == "reg_purge"
    with pytest.raises(ValueError, match="rp_b"):
        resolve_custom_ioc_type("rp_b")
    # The freed alias may now be claimed by a different type.
    register_custom_ioc_type("reg_purge_other", base_type="urls", aliases=("rp_b",))
    assert str(resolve_custom_ioc_type("rp_b")) == "reg_purge_other"


def test_register_custom_ioc_type_rejects_alias_shadowing_another_type_name() -> None:
    """Regression: an alias equal to another custom type's canonical name would hijack
    it (alias map is consulted first), making the original unresolvable -- reject it."""
    import pytest

    from iocparser.domain.enums import resolve_custom_ioc_type

    register_custom_ioc_type("shadow_target", base_type="urls")
    with pytest.raises(ValueError, match="shadows the canonical name"):
        register_custom_ioc_type("shadow_thief", base_type="urls", aliases=("shadow_target",))
    assert str(resolve_custom_ioc_type("shadow_target")) == "shadow_target"


def test_malformed_urls_do_not_break_source_normalization() -> None:
    source = Source.from_raw("url", "http://[::1")

    assert normalize_url_value("http://[::1") is None
    assert source.original_url == "http://[::1"
    assert source.normalized_url is None


def test_normalize_url_preserves_userinfo_case() -> None:
    # Host is lowercased for canonicalisation, but credentials are case-sensitive
    # and must not be folded (which would also collapse two distinct URLs).
    assert (
        normalize_url_value("http://User:PassWord@Host.COM/Path")
        == "http://User:PassWord@host.com/Path"
    )


def test_extraction_result_from_grouped_payload_groups_and_deduplicates() -> None:
    result = ExtractionResult.from_grouped_payload(
        normal_iocs={
            "domains": ["Example[.]COM", "Example[.]COM"],
            "ips": ["198.51.100.7"],
        },
        warning_iocs={
            "domains": [
                {
                    "value": "Example[.]COM",
                    "warning_list": "Known Good",
                    "description": "Whitelist",
                },
                {
                    "value": "Example[.]COM",
                    "warning_list": "Known Good",
                    "description": "Whitelist",
                },
                {
                    "value": "",
                    "warning_list": "Ignored",
                    "description": "Missing value",
                },
            ],
        },
    )

    assert result.grouped_iocs() == {
        "domains": ["Example[.]COM"],
        "ips": ["198.51.100.7"],
    }
    assert result.grouped_warnings() == {
        "domains": [
            {
                "value": "Example[.]COM",
                "warning_list": "Known Good",
                "description": "Whitelist",
            }
        ]
    }
    assert result.canonical_by_type() == {
        IOCType.DOMAIN: ("example.com",),
        IOCType.IP: ("198.51.100.7",),
    }


def test_persist_options_to_dict_is_storage_friendly() -> None:
    options = PersistOptions(
        defang=True,
        check_warnings=False,
        force_update=True,
        output_format="stix",
    )

    assert options.to_dict() == {
        "defang": True,
        "check_warnings": False,
        "force_update": True,
        "output_format": "stix",
    }
