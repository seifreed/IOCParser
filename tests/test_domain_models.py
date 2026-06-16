from __future__ import annotations

from iocparser.domain.models import (
    IOC,
    DomainValue,
    EmailValue,
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


def test_source_kind_and_ioc_type_resolve_aliases() -> None:
    assert SourceKind.from_name("file") is SourceKind.FILE
    assert IOCType.from_name("domain") is IOCType.DOMAIN
    assert IOCType.from_name("host") is IOCType.HOST
    assert IOCType.from_name("ip") is IOCType.IP
    assert IOCType.from_name("ipv4") is IOCType.IP
    assert IOCType.from_name("url") is IOCType.URL
    assert IOCType.from_name("email") is IOCType.EMAIL
    assert IOCType.from_name("hashes") is IOCType.SHA256


def test_value_objects_canonicalize_expected_values() -> None:
    assert DomainValue(" Example[.]COM ").canonical() == "example.com"
    assert UrlValue("hxxps://Example[.]COM/path").canonical() == "https://Example.COM/path"
    assert UrlValue("not really a url").canonical() == "not really a url"
    assert UrlValue("http://[::1").canonical() == "http://[::1"
    assert IpValue("2001:0db8::1").canonical() == "2001:db8::1"
    assert IpValue("not-an-ip").canonical() == "not-an-ip"
    assert EmailValue(" USER@Example[.]COM ").canonical() == "user@example.com"


def test_indicator_value_for_selects_specialized_types() -> None:
    assert type(indicator_value_for(IOCType.DOMAIN, "example.com")).__name__ == "DomainValue"
    assert type(indicator_value_for(IOCType.URL, "https://example.com")).__name__ == "UrlValue"
    assert type(indicator_value_for(IOCType.SHA256, "ABCD")).__name__ == "HashValue"
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
    assert value.canonical() == "https://Example.COM/path"


def test_register_custom_ioc_type_rejects_builtin_shadow() -> None:
    """A custom type named like a built-in/alias can never resolve, so registration
    must reject it instead of silently storing a dead definition."""
    import pytest

    for shadow in ("urls", "ip", "md5", "azure"):
        with pytest.raises(ValueError, match="shadows a built-in"):
            register_custom_ioc_type(shadow, base_type="urls")


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
