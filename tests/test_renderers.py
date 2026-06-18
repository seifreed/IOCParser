from __future__ import annotations

import json
from textwrap import dedent

import iocparser.domain.enums as enums_module
from iocparser.adapters.renderers import JSONOutputRenderer, STIXOutputRenderer, TextOutputRenderer
from iocparser.domain.enums import register_custom_ioc_type
from iocparser.domain.models import IOC, ExtractionResult, IOCType, WarningMatch
from iocparser.domain.results import IOCEvidence


def build_result() -> ExtractionResult:
    return ExtractionResult(
        iocs=(
            IOC.from_raw("domains", "Example[.]COM"),
            IOC.from_raw("urls", "hxxps://example[.]com/a"),
            IOC.from_raw("md5", "A" * 32),
            IOC.from_raw("jwt", "header.payload.signature"),
            IOC.from_raw("domains", "example.com"),
        ),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw("ips", "198.51.100.7"),
                warning_list="Known Benign",
                description="Public resolver",
            ),
            WarningMatch(
                ioc=IOC.from_raw("ips", "198.51.100.7"),
                warning_list="Known Benign",
                description="Public resolver",
            ),
            WarningMatch(
                ioc=IOC.from_raw("hosts", "Warn[.]Example"),
                warning_list="Internal Assets",
            ),
            WarningMatch(
                ioc=IOC.from_raw("domains", "Example[.]COM"),
                warning_list="Duplicate Pattern",
            ),
        ),
    )


def test_stix_output_renders_ssdeep_and_imphash_as_file_hashes() -> None:
    """ssdeep/imphash are file hashes and must render as STIX file:hashes patterns.

    They were missing from PATTERN_BUILDERS while tlsh/md5/sha* were present, so those
    IOCs vanished silently from STIX export. SSDEEP is a STIX-registered hash-algorithm
    name; IMPHASH is the conventional custom name.
    """
    result = ExtractionResult(
        iocs=(
            IOC.from_raw("ssdeep", "3:abcdef:ghi"),
            IOC.from_raw("imphash", "a" * 32),
        ),
    )

    bundle = json.loads(STIXOutputRenderer().render(result))
    patterns = {item["pattern"] for item in bundle["objects"]}

    assert "[file:hashes.'SSDEEP' = '3:abcdef:ghi']" in patterns
    assert f"[file:hashes.'IMPHASH' = '{'a' * 32}']" in patterns


def test_stix_output_renders_cryptocurrency_wallets() -> None:
    """bitcoin/ethereum/monero must render as STIX x-cryptocurrency objects, not vanish.

    STIX 2.1 has no native crypto SCO, so these wallet IOCs were silently dropped from
    STIX export; emit a custom x-cryptocurrency object like x-cloud-resource for ARNs.
    """
    result = ExtractionResult(
        iocs=(
            IOC.from_raw("bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            IOC.from_raw("ethereum", "0x32Be343B94f860124dC4fEe278FDCBD38C102D88"),
        ),
    )

    bundle = json.loads(STIXOutputRenderer().render(result))
    patterns = {item["pattern"] for item in bundle["objects"]}

    assert "[x-cryptocurrency:value = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa']" in patterns
    # EIP-55 checksum case must be preserved (not lowercased).
    assert "[x-cryptocurrency:value = '0x32Be343B94f860124dC4fEe278FDCBD38C102D88']" in patterns


def test_stix_type_filter_includes_custom_types_by_base_type() -> None:
    """--stix-types urls must keep custom IOC types derived from urls."""
    name = "renderer_custom_url"
    enums_module._custom_ioc_types.pop(name, None)
    try:
        register_custom_ioc_type(name, base_type="urls")
        result = ExtractionResult(iocs=(IOC.from_raw(name, "hxxps://example.com/a"),))

        bundle = json.loads(STIXOutputRenderer(allowed_types={IOCType.URL}).render(result))
        patterns = {item["pattern"] for item in bundle["objects"]}

        assert "[url:value = 'https://example.com/a']" in patterns
    finally:
        enums_module._custom_ioc_types.pop(name, None)


def test_stix_output_renders_cve_as_vulnerability_sdo() -> None:
    """CVEs must render as STIX Vulnerability SDOs (not dropped), and case variants dedup.

    STIX 2.1 models vulnerabilities as SDOs, not indicator patterns, so CVEs previously
    vanished from STIX export. They now emit a vulnerability object with a cve
    external_reference; the bundle dedup spans patternless SDOs by type+name.
    """
    result = ExtractionResult(
        iocs=(
            IOC.from_raw("cves", "CVE-2021-44228"),
            IOC.from_raw("cves", "cve-2021-44228"),
            IOC.from_raw("domains", "evil.com"),
        ),
    )

    bundle = json.loads(STIXOutputRenderer().render(result))
    vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]

    assert len(vulns) == 1  # case variants dedup to one
    assert vulns[0]["name"] == "CVE-2021-44228"
    assert vulns[0]["external_references"] == [
        {"source_name": "cve", "external_id": "CVE-2021-44228"}
    ]
    # The domain still renders as an indicator alongside the vulnerability.
    assert any(o["type"] == "indicator" for o in bundle["objects"])


def test_text_output_renderer_renders_golden_output() -> None:
    renderer = TextOutputRenderer()

    rendered = renderer.render(build_result())

    expected = dedent(
        """
        # Indicators of Compromise (IOCs) Extracted


        ## MD5 Hashes

        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

        ## Domains

        example.com

        ## Hosts

        warn.example

        ## IP Addresses

        198.51.100.7

        ## URLs

        https://example.com/a

        ## JWT Tokens

        header.payload.signature

        # Warning List Matches

        The following indicators were found in warning lists and might be false positives:


        ## Domains in Warning Lists

        Example[.]COM - *Duplicate Pattern*

        ## Hosts in Warning Lists

        Warn[.]Example - *Internal Assets*

        ## IP Addresses in Warning Lists

        198.51.100.7 - *Known Benign*
          Description: Public resolver
        """
    ).strip()

    assert rendered == expected


def test_text_output_renderer_includes_unlisted_ioc_types() -> None:
    renderer = TextOutputRenderer()
    result = ExtractionResult(
        iocs=(IOC.from_raw("ja3", "d4fdb5a4b9b3b1a5b2e2f7c9f8c6a111"),),
        warnings=(
            WarningMatch(
                ioc=IOC.from_raw("aws_access_keys", "AKIAIOSFODNN7EXAMPLE"),
                warning_list="Test Warning",
            ),
        ),
    )

    rendered = renderer.render(result)

    assert "## Ja3" in rendered
    assert "d4fdb5a4b9b3b1a5b2e2f7c9f8c6a111" in rendered
    assert "## Aws Access Keys in Warning Lists" in rendered
    assert "AKIAIOSFODNN7EXAMPLE - *Test Warning*" in rendered


def test_json_output_renderer_renders_sorted_and_exact_payload() -> None:
    renderer = JSONOutputRenderer()

    rendered = renderer.render(build_result())
    payload = json.loads(rendered)

    assert rendered == json.dumps(payload, indent=4, sort_keys=True)
    assert payload["schema_version"] == "1.0"
    assert payload["format"] == "json"
    assert payload["total_count"] == 9
    assert payload["counts_by_type"] == {
        "domains": 3,
        "hosts": 1,
        "ips": 2,
        "jwt": 1,
        "md5": 1,
        "urls": 1,
    }
    assert payload["records"]
    assert payload["domains"] == ["example.com"]
    assert payload["hosts"] == ["warn.example"]
    assert payload["ips"] == ["198.51.100.7"]
    assert payload["jwt"] == ["header.payload.signature"]
    assert payload["md5"] == ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert payload["urls"] == ["https://example.com/a"]
    assert payload["warning_list_matches"] == {
        "domains": [
            {
                "description": "",
                "value": "Example[.]COM",
                "warning_list": "Duplicate Pattern",
            }
        ],
        "hosts": [
            {
                "description": "",
                "value": "Warn[.]Example",
                "warning_list": "Internal Assets",
            }
        ],
        "ips": [
            {
                "description": "Public resolver",
                "value": "198.51.100.7",
                "warning_list": "Known Benign",
            }
        ],
    }


def test_stix_output_renderer_deduplicates_patterns_and_keeps_warning_metadata() -> None:
    renderer = STIXOutputRenderer()

    bundle = json.loads(renderer.render(build_result()))
    objects = bundle["objects"]
    patterns = {item["pattern"] for item in objects}

    assert len(objects) == 5
    assert patterns == {
        "[domain-name:value = 'example.com']",
        "[url:value = 'https://example.com/a']",
        "[file:hashes.'MD5' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
        "[ipv4-addr:value = '198.51.100.7']",
        "[domain-name:value = 'warn.example']",
    }
    assert all(item["type"] == "indicator" for item in objects)
    assert all(item["pattern_type"] == "stix" for item in objects)
    assert not any("header.payload.signature" in item["pattern"] for item in objects)

    ip_indicator = next(
        item for item in objects if item["pattern"] == "[ipv4-addr:value = '198.51.100.7']"
    )
    assert ip_indicator["x_warning_list"] == "Known Benign"
    assert ip_indicator["x_warning_description"] == "Public resolver"

    domain_indicator = next(
        item for item in objects if item["pattern"] == "[domain-name:value = 'example.com']"
    )
    assert "x_warning_list" not in domain_indicator


def test_stix_output_renderer_skips_unsupported_ioc_types() -> None:
    renderer = STIXOutputRenderer()

    assert renderer._build_indicator(IOCType.JWT, "header.payload.signature", None) is None


def test_text_renderer_attaches_context_to_each_value() -> None:
    """Each --with-context excerpt must immediately follow the value it describes.

    Regression: all values were emitted first and every context excerpt was then
    appended in a trailing block, so a reader could not tell which Context line
    belonged to which indicator.
    """
    result = ExtractionResult(
        iocs=(
            IOC.from_raw(
                "domains", "alpha.example", evidence=(IOCEvidence(excerpt="alpha-evidence"),)
            ),
            IOC.from_raw(
                "domains", "beta.example", evidence=(IOCEvidence(excerpt="beta-evidence"),)
            ),
        )
    )
    lines = TextOutputRenderer(include_context=True).render(result).splitlines()

    alpha_index = lines.index("alpha.example")
    beta_index = lines.index("beta.example")
    assert lines[alpha_index + 1] == "  Context: alpha-evidence"
    assert lines[beta_index + 1] == "  Context: beta-evidence"


def test_stix_cidr_uses_address_family_matching_the_value() -> None:
    """An IPv6 CIDR must render as ipv6-addr, not ipv4-addr.

    Regression: IOCType.CIDR mapped unconditionally to an ipv4-addr pattern,
    so a valid IPv6 CIDR produced semantically wrong STIX.
    """
    renderer = STIXOutputRenderer()

    ipv4 = renderer._build_indicator(IOCType.CIDR, "198.51.100.0/24", None)
    ipv6 = renderer._build_indicator(IOCType.CIDR, "2001:db8::/32", None)

    assert ipv4 is not None
    assert ipv6 is not None
    assert ipv4.pattern == "[ipv4-addr:value = '198.51.100.0/24']"
    assert ipv6.pattern == "[ipv6-addr:value = '2001:db8::/32']"


def test_stix_asn_without_digits_is_skipped_not_crashed() -> None:
    """An ASN value with no digits has no valid integer and must be skipped.

    Regression: _asn_builder emitted '[autonomous-system:number = ]', which
    stix2 rejected with InvalidValueError instead of skipping the indicator.
    """
    renderer = STIXOutputRenderer()

    assert renderer._build_indicator(IOCType.ASN, "AS", None) is None
    valid = renderer._build_indicator(IOCType.ASN, "AS64512", None)
    assert valid is not None
    assert valid.pattern == "[autonomous-system:number = 64512]"


def test_stix_output_renderer_initializes_pattern_builders_when_empty() -> None:
    original_builders = dict(STIXOutputRenderer.PATTERN_BUILDERS)
    STIXOutputRenderer.PATTERN_BUILDERS = {}
    try:
        renderer = STIXOutputRenderer()
        assert IOCType.DOMAIN in renderer.PATTERN_BUILDERS
        assert IOCType.URL in renderer.PATTERN_BUILDERS
    finally:
        STIXOutputRenderer.PATTERN_BUILDERS = original_builders
