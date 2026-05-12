from __future__ import annotations

import json
from textwrap import dedent

from iocparser.adapters.renderers import JSONOutputRenderer, STIXOutputRenderer, TextOutputRenderer
from iocparser.domain.models import IOC, ExtractionResult, IOCType, WarningMatch


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


def test_stix_output_renderer_initializes_pattern_builders_when_empty() -> None:
    original_builders = dict(STIXOutputRenderer.PATTERN_BUILDERS)
    STIXOutputRenderer.PATTERN_BUILDERS = {}
    try:
        renderer = STIXOutputRenderer()
        assert IOCType.DOMAIN in renderer.PATTERN_BUILDERS
        assert IOCType.URL in renderer.PATTERN_BUILDERS
    finally:
        STIXOutputRenderer.PATTERN_BUILDERS = original_builders
