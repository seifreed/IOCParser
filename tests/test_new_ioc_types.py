#!/usr/bin/env python3
# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive tests for the 23 newly added IOC types in IOCParser.

All tests execute real extraction through DefaultIOCExtractionEngine.extract_all(),
with no mocks, no monkeypatching, and no test doubles of any kind.

Author: Marc Rivero | @seifreed
"""

from iocparser.infrastructure.extraction import DefaultIOCExtractionEngine

# ---------------------------------------------------------------------------
# Phase 1 — Quick wins
# ---------------------------------------------------------------------------


def test_extract_cidr_valid_ranges():
    """CIDR blocks with prefix lengths 0-32 must be extracted and validated."""
    engine = DefaultIOCExtractionEngine()
    text = "Blocked networks: 192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/12, 0.0.0.0/0, 203.0.113.0/24"
    result = engine.extract_all(text)
    cidrs = result.get("cidr", [])

    assert "192.168.1.0/24" in cidrs
    assert "10.0.0.0/8" in cidrs
    assert "172.16.0.0/12" in cidrs
    assert "0.0.0.0/0" in cidrs
    assert "203.0.113.0/24" in cidrs


def test_extract_cidr_rejects_invalid_prefix():
    """CIDR blocks with prefix > 32 must be rejected by the validator."""
    engine = DefaultIOCExtractionEngine()
    # /33 and /99 exceed the valid IPv4 prefix range
    text = "Bad blocks: 192.168.1.0/33, 10.0.0.0/99"
    result = engine.extract_all(text)
    cidrs = result.get("cidr", [])

    assert "192.168.1.0/33" not in cidrs
    assert "10.0.0.0/99" not in cidrs


def test_extract_cidr_rejects_invalid_octet():
    """CIDR blocks whose IP octets exceed 255 must be rejected."""
    engine = DefaultIOCExtractionEngine()
    text = "Invalid: 999.1.1.0/24, 192.168.300.0/16"
    result = engine.extract_all(text)
    cidrs = result.get("cidr", [])

    assert "999.1.1.0/24" not in cidrs
    assert "192.168.300.0/16" not in cidrs


def test_extract_cidr_rejects_leading_zero_octets():
    """CIDR IPv4 octets must follow the same leading-zero rule as IP extraction."""
    engine = DefaultIOCExtractionEngine()
    text = "Invalid: 192.168.001.0/24, 10.01.0.0/8. Valid: 192.168.1.0/24"
    result = engine.extract_all(text)
    cidrs = result.get("cidr", [])

    assert "192.168.1.0/24" in cidrs
    assert "192.168.001.0/24" not in cidrs
    assert "10.01.0.0/8" not in cidrs


def test_extract_cidr_no_match_returns_absent_key():
    """Text with no CIDR notation must not produce a 'cidr' key at all."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No network ranges here, just text.")
    assert "cidr" not in result


# ---------------------------------------------------------------------------


def test_extract_mitre_software_valid_ids():
    """MITRE ATT&CK software IDs S0001-S9999 must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "Malware used: S0154 (Cobalt Strike), S0001 (HTRAN), S0404"
    result = engine.extract_all(text)
    software = result.get("mitre_software", [])

    assert "S0154" in software
    assert "S0001" in software
    assert "S0404" in software


def test_extract_mitre_software_rejects_lowercase():
    """Lowercase s-prefixed IDs must not match the MITRE software pattern."""
    engine = DefaultIOCExtractionEngine()
    # The pattern is \bS[0-9]{4}\b — uppercase S only
    text = "Invalid: s0001 s0154"
    result = engine.extract_all(text)
    software = result.get("mitre_software", [])

    assert "s0001" not in software
    assert "s0154" not in software


def test_extract_mitre_software_rejects_five_digit_ids():
    """IDs with five digits (S00001) must not match the four-digit pattern."""
    engine = DefaultIOCExtractionEngine()
    text = "Bad IDs: S00001, S12345"
    result = engine.extract_all(text)
    software = result.get("mitre_software", [])

    assert "S00001" not in software
    assert "S12345" not in software


def test_extract_mitre_software_no_match():
    """Text with no MITRE software IDs must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("Nothing to see here, T1055 is a technique not software.")
    assert "mitre_software" not in result


# ---------------------------------------------------------------------------


def test_extract_mitre_groups_valid_ids():
    """MITRE ATT&CK group IDs G0001-G9999 must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "Threat actors: G0007 (APT28), G0100, G0016"
    result = engine.extract_all(text)
    groups = result.get("mitre_groups", [])

    assert "G0007" in groups
    assert "G0100" in groups
    assert "G0016" in groups


def test_extract_mitre_groups_rejects_five_digit_ids():
    """Group IDs with five digits (G00001) must not match."""
    engine = DefaultIOCExtractionEngine()
    text = "Bad group: G00001"
    result = engine.extract_all(text)
    groups = result.get("mitre_groups", [])

    assert "G00001" not in groups


def test_extract_mitre_groups_no_match():
    """Text without MITRE group IDs must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("Only techniques: T1059.001")
    assert "mitre_groups" not in result


# ---------------------------------------------------------------------------


def test_extract_mitre_mitigations_valid_ids():
    """MITRE ATT&CK mitigation IDs starting with M1 must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "Mitigations applied: M1036, M1050, M1017"
    result = engine.extract_all(text)
    mitigations = result.get("mitre_mitigations", [])

    assert "M1036" in mitigations
    assert "M1050" in mitigations
    assert "M1017" in mitigations


def test_extract_mitre_mitigations_rejects_m0_prefix():
    """IDs starting with M0 (not M1) must be rejected — the pattern requires M1."""
    engine = DefaultIOCExtractionEngine()
    # Pattern is \bM1[0-9]{3}\b — only M1xxx qualifies
    text = "Invalid mitigation: M0036"
    result = engine.extract_all(text)
    mitigations = result.get("mitre_mitigations", [])

    assert "M0036" not in mitigations


def test_extract_mitre_mitigations_no_match():
    """Text without mitigation IDs must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No mitigations referenced in this document.")
    assert "mitre_mitigations" not in result


# ---------------------------------------------------------------------------


def test_extract_mitre_datasources_valid_ids():
    """MITRE ATT&CK data source IDs DS0001-DS9999 must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "Data sources: DS0029, DS0015, DS0022"
    result = engine.extract_all(text)
    datasources = result.get("mitre_datasources", [])

    assert "DS0029" in datasources
    assert "DS0015" in datasources
    assert "DS0022" in datasources


def test_extract_mitre_datasources_rejects_extra_digits():
    """DS IDs with five digits (DS00001) must not match."""
    engine = DefaultIOCExtractionEngine()
    text = "Bad datasource: DS00001"
    result = engine.extract_all(text)
    datasources = result.get("mitre_datasources", [])

    assert "DS00001" not in datasources


def test_extract_mitre_datasources_no_match():
    """Text without data source IDs must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("This report contains no data source references.")
    assert "mitre_datasources" not in result


# ---------------------------------------------------------------------------


def test_extract_onion_addresses_v2():
    """16-character base32 .onion addresses (v2) must be extracted."""
    engine = DefaultIOCExtractionEngine()
    # v2 onion: exactly 16 lowercase base32 chars (a-z, 2-7)
    text = "C2 at facebookcorewwwi.onion and expyuzz4wqqyqhjn.onion"
    result = engine.extract_all(text)
    onions = result.get("onion_addresses", [])

    assert "facebookcorewwwi.onion" in onions
    assert "expyuzz4wqqyqhjn.onion" in onions


def test_extract_onion_addresses_v3():
    """56-character base32 .onion addresses (v3) must be extracted."""
    engine = DefaultIOCExtractionEngine()
    # v3 onion: exactly 56 lowercase base32 chars
    v3_address = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion"
    text = f"Hidden service: {v3_address}"
    result = engine.extract_all(text)
    onions = result.get("onion_addresses", [])

    assert v3_address in onions


def test_extract_onion_addresses_rejects_too_short():
    """Onion addresses shorter than 16 chars must not be extracted."""
    engine = DefaultIOCExtractionEngine()
    # 10 chars — below minimum
    text = "Invalid: tooshort.onion"
    result = engine.extract_all(text)
    onions = result.get("onion_addresses", [])

    assert "tooshort.onion" not in onions


def test_extract_onion_addresses_no_match():
    """Text with no .onion addresses must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("Connecting to example.com on port 443.")
    assert "onion_addresses" not in result


# ---------------------------------------------------------------------------


def test_extract_aws_access_keys_akia_prefix():
    """AWS access key IDs with AKIA prefix must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "AWS key found: AKIAIOSFODNN7EXAMPLE in configuration file"
    result = engine.extract_all(text)
    keys = result.get("aws_access_keys", [])

    assert "AKIAIOSFODNN7EXAMPLE" in keys


def test_extract_aws_access_keys_all_prefixes():
    """All four valid AWS key prefixes (AKIA, ABIA, ACCA, ASIA) must be extracted.

    The pattern requires exactly 16 [0-9A-Z] chars after the 4-char prefix,
    so each key here is exactly 20 characters total.
    """
    engine = DefaultIOCExtractionEngine()
    # Pattern: (?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}
    # Each key = 4-char prefix + exactly 16 uppercase alphanumeric chars = 20 chars total.
    # The suffix "1234567890ABCDEF" is exactly 16 chars.
    text = (
        "Keys: AKIA1234567890ABCDEF ABIA1234567890ABCDEF ACCA1234567890ABCDEF ASIA1234567890ABCDEF"
    )
    result = engine.extract_all(text)
    keys = result.get("aws_access_keys", [])

    assert any(k.startswith("AKIA") for k in keys)
    assert any(k.startswith("ABIA") for k in keys)
    assert any(k.startswith("ACCA") for k in keys)
    assert any(k.startswith("ASIA") for k in keys)


def test_extract_aws_access_keys_rejects_wrong_prefix():
    """Access key IDs that do not start with a valid prefix must not match."""
    engine = DefaultIOCExtractionEngine()
    # AKIB is not a valid prefix; only AKIA/ABIA/ACCA/ASIA are
    text = "Invalid key: AKIBIOSFODNN7EXAMPLE1"
    result = engine.extract_all(text)
    keys = result.get("aws_access_keys", [])

    assert "AKIBIOSFODNN7EXAMPLE1" not in keys


def test_extract_aws_access_keys_no_match():
    """Text with no AWS access key patterns must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No credentials present in this log entry.")
    assert "aws_access_keys" not in result


# ---------------------------------------------------------------------------


def test_extract_pdb_paths_windows_style():
    """Windows PDB debug paths must be extracted regardless of drive letter."""
    engine = DefaultIOCExtractionEngine()
    text = r"Debug symbols at C:\Users\dev\Release\payload.pdb"
    result = engine.extract_all(text)
    paths = result.get("pdb_paths", [])

    assert any("payload.pdb" in p for p in paths)


def test_extract_pdb_paths_multiple():
    """Multiple PDB paths across different drives must each be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = (
        r"First: D:\Build\malware\x64\Release\dropper.pdb "
        r"Second: C:\Projects\loader\obj\loader.pdb"
    )
    result = engine.extract_all(text)
    paths = result.get("pdb_paths", [])

    assert len(paths) >= 2
    assert any("dropper.pdb" in p for p in paths)
    assert any("loader.pdb" in p for p in paths)


def test_extract_pdb_paths_no_match():
    """Text with no .pdb file paths must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("The binary was compiled without debug symbols.")
    assert "pdb_paths" not in result


# ---------------------------------------------------------------------------
# Phase 2 — TLS/Network fingerprints
# ---------------------------------------------------------------------------


def test_extract_ja3_with_context_keyword():
    """JA3 fingerprints must be extracted when preceded by the ja3: context label."""
    engine = DefaultIOCExtractionEngine()
    text = "TLS fingerprint ja3: a0e9f5d64349fb13191bc781f81f42e1 observed"
    result = engine.extract_all(text)
    ja3_list = result.get("ja3", [])

    assert "a0e9f5d64349fb13191bc781f81f42e1" in ja3_list


def test_extract_ja3_uppercase_keyword():
    """JA3 must also match with the uppercase JA3: label."""
    engine = DefaultIOCExtractionEngine()
    text = "Client fingerprint JA3: b742b407517bac9536a77a7b0fee28e9"
    result = engine.extract_all(text)
    ja3_list = result.get("ja3", [])

    assert "b742b407517bac9536a77a7b0fee28e9" in ja3_list


def test_extract_ja3_no_context_returns_absent_key():
    """A bare 32-char hex string without the ja3: label must not produce a ja3 entry."""
    engine = DefaultIOCExtractionEngine()
    # The ja3 pattern requires context keyword — bare hex is not enough
    text = "Fingerprint: a0e9f5d64349fb13191bc781f81f42e1"
    result = engine.extract_all(text)
    ja3_list = result.get("ja3", [])

    # The bare hash may appear as md5, but not as ja3
    assert "a0e9f5d64349fb13191bc781f81f42e1" not in ja3_list


# ---------------------------------------------------------------------------


def test_extract_ja3s_with_context_keyword():
    """JA3S server fingerprints must be extracted with the ja3s: label."""
    engine = DefaultIOCExtractionEngine()
    text = "Server TLS ja3s: b742b407517bac9536a77a7b0fee28e9 seen in capture"
    result = engine.extract_all(text)
    ja3s_list = result.get("ja3s", [])

    assert "b742b407517bac9536a77a7b0fee28e9" in ja3s_list


def test_extract_ja3s_uppercase_and_hyphen_variants():
    """JA3S must match JA3S: and JA3-S: label variants."""
    engine = DefaultIOCExtractionEngine()
    text_upper = "JA3S: ec7378c1a92f5a8dde7e8b7a1ddf33d1"
    text_hyphen = "JA3-S: ec7378c1a92f5a8dde7e8b7a1ddf33d1"

    result_upper = engine.extract_all(text_upper)
    result_hyphen = engine.extract_all(text_hyphen)

    assert "ec7378c1a92f5a8dde7e8b7a1ddf33d1" in result_upper.get("ja3s", [])
    assert "ec7378c1a92f5a8dde7e8b7a1ddf33d1" in result_hyphen.get("ja3s", [])


def test_extract_ja3s_no_match():
    """Text with no JA3S label must not produce the ja3s key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No TLS fingerprints in this document.")
    assert "ja3s" not in result


# ---------------------------------------------------------------------------


def test_extract_ja4_valid_format():
    """JA4 fingerprints in the canonical format must be extracted."""
    engine = DefaultIOCExtractionEngine()
    # Format: [qtd][1-9][0-9][dsi][0-9]{2,4}[a-z][0-9]{1,2}_[a-f0-9]{12}_[a-f0-9]{12}
    text = "JA4 fingerprint: t13d1516h2_8daaf6152771_b186095e22b6"
    result = engine.extract_all(text)
    ja4_list = result.get("ja4", [])

    assert "t13d1516h2_8daaf6152771_b186095e22b6" in ja4_list


def test_extract_ja4_multiple_fingerprints():
    """Multiple distinct JA4 fingerprints in one text must all be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = (
        "Fingerprints observed: t13d1516h2_8daaf6152771_b186095e22b6 "
        "and q13d0312c1_1234567890ab_abcdef012345"
    )
    result = engine.extract_all(text)
    ja4_list = result.get("ja4", [])

    assert len(ja4_list) >= 2


def test_extract_ja4_no_match():
    """Text with no JA4 patterns must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("Standard HTTP traffic with no TLS fingerprints.")
    assert "ja4" not in result


# ---------------------------------------------------------------------------


def test_extract_hassh_with_context_keyword():
    """HASSH SSH client fingerprints must be extracted with the hassh: label."""
    engine = DefaultIOCExtractionEngine()
    text = "SSH client HASSH: ec7378c1a92f5a8dde7e8b7a1ddf33d1 from 10.1.2.3"
    result = engine.extract_all(text)
    hassh_list = result.get("hassh", [])

    assert "ec7378c1a92f5a8dde7e8b7a1ddf33d1" in hassh_list


def test_extract_hassh_lowercase_keyword():
    """HASSH must also match with the lowercase hassh= assignment syntax."""
    engine = DefaultIOCExtractionEngine()
    text = "hassh=ec7378c1a92f5a8dde7e8b7a1ddf33d1"
    result = engine.extract_all(text)
    hassh_list = result.get("hassh", [])

    assert "ec7378c1a92f5a8dde7e8b7a1ddf33d1" in hassh_list


def test_extract_hassh_no_match():
    """Text without the HASSH label must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("SSH connection established on port 22.")
    assert "hassh" not in result


# ---------------------------------------------------------------------------


def test_extract_hassh_server_with_context_keyword():
    """HASSH server fingerprints must be extracted with the hassh_server: label."""
    engine = DefaultIOCExtractionEngine()
    text = "hassh_server: abc123def456abc123def456abc123de"
    result = engine.extract_all(text)
    hassh_s = result.get("hassh_server", [])

    assert "abc123def456abc123def456abc123de" in hassh_s


def test_extract_hassh_server_camelcase_variant():
    """HASSHServer label variant must also match."""
    engine = DefaultIOCExtractionEngine()
    text = "HASSHServer: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    result = engine.extract_all(text)
    hassh_s = result.get("hassh_server", [])

    assert "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" in hassh_s


def test_extract_hassh_server_no_match():
    """Text without HASSH server label must not produce the hassh_server key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("Server fingerprint not available.")
    assert "hassh_server" not in result


# ---------------------------------------------------------------------------


def test_extract_jarm_with_context_keyword():
    """JARM fingerprints (62 hex chars) must be extracted with the JARM: label."""
    engine = DefaultIOCExtractionEngine()
    # JARM fingerprint is exactly 62 hex chars
    jarm_value = "2ad2ad16d2ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5"
    text = f"JARM: {jarm_value}"
    result = engine.extract_all(text)
    jarm_list = result.get("jarm", [])

    assert jarm_value in jarm_list


def test_extract_jarm_lowercase_keyword():
    """JARM must also match with lowercase jarm: label."""
    engine = DefaultIOCExtractionEngine()
    jarm_value = "2ad2ad16d2ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5"
    text = f"jarm: {jarm_value}"
    result = engine.extract_all(text)
    jarm_list = result.get("jarm", [])

    assert jarm_value in jarm_list


def test_extract_jarm_rejects_short_value():
    """JARM values shorter than 62 hex chars must not match."""
    engine = DefaultIOCExtractionEngine()
    # 60 chars — one group too short
    short_value = "2ad2ad16d2ad2ad00042d42d00000069d641f34fe76acdc05c40262f881"
    text = f"JARM: {short_value}"
    result = engine.extract_all(text)
    jarm_list = result.get("jarm", [])

    assert short_value not in jarm_list


def test_extract_jarm_no_match():
    """Text without JARM label must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("TLS scan results are inconclusive.")
    assert "jarm" not in result


# ---------------------------------------------------------------------------
# Phase 3 — Cloud identifiers
# ---------------------------------------------------------------------------


def test_extract_aws_arns_iam_role():
    """AWS ARNs for IAM roles must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "Role ARN: arn:aws:iam::123456789012:role/Admin"
    result = engine.extract_all(text)
    arns = result.get("aws_arns", [])

    assert "arn:aws:iam::123456789012:role/Admin" in arns


def test_extract_aws_arns_s3_bucket():
    """AWS ARNs for S3 buckets must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "Exfil bucket: arn:aws:s3:::my-leaked-bucket"
    result = engine.extract_all(text)
    arns = result.get("aws_arns", [])

    assert "arn:aws:s3:::my-leaked-bucket" in arns


def test_extract_aws_arns_china_partition():
    """AWS China partition ARNs (aws-cn) must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "China region: arn:aws-cn:iam::123456789012:user/admin"
    result = engine.extract_all(text)
    arns = result.get("aws_arns", [])

    assert "arn:aws-cn:iam::123456789012:user/admin" in arns


def test_extract_aws_arns_multi_segment_partitions():
    """GovCloud and ISO partitions (multi-hyphen) must be extracted.

    Regression: the partition matched only one optional hyphen segment, so
    arn:aws-us-gov:... and arn:aws-iso-b:... were dropped entirely.
    """
    engine = DefaultIOCExtractionEngine()
    text = "Gov: arn:aws-us-gov:iam::123456789012:role/Admin ISO: arn:aws-iso-b:s3:::secret-bucket"
    arns = engine.extract_all(text).get("aws_arns", [])
    assert "arn:aws-us-gov:iam::123456789012:role/Admin" in arns
    assert "arn:aws-iso-b:s3:::secret-bucket" in arns


def test_extract_aws_arns_multiple():
    """Multiple ARNs in one text must all be captured."""
    engine = DefaultIOCExtractionEngine()
    text = (
        "Resources: arn:aws:iam::123456789012:role/Admin "
        "and arn:aws:lambda:us-east-1:123456789012:function:evil"
    )
    result = engine.extract_all(text)
    arns = result.get("aws_arns", [])

    assert len(arns) >= 2


def test_extract_aws_arns_no_match():
    """Text without ARN notation must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No cloud resources were referenced in this report.")
    assert "aws_arns" not in result


# ---------------------------------------------------------------------------


def test_extract_gcp_service_accounts_valid():
    """Valid GCP service account email addresses must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "Service account: my-svc@project-id.iam.gserviceaccount.com"
    result = engine.extract_all(text)
    accounts = result.get("gcp_service_accounts", [])

    assert "my-svc@project-id.iam.gserviceaccount.com" in accounts


def test_extract_gcp_service_accounts_multiple():
    """Multiple GCP service accounts must each be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = (
        "Accounts: compute-sa@myproject.iam.gserviceaccount.com "
        "storage-sa@otherproject.iam.gserviceaccount.com"
    )
    result = engine.extract_all(text)
    accounts = result.get("gcp_service_accounts", [])

    assert len(accounts) >= 2


def test_extract_gcp_service_accounts_rejects_plain_email():
    """Ordinary email addresses not under iam.gserviceaccount.com must not match."""
    engine = DefaultIOCExtractionEngine()
    text = "Contact: admin@example.com"
    result = engine.extract_all(text)
    accounts = result.get("gcp_service_accounts", [])

    assert "admin@example.com" not in accounts


def test_extract_gcp_service_accounts_no_match():
    """Text with no GCP service account addresses must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No Google Cloud resources in this report.")
    assert "gcp_service_accounts" not in result


# ---------------------------------------------------------------------------


def test_extract_azure_app_ids_tenant_id():
    """Azure tenant_id UUIDs must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "tenant_id: 72f988bf-86f1-41af-91ab-2d7cd011db47"
    result = engine.extract_all(text)
    app_ids = result.get("azure_app_ids", [])

    assert "72f988bf-86f1-41af-91ab-2d7cd011db47" in app_ids


def test_extract_azure_app_ids_client_id():
    """Azure client_id UUIDs must also be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "client_id: 9b0f4c9a-1234-5678-abcd-ef0123456789"
    result = engine.extract_all(text)
    app_ids = result.get("azure_app_ids", [])

    assert "9b0f4c9a-1234-5678-abcd-ef0123456789" in app_ids


def test_extract_azure_app_ids_app_id_keyword():
    """Azure app_id UUIDs must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "app_id: aaaabbbb-cccc-dddd-eeee-ffffffffffff"
    result = engine.extract_all(text)
    app_ids = result.get("azure_app_ids", [])

    assert "aaaabbbb-cccc-dddd-eeee-ffffffffffff" in app_ids


def test_extract_azure_app_ids_rejects_bare_uuid():
    """A UUID without an Azure context keyword must not appear in azure_app_ids."""
    engine = DefaultIOCExtractionEngine()
    # No tenant_id/app_id/client_id prefix — should not match the azure pattern
    text = "Reference: 72f988bf-86f1-41af-91ab-2d7cd011db47 was observed."
    result = engine.extract_all(text)
    app_ids = result.get("azure_app_ids", [])

    # The bare UUID must not be captured under azure_app_ids
    assert "72f988bf-86f1-41af-91ab-2d7cd011db47" not in app_ids


def test_extract_azure_app_ids_no_match():
    """Text without Azure ID keywords must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No Azure resources were used.")
    assert "azure_app_ids" not in result


# ---------------------------------------------------------------------------


def test_extract_docker_images_with_sha256_digest():
    """Docker image references with sha256 digests must be extracted."""
    engine = DefaultIOCExtractionEngine()
    digest = "a" * 64  # 64 valid hex chars
    text = f"Image pulled: registry.io/image:tag@sha256:{digest}"
    result = engine.extract_all(text)
    images = result.get("docker_images", [])

    assert any(digest in img for img in images)


def test_extract_docker_images_bare_name_with_digest():
    """Docker image name without registry but with digest must also be extracted."""
    engine = DefaultIOCExtractionEngine()
    digest = "b" * 64
    text = f"Container: ubuntu:22.04@sha256:{digest}"
    result = engine.extract_all(text)
    images = result.get("docker_images", [])

    assert any(digest in img for img in images)


def test_extract_docker_images_rejects_short_digest():
    """Docker image references with fewer than 64 hex chars after sha256: must not match."""
    engine = DefaultIOCExtractionEngine()
    # 32 chars — too short for SHA-256
    short_digest = "a" * 32
    text = f"Image: myimage:latest@sha256:{short_digest}"
    result = engine.extract_all(text)
    images = result.get("docker_images", [])

    assert not any(short_digest in img for img in images)


def test_extract_docker_images_no_match():
    """Text with no Docker image references must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("The container was deployed without a pinned digest.")
    assert "docker_images" not in result


# ---------------------------------------------------------------------------
# Phase 4 — Advanced detection artifacts
# ---------------------------------------------------------------------------


def test_extract_tlsh_with_context_keyword():
    """TLSH hashes with context keyword must be extracted (70-72 hex chars after label)."""
    engine = DefaultIOCExtractionEngine()
    # 70 uppercase hex chars
    tlsh_hex = "A" * 70
    text = f"TLSH: {tlsh_hex}"
    result = engine.extract_all(text)
    tlsh_list = result.get("tlsh", [])

    assert tlsh_hex in tlsh_list


def test_extract_tlsh_bare_t1_prefix():
    """TLSH hashes starting with T1 followed by 68+ uppercase hex must be extracted."""
    engine = DefaultIOCExtractionEngine()
    # T1 + 68 uppercase hex = 70 chars total, matches the bare pattern
    bare_tlsh = "T1" + "A" * 68
    text = f"Hash value: {bare_tlsh}"
    result = engine.extract_all(text)
    tlsh_list = result.get("tlsh", [])

    assert bare_tlsh in tlsh_list


def test_extract_tlsh_labelled_and_bare_canonicalize_identically():
    """The same T1-prefixed digest must dedup whether labelled or bare.

    Regression: the labelled branch stripped the T1 version prefix while the bare
    branch kept it, so one digest surfaced as two different, non-deduping values.
    """
    engine = DefaultIOCExtractionEngine()
    digest = "T1" + "A" * 70
    labelled = engine.extract_all(f"tlsh: {digest} seen").get("tlsh", [])
    bare = engine.extract_all(f"value {digest} seen").get("tlsh", [])
    assert labelled == [digest]
    assert bare == [digest]


def test_extract_tlsh_no_match():
    """Text without TLSH hashes must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No fuzzy hashes present in this sample report.")
    assert "tlsh" not in result


# ---------------------------------------------------------------------------


def test_extract_sigma_rule_ids_with_id_keyword():
    """Sigma rule UUIDs introduced by 'id:' must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "id: 72f988bf-86f1-41af-91ab-2d7cd011db47"
    result = engine.extract_all(text)
    rule_ids = result.get("sigma_rule_ids", [])

    assert "72f988bf-86f1-41af-91ab-2d7cd011db47" in rule_ids


def test_extract_sigma_rule_ids_with_sigma_id_keyword():
    """Sigma rule UUIDs introduced by 'sigma_id:' must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = "sigma_id: 9b0f4c9a-1234-5678-abcd-ef0123456789"
    result = engine.extract_all(text)
    rule_ids = result.get("sigma_rule_ids", [])

    assert "9b0f4c9a-1234-5678-abcd-ef0123456789" in rule_ids


def test_extract_sigma_rule_ids_rejects_bare_uuid():
    """A UUID without an id:/sigma_id: keyword must not appear in sigma_rule_ids."""
    engine = DefaultIOCExtractionEngine()
    text = "Reference: 72f988bf-86f1-41af-91ab-2d7cd011db47 was observed."
    result = engine.extract_all(text)
    rule_ids = result.get("sigma_rule_ids", [])

    assert "72f988bf-86f1-41af-91ab-2d7cd011db47" not in rule_ids


def test_extract_sigma_rule_ids_no_match():
    """Text without sigma/rule id labels must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("Detection rule with no identifier present.")
    assert "sigma_rule_ids" not in result


# ---------------------------------------------------------------------------


def test_extract_suricata_sids_valid():
    """Suricata/Snort SID values following 'sid:' must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = 'Rule: alert tcp any any -> any 80 (msg:"test"; sid:2024897; rev:1;)'
    result = engine.extract_all(text)
    sids = result.get("suricata_sids", [])

    assert "2024897" in sids


def test_extract_suricata_sids_multiple():
    """Multiple SIDs across separate rules must all be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = (
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1000001; rev:1;)\n'
        'alert udp any any -> any 53 (msg:"DNS"; sid:1000002; rev:2;)'
    )
    result = engine.extract_all(text)
    sids = result.get("suricata_sids", [])

    assert "1000001" in sids
    assert "1000002" in sids


def test_extract_suricata_sids_no_match():
    """Text without 'sid:' syntax must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("No detection rules are defined in this document.")
    assert "suricata_sids" not in result


# ---------------------------------------------------------------------------


def test_extract_snort_rules_complete_rule():
    """A well-formed Snort/Suricata rule with both sid: and msg: must be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = 'alert tcp any any -> any 80 (msg:"Malicious HTTP request"; sid:1000001; rev:1;)'
    result = engine.extract_all(text)
    rules = result.get("snort_rules", [])

    assert len(rules) >= 1
    assert any("sid:1000001" in r for r in rules)
    assert any('msg:"Malicious HTTP request"' in r for r in rules)


def test_extract_snort_rules_drop_action():
    """Rules with 'drop' action (not just 'alert') must also be extracted."""
    engine = DefaultIOCExtractionEngine()
    text = 'drop tcp any any -> any 443 (msg:"Blocked TLS"; sid:2000001; rev:1;)'
    result = engine.extract_all(text)
    rules = result.get("snort_rules", [])

    assert len(rules) >= 1


def test_extract_snort_rules_rejects_rule_missing_msg():
    """A rule fragment without msg: must not pass the validator."""
    engine = DefaultIOCExtractionEngine()
    # The validator requires both sid: and msg: to be present
    text = "alert tcp any any -> any 80 (sid:1000001; rev:1;)"
    result = engine.extract_all(text)
    rules = result.get("snort_rules", [])

    # No rule without msg: should survive validation
    assert not any("1000001" in r and "msg:" not in r for r in rules)


def test_extract_snort_rules_no_match():
    """Text without Snort/Suricata rule syntax must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all("Firewall logs show dropped packets to port 80.")
    assert "snort_rules" not in result


# ---------------------------------------------------------------------------


def test_extract_sigma_rules_complete_block():
    """A Sigma YAML block containing title:, detection:, and condition: must be extracted."""
    engine = DefaultIOCExtractionEngine()
    sigma_text = (
        "title: Suspicious PowerShell Execution\n"
        "id: 72f988bf-86f1-41af-91ab-2d7cd011db47\n"
        "status: experimental\n"
        "description: Detects suspicious PowerShell usage\n"
        "detection:\n"
        "    keywords:\n"
        "        - '-EncodedCommand'\n"
        "        - '-enc'\n"
        "    condition: keywords\n"
        "level: high\n"
    )
    result = engine.extract_all(sigma_text)
    sigma_list = result.get("sigma_rules", [])

    assert len(sigma_list) >= 1
    assert any("title:" in r for r in sigma_list)
    assert any("detection:" in r for r in sigma_list)
    assert any("condition:" in r for r in sigma_list)


def test_extract_sigma_rules_rejects_block_without_condition():
    """A Sigma-like block missing the condition: field must not pass validation."""
    engine = DefaultIOCExtractionEngine()
    # Missing condition: — the validator requires all three keywords
    incomplete_sigma = (
        "title: Missing Condition Rule\n"
        "detection:\n"
        "    keywords:\n"
        "        - 'powershell'\n"
        "level: medium\n"
    )
    result = engine.extract_all(incomplete_sigma)
    sigma_list = result.get("sigma_rules", [])

    # Any extracted entry must not be missing condition:
    for entry in sigma_list:
        assert "condition:" in entry


def test_extract_sigma_rules_no_match():
    """Text without a Sigma YAML structure must not produce the key."""
    engine = DefaultIOCExtractionEngine()
    result = engine.extract_all(
        "The detection rule was described in prose without YAML formatting."
    )
    assert "sigma_rules" not in result
