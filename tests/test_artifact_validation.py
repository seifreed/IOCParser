#!/usr/bin/env python3
"""
Regression tests for artifact validation bug fixes
"""


from iocparser.infrastructure.extractor_artifacts import DEFAULT_ARTIFACT_POLICY


class TestArtifactValidationRegression:
    def test_valid_cidr_survives_non_numeric_octet(self):
        """Regression: valid_cidr must not crash on non-numeric octets."""
        candidates = [
            "10.0.0.0",
            "10.0.0.0/not-a-prefix",
            "10.0.0.0/33",
            "10.0.0.0/24",
            "192.168.a.1/24",
            "10.0.0/24",
        ]
        result = DEFAULT_ARTIFACT_POLICY.valid_cidr(candidates)
        assert result == ["10.0.0.0/24"]

    def test_valid_cert_serials_rejects_non_hex(self):
        """Regression: valid_cert_serials must reject non-hex characters like g, z."""
        candidates = [
            "aa:bb:cc:dd:ee:ff:00:11",  # valid hex
            "gg:gg:gg:gg:gg:gg:gg:gg",  # invalid hex
            "zz:zz:zz:zz:zz:zz:zz:zz",  # invalid hex
        ]
        result = DEFAULT_ARTIFACT_POLICY.valid_cert_serials(candidates)
        assert result == ["aa:bb:cc:dd:ee:ff:00:11"]
