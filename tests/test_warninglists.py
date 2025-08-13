#!/usr/bin/env python3
"""
Unit tests for MISP warning lists functionality

Author: Marc Rivero | @seifreed
"""

import json
from unittest.mock import patch

import pytest

from iocparser.modules.warninglists import MISPWarningLists


class TestMISPWarningLists:
    """Test MISP warning lists functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create mock warning lists data
        self.mock_warning_lists = {
            'public-dns-v4': {
                'name': 'Public DNS Resolvers',
                'description': 'List of public DNS resolver IP addresses',
                'type': 'string',
                'matching_attributes': ['ip-src', 'ip-dst', 'ip'],
                'list': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9'],
            },
            'google-cidr': {
                'name': 'Google IP ranges',
                'description': 'IP ranges used by Google',
                'type': 'cidr',
                'matching_attributes': ['ip-src', 'ip-dst'],
                'list': ['8.8.8.0/24', '142.250.0.0/15', '172.217.0.0/16'],
            },
            'alexa-top1000': {
                'name': 'Alexa Top 1000',
                'description': 'Top 1000 most visited websites',
                'type': 'string',
                'matching_attributes': ['domain', 'hostname'],
                'list': ['google.com', 'facebook.com', 'youtube.com', 'amazon.com'],
            },
            'security-provider-domains': {
                'name': 'Security Provider Domains',
                'description': 'Domains of security providers',
                'type': 'substring',
                'matching_attributes': ['domain', 'hostname', 'url'],
                'list': ['virustotal', 'malwarebytes', 'kaspersky'],
            },
        }

    @patch('iocparser.modules.warninglists.requests.get')
    def test_initialization_with_cache(self, mock_get):
        """Test initialization with existing cache."""
        with patch('iocparser.modules.warninglists.Path.exists') as mock_exists:
            mock_exists.return_value = True

            with patch('builtins.open', create=True) as mock_open:
                # Mock cache metadata
                mock_metadata = {'last_update': 9999999999}  # Far future
                mock_cache = self.mock_warning_lists

                mock_open.return_value.__enter__.return_value.read.side_effect = [
                    json.dumps(mock_metadata),
                    json.dumps(mock_cache),
                ]

                # Should not make network request if cache is fresh
                MISPWarningLists(cache_duration=24)
                mock_get.assert_not_called()

    def test_clean_defanged_value(self):
        """Test defanging cleanup."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test various defanging patterns
        test_cases = [
            ('example[.]com', 'example.com'),
            ('192[.]168[.]1[.]1', '192.168.1.1'),
            ('user[@]example[.]com', 'user@example.com'),
            ('hxxp://example[.]com', 'http://example.com'),
            ('hxxps://test[.]org', 'https://test.org'),
            ('example{.}com', 'example.com'),
            ('192(.)168(.)1(.)1', '192.168.1.1'),
            ('test{@}email{.}com', 'test@email.com'),
        ]

        for defanged, expected in test_cases:
            result = warning_lists._clean_defanged_value(defanged)
            assert result == expected, f"Failed to clean {defanged}"

    def test_check_cidr(self):
        """Test CIDR range checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test CIDR checking
        cidr_list = ['192.168.1.0/24', '10.0.0.0/8', '8.8.8.8']

        # Should match
        assert warning_lists._check_cidr('192.168.1.100', cidr_list)
        assert warning_lists._check_cidr('10.5.5.5', cidr_list)
        assert warning_lists._check_cidr('8.8.8.8', cidr_list)

        # Should not match
        assert not warning_lists._check_cidr('192.168.2.1', cidr_list)
        assert not warning_lists._check_cidr('11.0.0.1', cidr_list)
        assert not warning_lists._check_cidr('8.8.8.9', cidr_list)

        # Invalid IP should return False
        assert not warning_lists._check_cidr('not.an.ip', cidr_list)
        assert not warning_lists._check_cidr('256.256.256.256', cidr_list)

    def test_check_value_in_list_string(self):
        """Test string type list checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        values = ['google.com', 'facebook.com', 'youtube.com']

        # Exact match (case insensitive)
        assert warning_lists._check_value_in_list('google.com', values, 'string')
        assert warning_lists._check_value_in_list('GOOGLE.COM', values, 'string')
        assert warning_lists._check_value_in_list('Google.Com', values, 'string')

        # No match
        assert not warning_lists._check_value_in_list('amazon.com', values, 'string')
        assert not warning_lists._check_value_in_list('sub.google.com', values, 'string')

    def test_check_value_in_list_substring(self):
        """Test substring type list checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        values = ['google', 'facebook', 'virus']

        # Substring match
        assert warning_lists._check_value_in_list('google.com', values, 'substring')
        assert warning_lists._check_value_in_list('mail.google.com', values, 'substring')
        assert warning_lists._check_value_in_list('virustotal.com', values, 'substring')

        # No match
        assert not warning_lists._check_value_in_list('amazon.com', values, 'substring')

    def test_check_value_in_list_regex(self):
        """Test regex type list checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        values = [r'.*\.google\.com$', r'^192\.168\.\d+\.\d+$']

        # Regex match
        assert warning_lists._check_value_in_list('mail.google.com', values, 'regex')
        assert warning_lists._check_value_in_list('192.168.1.1', values, 'regex')

        # No match
        assert not warning_lists._check_value_in_list('google.net', values, 'regex')
        assert not warning_lists._check_value_in_list('10.0.0.1', values, 'regex')

    def test_check_value_with_mock_lists(self):
        """Test check_value with mock warning lists."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)
        warning_lists.warning_lists = self.mock_warning_lists

        # Test IP in public DNS list
        is_warning, info = warning_lists.check_value('8.8.8.8', 'ips')
        assert is_warning
        assert info['name'] == 'Public DNS Resolvers'

        # Test IP in CIDR range
        is_warning, info = warning_lists.check_value('8.8.8.100', 'ips')
        assert is_warning
        assert info['name'] == 'Google IP ranges'

        # Test domain in Alexa list
        is_warning, info = warning_lists.check_value('google.com', 'domains')
        assert is_warning
        assert info['name'] == 'Alexa Top 1000'

        # Test domain with substring match
        is_warning, info = warning_lists.check_value('virustotal.com', 'domains')
        assert is_warning
        assert info['name'] == 'Security Provider Domains'

        # Test non-matching IP
        is_warning, info = warning_lists.check_value('192.168.1.1', 'ips')
        assert not is_warning
        assert info is None

    def test_separate_iocs_by_warnings(self):
        """Test IOC separation by warnings."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)
        warning_lists.warning_lists = self.mock_warning_lists

        # Input IOCs
        iocs = {
            'ips': ['8.8.8.8', '192.168.1.1', '1.1.1.1'],
            'domains': ['google.com', 'evil.com', 'facebook.com'],
            'urls': ['https://virustotal.com/scan', 'https://malware.com/payload'],
        }

        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)

        # Check normal IOCs
        assert '192.168.1.1' in normal_iocs.get('ips', [])
        assert 'evil.com' in normal_iocs.get('domains', [])
        assert 'https://malware.com/payload' in normal_iocs.get('urls', [])

        # Check warning IOCs
        warning_ips = [w['value'] for w in warning_iocs.get('ips', [])]
        assert '8.8.8.8' in warning_ips
        assert '1.1.1.1' in warning_ips

        warning_domains = [w['value'] for w in warning_iocs.get('domains', [])]
        assert 'google.com' in warning_domains
        assert 'facebook.com' in warning_domains

        warning_urls = [w['value'] for w in warning_iocs.get('urls', [])]
        assert 'https://virustotal.com/scan' in warning_urls

    def test_ipv6_support(self):
        """Test IPv6 address checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test IPv6 CIDR
        cidr_list = ['2001:db8::/32', '::1']

        # Should match
        assert warning_lists._check_cidr('2001:db8::1', cidr_list)
        assert warning_lists._check_cidr('2001:db8:abcd::1234', cidr_list)
        assert warning_lists._check_cidr('::1', cidr_list)

        # Should not match
        assert not warning_lists._check_cidr('2002:db8::1', cidr_list)
        assert not warning_lists._check_cidr('::2', cidr_list)

    def test_hash_type_mapping(self):
        """Test hash type IOC mapping."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Create mock hash warning list
        warning_lists.warning_lists = {
            'known-hashes': {
                'name': 'Known Software Hashes',
                'description': 'Hashes of known software',
                'type': 'string',
                'matching_attributes': ['md5', 'sha256', 'filename|md5', 'filename|sha256'],
                'list': ['5f4dcc3b5aa765d61d8327deb882cf99'],
            },
        }

        # Test MD5 hash
        is_warning, info = warning_lists.check_value('5f4dcc3b5aa765d61d8327deb882cf99', 'md5')
        assert is_warning
        assert info['name'] == 'Known Software Hashes'

        # Test SHA256 (not in list)
        is_warning, info = warning_lists.check_value(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'sha256',
        )
        assert not is_warning

    def test_edge_cases(self):
        """Test edge cases and error handling."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Empty lists
        assert not warning_lists._check_value_in_list('test', [], 'string')
        assert not warning_lists._check_value_in_list('test', None, 'string')

        # None values in list
        assert warning_lists._check_value_in_list('test', [None, 'test', None], 'string')

        # Invalid regex should not crash
        assert not warning_lists._check_value_in_list('test', ['[invalid(regex'], 'regex')

        # Invalid CIDR should not crash
        assert not warning_lists._check_cidr('192.168.1.1', ['not/a/cidr', '256.256.256.256/24'])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
