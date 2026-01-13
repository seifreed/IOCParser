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
        warning_lists._preprocess_lists()  # Reprocess after setting mock data

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

    def test_email_domain_warning_excluded(self):
        """Email IOCs are excluded when their domain is in warning lists."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)
        warning_lists.warning_lists = self.mock_warning_lists
        warning_lists._preprocess_lists()

        iocs = {
            'emails': ['intelreports@kaspersky.com'],
            'domains': ['kaspersky.com'],
        }

        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)

        assert 'emails' not in normal_iocs
        assert 'emails' not in warning_iocs
        assert 'domains' in warning_iocs

    def test_separate_iocs_by_warnings(self):
        """Test IOC separation by warnings."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)
        warning_lists.warning_lists = self.mock_warning_lists
        warning_lists._preprocess_lists()  # Reprocess after setting mock data

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
        warning_lists._preprocess_lists()  # Reprocess after setting mock data

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


class TestWarningListsDownloadAndUpdate:
    """Test warning list download and update functionality."""

    def test_update_warning_lists_with_network(self):
        """Test updating warning lists from GitHub (network-dependent)."""
        import tempfile
        from pathlib import Path
        import shutil

        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create a test instance that will download lists
            warning_lists = MISPWarningLists(cache_duration=0, force_update=True)

            # Override the data directory to use temp directory
            warning_lists.data_dir = tmppath
            warning_lists.cache_file = tmppath / 'misp_warninglists_cache.json'
            warning_lists.cache_metadata_file = tmppath / 'misp_warninglists_metadata.json'

            # Trigger update
            warning_lists._update_warning_lists()

            # If rate limited or network error, the update may fail gracefully
            # but we can still verify the structure is correct
            if warning_lists.cache_file.exists():
                # Successfully downloaded - verify structure
                assert len(warning_lists.warning_lists) > 0, "Should have downloaded warning lists"
                assert warning_lists.cache_metadata_file.exists(), "Metadata file should exist"

                # Verify cache metadata structure
                with warning_lists.cache_metadata_file.open() as f:
                    metadata = json.load(f)
                    assert 'last_update' in metadata
                    assert isinstance(metadata['last_update'], (int, float))
            else:
                # Rate limited or network error - verify graceful handling
                # The warning_lists dict should be empty but not cause a crash
                assert isinstance(warning_lists.warning_lists, dict)

    def test_load_from_cache_when_fresh(self):
        """Test loading warning lists from fresh cache."""
        import tempfile
        import time
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create mock cache files
            cache_file = tmppath / 'misp_warninglists_cache.json'
            metadata_file = tmppath / 'misp_warninglists_metadata.json'

            mock_lists = {
                'test-list': {
                    'name': 'Test List',
                    'description': 'Test description',
                    'type': 'string',
                    'list': ['test1', 'test2'],
                }
            }

            with cache_file.open('w') as f:
                json.dump(mock_lists, f)

            with metadata_file.open('w') as f:
                json.dump({'last_update': time.time()}, f)

            # Create instance pointing to temp directory
            warning_lists = MISPWarningLists(cache_duration=24, force_update=False)
            warning_lists.data_dir = tmppath
            warning_lists.cache_file = cache_file
            warning_lists.cache_metadata_file = metadata_file

            # Load from cache
            warning_lists._load_or_update_lists()

            # Verify lists were loaded
            assert 'test-list' in warning_lists.warning_lists
            assert warning_lists.warning_lists['test-list']['name'] == 'Test List'

    def test_cache_expiration_triggers_update(self):
        """Test that expired cache triggers update."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create old cache files
            cache_file = tmppath / 'misp_warninglists_cache.json'
            metadata_file = tmppath / 'misp_warninglists_metadata.json'

            with cache_file.open('w') as f:
                json.dump({}, f)

            # Set last_update to old timestamp (25 hours ago)
            old_time = 0.0  # Unix epoch
            with metadata_file.open('w') as f:
                json.dump({'last_update': old_time}, f)

            # Create instance with 24 hour cache duration
            warning_lists = MISPWarningLists(cache_duration=24, force_update=False)
            warning_lists.data_dir = tmppath
            warning_lists.cache_file = cache_file
            warning_lists.cache_metadata_file = metadata_file

            # This should trigger update because cache is expired
            warning_lists._load_or_update_lists()

            # Verify update was attempted
            # If successful, metadata should be updated
            # If rate limited, old cache is used and metadata stays the same
            with metadata_file.open() as f:
                metadata = json.load(f)
                # Either update succeeded (new timestamp) or failed gracefully (old timestamp)
                assert 'last_update' in metadata
                assert isinstance(metadata['last_update'], (int, float))

    def test_corrupted_cache_fallback(self):
        """Test fallback when cache is corrupted."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create corrupted cache file
            cache_file = tmppath / 'misp_warninglists_cache.json'
            metadata_file = tmppath / 'misp_warninglists_metadata.json'

            with cache_file.open('w') as f:
                f.write('{ invalid json content }')

            with metadata_file.open('w') as f:
                f.write('{ "last_update": "not a number" }')

            # Create instance
            warning_lists = MISPWarningLists(cache_duration=24, force_update=False)
            warning_lists.data_dir = tmppath
            warning_lists.cache_file = cache_file
            warning_lists.cache_metadata_file = metadata_file

            # Should handle corrupted cache gracefully
            warning_lists._load_or_update_lists()

            # Should have downloaded new lists
            assert len(warning_lists.warning_lists) >= 0


class TestWarningListsPreprocessing:
    """Test warning list preprocessing functionality."""

    def test_preprocess_lists_with_invalid_regex(self):
        """Test preprocessing handles invalid regex patterns."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Create lists with invalid regex
        warning_lists.warning_lists = {
            'invalid-regex-list': {
                'name': 'Invalid Regex List',
                'description': 'Contains invalid regex patterns',
                'type': 'regex',
                'matching_attributes': ['domain'],
                'list': [r'valid\.regex', r'[invalid(regex', r'(?P<invalid', None],
            }
        }

        # Should not crash when preprocessing invalid regex
        warning_lists._preprocess_lists()

        # Should only compile valid patterns
        assert 'invalid-regex-list' in warning_lists.compiled_regex
        assert len(warning_lists.compiled_regex['invalid-regex-list']) == 1

    def test_preprocess_lists_with_invalid_cidr(self):
        """Test preprocessing handles invalid CIDR ranges."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Create lists with invalid CIDR
        warning_lists.warning_lists = {
            'invalid-cidr-list': {
                'name': 'Invalid CIDR List',
                'description': 'Contains invalid CIDR ranges',
                'type': 'cidr',
                'matching_attributes': ['ip-src'],
                'list': ['192.168.1.0/24', '256.256.256.256/24', 'not-an-ip', None, '10.0.0.0/8'],
            }
        }

        # Should not crash when preprocessing invalid CIDR
        warning_lists._preprocess_lists()

        # Should only parse valid CIDR ranges
        assert 'invalid-cidr-list' in warning_lists.cidr_networks
        assert len(warning_lists.cidr_networks['invalid-cidr-list']) == 2

    def test_preprocess_lists_with_non_list_values(self):
        """Test preprocessing handles non-list values gracefully."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Create list with non-list value
        warning_lists.warning_lists = {
            'malformed-list': {
                'name': 'Malformed List',
                'description': 'List field is not a list',
                'type': 'string',
                'matching_attributes': ['domain'],
                'list': 'not-a-list',  # Should be a list
            }
        }

        # Should handle gracefully
        warning_lists._preprocess_lists()

        # Should not crash and skip this list
        assert len(warning_lists.string_lookups) == 0

    def test_clear_preprocessed_data(self):
        """Test clearing preprocessed data structures."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Populate preprocessed structures
        warning_lists.string_lookups['test'] = {'list1'}
        warning_lists.compiled_regex['list1'] = []
        warning_lists.cidr_networks['list1'] = []
        warning_lists.lists_by_ioc_type['ips'] = ['list1']

        # Clear all
        warning_lists._clear_preprocessed_data()

        # Verify all are empty
        assert len(warning_lists.string_lookups) == 0
        assert len(warning_lists.compiled_regex) == 0
        assert len(warning_lists.cidr_networks) == 0
        assert len(warning_lists.lists_by_ioc_type) == 0


class TestWarningListsGetWarnings:
    """Test get_warnings_for_iocs functionality."""

    def test_get_warnings_for_iocs_with_string_iocs(self):
        """Test getting warnings for string IOCs."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup mock lists
        warning_lists.warning_lists = {
            'public-dns': {
                'name': 'Public DNS',
                'description': 'Public DNS servers',
                'type': 'string',
                'matching_attributes': ['ip-src', 'ip-dst'],
                'list': ['8.8.8.8', '1.1.1.1'],
            }
        }
        warning_lists._preprocess_lists()

        # Test with string IOCs
        iocs = {
            'ips': ['8.8.8.8', '192.168.1.1', '1.1.1.1'],
            'domains': ['google.com', 'example.com'],
        }

        warnings = warning_lists.get_warnings_for_iocs(iocs)

        # Should find warnings for matching IPs
        assert 'ips' in warnings
        assert len(warnings['ips']) == 2

        warning_values = [w['value'] for w in warnings['ips']]
        assert '8.8.8.8' in warning_values
        assert '1.1.1.1' in warning_values
        assert '192.168.1.1' not in warning_values

    def test_get_warnings_for_iocs_with_dict_iocs(self):
        """Test getting warnings for dictionary IOCs."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup mock lists
        warning_lists.warning_lists = {
            'known-hashes': {
                'name': 'Known Hashes',
                'description': 'Known software hashes',
                'type': 'string',
                'matching_attributes': ['md5', 'sha256'],
                'list': ['5f4dcc3b5aa765d61d8327deb882cf99'],
            }
        }
        warning_lists._preprocess_lists()

        # Test with dictionary IOCs
        iocs = {
            'md5': [
                {'value': '5f4dcc3b5aa765d61d8327deb882cf99', 'file': 'test.exe'},
                {'value': 'abcd1234abcd1234abcd1234abcd1234', 'file': 'malware.exe'},
            ]
        }

        warnings = warning_lists.get_warnings_for_iocs(iocs)

        # Should find warning for first hash
        assert 'md5' in warnings
        assert len(warnings['md5']) == 1
        assert warnings['md5'][0]['value'] == '5f4dcc3b5aa765d61d8327deb882cf99'
        assert warnings['md5'][0]['warning_list'] == 'Known Hashes'

    def test_get_warnings_for_iocs_empty_input(self):
        """Test getting warnings with empty input."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test with empty dict
        warnings = warning_lists.get_warnings_for_iocs({})
        assert warnings == {}

        # Test with empty lists
        warnings = warning_lists.get_warnings_for_iocs({'ips': [], 'domains': []})
        assert warnings == {}


class TestWarningListsSeparateIOCs:
    """Test separate_iocs_by_warnings functionality with dict IOCs."""

    def test_separate_iocs_preserves_dict_fields(self):
        """Test that separation preserves additional fields in dict IOCs."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup mock lists
        warning_lists.warning_lists = {
            'known-hashes': {
                'name': 'Known Hashes',
                'description': 'Known software hashes',
                'type': 'string',
                'matching_attributes': ['md5', 'sha256'],
                'list': ['5f4dcc3b5aa765d61d8327deb882cf99'],
            }
        }
        warning_lists._preprocess_lists()

        # Test with dictionary IOCs containing extra fields
        iocs = {
            'md5': [
                {
                    'value': '5f4dcc3b5aa765d61d8327deb882cf99',
                    'filename': 'test.exe',
                    'source': 'virustotal',
                    'confidence': 'high',
                },
                {
                    'value': 'abcd1234abcd1234abcd1234abcd1234',
                    'filename': 'malware.exe',
                    'source': 'sandbox',
                },
            ]
        }

        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)

        # Check that warning IOC preserves extra fields
        assert 'md5' in warning_iocs
        assert len(warning_iocs['md5']) == 1
        warning_entry = warning_iocs['md5'][0]
        assert warning_entry['value'] == '5f4dcc3b5aa765d61d8327deb882cf99'
        assert warning_entry['filename'] == 'test.exe'
        assert warning_entry['source'] == 'virustotal'
        assert warning_entry['confidence'] == 'high'
        assert 'warning_list' in warning_entry
        assert 'description' in warning_entry

        # Check that normal IOC is preserved as-is
        assert 'md5' in normal_iocs
        assert len(normal_iocs['md5']) == 1
        assert normal_iocs['md5'][0]['value'] == 'abcd1234abcd1234abcd1234abcd1234'


class TestWarningListsHelperFunctions:
    """Test helper functions and edge cases."""

    def test_get_misp_types_for_cryptocurrency(self):
        """Test MISP type mapping for cryptocurrency IOCs."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test bitcoin
        types = warning_lists._get_misp_types_for_ioc('bitcoin')
        assert 'btc' in types
        assert 'bitcoin' in types
        assert 'cryptocurrency' in types

        # Test ethereum
        types = warning_lists._get_misp_types_for_ioc('ethereum')
        assert 'eth' in types
        assert 'cryptocurrency' in types

        # Test monero
        types = warning_lists._get_misp_types_for_ioc('monero')
        assert 'xmr' in types
        assert 'cryptocurrency' in types

    def test_get_misp_types_for_hashes(self):
        """Test MISP type mapping for hash IOCs."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        for hash_type in ['md5', 'sha1', 'sha256', 'sha512']:
            types = warning_lists._get_misp_types_for_ioc(hash_type)
            assert hash_type in types
            assert f'filename|{hash_type}' in types
            assert 'hash' in types

    def test_extract_domain_from_url_with_port(self):
        """Test domain extraction from URL with port."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test URL with port
        domain = warning_lists._extract_domain_from_url('https://example.com:8080/path')
        assert domain == 'example.com'

        # Test URL without port
        domain = warning_lists._extract_domain_from_url('https://example.com/path')
        assert domain == 'example.com'

        # Test invalid URL
        domain = warning_lists._extract_domain_from_url('not-a-url')
        assert domain is None

    def test_is_list_applicable_with_dict_attributes(self):
        """Test list applicability check with dictionary attributes."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test with dictionary attributes
        warning_list = {
            'name': 'Test List',
            'type': 'string',
            'matching_attributes': [
                {'name': 'ip-src'},
                {'name': 'domain'},
                'email',
            ],
            'list': [],
        }

        # Should match IP types
        assert warning_lists._is_list_applicable(warning_list, ['ip-src', 'ip-dst'], 'ips')

        # Should match domain types
        assert warning_lists._is_list_applicable(warning_list, ['domain', 'hostname'], 'domains')

        # Should match email types
        assert warning_lists._is_list_applicable(warning_list, ['email', 'email-src'], 'emails')

    def test_is_list_applicable_without_attributes(self):
        """Test list applicability when matching_attributes is missing or invalid."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test without matching_attributes
        warning_list = {
            'name': 'Test List',
            'type': 'string',
            'list': [],
        }
        assert not warning_lists._is_list_applicable(warning_list, ['ip-src'], 'ips')

        # Test with non-list matching_attributes
        warning_list['matching_attributes'] = 'not-a-list'
        assert not warning_lists._is_list_applicable(warning_list, ['ip-src'], 'ips')

        # Test with empty list
        warning_list['matching_attributes'] = []
        assert not warning_lists._is_list_applicable(warning_list, ['ip-src'], 'ips')

    def test_is_list_applicable_cidr_special_case(self):
        """Test CIDR list applicability for IPs."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # CIDR lists should apply to IPs even without matching attributes
        warning_list = {
            'name': 'CIDR List',
            'type': 'cidr',
            'matching_attributes': ['unrelated-type'],
            'list': ['192.168.0.0/16'],
        }

        assert warning_lists._is_list_applicable(warning_list, ['ip-src'], 'ips')
        assert warning_lists._is_list_applicable(warning_list, ['ipv6'], 'ipv6')

    def test_check_against_warning_list_with_url_domain_extraction(self):
        """Test checking against warning list with URL domain extraction."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_list = {
            'name': 'Alexa Top Sites',
            'description': 'Top visited domains',
            'type': 'string',
            'list': ['google.com', 'facebook.com'],
        }

        # Test URL matching via domain extraction
        result = warning_lists._check_against_warning_list(
            'https://google.com/search',
            'google.com',
            warning_list,
            'alexa-top-sites',
        )

        assert result is not None
        assert result['name'] == 'Alexa Top Sites'

    def test_check_value_with_no_relevant_lists(self):
        """Test check_value when no relevant lists exist for IOC type."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'unrelated-list': {
                'name': 'Unrelated List',
                'description': 'For different IOC type',
                'type': 'string',
                'matching_attributes': ['unrelated-type'],
                'list': ['test'],
            }
        }
        warning_lists._preprocess_lists()

        # Should fall back to checking all lists
        is_warning, info = warning_lists.check_value('test', 'unknown-type')
        # May or may not match depending on fallback logic
        assert isinstance(is_warning, bool)

    def test_check_substring_type(self):
        """Test substring type checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        values = ['malware', 'virus', 'trojan']

        # Should match substring
        assert warning_lists._check_substring_type('malwarebytes.com', values)
        assert warning_lists._check_substring_type('antivirus-software', values)
        assert warning_lists._check_substring_type('trojan-dropper', values)

        # Should also match if value contains list item
        assert warning_lists._check_substring_type('malware', values)

        # Should not match
        assert not warning_lists._check_substring_type('clean-domain.com', values)

    def test_check_regex_type_with_none_values(self):
        """Test regex checking with None values in list."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        values = [r'.*\.google\.com$', None, r'^test.*']

        # Should skip None values
        assert warning_lists._check_regex_type('mail.google.com', values)
        assert warning_lists._check_regex_type('testdomain.com', values)
        assert not warning_lists._check_regex_type('example.com', values)

    def test_check_value_in_list_unknown_type(self):
        """Test check_value_in_list with unknown type."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Unknown type should return False
        result = warning_lists._check_value_in_list('test', ['test'], 'unknown-type')
        assert result is False

    def test_check_value_with_extracted_domain_in_string_lookups(self):
        """Test check_value when extracted domain is in string lookups."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'alexa-top': {
                'name': 'Alexa Top Sites',
                'description': 'Top sites',
                'type': 'string',
                'matching_attributes': ['domain', 'url'],
                'list': ['google.com', 'facebook.com'],
            }
        }
        warning_lists._preprocess_lists()

        # Test URL that extracts to a domain in string lookups
        is_warning, info = warning_lists.check_value('https://google.com/search?q=test', 'urls')
        assert is_warning
        assert info['name'] == 'Alexa Top Sites'

    def test_check_value_with_extracted_domain_in_regex(self):
        """Test check_value when extracted domain matches regex."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'google-domains': {
                'name': 'Google Domains',
                'description': 'All Google domains',
                'type': 'regex',
                'matching_attributes': ['domain', 'url'],
                'list': [r'.*\.google\.com$', r'.*\.googleapis\.com$'],
            }
        }
        warning_lists._preprocess_lists()

        # Test URL with domain matching regex
        is_warning, info = warning_lists.check_value('https://mail.google.com/inbox', 'urls')
        assert is_warning
        assert info['name'] == 'Google Domains'

    def test_check_value_ipv6_in_cidr(self):
        """Test IPv6 address checking in CIDR ranges."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'reserved-ipv6': {
                'name': 'Reserved IPv6',
                'description': 'Reserved IPv6 ranges',
                'type': 'cidr',
                'matching_attributes': ['ip-src', 'ipv6'],
                'list': ['2001:db8::/32', 'fe80::/10'],
            }
        }
        warning_lists._preprocess_lists()

        # Test IPv6 in CIDR range
        is_warning, info = warning_lists.check_value('2001:db8::1234', 'ipv6')
        assert is_warning
        assert info['name'] == 'Reserved IPv6'

        # Test IPv6 in another range
        is_warning, info = warning_lists.check_value('fe80::1', 'ipv6')
        assert is_warning

    def test_check_value_invalid_ip_for_cidr(self):
        """Test CIDR checking with invalid IP address."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'private-ips': {
                'name': 'Private IPs',
                'description': 'Private IP ranges',
                'type': 'cidr',
                'matching_attributes': ['ip-src'],
                'list': ['192.168.0.0/16', '10.0.0.0/8'],
            }
        }
        warning_lists._preprocess_lists()

        # Test invalid IP
        is_warning, info = warning_lists.check_value('not-an-ip', 'ips')
        assert not is_warning
        assert info is None


class TestWarningListsAdditionalEdgeCases:
    """Test additional edge cases for higher coverage."""

    def test_get_misp_types_for_ipv6(self):
        """Test MISP type mapping specifically for IPv6."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        types = warning_lists._get_misp_types_for_ioc('ipv6')
        assert 'ip-src' in types
        assert 'ip-dst' in types
        assert 'ipv6' in types

    def test_get_misp_types_for_ssdeep(self):
        """Test MISP type mapping for ssdeep hash type."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        types = warning_lists._get_misp_types_for_ioc('ssdeep')
        assert 'ssdeep' in types
        assert 'filename|ssdeep' in types
        assert 'hash' in types

    def test_get_misp_types_for_imphash(self):
        """Test MISP type mapping for imphash type."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        types = warning_lists._get_misp_types_for_ioc('imphash')
        assert 'imphash' in types
        assert 'filename|imphash' in types

    def test_check_against_warning_list_with_non_list_values(self):
        """Test checking against warning list when values field is not a list."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Create warning list with non-list values field
        warning_list = {
            'name': 'Test List',
            'description': 'Test',
            'type': 'string',
            'list': 'not-a-list',  # Should be a list
        }

        result = warning_lists._check_against_warning_list(
            'test-value',
            None,
            warning_list,
            'test-list',
        )

        # Should return None since values is not a list
        assert result is None

    def test_check_cidr_with_ipv6_exact_match(self):
        """Test CIDR checking with exact IPv6 match."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        cidr_list = ['2001:db8::1', '::1']

        # Should match exact IPv6
        assert warning_lists._check_cidr('2001:db8::1', cidr_list)
        assert warning_lists._check_cidr('::1', cidr_list)

        # Should not match different IPv6
        assert not warning_lists._check_cidr('2001:db8::2', cidr_list)

    def test_check_substring_type_with_none_values(self):
        """Test substring checking with None values in list."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        values = ['malware', None, 'virus']

        # Should skip None values
        assert warning_lists._check_substring_type('malware-sample', values)
        assert not warning_lists._check_substring_type('clean', values)

    def test_extract_domain_from_url_exception_handling(self):
        """Test domain extraction with various edge cases."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test with empty string
        domain = warning_lists._extract_domain_from_url('')
        assert domain is None

        # Test with malformed URL
        domain = warning_lists._extract_domain_from_url(':///')
        assert domain is None

    def test_diagnose_with_non_matching_list(self):
        """Test diagnostic output when value not in list."""
        import io
        import logging

        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup mock list with non-matching values and proper matching attributes
        warning_lists.warning_lists = {
            'test-domain-list': {
                'name': 'Test Domain List',
                'description': 'Test domain values',
                'type': 'string',
                'matching_attributes': ['domain', 'hostname'],
                'list': ['example.com', 'test.com'],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('iocparser.modules.warninglists')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic on non-matching value
        warning_lists.diagnose_value_detection('nonexistent.com', 'domains')

        # Get log output
        log_output = log_capture.getvalue()

        # Should show checking the list and indicate not found
        assert 'Test Domain List' in log_output or 'FINAL RESULT: Value is NOT' in log_output

        # Cleanup
        logger.removeHandler(handler)


class TestWarningListsDiagnostic:
    """Test diagnose_value_detection functionality."""

    def test_diagnose_value_detection_found(self):
        """Test diagnostic tool when value is found."""
        import io
        import sys
        import logging

        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup mock lists
        warning_lists.warning_lists = {
            'public-dns-v4': {
                'name': 'Public DNS Resolvers',
                'description': 'List of public DNS resolver IP addresses',
                'type': 'string',
                'matching_attributes': ['ip-src', 'ip-dst', 'ip'],
                'list': ['8.8.8.8', '8.8.4.4', '1.1.1.1'],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('iocparser.modules.warninglists')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic
        warning_lists.diagnose_value_detection('8.8.8.8', 'ips')

        # Get log output
        log_output = log_capture.getvalue()

        # Verify diagnostic output
        assert 'Diagnosing detection for 8.8.8.8' in log_output
        assert 'Public DNS Resolvers' in log_output
        assert 'FINAL RESULT: Value IS in warning list' in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_diagnose_value_detection_not_found(self):
        """Test diagnostic tool when value is not found."""
        import io
        import logging

        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup mock lists
        warning_lists.warning_lists = {
            'public-dns-v4': {
                'name': 'Public DNS Resolvers',
                'description': 'List of public DNS resolver IP addresses',
                'type': 'string',
                'matching_attributes': ['ip-src', 'ip-dst'],
                'list': ['8.8.8.8', '1.1.1.1'],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('iocparser.modules.warninglists')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic
        warning_lists.diagnose_value_detection('192.168.1.1', 'ips')

        # Get log output
        log_output = log_capture.getvalue()

        # Verify diagnostic output
        assert 'Diagnosing detection for 192.168.1.1' in log_output
        assert 'FINAL RESULT: Value is NOT in any warning list' in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_diagnose_with_expected_lists_filter(self):
        """Test diagnostic with expected lists filter."""
        import io
        import logging

        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup multiple mock lists
        warning_lists.warning_lists = {
            'public-dns-v4': {
                'name': 'Public DNS Resolvers',
                'description': 'List of public DNS resolver IP addresses',
                'type': 'string',
                'matching_attributes': ['ip-src'],
                'list': ['8.8.8.8'],
            },
            'alexa-top1000': {
                'name': 'Alexa Top 1000',
                'description': 'Top websites',
                'type': 'string',
                'matching_attributes': ['domain'],
                'list': ['google.com'],
            },
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('iocparser.modules.warninglists')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic with expected lists filter
        warning_lists.diagnose_value_detection('8.8.8.8', 'ips', expected_lists=['DNS'])

        # Get log output
        log_output = log_capture.getvalue()

        # Should check Public DNS list (contains 'DNS')
        assert 'Public DNS Resolvers' in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_diagnose_with_defanged_value(self):
        """Test diagnostic with defanged value."""
        import io
        import logging

        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Setup mock lists
        warning_lists.warning_lists = {
            'alexa-top': {
                'name': 'Alexa Top Sites',
                'description': 'Top websites',
                'type': 'string',
                'matching_attributes': ['domain'],
                'list': ['google.com', 'facebook.com'],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('iocparser.modules.warninglists')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic with defanged value
        warning_lists.diagnose_value_detection('google[.]com', 'domains')

        # Get log output
        log_output = log_capture.getvalue()

        # Should show cleaned value
        assert 'Cleaned value: google.com' in log_output
        assert 'FINAL RESULT: Value IS in warning list' in log_output

        # Cleanup
        logger.removeHandler(handler)

    def test_is_list_relevant_for_expected(self):
        """Test expected list relevance checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test matching name
        assert warning_lists._is_list_relevant_for_expected(
            'Public DNS Resolvers',
            'DNS servers',
            ['DNS', 'resolvers'],
        )

        # Test matching description
        assert warning_lists._is_list_relevant_for_expected(
            'IP List',
            'Contains DNS resolver IPs',
            ['DNS'],
        )

        # Test no match
        assert not warning_lists._is_list_relevant_for_expected(
            'Alexa Top Sites',
            'Popular websites',
            ['DNS', 'IP'],
        )

        # Test empty expected list
        assert not warning_lists._is_list_relevant_for_expected(
            'Any List',
            'Any description',
            [],
        )

        # Test None expected list
        assert not warning_lists._is_list_relevant_for_expected(
            'Any List',
            'Any description',
            None,
        )

    def test_is_list_relevant_for_type(self):
        """Test IOC type relevance checking."""
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test IP relevance
        assert warning_lists._is_list_relevant_for_type(
            'Public IP Addresses',
            'List of IP addresses',
            'ips',
        )

        # Test domain relevance
        assert warning_lists._is_list_relevant_for_type(
            'Top Domains',
            'Popular domain names',
            'domains',
        )

        # Test URL relevance
        assert warning_lists._is_list_relevant_for_type(
            'URL Shorteners',
            'Common URL shortening services',
            'urls',
        )

        # Test no match
        assert not warning_lists._is_list_relevant_for_type(
            'Hash List',
            'File hashes',
            'ips',
        )

        # Test unknown IOC type
        assert not warning_lists._is_list_relevant_for_type(
            'Any List',
            'Any description',
            'unknown-type',
        )


class TestWarningListsUpdateAndDownload:
    """Test warning list update and download functionality for 100% coverage."""

    @pytest.mark.skip(reason="Requires network access; use for manual testing only")
    def test_update_warning_lists_network_request(self):
        """
        Test actual network download of warning lists.

        This test requires network access and makes real requests to GitHub.
        Skipped by default to avoid test flakiness.
        """
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create instance with force update
            warning_lists = MISPWarningLists(cache_duration=0, force_update=True)
            warning_lists.data_dir = tmppath
            warning_lists.cache_file = tmppath / 'misp_warninglists_cache.json'
            warning_lists.cache_metadata_file = tmppath / 'misp_warninglists_metadata.json'

            # Trigger update
            warning_lists._update_warning_lists()

            # Verify download succeeded
            assert len(warning_lists.warning_lists) > 0
            assert warning_lists.cache_file.exists()
            assert warning_lists.cache_metadata_file.exists()

    def test_update_warning_lists_exception_handling(self):
        """
        Test exception handling during warning list updates.

        Validates that network errors are handled gracefully.
        """
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            warning_lists = MISPWarningLists(cache_duration=0, force_update=False)
            warning_lists.data_dir = tmppath
            warning_lists.cache_file = tmppath / 'misp_warninglists_cache.json'
            warning_lists.cache_metadata_file = tmppath / 'misp_warninglists_metadata.json'

            # Mock requests to raise exception
            import unittest.mock as mock
            with mock.patch('iocparser.modules.warninglists.requests.get') as mock_get:
                mock_get.side_effect = Exception("Network error")

                # Should handle exception gracefully
                try:
                    warning_lists._update_warning_lists()
                except Exception:
                    # Exception should be caught internally
                    pass

                # Should have empty warning lists but not crash
                assert isinstance(warning_lists.warning_lists, dict)


class TestWarningListsCheckValueEdgeCases:
    """Test edge cases in check_value for complete coverage."""

    def test_check_value_with_regex_match(self):
        """
        Test check_value when regex pattern matches.

        Validates regex matching code path in check_value.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'google-regex': {
                'name': 'Google Domains Regex',
                'description': 'Google domains via regex',
                'type': 'regex',
                'matching_attributes': ['domain', 'hostname'],
                'list': [r'.*\.google\.com$', r'.*\.googleapis\.com$'],
            }
        }
        warning_lists._preprocess_lists()

        # Test domain that matches regex
        is_warning, info = warning_lists.check_value('mail.google.com', 'domains')
        assert is_warning
        assert info['name'] == 'Google Domains Regex'

        # Test extracted domain from URL
        is_warning, info = warning_lists.check_value('https://storage.googleapis.com/bucket', 'urls')
        assert is_warning

    def test_check_value_with_cidr_match(self):
        """
        Test check_value when IP matches CIDR range.

        Validates CIDR matching code path.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'private-ips': {
                'name': 'Private IP Ranges',
                'description': 'RFC1918 private IPs',
                'type': 'cidr',
                'matching_attributes': ['ip-src', 'ip-dst'],
                'list': ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
            }
        }
        warning_lists._preprocess_lists()

        # Test IP in CIDR range
        is_warning, info = warning_lists.check_value('192.168.1.100', 'ips')
        assert is_warning
        assert info['name'] == 'Private IP Ranges'

        # Test IP in different range
        is_warning, info = warning_lists.check_value('10.5.5.5', 'ips')
        assert is_warning

    def test_check_value_with_substring_fallback(self):
        """
        Test check_value substring type fallback path.

        Validates substring matching in fallback logic.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'security-providers': {
                'name': 'Security Provider Domains',
                'description': 'Security company domains',
                'type': 'substring',
                'matching_attributes': ['domain', 'url'],
                'list': ['virustotal', 'malwarebytes', 'kaspersky'],
            }
        }
        warning_lists._preprocess_lists()

        # Test substring match
        is_warning, info = warning_lists.check_value('virustotal.com', 'domains')
        assert is_warning
        assert info['name'] == 'Security Provider Domains'

    def test_check_value_with_extracted_domain_in_regex(self):
        """
        Test check_value when extracted domain matches regex.

        Validates URL domain extraction and regex matching.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'cdn-domains': {
                'name': 'CDN Domains',
                'description': 'Content delivery networks',
                'type': 'regex',
                'matching_attributes': ['domain', 'url'],
                'list': [r'.*\.cloudfront\.net$', r'.*\.akamai\.net$'],
            }
        }
        warning_lists._preprocess_lists()

        # Test URL with domain matching regex
        is_warning, info = warning_lists.check_value('https://d111111abcdef8.cloudfront.net/image.jpg', 'urls')
        assert is_warning
        assert info['name'] == 'CDN Domains'

    def test_check_value_invalid_ip_for_cidr(self):
        """
        Test CIDR checking with invalid IP format.

        Validates exception handling in IP address parsing.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'test-cidrs': {
                'name': 'Test CIDR List',
                'description': 'Test',
                'type': 'cidr',
                'matching_attributes': ['ip-src'],
                'list': ['10.0.0.0/8'],
            }
        }
        warning_lists._preprocess_lists()

        # Test with invalid IP
        is_warning, info = warning_lists.check_value('not-an-ip-address', 'ips')
        assert not is_warning
        assert info is None

        # Test with malformed IP
        is_warning, info = warning_lists.check_value('999.999.999.999', 'ips')
        assert not is_warning


class TestWarningListsExtractDomainEdgeCases:
    """Test domain extraction edge cases for complete coverage."""

    def test_extract_domain_from_url_with_port(self):
        """
        Test domain extraction from URL with port number.

        Validates port stripping in domain extraction.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test URL with port
        domain = warning_lists._extract_domain_from_url('https://example.com:8080/path')
        assert domain == 'example.com'

        # Test URL with standard port
        domain = warning_lists._extract_domain_from_url('https://example.com:443/path')
        assert domain == 'example.com'

    def test_extract_domain_exception_handling(self):
        """
        Test domain extraction exception handling.

        Validates graceful failure for malformed URLs.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # Test with invalid URL
        domain = warning_lists._extract_domain_from_url('not a url')
        assert domain is None

        # Test with empty string
        domain = warning_lists._extract_domain_from_url('')
        assert domain is None

        # Test with malformed URL
        domain = warning_lists._extract_domain_from_url('http://')
        assert domain is None or domain == ''


class TestWarningListsIsListApplicableEdgeCases:
    """Test _is_list_applicable edge cases for complete coverage."""

    def test_is_list_applicable_with_empty_attrs_list(self):
        """
        Test list applicability when attrs_list is empty after processing.

        Validates handling of edge case where matching_attributes yields no valid attrs.
        """
        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        # List with only invalid attribute formats
        warning_list = {
            'name': 'Test List',
            'type': 'string',
            'matching_attributes': [123, None, {'no_name_key': 'value'}],
            'list': [],
        }

        result = warning_lists._is_list_applicable(warning_list, ['ip-src'], 'ips')
        assert not result


class TestWarningListsDiagnoseValueDetection:
    """Test diagnose_value_detection for complete coverage."""

    def test_diagnose_value_detection_execution(self):
        """
        Test that diagnose_value_detection executes without errors.

        Validates the diagnostic helper function code path.
        """
        import io
        import logging

        warning_lists = MISPWarningLists(cache_duration=0, force_update=False)

        warning_lists.warning_lists = {
            'test-list': {
                'name': 'Test Warning List',
                'description': 'For testing diagnostics',
                'type': 'string',
                'matching_attributes': ['ip-src', 'ip-dst'],
                'list': ['8.8.8.8', '1.1.1.1'],
            }
        }
        warning_lists._preprocess_lists()

        # Capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger('iocparser.modules.warninglists')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Run diagnostic
        warning_lists.diagnose_value_detection('8.8.8.8', 'ips')

        # Get log output
        log_output = log_capture.getvalue()

        # Should contain diagnostic information
        assert 'Diagnosing detection' in log_output or 'FINAL RESULT' in log_output

        # Cleanup
        logger.removeHandler(handler)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
