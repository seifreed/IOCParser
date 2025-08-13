#!/usr/bin/env python3

"""
Enhanced module for extracting indicators of compromise (IOCs) from text.
Includes additional IOC types and improved extraction methods.

Author: Marc Rivero | @seifreed
"""

import re
import urllib.parse
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Pattern, Set, Tuple, Union

from tqdm import tqdm

from iocparser.modules.logger import get_logger

# Constants for validation
MIN_HASH_UNIQUE_CHARS = 4
MAX_DOMAIN_LENGTH = 253
MAX_DOMAIN_PART_LENGTH = 63
IPv4_PARTS_COUNT = 4
IPv4_MAX_OCTET = 255
MIN_HOSTNAME_LENGTH = 3
LARGE_TEXT_THRESHOLD = 10000
MAX_URL_CONTENT_LINES = 5

logger = get_logger(__name__)


class IOCExtractor:
    """Enhanced class for extracting different types of IOCs from text."""

    def __init__(self, defang: bool = True) -> None:
        """
        Initialize the extractor.

        Args:
            defang: If True, performs defanging on the results
        """
        self.defang = defang

        # Load valid TLDs
        self.valid_tlds: Set[str] = self._load_valid_tlds()

        # Define regex patterns for all IOC types
        self.patterns: Dict[str, Pattern[str]] = {
            # Hash patterns - more flexible to catch hashes in various contexts
            'md5': re.compile(r'(?:MD5|md5)\s*:?\s*([a-fA-F0-9]{32})|\b([a-fA-F0-9]{32})\b'),
            'sha1': re.compile(
                r'(?:SHA-1|SHA1|sha1)\s*:?\s*([a-fA-F0-9]{40})|\b([a-fA-F0-9]{40})\b',
            ),
            'sha256': re.compile(
                r'(?:SHA-256|SHA256|sha256)\s*:?\s*([a-fA-F0-9]{64})|\b([a-fA-F0-9]{64})\b',
            ),
            'sha512': re.compile(
                r'(?:SHA-512|SHA512|sha512)\s*:?\s*([a-fA-F0-9]{128})|\b([a-fA-F0-9]{128})\b',
            ),
            'ssdeep': re.compile(r'\b\d{2,}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\b'),
            'imphash': re.compile(r'\b[a-fA-F0-9]{32}\b'),  # Same as MD5 but context-dependent

            # Network indicators
            'domains': re.compile(
                r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b|'
                r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\(\.\)|\{\.\}|\.)){1,}'
                r'[a-zA-Z]{2,63})\b',
            ),
            'ips': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[\[\(]?\.[\]\)]?){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            ),
            'ipv6': re.compile(
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
                r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
                r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b',
            ),
            'urls': re.compile(
                r'\b(?:https?|hxxps?|h\[\.\]ttps?|s?ftp)://'
                r'(?!DOMAIN_NAME|IP:|\*\.|localhost|example\.)'
                r'[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]'
                r'(?:\.[a-zA-Z]{2,63})?(?::[0-9]{1,5})?'
                r'(?:/[-a-zA-Z0-9()@:%_\+.~#?&/=]*)?',
            ),
            'mac_addresses': re.compile(
                r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|'
                r'\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b',
            ),

            # Cryptocurrency
            'bitcoin': re.compile(r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'),
            'ethereum': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'monero': re.compile(r'\b4[0-9AB][a-zA-Z0-9]{93}\b'),

            # Email and communication
            'emails': re.compile(
                r'\b[a-zA-Z0-9][a-zA-Z0-9._-]*@'
                r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,63}\b',
            ),

            # Vulnerabilities and threats
            'cves': re.compile(r'\b(CVE-[0-9]{4}-[0-9]{4,7})\b', re.IGNORECASE),
            'mitre_attack': re.compile(r'\b(T[0-9]{4}(?:\.[0-9]{3})?)\b'),

            # Windows artifacts
            'registry': re.compile(
                r'\b((?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|'
                r'HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|'
                r'HKEY_CURRENT_CONFIG|HKCC)\\[\\A-Za-z0-9-_\s]+)\b',
            ),
            'mutex': re.compile(
                r'\b(?:Global\\|Local\\)?[A-Za-z0-9][A-Za-z0-9_\-]{2,}(?:Mutex|MUTEX)\b|'
                r'\bMutex:[A-Za-z0-9_\-]+\b',
            ),
            'service_names': re.compile(
                r'\b(?:Service|SERVICE):\s*([A-Za-z0-9][A-Za-z0-9_\-]{2,})\b|'
                r'\b([A-Za-z0-9][A-Za-z0-9_\-]{2,})(?:Service|Svc)\b',
            ),
            'named_pipes': re.compile(r'\\\\\\.\\pipe\\[A-Za-z0-9_\-]+'),

            # File indicators
            'filenames': re.compile(
                r'\b([A-Za-z0-9][A-Za-z0-9-_\.]{2,})\.'
                r'(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|'
                r'zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif|'
                r'ps1|vbs|wsf|hta|cmd|com|lnk|ini|inf|reg)\b',
                re.IGNORECASE,
            ),
            'filepaths': re.compile(
                r'\b[A-Z]:\\(?:[A-Za-z0-9-_\.\s]+\\)+[A-Za-z0-9-_\.\s]+(?:\.[A-Za-z]{2,4})?\b|'
                r'/(?:usr|bin|etc|var|tmp|home|opt|proc|sys|lib|dev)/(?:[A-Za-z0-9-_\.]+/)*[A-Za-z0-9-_\.]+\b',
            ),

            # User agents
            'user_agents': re.compile(
                r'User-Agent:\s*([^\r\n]+)|'
                r'Mozilla/[0-9\.]+\s+\([^)]+\)[^\r\n]*',
            ),

            # YARA rules - pattern that handles nested content properly
            'yara': re.compile(r'rule\s+\w+\s*\{(?:[^{}]|\{[^}]*\})*\}', re.DOTALL),

            # AS numbers
            'asn': re.compile(r'\bAS[0-9]{1,10}\b'),

            # JWT tokens
            'jwt': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        }

        # Common file extensions
        self.common_file_extensions: Set[str] = {
            'exe', 'dll', 'sys', 'cmd', 'bat', 'ps1', 'vbs', 'js', 'pdf',
            'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'jpg',
            'jpeg', 'png', 'gif', 'bmp', 'zip', 'rar', '7z', 'gz', 'tar',
            'pif', 'scr', 'msi', 'jar', 'py', 'pyc', 'pyo', 'php', 'asp',
            'aspx', 'jsp', 'htm', 'html', 'css', 'json', 'xml', 'reg',
            'ini', 'cfg', 'log', 'tmp', 'dat', 'db', 'sqlite', 'iso',
            'img', 'vhd', 'vmdk',
        }

        # Malware keywords
        self.malware_keywords: Set[str] = {
            'trojan', 'virus', 'worm', 'backdoor', 'rootkit', 'spyware',
            'adware', 'ransomware', 'malware', 'agent', 'dropper',
            'downloader', 'injector', 'stealer', 'keylogger', 'generic',
            'heur', 'suspicious', 'riskware', 'unwanted', 'pup', 'pua',
            'hacktool', 'exploit', 'obfuscated', 'packed', 'crypted',
            'banker', 'win32', 'win64', 'msil', 'android', 'linux',
            'macos', 'ios', 'symbian', 'unix', 'emotet', 'trickbot',
            'cobalt', 'mimikatz', 'lazarus', 'apt',
        }

    def _load_valid_tlds(self) -> Set[str]:
        """
        Load the list of valid TLDs.

        Returns:
            Set of valid TLDs
        """
        # Common TLDs
        common_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info',
            'biz', 'name', 'pro', 'museum', 'aero', 'coop', 'jobs',
            'travel', 'mobi', 'asia', 'tel', 'xxx', 'post', 'cat',
            'arpa', 'top', 'xyz', 'club', 'online', 'site', 'shop',
            'app', 'blog', 'dev', 'art', 'web', 'cloud', 'page',
            'store', 'host', 'tech', 'space', 'live', 'news', 'io',
            'co', 'me', 'tv', 'us', 'uk', 'ru', 'fr', 'de', 'jp',
            'cn', 'au', 'ca', 'in', 'it', 'nl', 'se', 'no', 'fi',
            'dk', 'ch', 'at', 'be', 'es', 'pt', 'br', 'mx', 'ar',
            'cl', 'pe', 've', 'za', 'pl', 'cz', 'gr', 'hu', 'ro',
            'ua', 'by', 'kz', 'th', 'sg', 'my', 'ph', 'vn', 'id',
            'tr', 'il', 'ae', 'sa', 'ir', 'pk', 'eg', 'ng', 'kr',
            'tw', 'hk', 'mo', 'eu', 'nz', 'ai', 'gg', 'im', 'je',
        }

        # Try to load from file
        tlds_file = Path(__file__).parent / 'data' / 'tlds.txt'
        if tlds_file.exists():
            try:
                with tlds_file.open(encoding='utf-8') as f:
                    return {line.strip().lower() for line in f if line.strip()}
            except Exception:
                logger.debug("Failed to load TLD list from file")

        return common_tlds

    def _extract_pattern(
        self,
        text: str,
        pattern_name: str,
    ) -> List[str]:
        """
        Extract matches for a specific pattern.

        Args:
            text: Text to search in
            pattern_name: Name of the pattern to use

        Returns:
            List of matched strings
        """
        if pattern_name not in self.patterns:
            return []

        pattern = self.patterns[pattern_name]
        matches: List[Union[str, Tuple[str, ...]]] = pattern.findall(text)

        # Clean up matches
        clean_matches: List[str] = []
        for match in matches:
            if isinstance(match, tuple):
                # Find first non-empty match in tuple
                for m in match:
                    if m:
                        clean_matches.append(m)
                        break
            elif match:
                clean_matches.append(match)

        return list(set(clean_matches))  # Remove duplicates

    def _is_valid_hash_pattern(self, hash_string: str) -> bool:
        """
        Check if a hash string has a valid pattern.

        Args:
            hash_string: Hash string to validate

        Returns:
            True if valid pattern, False otherwise
        """
        # Check for repeated characters (like all zeros or all f's)
        if len(set(hash_string.lower())) < MIN_HASH_UNIQUE_CHARS:
            return False

        # Check for sequential patterns
        return not any(pattern in hash_string.lower() for pattern in [
            '0123456789', 'abcdef', 'fedcba', '9876543210',
        ])

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate if a string is a valid domain.

        Args:
            domain: Domain string to validate

        Returns:
            True if valid domain, False otherwise
        """
        if not domain or '.' not in domain:
            return False

        # Check TLD
        parts = domain.lower().split('.')
        tld = parts[-1]

        if tld not in self.valid_tlds:
            return False

        # Check if it's not a file extension
        if tld in self.common_file_extensions:
            return False

        # Exclude JavaScript/programming constructs
        programming_keywords = {
            'document', 'window', 'console', 'function', 'addEventListener',
            'getElementById', 'querySelector', 'prototype', 'constructor',
            'toString', 'valueOf', 'typeof', 'instanceof', 'undefined',
            'gform', 'jquery', 'angular', 'react', 'vue',
        }

        # Check if any part is a programming keyword
        for part in parts:
            if part.lower() in programming_keywords:
                return False

        # IMPORTANT: Exclude well-known legitimate domains unless they're subdomains
        # These should only appear if there's a specific malicious URL, not just mentioned
        legitimate_domains = {
            'github.com', 'microsoft.com', 'google.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'youtube.com', 'wikipedia.org', 'amazon.com', 'apple.com',
            'stackoverflow.com', 'adobe.com', 'oracle.com', 'mozilla.org', 'apache.org',
            'wordpress.com', 'cloudflare.com', 'akamai.com', 'fastly.com', 'debian.org',
            'ubuntu.com', 'redhat.com', 'centos.org', 'python.org', 'nodejs.org',
            'npmjs.com', 'pypi.org', 'rubygems.org', 'docker.com', 'kubernetes.io',
            'microsoft.net', 'live.com', 'office.com', 'outlook.com', 'skype.com',
            'bing.com', 'yahoo.com', 'yandex.ru', 'baidu.com', 'duckduckgo.com',
            'reddit.com', 'instagram.com', 'whatsapp.com', 'telegram.org', 'slack.com',
            'zoom.us', 'dropbox.com', 'box.com', 'salesforce.com', 'atlassian.com',
            'jetbrains.com', 'visualstudio.com', 'eclipse.org', 'sourceforge.net',
            'gnu.org', 'kernel.org', 'w3.org', 'ietf.org', 'ieee.org',
            'cisco.com', 'vmware.com', 'ibm.com', 'intel.com', 'amd.com',
            'nvidia.com', 'dell.com', 'hp.com', 'lenovo.com', 'asus.com',
            'kaspersky.com', 'symantec.com', 'mcafee.com', 'trendmicro.com', 'avast.com',
            'bitdefender.com', 'eset.com', 'sophos.com', 'paloaltonetworks.com', 'fortinet.com',
            'fireeye.com', 'crowdstrike.com', 'sentinelone.com', 'carbonblack.com', 'cylance.com',
            'virustotal.com', 'hybrid-analysis.com', 'malwarebytes.com', 'spamhaus.org', 'sans.org',
            'mitre.org', 'cve.mitre.org', 'nvd.nist.gov', 'us-cert.gov', 'cert.org',
            'shodan.io', 'censys.io', 'zoomeye.org', 'riskiq.com', 'domaintools.com',
            'alibabacloud.com', 'aws.amazon.com', 'azure.microsoft.com',
            'cloud.google.com', 'digitalocean.com',
            'godaddy.com', 'namecheap.com', 'squarespace.com', 'wix.com',
            'habr.com', 'medium.com', 'dev.to', 'hashnode.com', 'blogger.com',
        }

        # Also check with 'learn.' or other common subdomains of legitimate sites
        legitimate_with_subdomains = {
            'learn.microsoft.com', 'docs.microsoft.com', 'support.microsoft.com',
            'developer.mozilla.org', 'wiki.debian.org', 'help.ubuntu.com',
            'access.redhat.com', 'bugzilla.redhat.com', 'git.kernel.org',
        }

        domain_lower = domain.lower()

        # If it's a known legitimate domain, exclude it
        if domain_lower in legitimate_domains or domain_lower in legitimate_with_subdomains:
            return False

        # If it's a subdomain of a legitimate domain but looks suspicious, keep it
        # For example: malware.github.com or c2.microsoft.com would be kept
        for legit in legitimate_domains:
            if domain_lower.endswith('.' + legit):
                # Check if the subdomain part looks suspicious
                subdomain = domain_lower.replace('.' + legit, '')
                suspicious_subdomain_keywords = [
                    'malware', 'c2', 'payload', 'evil', 'bad', 'attack', 'exploit',
                    'trojan', 'virus', 'worm', 'botnet', 'phishing', 'scam',
                    'backdoor', 'rootkit', 'keylogger', 'ransomware', 'crypter',
                ]
                if any(keyword in subdomain.lower() for keyword in suspicious_subdomain_keywords):
                    return True  # Keep suspicious subdomains
                return False  # Exclude normal subdomains of legitimate sites

        # Check domain length
        domain_length_valid = len(domain) <= MAX_DOMAIN_LENGTH
        parts_length_valid = all(len(part) <= MAX_DOMAIN_PART_LENGTH for part in parts)

        # Must have at least 2 parts (subdomain.tld)
        has_min_parts = len(parts) >= 2

        return domain_length_valid and parts_length_valid and has_min_parts

    def _defang_domain(self, domain: str) -> str:
        """
        Defang a domain by replacing dots.

        Args:
            domain: Domain to defang

        Returns:
            Defanged domain
        """
        return domain.replace('.', '[.]')

    def _defang_ip(self, ip: str) -> str:
        """
        Defang an IP address.

        Args:
            ip: IP address to defang

        Returns:
            Defanged IP
        """
        return ip.replace('.', '[.]')

    def _defang_url(self, url: str) -> str:
        """
        Defang a URL.

        Args:
            url: URL to defang

        Returns:
            Defanged URL
        """
        return (url.replace('http://', 'hxxp://')
                   .replace('https://', 'hxxps://')
                   .replace('.', '[.]'))

    def _extract_domains_from_urls(self, text: str) -> List[str]:
        """
        Extract domains from URLs in text.

        Args:
            text: Text to search in

        Returns:
            List of domains
        """
        urls = self._extract_pattern(text, 'urls')
        domains = []

        for url in urls:
            # Clean defanged URLs
            clean_url = url.replace('[.]', '.').replace('hxxp', 'http')

            try:
                parsed = urllib.parse.urlparse(clean_url)
                if parsed.netloc:
                    # Remove port if present
                    domain = parsed.netloc.split(':')[0]
                    if self._is_valid_domain(domain):
                        domains.append(domain)
            except Exception as e:
                logger.debug(f"Failed to parse URL {clean_url}: {e}")
                continue

        return domains

    # Extraction methods for each IOC type
    def extract_md5(self, text: str) -> List[str]:
        """Extract MD5 hashes from text."""
        candidates = self._extract_pattern(text, 'md5')
        return [h for h in candidates if self._is_valid_hash_pattern(h)]

    def extract_sha1(self, text: str) -> List[str]:
        """Extract SHA1 hashes from text."""
        candidates = self._extract_pattern(text, 'sha1')
        return [h for h in candidates if self._is_valid_hash_pattern(h)]

    def extract_sha256(self, text: str) -> List[str]:
        """Extract SHA256 hashes from text."""
        candidates = self._extract_pattern(text, 'sha256')
        return [h for h in candidates if self._is_valid_hash_pattern(h)]

    def extract_sha512(self, text: str) -> List[str]:
        """Extract SHA512 hashes from text."""
        return self._extract_pattern(text, 'sha512')

    def extract_ssdeep(self, text: str) -> List[str]:
        """Extract ssdeep hashes from text."""
        return self._extract_pattern(text, 'ssdeep')

    def extract_domains(self, text: str) -> List[str]:
        """Extract domain names from text."""
        domains = self._extract_pattern(text, 'domains')
        domains_from_urls = self._extract_domains_from_urls(text)

        all_domains = domains + domains_from_urls
        clean_domains = []

        for domain in all_domains:
            # Clean existing defanging
            clean_domain = domain.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')

            if self._is_valid_domain(clean_domain):
                if self.defang:
                    clean_domain = self._defang_domain(clean_domain)
                clean_domains.append(clean_domain)

        return list(set(clean_domains))

    def extract_ips(self, text: str) -> List[str]:
        """Extract IPv4 addresses from text."""
        ips = self._extract_pattern(text, 'ips')
        clean_ips = []

        for ip in ips:
            # Clean existing defanging
            clean_ip = ip.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')

            # Validate IP
            parts = clean_ip.split('.')
            if len(parts) == IPv4_PARTS_COUNT:
                try:
                    if all(0 <= int(part) <= IPv4_MAX_OCTET for part in parts):
                        if self.defang:
                            clean_ip = self._defang_ip(clean_ip)
                        clean_ips.append(clean_ip)
                except ValueError:
                    continue

        return list(set(clean_ips))

    def extract_ipv6(self, text: str) -> List[str]:
        """Extract IPv6 addresses from text."""
        return self._extract_pattern(text, 'ipv6')

    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text, intelligently filtering based on context."""
        urls = self._extract_pattern(text, 'urls')
        clean_urls = []

        for url in urls:
            try:
                # Clean defanging to parse
                clean_for_parse = url.replace('[.]', '.').replace('hxxp', 'http')
                from urllib.parse import urlparse
                parsed = urlparse(clean_for_parse)
                domain = parsed.netloc.lower()
                path = parsed.path.lower()

                # Always keep URLs from these potentially dangerous sites
                file_sharing_sites = {
                    'pastebin.com', 'paste.ee', 'hastebin.com', 'gist.github.com',
                    'drive.google.com', 'docs.google.com', 'dropbox.com', 'box.com',
                    'mediafire.com', 'mega.nz', 'wetransfer.com', 'sendspace.com',
                    'discord.com', 'discord.gg', 'telegram.me', 't.me',
                    'transfer.sh', 'file.io', 'anonfiles.com', 'bayfiles.com',
                }

                # Always keep if it's a file sharing site
                if any(site in domain for site in file_sharing_sites):
                    if self.defang:
                        clean_urls.append(self._defang_url(url))
                    else:
                        clean_urls.append(url)
                    continue

                # For GitHub/GitLab, keep if path suggests malicious content
                if 'github.com' in domain or 'gitlab.com' in domain or 'bitbucket.org' in domain:
                    suspicious_path_keywords = [
                        'malware', 'exploit', 'payload', 'shellcode', 'backdoor',
                        'c2', 'c&c', 'rat', 'trojan', 'ransomware', 'crypter',
                        'loader', 'dropper', 'injector', 'rootkit', 'keylogger',
                        'stealer', 'miner', 'botnet', 'virus', 'worm',
                        'hack', 'crack', 'keygen', 'poc', 'cve-',
                        'vulnerability', 'pentest', 'redteam', 'bypass',
                    ]
                    # Keep if path contains suspicious keywords
                    suspicious_tools = ['mimikatz', 'cobalt', 'empire', 'metasploit', 'dsefix']
                    if (any(keyword in path for keyword in suspicious_path_keywords) or
                        any(tool in path for tool in suspicious_tools)):
                        if self.defang:
                            clean_urls.append(self._defang_url(url))
                        else:
                            clean_urls.append(url)
                    continue

                # Skip pure documentation/support URLs from major vendors
                documentation_domains = [
                    'docs.microsoft.com', 'learn.microsoft.com', 'support.microsoft.com',
                    'developer.apple.com', 'support.apple.com', 'help.apple.com',
                    'developers.google.com', 'support.google.com', 'cloud.google.com/docs',
                    'docs.aws.amazon.com', 'docs.oracle.com', 'docs.python.org',
                    'developer.mozilla.org', 'stackoverflow.com', 'serverfault.com',
                ]

                if any(doc_domain in domain for doc_domain in documentation_domains):
                    # Skip unless path contains suspicious elements
                    suspicious_terms = ['exploit', 'vulnerability', 'cve-', 'poc', 'bypass']
                    if not any(susp in path for susp in suspicious_terms):
                        continue

                # For all other URLs, keep them if they're not obviously benign
                if domain and not domain.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                    if self.defang:
                        clean_urls.append(self._defang_url(url))
                    else:
                        clean_urls.append(url)

            except Exception:
                # If parsing fails, keep the URL
                if self.defang:
                    clean_urls.append(self._defang_url(url))
                else:
                    clean_urls.append(url)

        return list(set(clean_urls))

    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        emails = self._extract_pattern(text, 'emails')

        if self.defang:
            emails = [email.replace('@', '[@]').replace('.', '[.]') for email in emails]

        return list(set(emails))

    def extract_bitcoin(self, text: str) -> List[str]:
        """Extract Bitcoin addresses from text."""
        return self._extract_pattern(text, 'bitcoin')

    def extract_ethereum(self, text: str) -> List[str]:
        """Extract Ethereum addresses from text."""
        return self._extract_pattern(text, 'ethereum')

    def extract_monero(self, text: str) -> List[str]:
        """Extract Monero addresses from text."""
        return self._extract_pattern(text, 'monero')

    def extract_cves(self, text: str) -> List[str]:
        """Extract CVE identifiers from text."""
        return self._extract_pattern(text, 'cves')

    def extract_mitre_attack(self, text: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from text."""
        return self._extract_pattern(text, 'mitre_attack')

    def extract_registry(self, text: str) -> List[str]:
        """Extract Windows registry keys from text."""
        return self._extract_pattern(text, 'registry')

    def extract_mutex(self, text: str) -> List[str]:
        """Extract mutex names from text."""
        return self._extract_pattern(text, 'mutex')

    def extract_service_names(self, text: str) -> List[str]:
        """Extract Windows service names from text."""
        matches = self._extract_pattern(text, 'service_names')
        return list(set(matches))

    def extract_named_pipes(self, text: str) -> List[str]:
        """Extract Windows named pipes from text."""
        return self._extract_pattern(text, 'named_pipes')

    def extract_filenames(self, text: str) -> List[str]:
        """Extract filenames from text, only real files with extensions."""
        matches = self._extract_pattern(text, 'filenames')

        # Only keep matches that are actual full filenames (name + extension)
        real_filenames = []
        for match in matches:
            # Matches should always be strings from our pattern
            if isinstance(match, str) and '.' in match and len(match) > 4:
                real_filenames.append(match)

        # Common legitimate processes to exclude
        legitimate_processes = {
            'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe',
            'lsass.exe', 'services.exe', 'spoolsv.exe', 'taskhost.exe', 'dwm.exe',
            'userinit.exe', 'logonui.exe', 'wininit.exe', 'kernel32.dll',
            'ntdll.dll', 'user32.dll', 'notepad.exe', 'calc.exe', 'cmd.exe',
            'powershell.exe', 'conhost.exe', 'rundll32.exe', 'regsvr32.exe',
            'chrome.exe', 'firefox.exe', 'iexplore.exe', 'msiexec.exe',
        }

        # Filter out legitimate processes
        filtered_matches = [
            match for match in real_filenames
            if match.lower() not in legitimate_processes
        ]

        # Focus on files mentioned in security/threat context or with suspicious characteristics
        final_matches = []
        for match in filtered_matches:
            # Malware-related files
            if any(keyword in match.lower() for keyword in [
                'throttle', 'blood', 'haz8', 'all.exe', 'mimikatz', 'ransomware',
            ]) or any(av in match.lower() for av in [
                'avast', 'avg', 'bd', 'csfalcon', 'eset', 'kaspersky', 'mcafee',
                'sentinel', 'sophos', 'symantec', 'panda',
            ]) or (len([c for c in match if c.isdigit()]) >= 1 and
                  any(ext in match.lower() for ext in ['.exe', '.dll', '.sys'])):
                final_matches.append(match)

        return list(set(final_matches))[:30]  # Reduced limit for quality

    def extract_filepaths(self, text: str) -> List[str]:
        """Extract file paths from text with validation."""
        raw_paths = self._extract_pattern(text, 'filepaths')

        # Filter and clean paths
        valid_paths = []
        for path in raw_paths:
            # Clean up the path
            clean_path = path.strip()

            # Must be reasonable length and structure
            if (50 < len(clean_path) < 200 and
                ('\\' in clean_path or '/' in clean_path) and
                not any(word in clean_path.lower() for word in [
                    'folder on the', 'uploaded to', 'artifacts were', 'initially',
                ])):
                # Extract just the actual path part
                if '\\' in clean_path:
                    # Windows path
                    path_parts = clean_path.split()
                    for part in path_parts:
                        if ':\\' in part and len(part) > 10:
                            valid_paths.append(part)
                            break
                else:
                    valid_paths.append(clean_path)

        return list(set(valid_paths))

    def extract_mac_addresses(self, text: str) -> List[str]:
        """Extract MAC addresses from text."""
        return self._extract_pattern(text, 'mac_addresses')

    def extract_user_agents(self, text: str) -> List[str]:
        """Extract user agent strings from text."""
        return self._extract_pattern(text, 'user_agents')

    def extract_yara_rules(self, text: str) -> List[str]:
        """Extract YARA rules from text with better validation."""
        raw_rules = self._extract_pattern(text, 'yara')

        # Filter out invalid "rules" (like long text blocks)
        valid_rules = []
        for rule in raw_rules:
            # Must be reasonable length (not entire articles)
            if len(rule) < 3000 and 'rule ' in rule and '{' in rule:
                # Must have YARA-like structure (at least one section)
                if any(keyword in rule for keyword in ['strings:', 'condition:', 'meta:']):
                    # Clean up the rule
                    clean_rule = rule.strip()
                    # If it's missing the closing brace (truncated), add it
                    if not clean_rule.endswith('}'):
                        clean_rule += '\n}'
                    valid_rules.append(clean_rule)

        return valid_rules

    def extract_asn(self, text: str) -> List[str]:
        """Extract AS numbers from text."""
        return self._extract_pattern(text, 'asn')

    def extract_jwt(self, text: str) -> List[str]:
        """Extract JWT tokens from text."""
        return self._extract_pattern(text, 'jwt')

    def extract_hosts(self, text: str) -> List[str]:
        """
        Extract actual network hostnames and domains from text.
        Returns only valid domains and explicitly mentioned machine names.
        """
        # Primary source: valid domains
        all_domains: List[str] = self.extract_domains(text)

        # Filter out domains that are clearly not hosts
        valid_hosts = []
        for domain in all_domains:
            # Skip single-word entries without dots (these aren't real hosts)
            if '.' not in domain:
                continue

            # Skip common false positives that slip through
            domain_lower = domain.lower()
            if any(fp in domain_lower for fp in [
                'view', 'via', 'the', 'and', 'for', 'with', 'from',
                'document.', 'window.', 'console.', 'function.',
                'gform.', 'jquery.', '.addeventlistener', '.prototype',
            ]):
                continue

            # Must be a reasonable domain name
            parts = domain.split('.')
            if len(parts) >= 2 and all(len(part) > 0 for part in parts):
                valid_hosts.append(domain)

        # Secondary source: explicitly mentioned machine names (very rare)
        # Only from UNC paths or explicit NetBIOS contexts
        unc_pattern: Pattern[str] = re.compile(
            r'\\\\\\\\([A-Z][A-Z0-9\-]{2,14})(?:\\\\|\s)',
            re.IGNORECASE,
        )

        unc_matches: List[str] = unc_pattern.findall(text)
        for match in unc_matches:
            if match and len(match) > 3 and match.lower() not in ['users', 'windows', 'program']:
                valid_hosts.append(match)

        # Remove duplicates and return
        return list(set(valid_hosts))

    def extract_all(self, text: str) -> Dict[str, List[str]]:
        """
        Extract all types of IOCs from text.

        Args:
            text: Text to extract IOCs from

        Returns:
            Dictionary with IOC types as keys and lists of IOCs as values
        """
        iocs = {}

        # Extract all standard IOC types
        extraction_methods: List[Tuple[str, Callable[[str], List[str]]]] = [
            ('md5', self.extract_md5),
            ('sha1', self.extract_sha1),
            ('sha256', self.extract_sha256),
            ('sha512', self.extract_sha512),
            ('ssdeep', self.extract_ssdeep),
            ('domains', self.extract_domains),
            ('ips', self.extract_ips),
            ('ipv6', self.extract_ipv6),
            ('urls', self.extract_urls),
            ('emails', self.extract_emails),
            ('bitcoin', self.extract_bitcoin),
            ('ethereum', self.extract_ethereum),
            ('monero', self.extract_monero),
            ('cves', self.extract_cves),
            ('mitre_attack', self.extract_mitre_attack),
            ('registry', self.extract_registry),
            ('mutex', self.extract_mutex),
            ('service_names', self.extract_service_names),
            ('named_pipes', self.extract_named_pipes),
            ('filenames', self.extract_filenames),
            ('filepaths', self.extract_filepaths),
            ('mac_addresses', self.extract_mac_addresses),
            ('user_agents', self.extract_user_agents),
            ('yara', self.extract_yara_rules),
            ('asn', self.extract_asn),
            ('jwt', self.extract_jwt),
            ('hosts', self.extract_hosts),
        ]

        # Use tqdm for progress if text is large
        use_progress = len(text) > LARGE_TEXT_THRESHOLD

        extraction_iterable: Iterable[Tuple[str, Callable[[str], List[str]]]]
        if use_progress:
            extraction_iterable = tqdm(
                extraction_methods,
                desc="Extracting IOCs",
                unit="type",
            )
        else:
            extraction_iterable = extraction_methods

        def _extract_single_type(
            ioc_type: str, method: Callable[[str], List[str]], text: str,
        ) -> Optional[List[str]]:
            """Extract a single IOC type, handling errors safely."""
            try:
                results = method(text)
            except Exception as e:
                # Log error but continue with other extractions
                print(f"Error extracting {ioc_type}: {e!s}")
                return None
            else:
                return results if results else None

        for ioc_type, method in extraction_iterable:
            results = _extract_single_type(ioc_type, method, text)
            if results:
                iocs[ioc_type] = results

        return iocs
