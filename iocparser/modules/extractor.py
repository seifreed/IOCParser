#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for extracting indicators of compromise (IOCs) from text

Author: Marc Rivero | @seifreed
"""

import re
import regex
from tqdm import tqdm
import os
import urllib.parse


class IOCExtractor:
    """Class for extracting different types of IOCs from text."""

    def __init__(self, defang=True):
        """
        Initialize the extractor.

        Args:
            defang (bool): If True, performs defanging on the results
        """
        self.defang = defang
        
        # List of valid TLDs
        # Load list of valid TLDs from file or define the most common ones
        self.valid_tlds = self._load_valid_tlds()
        
        # Patrones de expresiones regulares para los diferentes tipos de IOCs
        self.patterns = {
            # MD5 (32 caracteres hexadecimales)
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            
            # SHA1 (40 caracteres hexadecimales)
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            
            # SHA256 (64 caracteres hexadecimales)
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            
            # SHA512 (128 caracteres hexadecimales)
            'sha512': re.compile(r'\b[a-fA-F0-9]{128}\b'),
            
            # Dominios - incluyendo dominios con defang como example[.]com o example(.)com
            'domains': re.compile(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b|\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\(\.\)|\{\.\}|\.)){1,}[a-zA-Z]{2,63})\b'),
            
            # IPs - incluyendo IPs con defang
            'ips': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[\[\(]?\.[\]\)]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            
            # URLs - excluyendo placeholders y requiriendo un dominio válido
            'urls': re.compile(r'\b(?:https?|hxxps?|h\[\.\]ttps?|s?ftp)://(?!DOMAIN_NAME|IP:|\*\.|localhost|example\.)[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?:\.[a-zA-Z]{2,63})(?::[0-9]{1,5})?(?:/[-a-zA-Z0-9()@:%_\+.~#?&/=]*)?'),
            
            # Bitcoin - More specific pattern that requires proper Bitcoin format
            'bitcoin': re.compile(r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'),
            
            # YARA rules
            'yara': re.compile(r'rule\s+\w+\s*({[^}]+})', re.DOTALL),
            
            # Email (patrón solicitado)
            'emails': re.compile(r'\b([a-z][_a-z0-9-.]+@[a-z0-9-]+\.[a-z]+)\b'),
            
            # CVE (patrón solicitado)
            'cves': re.compile(r'\b(CVE\-[0-9]{4}\-[0-9]{4,6})\b'),
            
            # Windows registry records (patrón solicitado)
            'registry': re.compile(r'\b((HKLM|HKCU)\\[\\A-Za-z0-9-_]+)\b'),
            
            # File names - Require at least 3 characters before the extension and avoid standalone extensions
            'filenames': re.compile(r'\b([A-Za-z0-9][A-Za-z0-9-_\.]{2,})\.(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif)\b'),
            
            # File paths (patrón solicitado)
            'filepaths': re.compile(r'\b[A-Z]:\\[A-Za-z0-9-_\.\\]+\b')
        }
        
        # Common file extensions that could be confused with domains
        self.common_file_extensions = {
            'exe', 'dll', 'sys', 'cmd', 'bat', 'ps1', 'vbs', 'js', 'pdf', 'doc', 'docx', 'xls', 
            'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'zip', 'rar', '7z', 
            'gz', 'tar', 'pif', 'scr', 'msi', 'jar', 'py', 'pyc', 'pyo', 'php', 'asp', 'aspx', 
            'jsp', 'htm', 'html', 'css', 'json', 'xml', 'reg', 'ini', 'cfg', 'log', 'tmp', 'dat'
        }
        
        # Common words in malware names that could be confused with domains
        self.malware_keywords = {
            'trojan', 'virus', 'worm', 'backdoor', 'rootkit', 'spyware', 'adware', 'ransomware',
            'malware', 'agent', 'dropper', 'downloader', 'injector', 'stealer', 'keylogger',
            'generic', 'heur', 'suspicious', 'riskware', 'unwanted', 'pup', 'pua', 'hacktool',
            'exploit', 'obfuscated', 'packed', 'crypted', 'banker', 'win32', 'win64', 'msil',
            'android', 'linux', 'macos', 'ios', 'symbian', 'unix'
        }

    def _load_valid_tlds(self):
        """
        Loads the list of valid TLDs.
        
        Returns:
            set: Set of valid TLDs
        """
        # List of most common TLDs
        common_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro',
            'museum', 'aero', 'coop', 'jobs', 'travel', 'mobi', 'asia', 'tel', 'xxx', 'post',
            'cat', 'arpa', 'top', 'xyz', 'club', 'online', 'site', 'shop', 'app', 'blog',
            'dev', 'art', 'web', 'cloud', 'page', 'store', 'host', 'tech', 'space', 'live',
            'news', 'io', 'co', 'me', 'tv', 'us', 'uk', 'ru', 'fr', 'de', 'jp', 'cn', 'au',
            'ca', 'in', 'it', 'nl', 'se', 'no', 'fi', 'dk', 'ch', 'at', 'be', 'es', 'pt',
            'br', 'mx', 'ar', 'cl', 'pe', 'co', 've', 'za', 'pl', 'cz', 'gr', 'hu', 'ro',
            'ua', 'by', 'kz', 'th', 'sg', 'my', 'ph', 'vn', 'id', 'tr', 'il', 'ae', 'sa',
            'ir', 'pk', 'eg', 'ng', 'kr', 'tw', 'hk', 'mo', 'eu', 'asia', 'nz'
        }
        
        # Try to load a more complete list if the file exists
        tlds_file = os.path.join(os.path.dirname(__file__), 'data', 'tlds.txt')
        
        if os.path.isfile(tlds_file):
            try:
                with open(tlds_file, 'r', encoding='utf-8') as f:
                    return {line.strip().lower() for line in f if line.strip()}
            except Exception:
                pass
        
        return common_tlds

    def extract_md5(self, text):
        """Extracts MD5 hashes from the text."""
        candidates = self._extract_pattern(text, 'md5')
        valid_hashes = []
        
        for candidate in candidates:
            # Detectar patrones anómalos en los hashes
            if not self._is_valid_hash_pattern(candidate):
                continue
                
            valid_hashes.append(candidate)
            
        return valid_hashes

    def extract_sha1(self, text):
        """Extracts SHA1 hashes from the text."""
        candidates = self._extract_pattern(text, 'sha1')
        valid_hashes = []
        
        for candidate in candidates:
            # Detectar patrones anómalos en los hashes
            if not self._is_valid_hash_pattern(candidate):
                continue
                
            valid_hashes.append(candidate)
            
        return valid_hashes

    def extract_sha256(self, text):
        """Extracts SHA256 hashes from the text."""
        candidates = self._extract_pattern(text, 'sha256')
        valid_hashes = []
        
        for candidate in candidates:
            # Detectar patrones anómalos en los hashes
            if not self._is_valid_hash_pattern(candidate):
                continue
                
            valid_hashes.append(candidate)
            
        return valid_hashes

    def extract_sha512(self, text):
        """Extracts SHA512 hashes from the text."""
        return self._extract_pattern(text, 'sha512')
    
    def extract_domains(self, text):
        """Extracts domains from the text."""
        domains = self._extract_pattern(text, 'domains')
        
        # También extraer dominios de URLs (incluidas las defanged)
        domains_from_urls = self._extract_domains_from_urls(text)
        
        # Combinar dominios directos y dominios extraídos de URLs
        all_domains = domains + domains_from_urls
        
        # Limpiar dominios extraídos (quitar defang si está presente)
        clean_domains = []
        for domain in all_domains:
            # If it's a tuple (from regex groups), take the first non-empty element
            if isinstance(domain, tuple):
                domain = next((d for d in domain if d), '')
                
            # Limpiar defanging existente
            domain = domain.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
            
            # Validar que es un dominio real y no un archivo o nombre de malware
            if self._is_valid_domain(domain):
                # Añadir defanging si está activado
                if self.defang:
                    domain = self._defang_domain(domain)
                    
                if domain:
                    clean_domains.append(domain)
                
        return list(set(clean_domains))

    def _extract_domains_from_urls(self, text):
        """
        Extrae dominios de URLs encontradas en el texto.
        
        Args:
            text (str): El texto de donde extraer las URLs
            
        Returns:
            list: Lista de dominios extraídos de URLs
        """
        # Primero, buscar patrones de URLs defanged más comunes directamente
        hxxp_pattern = re.compile(r'hxxps?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9\-]+)+\.\w+)')
        domains_from_hxxp = []
        
        for match in hxxp_pattern.finditer(text):
            domain = match.group(1)
            if domain:
                # Limpiar formato defanged
                domain = domain.replace('[.]', '.')
                domains_from_hxxp.append(domain)
        
        # Buscar también en las URLs generales
        urls = self._extract_pattern(text, 'urls')
        domains = []
        
        for url in urls:
            # Normalizar la URL primero
            normalized_url = url.lower()
            
            # Limpiar formato defanged
            normalized_url = normalized_url.replace('hxxp://', 'http://')
            normalized_url = normalized_url.replace('hxxps://', 'https://')
            normalized_url = normalized_url.replace('h[.]xxp://', 'http://')
            normalized_url = normalized_url.replace('h[.]xxps://', 'https://')
            
            # Handle square brackets in domain part (common in defanged URLs)
            domain_part_pattern = re.compile(r'https?://([^/]+)')
            domain_match = domain_part_pattern.search(normalized_url)
            
            if domain_match:
                domain = domain_match.group(1)
                domain = domain.replace('[.]', '.')
                domain = domain.replace('(.)', '.')
                domain = domain.replace('{.}', '.')
                domains.append(domain)
            else:
                # Si no podemos extraer el dominio con regex, intentamos con urlparse
                try:
                    # Reemplazar todos los caracteres de defanging antes de parsear
                    clean_url = normalized_url.replace('[.]', '.')
                    clean_url = clean_url.replace('(.)', '.')
                    clean_url = clean_url.replace('{.}', '.')
                    
                    # Si la URL empieza con un protocolo, parsearla
                    if clean_url.startswith(('http://', 'https://')):
                        parsed_url = urllib.parse.urlparse(clean_url)
                        if parsed_url.netloc:
                            domains.append(parsed_url.netloc)
                except Exception:
                    # Si hay un error al parsear, ignorar esta URL
                    continue
        
        # Combinar resultados y validar
        all_domains = domains_from_hxxp + domains
        
        # Verify duplicates
        return list(set(all_domains))

    def _is_valid_domain(self, domain):
        """
        Valida si una cadena es un dominio válido.
        
        Args:
            domain (str): El dominio a validar
            
        Returns:
            bool: True si es un dominio válido, False en caso contrario
        """
        # Split the domain into parts
        parts = domain.lower().split('.')
        
        # Check if it has at least two parts and a valid TLD
        if len(parts) < 2:
            return False
        
        # Get the extension (TLD)
        tld = parts[-1]
        
        # Check if it's a valid TLD
        if tld not in self.valid_tlds:
            return False
        
        # Check if it looks like a filename
        if len(parts) == 2 and parts[0] == 'a' and tld in self.common_file_extensions:
            return False  # Common pattern like "a.exe" or similar
            
        # Check if it's a common file extension
        if tld in self.common_file_extensions:
            return False
            
        # Check if it looks like a malware name
        domain_lower = domain.lower()
        if any(keyword in domain_lower for keyword in self.malware_keywords):
            # Check if it has a format like "Trojan.Win32.Agent"
            if re.match(r'([a-zA-Z]+\.){2,}[a-zA-Z]+', domain_lower):
                return False
                
        # Also check the full domain
        if domain.count('.') >= 1:
            # Check if it's a product name with version (example: kernel32.dll)
            if re.match(r'[a-zA-Z0-9]+[0-9]+\.[a-zA-Z]+', domain):
                return False
                
        # Si pasa todas las comprobaciones, es un dominio válido
        return True

    def extract_ips(self, text):
        """Extracts IP addresses from the text."""
        ips = self._extract_pattern(text, 'ips')
        
        # Limpiar IPs extraídas (quitar defang si está presente)
        clean_ips = []
        for ip in ips:
            # Limpiar defanging existente
            ip = ip.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
            
            # Añadir defanging si está activado
            if self.defang:
                ip = self._defang_ip(ip)
                
            clean_ips.append(ip)
                
        return list(set(clean_ips))

    def extract_urls(self, text):
        """
        Extract URLs from text and filter out invalid URLs.
        
        Args:
            text (str): The text to extract URLs from
            
        Returns:
            list: List of extracted URLs
        """
        # Extract URLs using the pattern
        urls = self._extract_pattern(text, 'urls')
        
        # Filter out invalid or placeholder URLs
        filtered_urls = []
        for url in urls:
            # Skip obvious placeholders and invalid URLs
            if re.search(r'DOMAIN_NAME|example\.com|localhost|IP:|127\.0\.0\.1|\*\.', url, re.IGNORECASE):
                continue
                
            # Skip URLs que no tienen al menos un punto en el dominio
            if not re.search(r'://[^/]+\.[^/]+', url):
                continue
                
            # Add the URL to the filtered list
            filtered_urls.append(url)
        
        # If defanging is enabled, defang the URLs
        if self.defang:
            filtered_urls = [self._defang_url(url) for url in filtered_urls]
        
        return filtered_urls

    def extract_bitcoin(self, text):
        """Extracts Bitcoin addresses from the text."""
        potential_addresses = self._extract_pattern(text, 'bitcoin')
        
        # Additional validation to filter out MD5 hashes and other false positives
        valid_addresses = []
        for addr in potential_addresses:
            # Skip if it's a known hash pattern (all lowercase hex)
            if re.match(r'^[0-9a-f]{32}$', addr):  # MD5 hash pattern
                continue
            if re.match(r'^[0-9a-f]{40}$', addr):  # SHA1 hash pattern
                continue
            if re.match(r'^[0-9a-f]{64}$', addr):  # SHA256 hash pattern
                continue
            
            # Add only if it's a valid Bitcoin address format
            # Real Bitcoin addresses have specific characteristics
            if (addr.startswith('1') and len(addr) >= 26 and len(addr) <= 34) or \
               (addr.startswith('3') and len(addr) >= 26 and len(addr) <= 34) or \
               (addr.startswith('bc1') and len(addr) >= 42 and len(addr) <= 62):
                valid_addresses.append(addr)
        
        return valid_addresses

    def extract_yara_rules(self, text):
        """Extracts Yara rules from the text."""
        return self._extract_pattern(text, 'yara')

    def extract_hosts(self, text):
        """Extracts hosts from the text."""
        extracted_hosts = self._extract_pattern(text, 'hosts')
        
        # Filtrar hosts válidos
        filtered_hosts = []
        for host in extracted_hosts:
            # Convertir defanged host a formato normal para validación
            clean_host = host.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
            if self._is_valid_domain(clean_host):
                if self.defang:
                    filtered_hosts.append(self._defang_domain(host))
                else:
                    filtered_hosts.append(host)
        
        return filtered_hosts
    
    def extract_emails(self, text):
        """Extracts email addresses from the text."""
        emails = self._extract_pattern(text, 'emails')
        
        filtered_emails = []
        for email in emails:
            # Verify that the email domain is valid
            domain = email.split('@')[1]
            
            # Skip emails from known security vendors
            known_security_vendors = [
                "kaspersky.com", "microsoft.com", "symantec.com", "mcafee.com",
                "trendmicro.com", "fireeye.com", "crowdstrike.com", "sophos.com",
                "eset.com", "avast.com", "bitdefender.com", "paloaltonetworks.com",
                "checkpoint.com", "fortinet.com", "virustotal.com", "abuse.ch"
            ]
            
            if any(domain.endswith(vendor) for vendor in known_security_vendors):
                continue
            
            if self._is_valid_domain(domain):
                if self.defang:
                    # Defang the email by replacing @ with [at] and . with [.]
                    defanged_email = email.replace('@', '[at]').replace('.', '[.]')
                    filtered_emails.append(defanged_email)
                else:
                    filtered_emails.append(email)
        
        return filtered_emails
    
    def extract_cves(self, text):
        """Extracts CVE identifiers from the text."""
        return self._extract_pattern(text, 'cves')
    
    def extract_registry(self, text):
        """Extracts Windows registry paths from the text."""
        return self._extract_pattern(text, 'registry')
    
    def extract_filenames(self, text):
        """Extracts suspicious filenames from the text."""
        filenames = self._extract_pattern(text, 'filenames')
        
        # Filter out standalone extensions and very short filenames
        filtered_filenames = []
        standalone_extensions = ['exe', 'dll', 'bat', 'sys', 'htm', 'html', 'js', 'jar', 
                               'jpg', 'png', 'vb', 'scr', 'pif', 'chm', 'zip', 'rar', 
                               'cab', 'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 
                               'swf', 'gif']
        
        for filename in filenames:
            # Skip if the filename is just a standalone extension
            if filename.lower() in standalone_extensions:
                continue
            
            # Skip if the filename is too short (less than 5 characters)
            if len(filename) < 5:
                continue
            
            # Skip if it's just one character plus extension (like a.exe)
            name_parts = filename.split('.')
            if len(name_parts) > 1 and len(name_parts[0]) < 3:
                continue
            
            filtered_filenames.append(filename)
        
        return filtered_filenames
    
    def extract_filepaths(self, text):
        """Extracts file paths from the text."""
        return self._extract_pattern(text, 'filepaths')

    def extract_all(self, text):
        """
        Extracts all types of IOCs from the text.
        
        Args:
            text (str): The text to search for IOCs
            
        Returns:
            dict: Dictionary with extracted IOCs, grouped by type
        """
        print("Extracting indicators of compromise...")
        
        # Preliminary processing to detect possible Yara rules and store them separately
        yara_text = text  # Save original text for extracting Yara rules
        
        # Special extraction of domains directly from defanged URLs
        defanged_domains = self._extract_defanged_domains_direct(text)
        
        # Create a dictionary to store results by type
        iocs = {
            'hashes': [],
            'domains': [],
            'ips': [],
            'urls': [],
            'bitcoin': [],
            'yara': [],
            'emails': [],
            'hosts': [],
            'cves': [],
            'registry': [],
            'filenames': [],
            'filepaths': []
        }
        
        # Extract hashes (MD5, SHA1, SHA256, SHA512)
        md5s = self.extract_md5(text)
        sha1s = self.extract_sha1(text)
        sha256s = self.extract_sha256(text)
        sha512s = self.extract_sha512(text)
        
        # To avoid duplicates, example: a SHA256 that also matches MD5
        # We add the hashes in reverse order of length
        all_hashes = []
        
        # Add SHA512
        for hash_value in sha512s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'sha512', 'value': hash_value})
        
        # Add SHA256
        for hash_value in sha256s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'sha256', 'value': hash_value})
        
        # Add SHA1
        for hash_value in sha1s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'sha1', 'value': hash_value})
        
        # Add MD5
        for hash_value in md5s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'md5', 'value': hash_value})
        
        # Extract other types of IOCs
        domain_list = self.extract_domains(text)
        # Add defanged domains extracted directly
        for domain in defanged_domains:
            if domain not in domain_list:
                domain_list.append(domain)
        iocs['domains'] = domain_list
        
        iocs['ips'] = self.extract_ips(text)
        iocs['urls'] = self.extract_urls(text)
        iocs['bitcoin'] = self.extract_bitcoin(text)
        iocs['yara'] = self.extract_yara_rules(yara_text)
        
        # Add the new types of IOCs - but filter hosts to avoid duplicating domains
        iocs['emails'] = self.extract_emails(text)
        
        # Extract hosts but exclude those already in domains
        hosts = self.extract_hosts(text)
        iocs['hosts'] = [h for h in hosts if h not in domain_list]
        
        iocs['cves'] = self.extract_cves(text)
        iocs['registry'] = self.extract_registry(text)
        iocs['filenames'] = self.extract_filenames(text)
        iocs['filepaths'] = self.extract_filepaths(text)
        
        # Remove empty sections
        iocs = {k: v for k, v in iocs.items() if v}
        
        return iocs

    def _extract_defanged_domains_direct(self, text):
        """
        Extracts domains directly from defanged URLs in the text.
        This method is designed to capture specific cases not handled by
        other extractors, such as hxxps://domain[.]tld
        
        Args:
            text (str): The text to search in
            
        Returns:
            list: List of found domains (with defang if activated)
        """
        # Patterns for common defanged URLs
        patterns = [
            # Pattern for hxxps://domain[.]tld/path
            re.compile(r'hxxps?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9\-]+)+?(?:\[\.\][a-zA-Z]{2,63}))', re.IGNORECASE),
            # Pattern for https://domain[.]tld/path
            re.compile(r'https?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9\-]+)+?(?:\[\.\][a-zA-Z]{2,63}))', re.IGNORECASE),
            # Specific pattern for cases like hxxps://testdomain123123[.]shop/
            re.compile(r'hxxps?://([a-zA-Z0-9][a-zA-Z0-9\-]*\d*)(?:\[\.\])([a-zA-Z]{2,63})', re.IGNORECASE)
        ]
        
        domains = []
        
        for pattern in patterns:
            for match in pattern.finditer(text):
                if len(match.groups()) == 1:
                    # For the first two patterns
                    domain = match.group(1)
                    if domain:
                        clean_domain = domain.replace('[.]', '.')
                        if self._is_valid_domain(clean_domain):
                            if self.defang:
                                domains.append(self._defang_domain(clean_domain))
                            else:
                                domains.append(clean_domain)
                elif len(match.groups()) == 2:
                    # For the third pattern
                    domain = match.group(1) + '.' + match.group(2)
                    if domain and self._is_valid_domain(domain):
                        if self.defang:
                            domains.append(self._defang_domain(domain))
                        else:
                            domains.append(domain)
                
        return list(set(domains))

    def _extract_pattern(self, text, pattern_name):
        """
        Extracts patterns using a specific regex.
        
        Args:
            text (str): The text from which to extract patterns
            pattern_name (str): The name of the pattern to extract
            
        Returns:
            list: List of unique matches
        """
        if pattern_name not in self.patterns:
            return []
            
        matches = self.patterns[pattern_name].findall(text)
        
        # If results are tuples (from regex groups), flatten them
        if matches and isinstance(matches[0], tuple):
            # If it's a pattern like 'domains' that has alternative groups
            if pattern_name == 'domains':
                return matches
            
            # For other patterns with groups, take all non-empty elements
            flat_matches = []
            for match in matches:
                flat_matches.extend([m for m in match if m])
            matches = flat_matches
            
        return list(set(matches))

    def _defang_domain(self, domain):
        """
        Performs defanging on a domain.
        
        Args:
            domain (str): The original domain
            
        Returns:
            str: The domain with defanging applied
        """
        return domain.replace('.', '[.]')

    def _defang_ip(self, ip):
        """
        Performs defanging on an IP address.
        
        Args:
            ip (str): The original IP address
            
        Returns:
            str: The IP address with defanging applied
        """
        return ip.replace('.', '[.]')

    def _defang_url(self, url):
        """
        Performs defanging on a URL.
        
        Args:
            url (str): The original URL
            
        Returns:
            str: The URL with defanging applied
        """
        defanged = url
        defanged = defanged.replace('http://', 'hxxp://')
        defanged = defanged.replace('https://', 'hxxps://')
        defanged = defanged.replace('.', '[.]')
        return defanged 

    def _is_valid_hash_pattern(self, hash_str):
        """
        Comprueba si un hash tiene un patrón de distribución normal.
        
        Args:
            hash_str (str): El hash a comprobar
        
        Returns:
            bool: True si el hash parece válido, False si tiene patrones anómalos
        """
        # Longitud del hash
        hash_len = len(hash_str)
        
        # 1. Comprobar si hay demasiados ceros (más de la mitad)
        if hash_str.count('0') > hash_len / 2:
            return False
            
        # 2. Comprobar si hay demasiados caracteres repetidos consecutivos
        # (más de 1/4 de la longitud del hash)
        if re.search(r'(.)\1{' + str(int(hash_len / 4)) + r',}', hash_str):
            return False
            
        # 3. Comprobar patrones de repetición
        # (secuencias repetidas de longitud mayor a 1/8 del hash)
        seq_len = max(2, int(hash_len / 8))
        for i in range(len(hash_str) - seq_len + 1):
            seq = hash_str[i:i+seq_len]
            # Si la secuencia aparece más de 2 veces, considerar anómalo
            if hash_str.count(seq) > 2:
                return False
        
        # 4. Verificar la distribución de caracteres
        # Un hash criptográfico debería tener una distribución relativamente uniforme
        char_counts = {}
        for char in hash_str:
            if char in char_counts:
                char_counts[char] += 1
            else:
                char_counts[char] = 1
                
        # Si algún carácter aparece mucho más que otros (más del 20% del total),
        # considerar el hash como potencialmente inválido
        max_count = max(char_counts.values())
        if max_count > hash_len * 0.2:
            return False
        
        return True 