#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for managing MISP warning lists to detect false positives

Author: Marc Rivero | @seifreed
"""

import os
import json
import re
import requests
import time
from urllib.parse import urlparse
from colorama import Fore, Style
from tqdm import tqdm


class MISPWarningLists:
    """Class for managing MISP warning lists to detect false positives"""
    
    def __init__(self, cache_duration=24, force_update=False):
        """
        Initialize the warning lists manager.
        
        Args:
            cache_duration (int): Duration in hours to keep the local cache before updating
            force_update (bool): If True, force update regardless of cache age
        """
        self.cache_duration = cache_duration  # hours
        self.force_update = force_update
        self.warning_lists = {}
        self.data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'data')
        self.cache_file = os.path.join(self.data_dir, 'misp_warninglists_cache.json')
        self.cache_metadata_file = os.path.join(self.data_dir, 'misp_warninglists_metadata.json')
        self.github_api_base = "https://api.github.com/repos/MISP/misp-warninglists/contents/lists"
        self.github_raw_base = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"
        
        # Create the data directory if it doesn't exist
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        
        # Load or update the lists
        self._load_or_update_lists()
    
    def _load_or_update_lists(self):
        """Load lists from cache or update them if necessary"""
        # Check if cache exists and its age
        if not self.force_update and self.cache_duration > 0 and os.path.exists(self.cache_file) and os.path.exists(self.cache_metadata_file):
            try:
                with open(self.cache_metadata_file, 'r') as f:
                    metadata = json.load(f)
                last_update = metadata.get('last_update', 0)
                current_time = time.time()
                
                # Check if the cache is up to date
                if current_time - last_update < self.cache_duration * 3600:
                    print(f"{Fore.BLUE}[*] Loading MISP warning lists from local cache...{Style.RESET_ALL}")
                    with open(self.cache_file, 'r') as f:
                        self.warning_lists = json.load(f)
                    print(f"{Fore.GREEN}[+] Loaded {len(self.warning_lists)} MISP warning lists from cache{Style.RESET_ALL}")
                    return
            except Exception:
                pass
        
        # If we get here, we need to update the lists
        self._update_warning_lists()
    
    def _update_warning_lists(self):
        """Update warning lists from the MISP GitHub repository"""
        try:
            print(f"{Fore.YELLOW}[!] Updating MISP warning lists from GitHub repository...{Style.RESET_ALL}")
            
            response = requests.get(self.github_api_base)
            response.raise_for_status()
            directories = response.json()
            
            # Get list of directories
            list_directories = []
            for item in directories:
                if item['type'] == 'dir':
                    list_directories.append(item['name'])
            
            # Process each directory to get the warning list
            print(f"{Fore.BLUE}[*] Downloading {len(list_directories)} MISP warning lists...{Style.RESET_ALL}")
            
            for directory in tqdm(list_directories, desc="Downloading warning lists", unit="list"):
                try:
                    list_url = f"{self.github_raw_base}/{directory}/list.json"
                    list_response = requests.get(list_url)
                    list_response.raise_for_status()
                    warning_list = list_response.json()
                    
                    # Save the list in the dictionary
                    self.warning_lists[directory] = warning_list
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Error downloading warning list {directory}: {str(e)}{Style.RESET_ALL}")
            
            # Save lists to cache
            with open(self.cache_file, 'w') as f:
                json.dump(self.warning_lists, f)
            
            # Save cache metadata
            with open(self.cache_metadata_file, 'w') as f:
                json.dump({'last_update': time.time()}, f)
            
            print(f"{Fore.GREEN}[+] Successfully updated {len(self.warning_lists)} MISP warning lists{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not update warning lists: {str(e)}{Style.RESET_ALL}")
            
            # If a cache is available, try to use it despite the error
            if os.path.exists(self.cache_file):
                try:
                    with open(self.cache_file, 'r') as f:
                        self.warning_lists = json.load(f)
                    print(f"{Fore.YELLOW}[!] Using cached warning lists{Style.RESET_ALL}")
                except Exception:
                    print(f"{Fore.RED}[ERROR] Could not load warning lists from cache{Style.RESET_ALL}")
    
    def check_value(self, value, ioc_type):
        """
        Check if a value is on any warning list.
        
        Args:
            value (str): The value to check
            ioc_type (str): The type of IOC (ip, domain, url, etc.)
            
        Returns:
            dict: Warning information if the value is on a warning list, otherwise None
        """
        # Map IOC type to MISP attribute types
        misp_types = []
        
        if ioc_type == 'domains':
            misp_types = ['hostname', 'domain', 'domain|ip']
        elif ioc_type == 'ips':
            # For IPs, search all possible attribute types
            misp_types = ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'domain|ip', 'ip', 'ip-range']
        elif ioc_type == 'urls':
            misp_types = ['url', 'uri', 'link']
        elif ioc_type == 'hashes':
            misp_types = ['md5', 'sha1', 'sha256', 'filename|md5', 'filename|sha1', 'filename|sha256', 'hash']
        elif ioc_type == 'emails':
            misp_types = ['email', 'email-src', 'email-dst', 'target-email']
        elif ioc_type == 'bitcoin':
            misp_types = ['btc', 'bitcoin', 'cryptocurrency']
        else:
            # For other types, use a more generic approach
            misp_types = [ioc_type, 'other']
        
        # Clean value for checking (remove defang markers)
        clean_value = value.replace('[.]', '.').replace('(.)','').replace('{.}','').replace('[:]', ':')
        
        # Special handling for URLs - extract domain for checking
        extracted_domain = None
        if ioc_type == 'urls':
            # Extract domain from URL for better matching against domain lists
            url_value = clean_value.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
            domain_match = re.search(r'https?://([^:/]+)', url_value)
            if domain_match:
                extracted_domain = domain_match.group(1)
        
        # Verificar cada lista de MISP
        for list_id, warning_list in self.warning_lists.items():
            # Skip lists that don't have matching attributes
            if 'matching_attributes' not in warning_list or not warning_list['matching_attributes']:
                continue
            
            # Check if any attribute type matches
            has_matching_type = False
            
            # To be more flexible, check if any type matches partially
            for misp_type in misp_types:
                for warning_attr in warning_list['matching_attributes']:
                    if misp_type in warning_attr or warning_attr in misp_type:
                        has_matching_type = True
                        break
                if has_matching_type:
                    break
            
            if not has_matching_type:
                # If there's no type match, it could be a "cidr" type list
                # which is normally used for IPs
                if ioc_type == 'ips' and warning_list.get('type') == 'cidr':
                    has_matching_type = True
            
            if not has_matching_type:
                continue
            
            name = warning_list.get('name', list_id)
            description = warning_list.get('description', '')
            
            # Check if the list is of type string, substring, regex or cidr
            list_type = warning_list.get('type', 'string')
            values = warning_list.get('list', [])
            
            # Check with original value
            if self._check_value_in_list(clean_value, values, list_type):
                return True, {
                    'name': name,
                    'description': description
                }
            
            # Also check the extracted domain for URLs
            if extracted_domain and self._check_value_in_list(extracted_domain, values, list_type):
                return True, {
                    'name': name,
                    'description': description
                }
        
        return False, None
    
    def _check_value_in_list(self, value, values, list_type):
        """
        Check if a value is in a warning list.
        
        Args:
            value (str): The value to check
            values (list): The list of values to check against
            list_type (str): The type of comparison to perform (string, substring, regex, cidr)
            
        Returns:
            bool: True if the value is in the list, False otherwise
        """
        if list_type == 'string':
            # Direct string comparison (case-insensitive)
            return value.lower() in [v.lower() for v in values if isinstance(v, str)]
        
        elif list_type == 'substring':
            # Check if any value in the list is a substring of the value
            for list_value in values:
                if isinstance(list_value, str) and list_value.lower() in value.lower():
                    return True
            # Also check if the value is a substring of any value in the list
            # (some lists may store complete IP ranges)
            for list_value in values:
                if isinstance(list_value, str) and value.lower() in list_value.lower():
                    return True
            return False
        
        elif list_type == 'regex':
            # Check if any regex in the list matches the value
            for regex_pattern in values:
                try:
                    if isinstance(regex_pattern, str) and re.search(regex_pattern, value, re.IGNORECASE):
                        return True
                except Exception:
                    # Skip invalid regex patterns
                    continue
            return False
            
        elif list_type == 'cidr':
            # For CIDR types, check if the IP is in any of the ranges
            try:
                # For this type we would need the ipaddress library to verify IP ranges
                # as an alternative, we can check if the IP matches exactly with any IP
                # in the list or with any range prefix
                ip_parts = value.split('.')
                if len(ip_parts) != 4:  # Not a valid IPv4
                    return False
                    
                # Check exact match first
                if value in values:
                    return True
                
                # Check prefix match
                for list_value in values:
                    if isinstance(list_value, str):
                        # Check if it's a CIDR range (e.g., "8.8.8.0/24")
                        if '/' in list_value:
                            cidr_ip, cidr_prefix = list_value.split('/')
                            cidr_parts = cidr_ip.split('.')
                            
                            # Only handle IPv4 for now
                            if len(cidr_parts) != 4:
                                continue
                                
                            # Check prefix
                            prefix_len = int(cidr_prefix)
                            full_bytes = prefix_len // 8
                            
                            # Check full bytes
                            match = True
                            for i in range(full_bytes):
                                if i >= len(ip_parts) or i >= len(cidr_parts):
                                    match = False
                                    break
                                if ip_parts[i] != cidr_parts[i]:
                                    match = False
                                    break
                            
                            # If all full bytes match, it's a match
                            if match and full_bytes > 0:
                                return True
                        # Also check exact match
                        elif value == list_value:
                            return True
            except Exception:
                # If there's any error, ignore
                pass
                
            return False
        
        return False
    
    def get_warnings_for_iocs(self, iocs):
        """
        Check all IOCs against warning lists and return warnings for any matches.
        
        Args:
            iocs (dict): Dictionary with IOCs grouped by type
            
        Returns:
            dict: Dictionary with warnings grouped by IOC type
        """
        warnings = {}
        
        for ioc_type, ioc_list in iocs.items():
            type_warnings = []
            
            for ioc in ioc_list:
                # If the IOC is a dictionary (like with hashes), use the 'value' key
                if isinstance(ioc, dict) and 'value' in ioc:
                    value = ioc['value']
                else:
                    value = ioc
                
                # Eliminar los corchetes agregados durante el defanging para la verificación
                clean_value = value.replace('[.]', '.').replace('[:]', ':')
                
                in_warning_list, warning_list = self.check_value(clean_value, ioc_type)
                if in_warning_list:
                    type_warnings.append({
                        'value': value,
                        'warning_list': warning_list['name'],
                        'description': warning_list['description']
                    })
            
            if type_warnings:
                warnings[ioc_type] = type_warnings
        
        return warnings
    
    def separate_iocs_by_warnings(self, iocs):
        """
        Separate IOCs into normal IOCs and warning list IOCs.
        
        Args:
            iocs (dict): Dictionary with IOCs grouped by type
            
        Returns:
            tuple: (normal_iocs, warning_iocs) dictionaries
        """
        print(f"{Fore.BLUE}[*] Checking IOCs against MISP Warning Lists...{Style.RESET_ALL}")
        
        normal_iocs = {k: [] for k in iocs.keys()}
        warning_iocs = {k: [] for k in iocs.keys()}
        
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                # If the IOC is a dictionary (like with hashes), use the 'value' key
                if isinstance(ioc, dict) and 'value' in ioc:
                    value = ioc['value']
                    clean_value = value.replace('[.]', '.').replace('[:]', ':')
                    in_warning_list, warning_info = self.check_value(clean_value, ioc_type)
                    
                    if in_warning_list:
                        warning_iocs[ioc_type].append({
                            'value': ioc['value'],
                            'type': ioc['type'] if 'type' in ioc else None,
                            'warning_list': warning_info['name'],
                            'description': warning_info['description']
                        })
                    else:
                        normal_iocs[ioc_type].append(ioc)
                else:
                    # For simple string IOCs
                    clean_value = ioc.replace('[.]', '.').replace('[:]', ':')
                    in_warning_list, warning_info = self.check_value(clean_value, ioc_type)
                    
                    if in_warning_list:
                        warning_iocs[ioc_type].append({
                            'value': ioc,
                            'warning_list': warning_info['name'],
                            'description': warning_info['description']
                        })
                    else:
                        normal_iocs[ioc_type].append(ioc)
        
        # Remove empty categories
        normal_iocs = {k: v for k, v in normal_iocs.items() if v}
        warning_iocs = {k: v for k, v in warning_iocs.items() if v}
        
        print(f"{Fore.GREEN}[+] IOCs verification against MISP Warning Lists completed{Style.RESET_ALL}")
        
        return normal_iocs, warning_iocs

    def _diagnose_dns_ip_detection(self, ip_address):
        """
        Diagnostic to understand why a public DNS IP is not detected in MISP lists.
        
        Args:
            ip_address (str): The IP address to diagnose
        """
        print(f"{Fore.YELLOW}[!] Diagnostic: Checking why {ip_address} is not detected as a public DNS in MISP lists{Style.RESET_ALL}")
        
        # Look for lists that might contain the IP
        dns_lists = []
        public_ip_lists = []
        
        for list_id, warning_list in self.warning_lists.items():
            # Search for lists related to DNS or public IPs
            name = warning_list.get('name', '').lower()
            description = warning_list.get('description', '').lower()
            
            if 'dns' in name or 'dns' in description:
                dns_lists.append((list_id, warning_list))
                
            if ('public' in name and 'ip' in name) or ('well-known' in name and 'ip' in name):
                public_ip_lists.append((list_id, warning_list))
        
        print(f"{Fore.BLUE}[*] DNS-related lists found: {len(dns_lists)}{Style.RESET_ALL}")
        for list_id, warning_list in dns_lists:
            list_type = warning_list.get('type', 'string')
            values = warning_list.get('list', [])
            
            # Check if the IP is in the list
            if self._check_value_in_list(ip_address, values, list_type):
                print(f"{Fore.GREEN}[+] The IP {ip_address} is in the list {list_id} ({warning_list.get('name', '')}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] The IP {ip_address} is NOT in the list {list_id} ({warning_list.get('name', '')}){Style.RESET_ALL}")
                
                # If the list contains values, show some examples
                if values and len(values) > 0:
                    print(f"{Fore.BLUE}[*] Examples of values in this list: {values[:3]}{Style.RESET_ALL}")
        
        print(f"{Fore.BLUE}[*] Public IP-related lists found: {len(public_ip_lists)}{Style.RESET_ALL}")
        for list_id, warning_list in public_ip_lists:
            list_type = warning_list.get('type', 'string')
            values = warning_list.get('list', [])
            
            # Check if the IP is in the list
            if self._check_value_in_list(ip_address, values, list_type):
                print(f"{Fore.GREEN}[+] The IP {ip_address} is in the list {list_id} ({warning_list.get('name', '')}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] The IP {ip_address} is NOT in the list {list_id} ({warning_list.get('name', '')}){Style.RESET_ALL}")
                
                # If the list contains values, show some examples
                if values and len(values) > 0:
                    print(f"{Fore.BLUE}[*] Examples of values in this list: {values[:3]}{Style.RESET_ALL}")
        
        # If no lists were found, alert
        if not dns_lists and not public_ip_lists:
            print(f"{Fore.RED}[ERROR] No DNS or public IP-related lists found in MISP lists{Style.RESET_ALL}")
            print(f"{Fore.RED}[ERROR] It's possible that MISP lists were not downloaded correctly{Style.RESET_ALL}") 