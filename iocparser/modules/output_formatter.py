#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for formatting IOCs output in different formats

Author: Marc Rivero | @seifreed
"""

import json
import os
from abc import ABC, abstractmethod


class OutputFormatter(ABC):
    """Abstract base class for all output formatters."""
    
    def __init__(self, data, warning_iocs=None):
        """
        Initialize the output formatter.
        
        Args:
            data (dict): Data to format
            warning_iocs (dict, optional): IOCs found in warning lists
        """
        self.data = data
        self.warning_iocs = warning_iocs or {}
    
    @abstractmethod
    def format(self):
        """
        Format the data.
        
        Returns:
            str: The formatted data
        """
        pass
    
    @abstractmethod
    def save(self, output_file):
        """
        Save the formatted data to a file.
        
        Args:
            output_file (str): Path to the output file
        """
        pass


class JSONFormatter(OutputFormatter):
    """Class for formatting output in JSON."""
    
    def format(self):
        """
        Format the data in JSON.
        
        Returns:
            str: The data formatted in JSON
        """
        # For hashes, maintain the original structure
        data_copy = self.data.copy()
        
        # Add warning_iocs if available
        if self.warning_iocs:
            data_copy['warning_list_matches'] = self.warning_iocs
        
        # For other types, sort the lists for consistency
        for key in data_copy:
            if key != 'hashes' and key != 'warning_list_matches' and isinstance(data_copy[key], list):
                data_copy[key] = sorted(data_copy[key])
        
        # Sort dictionary keys for consistency
        return json.dumps(data_copy, indent=4, sort_keys=True)
    
    def save(self, output_file):
        """
        Save the formatted data to a JSON file.
        
        Args:
            output_file (str): Path to the output file
        """
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        # For hashes, maintain the original structure
        data_copy = self.data.copy()
        
        # Add warning_iocs if available
        if self.warning_iocs:
            data_copy['warning_list_matches'] = self.warning_iocs
        
        # For other types, sort the lists for consistency
        for key in data_copy:
            if key != 'hashes' and key != 'warning_list_matches' and isinstance(data_copy[key], list):
                data_copy[key] = sorted(data_copy[key])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data_copy, f, indent=4, ensure_ascii=False, sort_keys=True)


class TextFormatter(OutputFormatter):
    """Class for formatting output in plain text."""
    
    def format(self):
        """
        Format the data in plain text.
        
        Returns:
            str: The data formatted in plain text
        """
        output = ["# Indicators of Compromise (IOCs) Extracted\n"]
        
        # Sort sections in a more logical order
        section_order = [
            ('hashes', 'Hashes'),
            ('domains', 'Domains'),
            ('ips', 'IP Addresses'),
            ('urls', 'URLs'),
            ('emails', 'Email Addresses'),
            ('hosts', 'Hosts'),
            ('cves', 'Vulnerabilities (CVEs)'),
            ('registry', 'Windows Registry Keys'),
            ('filenames', 'Filenames'),
            ('filepaths', 'Filepaths'),
            ('bitcoin', 'Bitcoin Addresses'),
            ('yara', 'YARA Rules')
        ]
        
        # Process each section in the specified order
        for section_key, section_title in section_order:
            if section_key in self.data and self.data[section_key]:
                output.append(f"\n## {section_title}\n")
                
                # Sort entries alphabetically for better readability
                if section_key == 'hashes':
                    # For hashes, first group by type
                    hashes_by_type = {}
                    for hash_obj in self.data[section_key]:
                        hash_type = hash_obj.get('type', 'unknown')
                        if hash_type not in hashes_by_type:
                            hashes_by_type[hash_type] = []
                        hashes_by_type[hash_type].append(hash_obj.get('value', ''))
                    
                    # Then sort each group
                    for hash_type in sorted(hashes_by_type.keys()):
                        sorted_hashes = sorted(hashes_by_type[hash_type])
                        for hash_value in sorted_hashes:
                            output.append(hash_value)
                
                elif section_key == 'yara':
                    # For YARA rules, don't sort, as they are large text blocks
                    for rule in self.data[section_key]:
                        output.append(f"```\n{rule}\n```\n")
                
                else:
                    # For all other types, sort alphabetically
                    sorted_items = sorted(self.data[section_key])
                    for item in sorted_items:
                        output.append(item)
        
        # Add warning list IOCs if available
        if self.warning_iocs:
            output.append("\n# Warning List Matches\n")
            output.append("The following indicators were found in warning lists and might be false positives:\n")
            
            for section_key, section_title in section_order:
                if section_key in self.warning_iocs and self.warning_iocs[section_key]:
                    output.append(f"\n## {section_title} in Warning Lists\n")
                    
                    for ioc in self.warning_iocs[section_key]:
                        if isinstance(ioc, dict):
                            value = ioc.get('value', '')
                            warning_list = ioc.get('warning_list', 'Unknown list')
                            description = ioc.get('description', '')
                            output.append(f"{value} - *{warning_list}*")
                            if description:
                                output.append(f"  Description: {description}")
                        else:
                            output.append(ioc)
        
        # Remove extra blank lines
        return "\n".join(output)
        
    def save(self, output_file):
        """
        Save the formatted data to a text file.
        
        Args:
            output_file (str): Path to the output file
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(self.format())
        except Exception as e:
            print(f"Error saving text file: {str(e)}") 