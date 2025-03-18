#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
"""

import argparse
import json
import os
import sys
import re
from colorama import init, Fore, Style
import magic
import requests
from urllib.parse import urlparse

from iocparser.modules.extractor import IOCExtractor
from iocparser.modules.file_parser import PDFParser, HTMLParser
from iocparser.modules.output_formatter import JSONFormatter, TextFormatter
from iocparser.modules.warninglists import MISPWarningLists

# Initialize colorama only when running as a script, not when imported
if __name__ == "__main__":
    init(autoreset=True)


def banner():
    """Display the tool banner."""
    print(f"""{Fore.CYAN}
╔═══════════════════════════════════════════════╗
║                                               ║
║              IOC Parser v1.0                  ║
║                                               ║
║     Indicators of Compromise Extractor        ║
║                                               ║
║       Author: Marc Rivero | @seifreed         ║
║                                               ║
╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def detect_file_type(file_path):
    """Automatically detect the file type."""
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        
        # Detectar PDF
        if "pdf" in file_type.lower():
            return "pdf"
        # Detectar HTML/XML
        elif any(x in file_type.lower() for x in ["html", "xml", "text/plain"]):
            # Si es text/plain, intentamos detectar por extensión
            if "text/plain" in file_type.lower():
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ['.html', '.htm', '.xml']:
                    return "html"
                # Para archivos .txt o sin extensión, asumimos que son texto plano
                return "text"
            return "html"
        # Detectar archivos de texto plano
        elif "text" in file_type.lower():
            return "text"
        # Si es un formato desconocido, intentamos por extensión
        else:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.pdf']:
                return "pdf"
            elif ext in ['.html', '.htm', '.xml']:
                return "html"
            elif ext in ['.txt', '.log', '.md', '.csv', '.json']:
                return "text"
            
        # If we can't determine the type, assume text
        return "text"
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error detecting file type: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Assuming it's a plain text file{Style.RESET_ALL}")
        return "text"


def download_url_to_temp(url):
    """Download URL content to a temporary file."""
    try:
        print(f"{Fore.GREEN}[+] Downloading content from {url}{Style.RESET_ALL}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Create temporary directory if it doesn't exist
        temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        # Create filename based on URL
        url_parts = urlparse(url)
        file_name = os.path.basename(url_parts.path)
        if not file_name:
            file_name = url_parts.netloc.replace('.', '_')
        
        # Add extension if needed
        content_type = response.headers.get('Content-Type', '').lower()
        if 'application/pdf' in content_type and not file_name.endswith('.pdf'):
            file_name += '.pdf'
        elif 'text/html' in content_type and not file_name.endswith(('.html', '.htm')):
            file_name += '.html'
        
        temp_file = os.path.join(temp_dir, file_name)
        
        # Save content
        with open(temp_file, 'wb') as f:
            f.write(response.content)
        
        return temp_file
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Could not download content from {url}: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


def get_output_filename(input_source, is_json=False):
    """
    Generate an output filename based on the input name.
    
    Args:
        input_source (str): The input file or URL
        is_json (bool): If True, use .json extension, if not, .txt
        
    Returns:
        str: Output filename
    """
    # If it's a URL, convert to a valid filename
    if input_source.startswith(('http://', 'https://')):
        url_parts = urlparse(input_source)
        # Use the hostname and path to create a filename
        base_name = url_parts.netloc
        if url_parts.path and url_parts.path != '/':
            # Add the last path component, if it exists
            path_parts = url_parts.path.strip('/').split('/')
            if path_parts[-1]:
                base_name += '_' + path_parts[-1]
                
        # Clean invalid filename characters
        base_name = re.sub(r'[^\w\-\.]', '_', base_name)
    else:
        # If it's a file, use its name without extension
        base_name = os.path.splitext(os.path.basename(input_source))[0]
        
    # Add extension based on format
    extension = '.json' if is_json else '.txt'
    
    # Ensure filename isn't too long
    if len(base_name) > 50:
        base_name = base_name[:50]
        
    return base_name + '_iocs' + extension


def print_warning_lists(warnings):
    """
    Print warnings from MISP warning lists.
    
    Args:
        warnings (dict): Dictionary with warnings by IOC type
    """
    if not warnings:
        return
    
    print(f"\n{Fore.YELLOW}[!] WARNING: IOCs found that might be false positives according to MISP warning lists:{Style.RESET_ALL}")
    
    for ioc_type, type_warnings in warnings.items():
        print(f"\n{Fore.YELLOW}IOCs of type {ioc_type} with warnings:{Style.RESET_ALL}")
        for warning in type_warnings:
            print(f"  {Fore.RED}● {warning['value']} - List: {warning['warning_list']}{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}Description: {warning['description']}{Style.RESET_ALL}")


def main():
    """Main function."""
    banner()
    
    parser = argparse.ArgumentParser(description="Indicators of Compromise (IOCs) Extractor")
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("-f", "--file", help="Path to the file to analyze")
    input_group.add_argument("-u", "--url", help="URL of the report to analyze")
    input_group.add_argument("url_direct", nargs="?", help="Direct URL as positional argument")
    
    parser.add_argument("-o", "--output", help="Output file path (use - for stdout)")
    parser.add_argument("-t", "--type", choices=["pdf", "html", "text"], 
                        help="Force specific file type (default: automatic detection)")
    parser.add_argument("--json", action="store_true", help="Display or save results in JSON format")
    parser.add_argument("--no-defang", action="store_true", help="Disable automatic defanging")
    parser.add_argument("--no-check-warnings", action="store_true", help="Don't check IOCs against MISP warning lists")
    parser.add_argument("--force-update", action="store_true", help="Force update of MISP warning lists")
    parser.add_argument("--init", action="store_true", help="Download and initialize MISP warning lists")
    
    args = parser.parse_args()
    
    # If init argument is specified, download and update MISP lists and exit
    if args.init:
        print(f"{Fore.GREEN}[+] Initializing and updating MISP warning lists...{Style.RESET_ALL}")
        warning_lists = MISPWarningLists(cache_duration=0, force_update=True)  # Force update
        total_lists = len(warning_lists.warning_lists)
        print(f"{Fore.GREEN}[+] Initialization completed. Downloaded {total_lists} warning lists.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Available lists: {Style.RESET_ALL}")
        
        # Show available list categories grouped
        categories = {}
        for list_id, wlist in warning_lists.warning_lists.items():
            category = wlist.get('name', '').split(' ')[0].lower() if 'name' in wlist else 'other'
            if category not in categories:
                categories[category] = []
            categories[category].append(list_id)
        
        for category, lists in sorted(categories.items()):
            print(f"{Fore.CYAN}  {category.capitalize()}: {len(lists)} lists{Style.RESET_ALL}")
            
        return
    
    # Verify that at least a file or URL is provided
    if not args.file and not args.url and not args.url_direct:
        parser.print_help()
        print(f"\n{Fore.RED}[ERROR] A file (-f) or URL (-u) must be provided for analysis{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Or use --init to download and update MISP warning lists{Style.RESET_ALL}")
        sys.exit(1)
    
    # Determine data source (local file or URL)
    if args.file:
        input_source = args.file
        input_display = args.file
        # Verify the file exists
        if not os.path.isfile(input_source):
            print(f"{Fore.RED}[ERROR] The file {input_source} does not exist or is not accessible.{Style.RESET_ALL}")
            sys.exit(1)
        
        # Detect file type if not specified or use specified type
        file_type = args.type if args.type else detect_file_type(input_source)
        print(f"{Fore.GREEN}[+] Processing file {input_source} of type {file_type.upper()}{Style.RESET_ALL}")
    elif args.url or args.url_direct:
        url = args.url if args.url else args.url_direct
        input_display = url
        # Download content to temporary file
        input_source = download_url_to_temp(url)
        
        # Use specified type or detect automatically
        file_type = args.type if args.type else detect_file_type(input_source)
        print(f"{Fore.GREEN}[+] Processing URL {url} of type {file_type.upper()}{Style.RESET_ALL}")
    
    # Parse the file according to its type
    if file_type == "pdf":
        parser = PDFParser(input_source)
        text_content = parser.extract_text()
    elif file_type == "html":
        parser = HTMLParser(input_source)
        text_content = parser.extract_text()
    else:  # text or unknown format
        # For plain text files, simply read the content
        try:
            with open(input_source, 'r', encoding='utf-8', errors='ignore') as f:
                text_content = f.read()
            print(f"{Fore.GREEN}[+] Text content read successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not read the file: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Extract IOCs
    extractor = IOCExtractor(defang=(not args.no_defang))
    iocs = extractor.extract_all(text_content)
    
    # Show summary
    total_iocs = sum(len(iocs[k]) for k in iocs)
    print(f"{Fore.GREEN}[+] Found {total_iocs} indicators of compromise:{Style.RESET_ALL}")
    for ioc_type, ioc_list in iocs.items():
        if ioc_list:
            print(f"    {Fore.CYAN}● {ioc_type}: {len(ioc_list)}{Style.RESET_ALL}")
    
    # Check against warning lists if enabled
    if not args.no_check_warnings:
        print(f"{Fore.BLUE}[*] Checking IOCs against MISP warning lists...{Style.RESET_ALL}")
        warning_lists = MISPWarningLists(force_update=args.force_update)
        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)
        
        if warning_iocs:
            print_warning_lists(warning_iocs)
            warnings_count = sum(len(warnings) for warnings in warning_iocs.values())
            print(f"{Fore.YELLOW}[!] Found {warnings_count} potential false positives{Style.RESET_ALL}")
    else:
        normal_iocs = iocs
        warning_iocs = {}
    
    # Format results according to the required format
    if args.json:
        formatter = JSONFormatter(normal_iocs, warning_iocs=warning_iocs)
        output_format = "JSON"
    else:
        formatter = TextFormatter(normal_iocs, warning_iocs=warning_iocs)
        output_format = "text"
    
    formatted_output = formatter.format()
    
    # Determine what to do with the output
    if args.output:
        # If "-" is specified as output, only display on the console
        if args.output == "-":
            print(formatted_output)
            print(f"{Fore.GREEN}[+] Results displayed in {output_format} format{Style.RESET_ALL}")
        else:
            # Save to the specified file
            output_file = args.output
            formatter.save(output_file)
            print(f"{Fore.GREEN}[+] Results saved in {output_format} format: {output_file}{Style.RESET_ALL}")
    else:
        # If no output file is specified
        if args.json:
            # For JSON output, display on screen and also save to file automatically
            print(formatted_output)
            output_file = get_output_filename(input_display, is_json=True)
            formatter.save(output_file)
            print(f"{Fore.GREEN}[+] Results saved in JSON format: {output_file}{Style.RESET_ALL}")
        else:
            # For text output, display on screen and also save to file automatically
            print(formatted_output)
            output_file = get_output_filename(input_display, is_json=False)
            formatter.save(output_file)
            print(f"{Fore.GREEN}[+] Results saved in text format: {output_file}{Style.RESET_ALL}")
    
    # Clean up temporary file if we're processing a URL
    if (args.url or args.url_direct) and os.path.exists(input_source) and 'temp' in input_source:
        try:
            os.remove(input_source)
            print(f"{Fore.GREEN}[+] Temporary file deleted{Style.RESET_ALL}")
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
        sys.exit(1) 