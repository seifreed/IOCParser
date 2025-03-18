"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
"""

from iocparser.modules.extractor import IOCExtractor
from iocparser.modules.file_parser import PDFParser, HTMLParser
from iocparser.modules.output_formatter import JSONFormatter, TextFormatter
from iocparser.modules.warninglists import MISPWarningLists
from iocparser.main import detect_file_type, get_output_filename

__version__ = "1.0.0"

# Export main functionality for library use
__all__ = [
    'IOCExtractor',
    'PDFParser',
    'HTMLParser',
    'JSONFormatter',
    'TextFormatter',
    'MISPWarningLists',
    'detect_file_type',
    'get_output_filename',
    'extract_iocs_from_file',
    'extract_iocs_from_text'
]

def extract_iocs_from_file(file_path, check_warnings=True, force_update=False, file_type=None, defang=True):
    """
    Extract IOCs from a file.
    
    Args:
        file_path (str): Path to the file
        check_warnings (bool): Whether to check IOCs against MISP warning lists
        force_update (bool): Whether to force update the MISP warning lists
        file_type (str): Force a specific file type (pdf, html, text)
        defang (bool): Whether to defang the IOCs
        
    Returns:
        tuple: (normal_iocs, warning_iocs) where each is a dict with IOC types as keys
    """
    import os
    
    # Verify the file exists
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist or is not accessible.")
    
    # Detect file type if not specified
    detected_type = file_type if file_type else detect_file_type(file_path)
    
    # Parse the file according to its type
    if detected_type == "pdf":
        from iocparser.modules.file_parser import PDFParser
        parser = PDFParser(file_path)
        text_content = parser.extract_text()
    elif detected_type == "html":
        from iocparser.modules.file_parser import HTMLParser
        parser = HTMLParser(file_path)
        text_content = parser.extract_text()
    else:  # text or unknown format
        # For plain text files, simply read the content
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            text_content = f.read()
    
    # Process the text content
    return extract_iocs_from_text(text_content, check_warnings, force_update, defang)

def extract_iocs_from_text(text_content, check_warnings=True, force_update=False, defang=True):
    """
    Extract IOCs from text content.
    
    Args:
        text_content (str): The text to extract IOCs from
        check_warnings (bool): Whether to check IOCs against MISP warning lists
        force_update (bool): Whether to force update the MISP warning lists
        defang (bool): Whether to defang the IOCs
        
    Returns:
        tuple: (normal_iocs, warning_iocs) where each is a dict with IOC types as keys
    """
    # Extract IOCs
    extractor = IOCExtractor(defang=defang)
    iocs = extractor.extract_all(text_content)
    
    # Check against warning lists if enabled
    if check_warnings:
        warning_lists = MISPWarningLists(force_update=force_update)
        normal_iocs, warning_iocs = warning_lists.separate_iocs_by_warnings(iocs)
        return normal_iocs, warning_iocs
    else:
        # If not checking warnings, all IOCs are considered normal
        return iocs, {}
