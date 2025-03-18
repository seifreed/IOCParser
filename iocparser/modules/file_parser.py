#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for extracting text from different file types

Author: Marc Rivero | @seifreed
"""

import os
from abc import ABC, abstractmethod
import pdfplumber
from bs4 import BeautifulSoup
import requests
import re
from tqdm import tqdm


class FileParser(ABC):
    """Abstract base class for all file parsers."""
    
    def __init__(self, file_path):
        """
        Initialize the file parser.
        
        Args:
            file_path (str): Path to the file to parse
        """
        self.file_path = file_path
        
        # Verify the file exists if it's not a URL
        if not file_path.startswith(('http://', 'https://')) and not os.path.isfile(self.file_path):
            raise FileNotFoundError(f"The file {self.file_path} does not exist")
    
    @abstractmethod
    def extract_text(self):
        """
        Extract text from the file.
        
        Returns:
            str: The extracted text content
        """
        pass


class PDFParser(FileParser):
    """Class for extracting text from PDF files."""
    
    def extract_text(self):
        """
        Extract text from a PDF file.
        
        Returns:
            str: The extracted text content
        """
        print(f"Extracting text from PDF: {self.file_path}")
        
        text_content = ""
        
        try:
            with pdfplumber.open(self.file_path) as pdf:
                total_pages = len(pdf.pages)
                
                # Use tqdm to show progress
                for page_num in tqdm(range(total_pages), desc="Processing pages"):
                    page = pdf.pages[page_num]
                    text_content += page.extract_text() or ""
                    
                    # Also extract tables as they might contain IOCs
                    tables = page.extract_tables()
                    for table in tables:
                        for row in table:
                            text_content += " ".join([str(cell) for cell in row if cell]) + "\n"
        
        except Exception as e:
            raise Exception(f"Error processing PDF: {str(e)}")
        
        return text_content


class HTMLParser(FileParser):
    """Class for extracting text from HTML files."""
    
    def extract_text(self):
        """
        Extract text from an HTML file.
        
        Returns:
            str: The extracted text content
        """
        print(f"Extracting text from HTML: {self.file_path}")
        
        try:
            # Check if it's a URL or a local file
            if self.file_path.startswith(('http://', 'https://')):
                response = requests.get(self.file_path, timeout=30)
                response.raise_for_status()  # Ensure request was successful
                content = response.text
            else:
                with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            
            # Check if the content looks like a URL instead of HTML
            if content.strip().startswith(('http://', 'https://', 'hxxp://', 'hxxps://')) and len(content.strip().splitlines()) < 5:
                # If the content appears to be just a URL, return the text as is
                return content.strip()
            
            # Parse the HTML with BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Remove scripts and styles that we're not interested in
            for tag in soup(['script', 'style', 'meta', 'noscript', 'head']):
                tag.decompose()
            
            # Get the text
            text = soup.get_text(separator=' ', strip=True)
            
            # Clean multiple whitespaces
            text = re.sub(r'\s+', ' ', text)
            
            return text
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error accessing URL: {str(e)}")
        except Exception as e:
            raise Exception(f"Error processing HTML: {str(e)}")


# Function to determine the file type and return the appropriate parser
def get_parser(file_path):
    """
    Determine the file type and return the appropriate parser.
    
    Args:
        file_path (str): Path to the file or URL
        
    Returns:
        FileParser: The appropriate parser for the file type
    """
    # If it's a URL, determine the type by extension or assume HTML
    if file_path.startswith(('http://', 'https://')):
        if file_path.endswith('.pdf'):
            return PDFParser(file_path)
        else:
            return HTMLParser(file_path)
    
    # For local files, determine by extension
    if file_path.endswith('.pdf'):
        return PDFParser(file_path)
    elif file_path.endswith(('.html', '.htm')):
        return HTMLParser(file_path)
    else:
        raise ValueError(f"Unsupported file type: {file_path}") 