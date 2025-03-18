#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para extraer texto de diferentes tipos de archivos
"""

import os
from abc import ABC, abstractmethod
import pdfplumber
from bs4 import BeautifulSoup
import requests
import re
from tqdm import tqdm


class FileParser(ABC):
    """Clase base abstracta para todos los analizadores de archivos."""
    
    def __init__(self, file_path):
        """
        Inicializa el analizador de archivos.
        
        Args:
            file_path (str): Ruta al archivo a analizar
        """
        self.file_path = file_path
        
        # Verificar que el archivo existe si no es una URL
        if not file_path.startswith(('http://', 'https://')) and not os.path.isfile(self.file_path):
            raise FileNotFoundError(f"El archivo {self.file_path} no existe")
    
    @abstractmethod
    def extract_text(self):
        """
        Extrae texto del archivo.
        
        Returns:
            str: El contenido de texto extraído
        """
        pass


class PDFParser(FileParser):
    """Clase para extraer texto de archivos PDF."""
    
    def extract_text(self):
        """
        Extrae texto de un archivo PDF.
        
        Returns:
            str: El contenido de texto extraído
        """
        print(f"Extrayendo texto del PDF: {self.file_path}")
        
        text_content = ""
        
        try:
            with pdfplumber.open(self.file_path) as pdf:
                total_pages = len(pdf.pages)
                
                # Usar tqdm para mostrar progreso
                for page_num in tqdm(range(total_pages), desc="Procesando páginas"):
                    page = pdf.pages[page_num]
                    text_content += page.extract_text() or ""
                    
                    # También extraemos tablas ya que pueden contener IOCs
                    tables = page.extract_tables()
                    for table in tables:
                        for row in table:
                            text_content += " ".join([str(cell) for cell in row if cell]) + "\n"
        
        except Exception as e:
            raise Exception(f"Error al procesar el PDF: {str(e)}")
        
        return text_content


class HTMLParser(FileParser):
    """Clase para extraer texto de archivos HTML."""
    
    def extract_text(self):
        """
        Extrae texto de un archivo HTML.
        
        Returns:
            str: El contenido de texto extraído
        """
        print(f"Extrayendo texto del HTML: {self.file_path}")
        
        try:
            # Comprobar si es una URL o un archivo local
            if self.file_path.startswith(('http://', 'https://')):
                response = requests.get(self.file_path, timeout=30)
                response.raise_for_status()  # Asegurar que la solicitud fue exitosa
                content = response.text
            else:
                with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            
            # Verificar si el contenido parece una URL en lugar de HTML
            if content.strip().startswith(('http://', 'https://', 'hxxp://', 'hxxps://')) and len(content.strip().splitlines()) < 5:
                # Si el contenido parece ser solo una URL, devolver el texto como está
                return content.strip()
            
            # Parsear el HTML con BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Eliminar scripts y estilos que no nos interesan
            for tag in soup(['script', 'style', 'meta', 'noscript', 'head']):
                tag.decompose()
            
            # Obtener el texto
            text = soup.get_text(separator=' ', strip=True)
            
            # Limpiar espacios en blanco múltiples
            text = re.sub(r'\s+', ' ', text)
            
            return text
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error al acceder a la URL: {str(e)}")
        except Exception as e:
            raise Exception(f"Error al procesar el HTML: {str(e)}")


# Función para determinar el tipo de archivo y devolver el parser apropiado
def get_parser(file_path):
    """
    Determina el tipo de archivo y devuelve el parser apropiado.
    
    Args:
        file_path (str): Ruta al archivo o URL
        
    Returns:
        FileParser: El parser apropiado para el tipo de archivo
    """
    # Si es una URL, determinar el tipo por la extensión o asumir HTML
    if file_path.startswith(('http://', 'https://')):
        if file_path.endswith('.pdf'):
            return PDFParser(file_path)
        else:
            return HTMLParser(file_path)
    
    # Para archivos locales, determinar por la extensión
    if file_path.endswith('.pdf'):
        return PDFParser(file_path)
    elif file_path.endswith(('.html', '.htm')):
        return HTMLParser(file_path)
    else:
        raise ValueError(f"Tipo de archivo no soportado: {file_path}") 