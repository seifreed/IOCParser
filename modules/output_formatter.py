#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para formatear la salida de los IOCs en diferentes formatos
"""

import json
import os
from abc import ABC, abstractmethod


class OutputFormatter(ABC):
    """Clase base abstracta para todos los formateadores de salida."""
    
    def __init__(self, data):
        """
        Inicializa el formateador de salida.
        
        Args:
            data (dict): Datos a formatear
        """
        self.data = data
    
    @abstractmethod
    def format(self):
        """
        Formatea los datos.
        
        Returns:
            str: Los datos formateados
        """
        pass
    
    @abstractmethod
    def save(self, output_file):
        """
        Guarda los datos formateados en un archivo.
        
        Args:
            output_file (str): Ruta del archivo de salida
        """
        pass


class JSONFormatter(OutputFormatter):
    """Clase para formatear la salida en JSON."""
    
    def format(self):
        """
        Formatea los datos en JSON.
        
        Returns:
            str: Los datos formateados en JSON
        """
        # Para hashes, mantener la estructura original
        data_copy = self.data.copy()
        
        # Para los demás tipos, ordenar las listas para consistencia
        for key in data_copy:
            if key != 'hashes' and isinstance(data_copy[key], list):
                data_copy[key] = sorted(data_copy[key])
        
        # Ordenar las claves del diccionario para consistencia
        return json.dumps(data_copy, indent=4, sort_keys=True)
    
    def save(self, output_file):
        """
        Guarda los datos formateados en un archivo JSON.
        
        Args:
            output_file (str): Ruta del archivo de salida
        """
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        # Para hashes, mantener la estructura original
        data_copy = self.data.copy()
        
        # Para los demás tipos, ordenar las listas para consistencia
        for key in data_copy:
            if key != 'hashes' and isinstance(data_copy[key], list):
                data_copy[key] = sorted(data_copy[key])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data_copy, f, indent=4, ensure_ascii=False, sort_keys=True)


class TextFormatter(OutputFormatter):
    """Clase para formatear la salida en texto plano."""
    
    def format(self):
        """
        Formatea los datos en texto plano.
        
        Returns:
            str: Los datos formateados en texto plano
        """
        output = ["# Indicadores de Compromiso (IOCs) Extraídos\n"]
        
        # Ordenar las secciones de forma más lógica
        section_order = [
            ('hashes', 'Hashes'),
            ('domains', 'Dominios'),
            ('ips', 'Direcciones IP'),
            ('urls', 'URLs'),
            ('emails', 'Direcciones de Correo Electrónico'),
            ('hosts', 'Hosts'),
            ('cves', 'Vulnerabilidades (CVEs)'),
            ('registry', 'Registros de Windows'),
            ('filenames', 'Nombres de Archivos'),
            ('filepaths', 'Rutas de Archivos'),
            ('bitcoin', 'Direcciones Bitcoin'),
            ('yara', 'Reglas YARA')
        ]
        
        # Procesar cada sección en el orden especificado
        for section_key, section_title in section_order:
            if section_key in self.data and self.data[section_key]:
                output.append(f"\n## {section_title}\n")
                
                # Ordenar alfabéticamente las entradas para mejor legibilidad
                if section_key == 'hashes':
                    # Para hashes, primero agrupar por tipo
                    hashes_by_type = {}
                    for hash_obj in self.data[section_key]:
                        hash_type = hash_obj.get('type', 'unknown')
                        if hash_type not in hashes_by_type:
                            hashes_by_type[hash_type] = []
                        hashes_by_type[hash_type].append(hash_obj.get('value', ''))
                    
                    # Luego ordenar cada grupo
                    for hash_type in sorted(hashes_by_type.keys()):
                        sorted_hashes = sorted(hashes_by_type[hash_type])
                        for hash_value in sorted_hashes:
                            output.append(hash_value)
                
                elif section_key == 'yara':
                    # Para reglas YARA, no ordenar, ya que son bloques de texto grandes
                    for rule in self.data[section_key]:
                        output.append(f"```\n{rule}\n```\n")
                
                else:
                    # Para todos los demás tipos, ordenar alfabéticamente
                    sorted_items = sorted(self.data[section_key])
                    for item in sorted_items:
                        output.append(item)
        
        # Eliminar líneas vacías adicionales
        formatted_output = "\n".join(output)
        formatted_output = formatted_output.replace("\n\n\n", "\n\n")
        
        return formatted_output

    def save(self, output_file):
        """
        Guarda los datos formateados en un archivo de texto.
        
        Args:
            output_file (str): Ruta del archivo de salida
        """
        formatted_output = self.format()
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
        except Exception as e:
            print(f"Error al guardar el archivo: {str(e)}") 