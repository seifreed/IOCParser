#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para gestionar las listas de advertencia (warning lists) de MISP para detectar falsos positivos
"""

import os
import json
import re
import requests
import time
from urllib.parse import urlparse
from colorama import Fore, Style


class MISPWarningLists:
    """Clase para gestionar las listas de advertencia (warning lists) de MISP"""
    
    def __init__(self, cache_duration=24):
        """
        Inicializa el gestor de listas de advertencia.
        
        Args:
            cache_duration (int): Duración en horas que se mantendrá la caché local antes de actualizarla
        """
        self.cache_duration = cache_duration  # horas
        self.warning_lists = {}
        self.data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'data')
        self.cache_file = os.path.join(self.data_dir, 'misp_warninglists_cache.json')
        self.cache_metadata_file = os.path.join(self.data_dir, 'misp_warninglists_metadata.json')
        self.github_api_base = "https://api.github.com/repos/MISP/misp-warninglists/contents/lists"
        self.github_raw_base = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"
        
        # Crear el directorio de datos si no existe
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        
        # Cargar o actualizar las listas
        self._load_or_update_lists()
    
    def _load_or_update_lists(self):
        """Cargar las listas de la caché o actualizarlas si es necesario"""
        # Verificar si existe la caché y su antigüedad
        if os.path.exists(self.cache_file) and os.path.exists(self.cache_metadata_file):
            try:
                with open(self.cache_metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                # Verificar si la caché está actualizada
                cache_time = metadata.get('timestamp', 0)
                current_time = time.time()
                if (current_time - cache_time) < (self.cache_duration * 3600):  # Convertir horas a segundos
                    # La caché es válida, cargarla
                    with open(self.cache_file, 'r') as f:
                        self.warning_lists = json.load(f)
                    return
            except Exception:
                # Si hay algún error al leer la caché, actualizarla
                pass
        
        # Actualizar la caché
        self._update_warning_lists()
    
    def _update_warning_lists(self):
        """Actualizar las listas de advertencia desde el repositorio de GitHub"""
        try:
            print(f"{Fore.YELLOW}[!] Actualizando listas de advertencia de MISP desde GitHub...{Style.RESET_ALL}")
            
            # Obtener lista de directorios
            response = requests.get(self.github_api_base, timeout=30)
            response.raise_for_status()
            directories = [item['name'] for item in response.json() if item['type'] == 'dir']
            
            # Procesar cada directorio para obtener la lista de advertencia
            for directory in directories:
                try:
                    # Descargar el archivo list.json de cada directorio
                    list_url = f"{self.github_raw_base}/{directory}/list.json"
                    response = requests.get(list_url, timeout=30)
                    response.raise_for_status()
                    warning_list = response.json()
                    
                    # Guardar la lista en el diccionario
                    list_name = warning_list.get('name', directory)
                    self.warning_lists[list_name] = {
                        'name': list_name,
                        'description': warning_list.get('description', ''),
                        'list': warning_list.get('list', []),
                        'matching_attributes': warning_list.get('matching_attributes', []),
                        'type': warning_list.get('type', 'string')
                    }
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] No se pudo procesar la lista {directory}: {str(e)}{Style.RESET_ALL}")
            
            # Guardar las listas en caché
            with open(self.cache_file, 'w') as f:
                json.dump(self.warning_lists, f)
            
            # Guardar metadatos de la caché
            with open(self.cache_metadata_file, 'w') as f:
                json.dump({'timestamp': time.time()}, f)
            
            print(f"{Fore.GREEN}[+] Se han actualizado {len(self.warning_lists)} listas de advertencia de MISP{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] No se pudo actualizar las listas de advertencia: {str(e)}{Style.RESET_ALL}")
            
            # Si hay una caché disponible, intentar usarla a pesar del error
            if os.path.exists(self.cache_file):
                try:
                    with open(self.cache_file, 'r') as f:
                        self.warning_lists = json.load(f)
                    print(f"{Fore.YELLOW}[!] Usando listas de advertencia en caché{Style.RESET_ALL}")
                except Exception:
                    print(f"{Fore.RED}[ERROR] No se pudo cargar las listas de advertencia desde la caché{Style.RESET_ALL}")
    
    def check_value(self, value, ioc_type):
        """
        Verifica si un valor está en alguna lista de advertencia.
        
        Args:
            value (str): El valor a verificar
            ioc_type (str): El tipo de IOC (domain, ip, url, hash, etc.)
            
        Returns:
            tuple: (está_en_lista, info_de_lista) o (False, None) si no está en ninguna lista
        """
        # Mapear el tipo de IOC a los tipos de atributos de MISP
        misp_types = {
            'domains': ['hostname', 'domain', 'domain|ip'],
            'ips': ['ip-src', 'ip-dst', 'ip'],
            'urls': ['url', 'uri'],
            'hashes': ['md5', 'sha1', 'sha256', 'hash'],
            'emails': ['email', 'email-src', 'email-dst'],
            'bitcoin': ['btc', 'bitcoin'],
            'yara': ['yara']
        }
        
        # Verificaciones especiales para IPs comunes
        if ioc_type == 'ips':
            clean_value = value.replace('[.]', '.')
            
            # localhost y redes privadas
            if clean_value == '127.0.0.1' or clean_value.startswith('192.168.') or clean_value.startswith('10.'):
                return True, {
                    'name': 'RFC 1918 - Private IP space',
                    'description': 'Esta es una dirección IP privada o localhost que no debería considerarse un IOC malicioso.'
                }
            
            # DNS públicos conocidos
            if clean_value in ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9', '208.67.222.222']:
                return True, {
                    'name': 'Public DNS resolvers',
                    'description': 'Esta es una dirección IP de un resolvedor de DNS público conocido (como Google DNS, Cloudflare, etc.)'
                }
        
        # Verificaciones especiales para dominios comunes
        if ioc_type == 'domains':
            clean_value = value.replace('[.]', '.')
            
            # Dominios de ejemplo
            if clean_value in ['example.com', 'example.org', 'example.net']:
                return True, {
                    'name': 'Example domains',
                    'description': 'Este es un dominio de ejemplo que no debe considerarse un IOC malicioso.'
                }
        
        attribute_types = misp_types.get(ioc_type, [])
        if not attribute_types:
            return False, None
        
        # Verificar cada lista
        for list_name, warning_list in self.warning_lists.items():
            # Verificar si la lista tiene matching_attributes definidos
            matching_attributes = warning_list.get('matching_attributes', [])
            
            # Verificar si el tipo de atributo coincide con la lista
            if matching_attributes and any(attr_type in matching_attributes for attr_type in attribute_types):
                list_type = warning_list.get('type', 'string')
                list_values = warning_list.get('list', [])
                
                # Verificar si la lista es de tipo string, substring o regex
                if list_type == 'string':
                    if value in list_values:
                        return True, warning_list
                    # Para IPs y dominios, verificar con variantes sin defang
                    clean_value = value.replace('[.]', '.').replace('[:]', ':')
                    if clean_value in list_values:
                        return True, warning_list
                    
                elif list_type == 'substring':
                    for item in list_values:
                        if str(item) in value:
                            return True, warning_list
                
                elif list_type == 'regex':
                    for regex in list_values:
                        try:
                            if re.search(regex, value):
                                return True, warning_list
                        except:
                            # Si hay algún problema con la expresión regular, omitirla
                            pass
        
        return False, None
    
    def get_warnings_for_iocs(self, iocs):
        """
        Obtiene advertencias para una lista de IOCs.
        
        Args:
            iocs (dict): Diccionario con tipos de IOC y sus valores
            
        Returns:
            dict: Diccionario con IOCs que tienen advertencias
        """
        warnings = {}
        
        for ioc_type, ioc_list in iocs.items():
            type_warnings = []
            
            for ioc in ioc_list:
                # Si el IOC es un diccionario (como en hashes), usar la clave 'value'
                if isinstance(ioc, dict):
                    value = ioc.get('value', '')
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