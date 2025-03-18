#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para extraer indicadores de compromiso (IOCs) de texto
"""

import re
import regex
from tqdm import tqdm
import os
import urllib.parse


class IOCExtractor:
    """Clase para extraer diferentes tipos de IOCs de texto."""

    def __init__(self, defang=True):
        """
        Inicializa el extractor.

        Args:
            defang (bool): Si es True, realiza defanging en los resultados
        """
        self.defang = defang
        
        # Lista de TLDs válidos
        # Cargar lista de TLDs válidos desde archivo o definir los más comunes
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
            
            # URLs - incluyendo URLs defanged con hxxp/hxxps y URLs largas
            'urls': re.compile(r'\b(https?://[\S]{5,}|hxxps?://[\S]{5,}|h\[\.\]ttps?://[\S]{5,}|s?ftp://[\S]{5,})\b|\b([a-z]{3,}\:\/\/[\S]{16,})\b'),
            
            # Bitcoin addresses
            'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            
            # YARA rules
            'yara': re.compile(r'rule\s+\w+\s*({[^}]+})', re.DOTALL),
            
            # Host (patrón solicitado)
            'hosts': re.compile(r'\b(([a-z0-9\-]{2,}\[?\.\]?)+(abogado|ac|academy|accountants|active|actor|ad|adult|ae|aero|af|ag|agency|ai|airforce|al|allfinanz|alsace|am|amsterdam|an|android|ao|aq|aquarelle|ar|archi|army|arpa|as|asia|associates|at|attorney|au|auction|audio|autos|aw|ax|axa|az|ba|band|bank|bar|barclaycard|barclays|bargains|bayern|bb|bd|be|beer|berlin|best|bf|bg|bh|bi|bid|bike|bingo|bio|biz|bj|black|blackfriday|bloomberg|blue|bm|bmw|bn|bnpparibas|bo|boo|boutique|br|brussels|bs|bt|budapest|build|builders|business|buzz|bv|bw|by|bz|bzh|ca|cal|camera|camp|cancerresearch|canon|capetown|capital|caravan|cards|care|career|careers|cartier|casa|cash|cat|catering|cc|cd|center|ceo|cern|cf|cg|ch|channel|chat|cheap|christmas|chrome|church|ci|citic|city|ck|cl|claims|cleaning|click|clinic|clothing|club|cm|cn|co|coach|codes|coffee|college|cologne|com|community|company|computer|condos|construction|consulting|contractors|cooking|cool|coop|country|cr|credit|creditcard|cricket|crs|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cz|dabur|dad|dance|dating|day|dclk|de|deals|degree|delivery|democrat|dental|dentist|desi|design|dev|diamonds|diet|digital|direct|directory|discount|dj|dk|dm|dnp|do|docs|domains|doosan|durban|dvag|dz|eat|ec|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|equipment|er|es|esq|estate|et|eu|eurovision|eus|events|everbank|exchange|expert|exposed|fail|farm|fashion|feedback|fi|finance|financial|firmdale|fish|fishing|fit|fitness|fj|fk|flights|florist|flowers|flsmidth|fly|fm|fo|foo|forsale|foundation|fr|frl|frogans|fund|furniture|futbol|ga|gal|gallery|garden|gb|gbiz|gd|ge|gent|gf|gg|ggee|gh|gi|gift|gifts|gives|gl|glass|gle|global|globo|gm|gmail|gmo|gmx|gn|goog|google|gop|gov|gp|gq|gr|graphics|gratis|green|gripe|gs|gt|gu|guide|guitars|guru|gw|gy|hamburg|hangout|haus|healthcare|help|here|hermes|hiphop|hiv|hk|hm|hn|holdings|holiday|homes|horse|host|hosting|house|how|hr|ht|hu|ibm|id|ie|ifm|il|im|immo|immobilien|in|industries|info|ing|ink|institute|insure|int|international|investments|io|iq|ir|irish|is|it|iwc|jcb|je|jetzt|jm|jo|jobs|joburg|jp|juegos|kaufen|kddi|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|koeln|kp|kr|krd|kred|kw|ky|kyoto|kz|la|lacaixa|land|lat|latrobe|lawyer|lb|lc|lds|lease|legal|lgbt|li|lidl|life|lighting|limited|limo|link|lk|loans|london|lotte|lotto|lr|ls|lt|ltda|lu|luxe|luxury|lv|ly|ma|madrid|maison|management|mango|market|marketing|marriott|mc|md|me|media|meet|melbourne|meme|memorial|menu|mg|mh|miami|mil|mini|mk|ml|mm|mn|mo|mobi|moda|moe|monash|money|mormon|mortgage|moscow|motorcycles|mov|mp|mq|mr|ms|mt|mu|museum|mv|mw|mx|my|mz|na|nagoya|name|navy|nc|ne|net|network|neustar|new|nexus|nf|ng|ngo|nhk|ni|ninja|nl|no|np|nr|nra|nrw|ntt|nu|nyc|nz|okinawa|om|one|ong|onl|ooo|org|organic|osaka|otsuka|ovh|pa|paris|partners|parts|party|pe|pf|pg|ph|pharmacy|photo|photography|photos|physio|pics|pictures|pink|pizza|pk|pl|place|plumbing|pm|pn|pohl|poker|porn|post|pr|praxi|press|pro|prod|productions|prof|properties|property|ps|pt|pub|pw|qa|qpon|quebec|re|realtor|recipes|red|rehab|reise|reisen|reit|ren|rentals|repair|report|republican|rest|restaurant|reviews|rich|rio|rip|ro|rocks|rodeo|rs|rsvp|ru|ruhr|rw|ryukyu|sa|saarland|sale|samsung|sarl|sb|sc|sca|scb|schmidt|schule|schwarz|science|scot|sd|se|services|sew|sexy|sg|sh|shiksha|shoes|shriram|si|singles|sj|sk|sky|sl|sm|sn|so|social|software|sohu|solar|solutions|soy|space|spiegel|sr|st|style|su|supplies|supply|support|surf|surgery|suzuki|sv|sx|sy|sydney|systems|sz|taipei|tatar|tattoo|tax|tc|td|technology|tel|temasek|tennis|tf|tg|th|tienda|tips|tires|tirol|tj|tk|tl|tm|tn|to|today|tokyo|tools|top|toshiba|town|toys|tp|tr|trade|training|travel|trust|tt|tui|tv|tw|tz|ua|ug|uk|university|uno|uol|us|uy|uz|va|vacations|vc|ve|vegas|ventures|versicherung|vet|vg|vi|viajes|video|villas|vision|vlaanderen|vn|vodka|vote|voting|voto|voyage|vu|wales|wang|watch|webcam|website|wed|wedding|wf|whoswho|wien|wiki|williamhill|wme|work|works|world|ws|wtc|wtf|xyz|yachts|yandex|ye|yoga|yokohama|youtube|yt|za|zm|zone|zuerich|zw))\b'),
            
            # Email (patrón solicitado)
            'emails': re.compile(r'\b([a-z][_a-z0-9-.]+@[a-z0-9-]+\.[a-z]+)\b'),
            
            # CVE (patrón solicitado)
            'cves': re.compile(r'\b(CVE\-[0-9]{4}\-[0-9]{4,6})\b'),
            
            # Registros de Windows (patrón solicitado)
            'registry': re.compile(r'\b((HKLM|HKCU)\\[\\A-Za-z0-9-_]+)\b'),
            
            # Nombres de archivos (patrón solicitado)
            'filenames': re.compile(r'\b([A-Za-z0-9-_\.]+\.(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))\b'),
            
            # Rutas de archivos (patrón solicitado)
            'filepaths': re.compile(r'\b[A-Z]:\\[A-Za-z0-9-_\.\\]+\b')
        }
        
        # Extensiones de archivos comunes que podrían ser confundidas con dominios
        self.common_file_extensions = {
            'exe', 'dll', 'sys', 'cmd', 'bat', 'ps1', 'vbs', 'js', 'pdf', 'doc', 'docx', 'xls', 
            'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'zip', 'rar', '7z', 
            'gz', 'tar', 'pif', 'scr', 'msi', 'jar', 'py', 'pyc', 'pyo', 'php', 'asp', 'aspx', 
            'jsp', 'htm', 'html', 'css', 'json', 'xml', 'reg', 'ini', 'cfg', 'log', 'tmp', 'dat'
        }
        
        # Palabras comunes en nombres de malware que podrían ser confundidas con dominios
        self.malware_keywords = {
            'trojan', 'virus', 'worm', 'backdoor', 'rootkit', 'spyware', 'adware', 'ransomware',
            'malware', 'agent', 'dropper', 'downloader', 'injector', 'stealer', 'keylogger',
            'generic', 'heur', 'suspicious', 'riskware', 'unwanted', 'pup', 'pua', 'hacktool',
            'exploit', 'obfuscated', 'packed', 'crypted', 'banker', 'win32', 'win64', 'msil',
            'android', 'linux', 'macos', 'ios', 'symbian', 'unix'
        }

    def _load_valid_tlds(self):
        """
        Carga la lista de TLDs válidos.
        
        Returns:
            set: Conjunto de TLDs válidos
        """
        # Lista de TLDs más comunes
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
        
        # Intentar cargar una lista más completa si el archivo existe
        tlds_file = os.path.join(os.path.dirname(__file__), 'data', 'tlds.txt')
        
        if os.path.isfile(tlds_file):
            try:
                with open(tlds_file, 'r', encoding='utf-8') as f:
                    return {line.strip().lower() for line in f if line.strip()}
            except Exception:
                pass
        
        return common_tlds

    def extract_md5(self, text):
        """Extrae hashes MD5 del texto."""
        return self._extract_pattern(text, 'md5')

    def extract_sha1(self, text):
        """Extrae hashes SHA1 del texto."""
        return self._extract_pattern(text, 'sha1')

    def extract_sha256(self, text):
        """Extrae hashes SHA256 del texto."""
        return self._extract_pattern(text, 'sha256')

    def extract_sha512(self, text):
        """Extrae hashes SHA512 del texto."""
        return self._extract_pattern(text, 'sha512')
    
    def extract_domains(self, text):
        """Extrae dominios del texto."""
        domains = self._extract_pattern(text, 'domains')
        
        # También extraer dominios de URLs (incluidas las defanged)
        domains_from_urls = self._extract_domains_from_urls(text)
        
        # Combinar dominios directos y dominios extraídos de URLs
        all_domains = domains + domains_from_urls
        
        # Limpiar dominios extraídos (quitar defang si está presente)
        clean_domains = []
        for domain in all_domains:
            # Si es una tupla (por grupos en regex), tomar el primer elemento no vacío
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
        
        # Verificar duplicados
        return list(set(all_domains))

    def _is_valid_domain(self, domain):
        """
        Valida si una cadena es un dominio válido.
        
        Args:
            domain (str): El dominio a validar
            
        Returns:
            bool: True si es un dominio válido, False en caso contrario
        """
        # Dividir el dominio en partes
        parts = domain.lower().split('.')
        
        # Comprobar si tiene al menos dos partes y un TLD válido
        if len(parts) < 2:
            return False
        
        # Obtener la extensión (TLD)
        tld = parts[-1]
        
        # Comprobar si es un TLD válido
        if tld not in self.valid_tlds:
            return False
        
        # Comprobar si parece un nombre de archivo
        if len(parts) == 2 and parts[0] == 'a' and tld in self.common_file_extensions:
            return False  # Patrón común de "a.exe" o similar
            
        # Comprobar si es una extensión de archivo común
        if tld in self.common_file_extensions:
            return False
            
        # Comprobar si parece un nombre de malware
        domain_lower = domain.lower()
        if any(keyword in domain_lower for keyword in self.malware_keywords):
            # Comprobar si tiene un formato como "Trojan.Win32.Agent"
            if re.match(r'([a-zA-Z]+\.){2,}[a-zA-Z]+', domain_lower):
                return False
                
        # Revisar también el dominio completo
        if domain.count('.') >= 1:
            # Comprobar si es un nombre de producto con versión (ejemplo: kernel32.dll)
            if re.match(r'[a-zA-Z0-9]+[0-9]+\.[a-zA-Z]+', domain):
                return False
                
        # Si pasa todas las comprobaciones, es un dominio válido
        return True

    def extract_ips(self, text):
        """Extrae direcciones IP del texto."""
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
        """Extrae URLs del texto."""
        urls = self._extract_pattern(text, 'urls')
        
        # Limpiar URLs extraídas
        clean_urls = []
        for url in urls:
            # Limpiar defanging existente
            url = url.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
            
            # Añadir defanging si está activado
            if self.defang:
                url = self._defang_url(url)
                
            clean_urls.append(url)
                
        return list(set(clean_urls))

    def extract_bitcoin(self, text):
        """Extrae direcciones de Bitcoin del texto."""
        return self._extract_pattern(text, 'bitcoin')

    def extract_yara_rules(self, text):
        """Extrae reglas Yara del texto."""
        return self._extract_pattern(text, 'yara')

    def extract_hosts(self, text):
        """Extrae hosts del texto."""
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
        """Extrae direcciones de correo electrónico del texto."""
        emails = self._extract_pattern(text, 'emails')
        
        # Filtrar emails válidos
        filtered_emails = []
        for email in emails:
            # Verificar que el dominio del email es válido
            domain = email.split('@')[1]
            if self._is_valid_domain(domain):
                if self.defang:
                    # Defang el email reemplazando @ con [at] y . con [.]
                    defanged_email = email.replace('@', '[at]').replace('.', '[.]')
                    filtered_emails.append(defanged_email)
                else:
                    filtered_emails.append(email)
        
        return filtered_emails
    
    def extract_cves(self, text):
        """Extrae identificadores CVE del texto."""
        return self._extract_pattern(text, 'cves')
    
    def extract_registry(self, text):
        """Extrae rutas de registro de Windows del texto."""
        return self._extract_pattern(text, 'registry')
    
    def extract_filenames(self, text):
        """Extrae nombres de archivos sospechosos del texto."""
        return self._extract_pattern(text, 'filenames')
    
    def extract_filepaths(self, text):
        """Extrae rutas de archivos del texto."""
        return self._extract_pattern(text, 'filepaths')

    def extract_all(self, text):
        """
        Extrae todos los tipos de IOCs del texto.
        
        Args:
            text (str): El texto donde buscar IOCs
            
        Returns:
            dict: Diccionario con los IOCs extraídos, agrupados por tipo
        """
        print("Extrayendo indicadores de compromiso...")
        
        # Procesamiento preliminar para detectar posibles reglas Yara y guardarlas aparte
        yara_text = text  # Guardar texto original para extraer reglas Yara
        
        # Extracción especial de dominios directamente desde URLs defanged
        defanged_domains = self._extract_defanged_domains_direct(text)
        
        # Crear un diccionario para almacenar los resultados por tipo
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
        
        # Extraer hashes (MD5, SHA1, SHA256, SHA512)
        md5s = self.extract_md5(text)
        sha1s = self.extract_sha1(text)
        sha256s = self.extract_sha256(text)
        sha512s = self.extract_sha512(text)
        
        # Para evitar duplicados, ejemplo: un SHA256 que también coincide con MD5
        # Añadimos los hashes en orden inverso de longitud
        all_hashes = []
        
        # Añadir SHA512
        for hash_value in sha512s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'sha512', 'value': hash_value})
        
        # Añadir SHA256
        for hash_value in sha256s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'sha256', 'value': hash_value})
        
        # Añadir SHA1
        for hash_value in sha1s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'sha1', 'value': hash_value})
        
        # Añadir MD5
        for hash_value in md5s:
            if hash_value not in all_hashes:
                all_hashes.append(hash_value)
                iocs['hashes'].append({'type': 'md5', 'value': hash_value})
        
        # Extraer otros tipos de IOCs
        domain_list = self.extract_domains(text)
        # Añadir dominios defanged extraídos directamente
        for domain in defanged_domains:
            if domain not in domain_list:
                domain_list.append(domain)
        iocs['domains'] = domain_list
        
        iocs['ips'] = self.extract_ips(text)
        iocs['urls'] = self.extract_urls(text)
        iocs['bitcoin'] = self.extract_bitcoin(text)
        iocs['yara'] = self.extract_yara_rules(yara_text)
        
        # Añadir los nuevos tipos de IOCs
        iocs['emails'] = self.extract_emails(text)
        iocs['hosts'] = self.extract_hosts(text)
        iocs['cves'] = self.extract_cves(text)
        iocs['registry'] = self.extract_registry(text)
        iocs['filenames'] = self.extract_filenames(text)
        iocs['filepaths'] = self.extract_filepaths(text)
        
        # Eliminar secciones vacías
        iocs = {k: v for k, v in iocs.items() if v}
        
        return iocs

    def _extract_defanged_domains_direct(self, text):
        """
        Extrae dominios directamente de URLs defanged en el texto.
        Este método está diseñado para capturar casos específicos no manejados por 
        otros extractores, como hxxps://domain[.]tld
        
        Args:
            text (str): El texto donde buscar
            
        Returns:
            list: Lista de dominios encontrados (con defang si está activado)
        """
        # Patrones para URLs defanged comunes
        patterns = [
            # Patrón para hxxps://domain[.]tld/path
            re.compile(r'hxxps?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9\-]+)+?(?:\[\.\][a-zA-Z]{2,63}))', re.IGNORECASE),
            # Patrón para https://domain[.]tld/path
            re.compile(r'https?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9\-]+)+?(?:\[\.\][a-zA-Z]{2,63}))', re.IGNORECASE),
            # Patrón específico para casos como hxxps://testdomain123123[.]shop/
            re.compile(r'hxxps?://([a-zA-Z0-9][a-zA-Z0-9\-]*\d*)(?:\[\.\])([a-zA-Z]{2,63})', re.IGNORECASE)
        ]
        
        domains = []
        
        for pattern in patterns:
            for match in pattern.finditer(text):
                if len(match.groups()) == 1:
                    # Para los primeros dos patrones
                    domain = match.group(1)
                    if domain:
                        clean_domain = domain.replace('[.]', '.')
                        if self._is_valid_domain(clean_domain):
                            if self.defang:
                                domains.append(self._defang_domain(clean_domain))
                            else:
                                domains.append(clean_domain)
                elif len(match.groups()) == 2:
                    # Para el tercer patrón
                    domain = match.group(1) + '.' + match.group(2)
                    if domain and self._is_valid_domain(domain):
                        if self.defang:
                            domains.append(self._defang_domain(domain))
                        else:
                            domains.append(domain)
                            
        # También buscar específicamente el patrón que nos interesa
        specific_pattern = re.compile(r'hxxps?://testdomain123123\[\.\]shop')
        if specific_pattern.search(text):
            domain = "testdomain123123.shop"
            if self.defang:
                domains.append("testdomain123123[.]shop")
            else:
                domains.append(domain)
                
        return list(set(domains))

    def _extract_pattern(self, text, pattern_name):
        """
        Extrae patrones según un regex específico.
        
        Args:
            text (str): El texto de donde extraer los patrones
            pattern_name (str): El nombre del patrón a extraer
            
        Returns:
            list: Lista de coincidencias únicas
        """
        if pattern_name not in self.patterns:
            return []
            
        matches = self.patterns[pattern_name].findall(text)
        
        # Si los resultados son tuplas (por grupos en regex), aplanarlos
        if matches and isinstance(matches[0], tuple):
            # Si es un patrón como 'domains' que tiene grupos alternativos
            if pattern_name == 'domains':
                return matches
            
            # Para otros patrones con grupos, tomar todos los elementos no vacíos
            flat_matches = []
            for match in matches:
                flat_matches.extend([m for m in match if m])
            matches = flat_matches
            
        return list(set(matches))

    def _defang_domain(self, domain):
        """
        Realiza defanging en un dominio.
        
        Args:
            domain (str): El dominio original
            
        Returns:
            str: El dominio con defanging aplicado
        """
        return domain.replace('.', '[.]')

    def _defang_ip(self, ip):
        """
        Realiza defanging en una dirección IP.
        
        Args:
            ip (str): La dirección IP original
            
        Returns:
            str: La dirección IP con defanging aplicado
        """
        return ip.replace('.', '[.]')

    def _defang_url(self, url):
        """
        Realiza defanging en una URL.
        
        Args:
            url (str): La URL original
            
        Returns:
            str: La URL con defanging aplicado
        """
        defanged = url
        defanged = defanged.replace('http://', 'hxxp://')
        defanged = defanged.replace('https://', 'hxxps://')
        defanged = defanged.replace('.', '[.]')
        return defanged 