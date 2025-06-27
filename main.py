#!/usr/bin/env python3
"""
TinyCTI - Framework modulaire léger de collecte et publication d'IOCs
Architecture respectant le cahier des charges technique
"""

import os
import sys
import json
import csv
import yaml
import logging
import hashlib
import re
import time
import random
import sqlite3
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from urllib.parse import urlparse
import importlib.util
import traceback
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Bibliothèques externes
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    import feedparser
    import iocextract
    import stix2
    import taxii2client
    from cerberus import Validator
    from flask import Flask, jsonify, request, render_template_string
    from werkzeug.serving import make_server
except ImportError as e:
    print(f"Erreur d'import: {e}")
    print("Installez les dépendances: pip install requests feedparser iocextract stix2 taxii2-client cerberus flask")
    sys.exit(1)

# ===============================
# CONFIGURATION ET VALIDATION
# ===============================

class ConfigurationError(Exception):
    """Erreur de configuration"""
    pass

class ConfigurationLoader:
    """Gestionnaire de configuration centralisé"""
    
    SCHEMA = {
        'feeds': {
            'type': 'list',
            'required': True,
            'schema': {
                'type': 'dict',
                'schema': {
                    'name': {'type': 'string', 'required': True},
                    'type': {'type': 'string', 'required': True, 'allowed': ['text', 'csv', 'json', 'stix', 'taxii', 'rss']},
                    'url': {'type': 'string', 'required': True},
                    'enabled': {'type': 'boolean', 'default': True},
                    'retention': {'type': 'string', 'default': 'live', 'allowed': ['live', 'chaud', 'tiede', 'froid']},
                    'api_keys': {'type': 'list', 'default': []},
                    'delimiter': {'type': 'string', 'default': ','},
                    'encoding': {'type': 'string', 'default': 'utf-8'},
                    'column': {'type': ['string', 'integer'], 'default': 0},
                    'has_header': {'type': 'boolean', 'default': True},
                    'json_path': {'type': 'list', 'default': []},
                    'timeout': {'type': 'integer', 'default': 30},
                    'max_retries': {'type': 'integer', 'default': 3},
                    # Champs TAXII
                    'collection_id': {'type': 'string'},
                    'limit': {'type': 'integer', 'default': 100},
                    'username': {'type': 'string'},
                    'password': {'type': 'string'},
                    # Champs RSS
                    'max_entries': {'type': 'integer', 'default': 100},
                    # Planification par flux
                    'schedule': {'type': 'string', 'default': '1h'},  # Ex: "30m", "2h", "1d"
                    'priority': {'type': 'integer', 'default': 5, 'min': 1, 'max': 10},  # 1=haute, 10=basse
                    'rate_limit': {'type': 'integer', 'default': 0},  # Secondes entre requêtes
                    # Options CSV avancées
                    'auto_detect_column': {'type': 'boolean', 'default': False},  # Auto-détection de la meilleure colonne
                    'skip_malformed_lines': {'type': 'boolean', 'default': True},  # Ignore les lignes malformées
                    'min_columns': {'type': 'integer', 'default': 0},  # Nombre minimum de colonnes requis
                }
            }
        },
        'output_dir': {'type': 'string', 'default': 'iocs'},
        'max_file_size': {'type': 'integer', 'default': 10485760},
        'parallel_feeds': {'type': 'boolean', 'default': False},
        'max_workers': {'type': 'integer', 'default': 4},
        'daemon': {
            'type': 'dict',
            'default': {
                'enabled': False,
                'default_schedule': '1h',
                'check_interval': '60s',
                'max_concurrent_feeds': 3
            }
        },
        'retention_policy': {
            'type': 'dict',
            'default': {
                'live_to_chaud': '24h',
                'chaud_to_tiede': '7d',
                'tiede_to_froid': '30d',
                'froid_retention': '365d'
            }
        },
        'logging': {
            'type': 'dict',
            'default': {
                'level': 'INFO',
                'file': 'tinycti.log',
                'max_size': '10MB',
                'backup_count': 5
            }
        },
        'security': {
            'type': 'dict',
            'default': {
                'max_file_size': 52428800,
                'max_json_depth': 10,
                'validate_ssl': True,
                'user_agent': 'TinyCTI/1.0'
            }
        },
        'api': {
            'type': 'dict',
            'default': {
                'enabled': False,
                'host': '127.0.0.1',
                'port': 5000,
                'auto_export_ngfw': True
            }
        },
        'ngfw_export': {
            'type': 'dict',
            'default': {
                'enabled': True,
                'output_dir': 'ngfw',
                'auto_export_after_collection': True,
                'generate_pfsense_aliases': True,
                'generate_iptables_rules': True
            }
        }
    }
    
    def __init__(self, config_file: str):
        self.config_file = Path(config_file)
        self.config = None
        self.logger = logging.getLogger(f'{__name__}.ConfigLoader')
    
    def load_config(self) -> Dict[str, Any]:
        """Charge et valide la configuration"""
        try:
            if not self.config_file.exists():
                raise ConfigurationError(f"Fichier de configuration non trouvé: {self.config_file}")
            
            with open(self.config_file, 'r', encoding='utf-8') as f:
                raw_config = yaml.safe_load(f)
            
            if not raw_config:
                raise ConfigurationError("Fichier de configuration vide")
            
            # Validation avec Cerberus
            validator = Validator(self.SCHEMA)
            if not validator.validate(raw_config):
                errors = self._format_validation_errors(validator.errors)
                raise ConfigurationError(f"Configuration invalide:\n{errors}")
            
            self.config = validator.normalized(raw_config)
            self._validate_business_rules()
            
            self.logger.info(f"Configuration chargée: {len(self.config['feeds'])} flux définis")
            return self.config
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Erreur de syntaxe YAML: {e}")
        except Exception as e:
            raise ConfigurationError(f"Erreur lors du chargement de la configuration: {e}")
    
    def _format_validation_errors(self, errors: Dict) -> str:
        """Formate les erreurs de validation"""
        formatted = []
        for field, error_list in errors.items():
            if isinstance(error_list, list):
                for error in error_list:
                    formatted.append(f"  - {field}: {error}")
            else:
                formatted.append(f"  - {field}: {error_list}")
        return "\n".join(formatted)
    
    def _validate_business_rules(self):
        """Valide les règles métier spécifiques"""
        # Vérifier l'unicité des noms de flux
        feed_names = [feed['name'] for feed in self.config['feeds']]
        if len(feed_names) != len(set(feed_names)):
            raise ConfigurationError("Les noms de flux doivent être uniques")
        
        # Vérifier les URLs
        for feed in self.config['feeds']:
            url = feed['url']
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ConfigurationError(f"URL invalide pour le flux '{feed['name']}': {url}")

# ===============================
# GESTION DES CLÉS API
# ===============================

class APIKeyManager:
    """Gestionnaire des clés API avec rotation automatique"""
    
    def __init__(self):
        self.key_status: Dict[str, Dict] = {}
        self.key_usage: Dict[str, int] = {}
        self.logger = logging.getLogger(f'{__name__}.APIKeyManager')
        self._lock = threading.Lock()
    
    def add_keys(self, feed_name: str, keys: List[str]):
        """Ajoute des clés API pour un flux"""
        with self._lock:
            for key in keys:
                key_id = self._get_key_id(key)
                self.key_status[key_id] = {
                    'key': key,
                    'feed': feed_name,
                    'active': True,
                    'last_used': None,
                    'error_count': 0,
                    'rate_limited_until': None
                }
                self.key_usage[key_id] = 0
    
    def get_key(self, feed_name: str) -> Optional[str]:
        """Récupère une clé API disponible pour un flux"""
        with self._lock:
            available_keys = []
            
            for key_id, status in self.key_status.items():
                if (status['feed'] == feed_name and 
                    status['active'] and 
                    self._is_key_available(status)):
                    available_keys.append((key_id, status))
            
            if not available_keys:
                self.logger.warning(f"Aucune clé API disponible pour le flux {feed_name}")
                return None
            
            # Sélectionne la clé la moins utilisée
            key_id, status = min(available_keys, key=lambda x: self.key_usage[x[0]])
            self.key_usage[key_id] += 1
            status['last_used'] = datetime.now()
            
            self.logger.debug(f"Clé API sélectionnée pour {feed_name}: {self._get_key_id(status['key'])}")
            return status['key']
    
    def report_key_error(self, key: str, error_type: str, retry_after: Optional[int] = None):
        """Signale une erreur pour une clé API"""
        key_id = self._get_key_id(key)
        
        with self._lock:
            if key_id in self.key_status:
                status = self.key_status[key_id]
                status['error_count'] += 1
                
                if error_type == 'rate_limit' and retry_after:
                    status['rate_limited_until'] = datetime.now() + timedelta(seconds=retry_after)
                    self.logger.warning(f"Clé API {key_id} limitée jusqu'à {status['rate_limited_until']}")
                
                elif error_type == 'invalid':
                    status['active'] = False
                    self.logger.error(f"Clé API {key_id} désactivée (invalide)")
                
                elif status['error_count'] >= 5:
                    status['active'] = False
                    self.logger.error(f"Clé API {key_id} désactivée (trop d'erreurs)")
    
    def _get_key_id(self, key: str) -> str:
        """Génère un ID anonymisé pour une clé"""
        return f"key_{hashlib.md5(key.encode()).hexdigest()[:8]}"
    
    def _is_key_available(self, status: Dict) -> bool:
        """Vérifie si une clé est disponible"""
        if status['rate_limited_until']:
            return datetime.now() > status['rate_limited_until']
        return True

# ===============================
# GESTION DES IOCs
# ===============================

class IOCType(Enum):
    """Types d'IOCs supportés"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA512 = "hash_sha512"
    EMAIL = "email"

class RetentionBucket(Enum):
    """Buckets de rétention"""
    LIVE = "live"
    CHAUD = "chaud"
    TIEDE = "tiede"
    FROID = "froid"

@dataclass
class IOC:
    """Représente un IOC avec ses métadonnées"""
    value: str
    type: IOCType
    source: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    retention: RetentionBucket = RetentionBucket.LIVE
    confidence: float = 1.0
    
    def __hash__(self):
        return hash((self.value, self.type))
    
    def __eq__(self, other):
        if not isinstance(other, IOC):
            return False
        return self.value == other.value and self.type == other.type

class IOCClassificationError(Exception):
    """Erreur de classification d'IOC"""
    pass

class IOCClassifier:
    """Classificateur d'IOCs avec validation avancée"""
    
    # Patterns regex stricts pour éviter les faux positifs
    PATTERNS = {
        IOCType.IPV4: re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
        IOCType.IPV6: re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'),
        IOCType.DOMAIN: re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'),
        IOCType.URL: re.compile(r'^https?://[^\s<>"\']+$'),
        IOCType.HASH_MD5: re.compile(r'^[a-fA-F0-9]{32}$'),
        IOCType.HASH_SHA1: re.compile(r'^[a-fA-F0-9]{40}$'),
        IOCType.HASH_SHA256: re.compile(r'^[a-fA-F0-9]{64}$'),
        IOCType.HASH_SHA512: re.compile(r'^[a-fA-F0-9]{128}$'),
        IOCType.EMAIL: re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    }
    
    # IPs privées à exclure
    PRIVATE_IP_PATTERNS = [
        re.compile(r'^10\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
        re.compile(r'^127\.'),
        re.compile(r'^169\.254\.'),
        re.compile(r'^224\.'),  # Multicast
        re.compile(r'^0\.0\.0\.0$'),
        re.compile(r'^255\.255\.255\.255$')
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(f'{__name__}.IOCClassifier')
        self.stats = {
            'classified': 0,
            'rejected': 0,
            'errors': 0
        }
    
    def classify_ioc(self, value: str) -> Optional[IOCType]:
        """Classifie un IOC et retourne son type"""
        if not value or not isinstance(value, str):
            return None
        
        try:
            value = value.strip().lower()
            
            # Validation de longueur
            if len(value) > 2048:  # Protection contre les données trop longues
                self.logger.warning(f"IOC trop long ignoré: {len(value)} caractères")
                return None
            
            # Test avec iocextract d'abord
            ioc_type = self._classify_with_iocextract(value)
            if ioc_type:
                return ioc_type
            
            # Fallback sur les regex
            for ioc_type, pattern in self.PATTERNS.items():
                if pattern.match(value):
                    if ioc_type == IOCType.IPV4 and self._is_private_ip(value):
                        continue
                    self.stats['classified'] += 1
                    return ioc_type
            
            self.stats['rejected'] += 1
            return None
            
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Erreur lors de la classification de '{value}': {e}")
            return None
    
    def _classify_with_iocextract(self, value: str) -> Optional[IOCType]:
        """Classification avec iocextract"""
        try:
            # Test chaque type d'IOC
            if list(iocextract.extract_ipv4s([value])):
                return IOCType.IPV4 if not self._is_private_ip(value) else None
            
            if list(iocextract.extract_ipv6s([value])):
                return IOCType.IPV6
            
            if list(iocextract.extract_domains([value])):
                return IOCType.DOMAIN
            
            if list(iocextract.extract_urls([value])):
                return IOCType.URL
            
            if list(iocextract.extract_hashes([value])):
                if len(value) == 32:
                    return IOCType.HASH_MD5
                elif len(value) == 40:
                    return IOCType.HASH_SHA1
                elif len(value) == 64:
                    return IOCType.HASH_SHA256
                elif len(value) == 128:
                    return IOCType.HASH_SHA512
            
            if list(iocextract.extract_emails([value])):
                return IOCType.EMAIL
                
        except Exception:
            pass
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée"""
        for pattern in self.PRIVATE_IP_PATTERNS:
            if pattern.match(ip):
                return True
        return False
    
    def extract_iocs_from_text(self, text: str) -> List[str]:
        """Extrait tous les IOCs d'un texte"""
        if not text:
            return []
        
        iocs = set()
        
        try:
            # Limite la taille du texte pour éviter les problèmes de mémoire
            if len(text) > 1024 * 1024:  # 1MB
                self.logger.warning("Texte trop long, troncature à 1MB")
                text = text[:1024 * 1024]
            
            # Extraction avec iocextract
            iocs.update(iocextract.extract_ipv4s([text]))
            iocs.update(iocextract.extract_ipv6s([text]))
            iocs.update(iocextract.extract_domains([text]))
            iocs.update(iocextract.extract_urls([text]))
            iocs.update(iocextract.extract_hashes([text]))
            iocs.update(iocextract.extract_emails([text]))
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'extraction d'IOCs: {e}")
        
        return list(iocs)
    
    def get_stats(self) -> Dict[str, int]:
        """Retourne les statistiques de classification"""
        return self.stats.copy()

# ===============================
# GESTION DES PLUGINS
# ===============================

class PluginError(Exception):
    """Erreur de plugin"""
    pass

class BasePlugin(ABC):
    """Classe de base pour tous les plugins"""
    
    def __init__(self, config: Dict[str, Any], name: str, api_manager: APIKeyManager):
        self.config = config
        self.name = name
        self.api_manager = api_manager
        self.logger = logging.getLogger(f'{__name__}.Plugin.{name}')
        self.session = self._create_session()
        
        # Statistiques du plugin
        self.stats = {
            'requests_made': 0,
            'bytes_downloaded': 0,
            'iocs_extracted': 0,
            'errors': 0,
            'retries': 0
        }
    
    def _create_session(self) -> requests.Session:
        """Crée une session HTTP avec retry automatique"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config.get('max_retries', 3),
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    @abstractmethod
    def collect(self) -> str:
        """Collecte les données brutes depuis la source"""
        pass
    
    @abstractmethod
    def parse(self, raw_data: str) -> List[IOC]:
        """Parse les données brutes et retourne une liste d'IOCs"""
        pass
    
    def validate_config(self) -> bool:
        """Valide la configuration du plugin"""
        required_fields = ['url']
        for field in required_fields:
            if field not in self.config:
                raise PluginError(f"Champ obligatoire manquant: {field}")
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du plugin"""
        return self.stats.copy()

class HTTPPlugin(BasePlugin):
    """Plugin de base pour les sources HTTP"""
    
    def _make_request(self, url: str, **kwargs) -> requests.Response:
        """Effectue une requête HTTP avec gestion d'erreurs"""
        headers = kwargs.get('headers', {})
        
        # Ajoute une clé API si disponible
        api_key = self.api_manager.get_key(self.name)
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        # Headers par défaut
        headers.setdefault('User-Agent', 'TinyCTI/1.0')
        
        try:
            self.stats['requests_made'] += 1
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.config.get('timeout', 30),
                **kwargs
            )
            
            # Gestion des erreurs d'API
            if response.status_code == 401 and api_key:
                self.api_manager.report_key_error(api_key, 'invalid')
                raise PluginError(f"Clé API invalide pour {self.name}")
            
            elif response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                if api_key:
                    self.api_manager.report_key_error(api_key, 'rate_limit', retry_after)
                raise PluginError(f"Limite de taux atteinte pour {self.name}, retry après {retry_after}s")
            
            response.raise_for_status()
            self.stats['bytes_downloaded'] += len(response.content)
            
            return response
            
        except requests.exceptions.Timeout:
            self.stats['errors'] += 1
            raise PluginError(f"Timeout lors de la requête vers {url}")
        
        except requests.exceptions.ConnectionError:
            self.stats['errors'] += 1
            raise PluginError(f"Erreur de connexion vers {url}")
        
        except requests.exceptions.HTTPError as e:
            self.stats['errors'] += 1
            raise PluginError(f"Erreur HTTP {e.response.status_code}: {e}")
        
        except Exception as e:
            self.stats['errors'] += 1
            raise PluginError(f"Erreur lors de la requête: {e}")

class TextPlugin(HTTPPlugin):
    """Plugin pour les flux texte brut"""
    
    def collect(self) -> str:
        """Collecte depuis une URL texte"""
        url = self.config['url']
        response = self._make_request(url)
        return response.text
    
    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le texte brut et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier()
        
        try:
            lines = raw_data.split('\n')
            self.logger.debug(f"Traitement de {len(lines)} lignes")
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Ignore les lignes vides et les commentaires
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                # Limite la longueur des lignes
                if len(line) > 2048:
                    self.logger.warning(f"Ligne {line_num} trop longue, ignorée")
                    continue
                
                # Classification directe de la ligne
                ioc_type = classifier.classify_ioc(line)
                if ioc_type:
                    ioc = IOC(
                        value=line.lower(),
                        type=ioc_type,
                        source=self.name,
                        retention=RetentionBucket(self.config.get('retention', 'live'))
                    )
                    iocs.append(ioc)
                else:
                    # Extraction d'IOCs multiples dans la ligne
                    extracted = classifier.extract_iocs_from_text(line)
                    for value in extracted:
                        ioc_type = classifier.classify_ioc(value)
                        if ioc_type:
                            ioc = IOC(
                                value=value.lower(),
                                type=ioc_type,
                                source=self.name,
                                retention=RetentionBucket(self.config.get('retention', 'live'))
                            )
                            iocs.append(ioc)
            
            self.stats['iocs_extracted'] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")
            
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Erreur lors du parsing texte: {e}")
            raise PluginError(f"Erreur de parsing: {e}")
        
        return iocs

class CSVPlugin(HTTPPlugin):
    """Plugin pour les flux CSV avec gestion robuste des erreurs"""
    
    def collect(self) -> str:
        """Collecte depuis une URL CSV"""
        url = self.config['url']
        response = self._make_request(url)
        return response.text
    
    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le CSV et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier()
        
        try:
            # Configuration CSV
            delimiter = self.config.get('delimiter', ',')
            encoding = self.config.get('encoding', 'utf-8')
            column = self.config.get('column', 0)
            has_header = self.config.get('has_header', True)
            
            # Validation des paramètres
            if delimiter not in [',', ';', '\t', '|']:
                raise PluginError(f"Délimiteur CSV non supporté: {delimiter}")
            
            lines = raw_data.splitlines()
            if not lines:
                raise PluginError("Fichier CSV vide")
            
            # Protection contre les fichiers trop gros
            if len(lines) > 100000:
                self.logger.warning(f"Fichier CSV très volumineux ({len(lines)} lignes), traitement des 100000 premières")
                lines = lines[:100000]
            
            reader = csv.reader(lines, delimiter=delimiter)
            
            header = None
            if has_header:
                try:
                    header = next(reader)
                    self.logger.debug(f"En-têtes CSV détectés: {header}")
                    # Analyse de la structure
                    self._analyze_csv_structure(header, lines[:10], delimiter)
                except StopIteration:
                    raise PluginError("Fichier CSV vide ou mal formaté")
            
            # Détermine l'index de la colonne
            col_index = self._get_column_index(column, header)
            
            # Auto-détection de colonne si demandée
            if self.config.get('auto_detect_column', False):
                col_index = self._auto_detect_best_column(lines[:50], delimiter, has_header, classifier)
                self.logger.info(f"Auto-détection: utilisation de la colonne {col_index}")
            
            # Option pour ignorer les lignes malformées
            skip_malformed = self.config.get('skip_malformed_lines', True)
            min_columns = self.config.get('min_columns', 0)
            
            # Statistiques d'erreurs pour éviter le spam de logs
            error_stats = {
                'lines_processed': 0,
                'lines_skipped': 0,
                'column_missing': 0,
                'empty_values': 0,
                'invalid_iocs': 0,
                'last_error_line': 0
            }
            
            for row_num, row in enumerate(reader, 2 if has_header else 1):
                error_stats['lines_processed'] += 1
                
                if not row:
                    error_stats['lines_skipped'] += 1
                    continue
                
                try:
                    # Sécurité: vérifie la longueur des cellules
                    for i, cell in enumerate(row):
                        if len(cell) > 2048:
                            self.logger.warning(f"Cellule trop longue ligne {row_num}, colonne {i}, troncature")
                            row[i] = cell[:2048]
                    
                    # Vérifie si la colonne existe
                    if col_index >= len(row):
                        error_stats['column_missing'] += 1
                        error_stats['last_error_line'] = row_num
                        
                        # Log groupé seulement pour les premières erreurs
                        if error_stats['column_missing'] <= 5:
                            self.logger.warning(f"Ligne {row_num}: colonne {col_index} inexistante (ligne a {len(row)} colonnes)")
                        elif error_stats['column_missing'] == 6:
                            self.logger.warning("Trop d'erreurs de colonnes manquantes, suppression des logs suivants...")
                        
                        # Ignore la ligne si skip_malformed est activé
                        if skip_malformed:
                            continue
                        else:
                            # Essaie avec une colonne alternative (dernière colonne disponible)
                            if len(row) > 0:
                                col_index_alt = len(row) - 1
                                ioc_value = row[col_index_alt].strip()
                                if ioc_value:
                                    self.logger.debug(f"Utilisation colonne alternative {col_index_alt} pour ligne {row_num}")
                                else:
                                    continue
                            else:
                                continue
                    else:
                        # Récupère la valeur IOC normalement
                        ioc_value = row[col_index].strip()
                    
                    # Vérifie le nombre minimum de colonnes si spécifié
                    if min_columns > 0 and len(row) < min_columns:
                        error_stats['lines_skipped'] += 1
                        continue
                    if not ioc_value:
                        error_stats['empty_values'] += 1
                        continue
                    
                    # Classifie l'IOC
                    ioc_type = classifier.classify_ioc(ioc_value)
                    if ioc_type:
                        ioc = IOC(
                            value=ioc_value.lower(),
                            type=ioc_type,
                            source=self.name,
                            retention=RetentionBucket(self.config.get('retention', 'live'))
                        )
                        iocs.append(ioc)
                    else:
                        error_stats['invalid_iocs'] += 1
                    
                except Exception as e:
                    error_stats['lines_skipped'] += 1
                    if error_stats['lines_skipped'] <= 3:
                        self.logger.warning(f"Erreur ligne {row_num}: {e}")
                    continue
            
            # Log final des statistiques d'erreurs
            self._log_csv_statistics(error_stats)
            
            self.stats['iocs_extracted'] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")
            
        except csv.Error as e:
            self.stats['errors'] += 1
            raise PluginError(f"Erreur de format CSV: {e}")
        
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Erreur lors du parsing CSV: {e}")
            raise PluginError(f"Erreur de parsing: {e}")
        
        return iocs
    
    def _analyze_csv_structure(self, header: List[str], sample_lines: List[str], delimiter: str):
        """Analyse la structure du CSV pour détecter les problèmes"""
        try:
            self.logger.debug(f"Analyse de la structure CSV avec délimiteur '{delimiter}'")
            
            if header:
                self.logger.debug(f"Nombre de colonnes d'en-tête: {len(header)}")
                for i, col_name in enumerate(header):
                    self.logger.debug(f"  Colonne {i}: '{col_name}'")
            
            # Analyse quelques lignes d'exemple
            column_counts = []
            for line in sample_lines[1:6]:  # Skip header
                if line.strip():
                    try:
                        row = next(csv.reader([line], delimiter=delimiter))
                        column_counts.append(len(row))
                    except:
                        continue
            
            if column_counts:
                min_cols = min(column_counts)
                max_cols = max(column_counts)
                avg_cols = sum(column_counts) / len(column_counts)
                
                self.logger.debug(f"Analyse des colonnes - Min: {min_cols}, Max: {max_cols}, Moyenne: {avg_cols:.1f}")
                
                # Avertissement si structure incohérente
                if max_cols - min_cols > 2:
                    self.logger.warning(f"Structure CSV incohérente: {min_cols}-{max_cols} colonnes par ligne")
                
                # Recommandation pour la colonne cible
                target_column = self.config.get('column', 0)
                if isinstance(target_column, int) and target_column >= min_cols:
                    self.logger.warning(f"Colonne cible {target_column} peut être absente de certaines lignes (min colonnes: {min_cols})")
                    
                    # Suggère une colonne alternative si possible
                    if min_cols > 0:
                        suggested_col = min(target_column, min_cols - 1)
                        if suggested_col != target_column:
                            self.logger.info(f"Suggestion: utiliser la colonne {suggested_col} pour plus de compatibilité")
        
        except Exception as e:
            self.logger.warning(f"Impossible d'analyser la structure CSV: {e}")
    
    def _auto_detect_best_column(self, sample_lines: List[str], delimiter: str, has_header: bool, classifier: IOCClassifier) -> int:
        """Auto-détecte la meilleure colonne contenant des IOCs"""
        try:
            self.logger.info("Auto-détection de la meilleure colonne pour les IOCs...")
            
            reader = csv.reader(sample_lines, delimiter=delimiter)
            
            # Skip header si présent
            if has_header:
                header = next(reader, None)
                self.logger.debug(f"En-têtes pour auto-détection: {header}")
            
            # Analyse chaque colonne
            column_scores = {}
            sample_rows = list(reader)[:20]  # Analyse 20 lignes max
            
            if not sample_rows:
                self.logger.warning("Pas assez de données pour l'auto-détection, utilisation colonne 0")
                return 0
            
            # Détermine le nombre max de colonnes
            max_columns = max(len(row) for row in sample_rows if row)
            
            for col_idx in range(max_columns):
                valid_iocs = 0
                total_values = 0
                
                for row in sample_rows:
                    if col_idx < len(row):
                        value = row[col_idx].strip()
                        if value and not value.startswith('#'):
                            total_values += 1
                            if classifier.classify_ioc(value):
                                valid_iocs += 1
                
                # Score = pourcentage d'IOCs valides
                if total_values > 0:
                    score = (valid_iocs / total_values) * 100
                    column_scores[col_idx] = {
                        'score': score,
                        'valid_iocs': valid_iocs,
                        'total_values': total_values
                    }
                    
                    self.logger.debug(f"Colonne {col_idx}: {valid_iocs}/{total_values} IOCs valides ({score:.1f}%)")
            
            if not column_scores:
                self.logger.warning("Aucune colonne avec des IOCs détectée, utilisation colonne 0")
                return 0
            
            # Sélectionne la colonne avec le meilleur score
            best_col = max(column_scores.keys(), key=lambda k: column_scores[k]['score'])
            best_score = column_scores[best_col]
            
            self.logger.info(f"Meilleure colonne détectée: {best_col} ({best_score['valid_iocs']}/{best_score['total_values']} IOCs, {best_score['score']:.1f}%)")
            
            return best_col
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'auto-détection: {e}")
            return 0
    
    def analyze_csv_structure(self) -> Dict[str, Any]:
        """Analyse complète de la structure CSV (méthode utilitaire)"""
        try:
            # Collecte un échantillon de données
            raw_data = self.collect()
            lines = raw_data.splitlines()[:100]  # Analyse les 100 premières lignes
            
            delimiter = self.config.get('delimiter', ',')
            has_header = self.config.get('has_header', True)
            
            reader = csv.reader(lines, delimiter=delimiter)
            
            analysis = {
                'total_lines': len(lines),
                'delimiter': delimiter,
                'has_header': has_header,
                'columns': [],
                'recommendations': []
            }
            
            # Analyse l'en-tête
            if has_header:
                header = next(reader, None)
                if header:
                    analysis['header'] = header
                    analysis['num_columns'] = len(header)
            
            # Analyse quelques lignes de données
            data_rows = []
            for i, row in enumerate(reader):
                if i >= 20:  # Limite à 20 lignes
                    break
                if row:
                    data_rows.append(row)
            
            if data_rows:
                # Statistiques des colonnes
                max_cols = max(len(row) for row in data_rows)
                min_cols = min(len(row) for row in data_rows)
                
                analysis['min_columns'] = min_cols
                analysis['max_columns'] = max_cols
                analysis['consistent_structure'] = (max_cols == min_cols)
                
                # Analyse chaque colonne
                classifier = IOCClassifier()
                for col_idx in range(max_cols):
                    col_analysis = {
                        'index': col_idx,
                        'name': header[col_idx] if has_header and col_idx < len(header) else f'Column_{col_idx}',
                        'sample_values': [],
                        'ioc_count': 0,
                        'total_values': 0,
                        'ioc_types': set()
                    }
                    
                    for row in data_rows[:10]:  # Échantillon de 10 lignes
                        if col_idx < len(row):
                            value = row[col_idx].strip()
                            if value:
                                col_analysis['sample_values'].append(value)
                                col_analysis['total_values'] += 1
                                
                                ioc_type = classifier.classify_ioc(value)
                                if ioc_type:
                                    col_analysis['ioc_count'] += 1
                                    col_analysis['ioc_types'].add(ioc_type.value)
                    
                    col_analysis['ioc_types'] = list(col_analysis['ioc_types'])
                    col_analysis['ioc_percentage'] = (col_analysis['ioc_count'] / col_analysis['total_values'] * 100) if col_analysis['total_values'] > 0 else 0
                    
                    analysis['columns'].append(col_analysis)
                
                # Génère des recommandations
                best_ioc_column = max(analysis['columns'], key=lambda c: c['ioc_percentage']) if analysis['columns'] else None
                
                if best_ioc_column and best_ioc_column['ioc_percentage'] > 50:
                    analysis['recommendations'].append(f"Colonne recommandée: {best_ioc_column['index']} ('{best_ioc_column['name']}') - {best_ioc_column['ioc_percentage']:.1f}% d'IOCs")
                
                if not analysis['consistent_structure']:
                    analysis['recommendations'].append(f"Structure incohérente: {min_cols}-{max_cols} colonnes par ligne. Considérez skip_malformed_lines: true")
                
                if min_cols > 0:
                    analysis['recommendations'].append(f"Définir min_columns: {min_cols} pour filtrer les lignes incomplètes")
            
            return analysis
            
        except Exception as e:
            return {'error': f"Erreur d'analyse: {e}"}
    
    def _log_csv_statistics(self, error_stats: Dict[str, int]):
        """Log les statistiques d'erreurs de façon groupée"""
        total_processed = error_stats['lines_processed']
        
        if total_processed == 0:
            return
        
        self.logger.info(f"Statistiques de parsing CSV pour {self.name}:")
        self.logger.info(f"  Lignes traitées: {total_processed}")
        
        if error_stats['lines_skipped'] > 0:
            skip_percent = (error_stats['lines_skipped'] / total_processed) * 100
            self.logger.warning(f"  Lignes ignorées: {error_stats['lines_skipped']} ({skip_percent:.1f}%)")
        
        if error_stats['column_missing'] > 0:
            col_percent = (error_stats['column_missing'] / total_processed) * 100
            self.logger.warning(f"  Colonnes manquantes: {error_stats['column_missing']} ({col_percent:.1f}%) - Dernière ligne: {error_stats['last_error_line']}")
        
        if error_stats['empty_values'] > 0:
            empty_percent = (error_stats['empty_values'] / total_processed) * 100
            self.logger.info(f"  Valeurs vides ignorées: {error_stats['empty_values']} ({empty_percent:.1f}%)")
        
        if error_stats['invalid_iocs'] > 0:
            invalid_percent = (error_stats['invalid_iocs'] / total_processed) * 100
            self.logger.info(f"  IOCs invalides: {error_stats['invalid_iocs']} ({invalid_percent:.1f}%)")
    
    def _get_column_index(self, column: Union[str, int], header: Optional[List[str]]) -> int:
        """Détermine l'index de la colonne avec validation améliorée"""
        if isinstance(column, int):
            if column < 0:
                raise PluginError("L'index de colonne ne peut pas être négatif")
            return column
        
        elif isinstance(column, str) and header:
            try:
                return header.index(column)
            except ValueError:
                # Recherche insensible à la casse
                for i, col_name in enumerate(header):
                    if col_name.lower() == column.lower():
                        self.logger.info(f"Colonne trouvée avec correspondance insensible à la casse: '{column}' -> index {i}")
                        return i
                
                # Recherche partielle
                for i, col_name in enumerate(header):
                    if column.lower() in col_name.lower():
                        self.logger.info(f"Colonne trouvée avec correspondance partielle: '{column}' dans '{col_name}' -> index {i}")
                        return i
                
                raise PluginError(f"Colonne '{column}' non trouvée dans l'en-tête. Colonnes disponibles: {header}")
        
        else:
            raise PluginError("Impossible de déterminer l'index de la colonne")

class JSONPlugin(HTTPPlugin):
    """Plugin pour les flux JSON"""
    
    def collect(self) -> str:
        """Collecte depuis une API JSON"""
        url = self.config['url']
        response = self._make_request(url)
        return response.text
    
    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le JSON et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier()
        
        try:
            # Limite la taille des données JSON
            if len(raw_data) > 50 * 1024 * 1024:  # 50MB
                raise PluginError("Fichier JSON trop volumineux (> 50MB)")
            
            data = json.loads(raw_data)
            
            # Chemin d'accès aux IOCs dans le JSON
            json_path = self.config.get('json_path', [])
            
            # Navigue dans la structure JSON
            current = data
            for key in json_path:
                if isinstance(current, dict):
                    current = current.get(key, [])
                elif isinstance(current, list) and str(key).isdigit():
                    idx = int(key)
                    if 0 <= idx < len(current):
                        current = current[idx]
                    else:
                        current = []
                else:
                    current = []
                    break
            
            # Extrait les IOCs
            self._extract_iocs_from_json(current, classifier, iocs)
            
            self.stats['iocs_extracted'] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")
            
        except json.JSONDecodeError as e:
            self.stats['errors'] += 1
            raise PluginError(f"JSON invalide: {e}")
        
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Erreur lors du parsing JSON: {e}")
            raise PluginError(f"Erreur de parsing: {e}")
        
        return iocs
    
    def _extract_iocs_from_json(self, data: Any, classifier: IOCClassifier, iocs: List[IOC], depth: int = 0):
        """Extrait récursivement les IOCs d'une structure JSON"""
        # Protection contre les structures trop profondes
        if depth > 10:
            return
        
        if isinstance(data, str):
            # Classifie directement la chaîne
            ioc_type = classifier.classify_ioc(data)
            if ioc_type:
                ioc = IOC(
                    value=data.lower(),
                    type=ioc_type,
                    source=self.name,
                    retention=RetentionBucket(self.config.get('retention', 'live'))
                )
                iocs.append(ioc)
            else:
                # Extraction d'IOCs multiples dans la chaîne
                extracted = classifier.extract_iocs_from_text(data)
                for value in extracted:
                    ioc_type = classifier.classify_ioc(value)
                    if ioc_type:
                        ioc = IOC(
                            value=value.lower(),
                            type=ioc_type,
                            source=self.name,
                            retention=RetentionBucket(self.config.get('retention', 'live'))
                        )
                        iocs.append(ioc)
        
        elif isinstance(data, list):
            for item in data[:1000]:  # Limite à 1000 éléments
                self._extract_iocs_from_json(item, classifier, iocs, depth + 1)
        
        elif isinstance(data, dict):
            for key, value in list(data.items())[:100]:  # Limite à 100 clés
                self._extract_iocs_from_json(value, classifier, iocs, depth + 1)

class STIXPlugin(HTTPPlugin):
    """Plugin pour les flux STIX 2.x"""
    
    def collect(self) -> str:
        """Collecte depuis une source STIX"""
        url = self.config['url']
        response = self._make_request(url)
        return response.text
    
    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le STIX et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier()
        
        try:
            # Parse le bundle STIX
            bundle = stix2.parse(raw_data)
            
            if not hasattr(bundle, 'objects'):
                raise PluginError("Bundle STIX invalide: pas d'objets")
            
            for obj in bundle.objects:
                if obj.type == 'indicator' and hasattr(obj, 'pattern'):
                    try:
                        # Parse les patterns STIX
                        extracted_values = self._parse_stix_pattern(obj.pattern)
                        
                        for value in extracted_values:
                            ioc_type = classifier.classify_ioc(value)
                            if ioc_type:
                                ioc = IOC(
                                    value=value.lower(),
                                    type=ioc_type,
                                    source=self.name,
                                    retention=RetentionBucket(self.config.get('retention', 'live'))
                                )
                                iocs.append(ioc)
                    
                    except Exception as e:
                        self.logger.warning(f"Erreur lors du parsing du pattern STIX: {e}")
                        continue
            
            self.stats['iocs_extracted'] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")
            
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Erreur lors du parsing STIX: {e}")
            raise PluginError(f"Erreur de parsing STIX: {e}")
        
        return iocs
    
    def _parse_stix_pattern(self, pattern: str) -> List[str]:
        """Parse un pattern STIX et extrait les valeurs"""
        values = []
        
        # Patterns courants dans STIX
        patterns = [
            r"'([^']+)'",  # Valeurs entre guillemets simples
            r'"([^"]+)"',  # Valeurs entre guillemets doubles
        ]
        
        for regex in patterns:
            matches = re.findall(regex, pattern)
            values.extend(matches)
        
        return values

class RSSPlugin(HTTPPlugin):
    """Plugin pour les flux RSS"""
    
    def collect(self) -> str:
        """Collecte depuis un flux RSS"""
        url = self.config['url']
        response = self._make_request(url)
        return response.text
    
    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le RSS et extrait les IOCs du contenu"""
        iocs = []
        classifier = IOCClassifier()
        
        try:
            feed = feedparser.parse(raw_data)
            
            if feed.bozo and feed.bozo_exception:
                self.logger.warning(f"RSS mal formé: {feed.bozo_exception}")
            
            if not hasattr(feed, 'entries') or not feed.entries:
                raise PluginError("Flux RSS vide ou invalide")
            
            # Limite le nombre d'entrées à traiter
            max_entries = self.config.get('max_entries', 100)
            entries_to_process = feed.entries[:max_entries]
            
            for entry in entries_to_process:
                # Extrait le contenu textuel
                text_content = []
                
                if hasattr(entry, 'title') and entry.title:
                    text_content.append(entry.title)
                
                if hasattr(entry, 'description') and entry.description:
                    text_content.append(entry.description)
                
                if hasattr(entry, 'summary') and entry.summary:
                    text_content.append(entry.summary)
                
                # Combine tout le texte
                combined_text = ' '.join(text_content)
                
                if combined_text:
                    # Extrait les IOCs
                    extracted = classifier.extract_iocs_from_text(combined_text)
                    for value in extracted:
                        ioc_type = classifier.classify_ioc(value)
                        if ioc_type:
                            ioc = IOC(
                                value=value.lower(),
                                type=ioc_type,
                                source=self.name,
                                retention=RetentionBucket(self.config.get('retention', 'live'))
                            )
                            iocs.append(ioc)
            
            self.stats['iocs_extracted'] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")
            
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Erreur lors du parsing RSS: {e}")
            raise PluginError(f"Erreur de parsing RSS: {e}")
        
        return iocs

class TAXIIPlugin(BasePlugin):
    """Plugin pour les serveurs TAXII 2.x"""
    
    def __init__(self, config: Dict[str, Any], name: str, api_manager: APIKeyManager):
        super().__init__(config, name, api_manager)
        self.taxii_client = None
    
    def validate_config(self) -> bool:
        """Valide la configuration TAXII"""
        required_fields = ['url', 'collection_id']
        for field in required_fields:
            if field not in self.config:
                raise PluginError(f"Champ TAXII obligatoire manquant: {field}")
        return True
    
    def collect(self) -> str:
        """Collecte depuis un serveur TAXII"""
        try:
            # Initialise le client TAXII
            api_root_url = self.config['url']
            
            # Authentification
            username = self.config.get('username')
            password = self.config.get('password')
            api_key = self.api_manager.get_key(self.name)
            
            if api_key:
                # Authentification par clé API
                server = taxii2client.Server(api_root_url, headers={'Authorization': f'Bearer {api_key}'})
            elif username and password:
                # Authentification par login/password
                server = taxii2client.Server(api_root_url, user=username, password=password)
            else:
                # Pas d'authentification
                server = taxii2client.Server(api_root_url)
            
            # Récupère l'API root
            api_root = server.api_roots[0] if server.api_roots else server.default
            
            # Récupère la collection
            collection_id = self.config['collection_id']
            collection = None
            
            for coll in api_root.collections:
                if coll.id == collection_id:
                    collection = coll
                    break
            
            if not collection:
                raise PluginError(f"Collection TAXII non trouvée: {collection_id}")
            
            # Récupère les objets
            limit = self.config.get('limit', 100)
            objects = collection.get_objects(limit=limit)
            
            self.stats['requests_made'] += 1
            
            # Retourne les objets sous forme de bundle STIX
            if objects.get('objects'):
                bundle_data = {
                    'type': 'bundle',
                    'id': f'bundle--{time.time()}',
                    'objects': objects['objects']
                }
                return json.dumps(bundle_data)
            else:
                return '{"type": "bundle", "objects": []}'
            
        except Exception as e:
            self.stats['errors'] += 1
            self.logger.error(f"Erreur lors de la collecte TAXII: {e}")
            raise PluginError(f"Erreur TAXII: {e}")
    
    def parse(self, raw_data: str) -> List[IOC]:
        """Parse les données TAXII (utilise le parser STIX)"""
        # Délègue au plugin STIX
        stix_plugin = STIXPlugin(self.config, self.name, self.api_manager)
        return stix_plugin.parse(raw_data)

# ===============================
# GESTIONNAIRE DE PLUGINS
# ===============================

class PluginManager:
    """Gestionnaire de plugins avec découverte dynamique"""
    
    def __init__(self, api_manager: APIKeyManager):
        self.api_manager = api_manager
        self.plugins = {}
        self.logger = logging.getLogger(f'{__name__}.PluginManager')
        self._register_builtin_plugins()
    
    def _register_builtin_plugins(self):
        """Enregistre les plugins intégrés"""
        self.plugins = {
            'text': TextPlugin,
            'csv': CSVPlugin,
            'json': JSONPlugin,
            'stix': STIXPlugin,
            'rss': RSSPlugin,
            'taxii': TAXIIPlugin
        }
        self.logger.info(f"Plugins enregistrés: {list(self.plugins.keys())}")
    
    def create_plugin(self, feed_config: Dict[str, Any]) -> BasePlugin:
        """Crée une instance de plugin selon la configuration"""
        plugin_type = feed_config.get('type')
        
        if plugin_type not in self.plugins:
            raise PluginError(f"Type de plugin non supporté: {plugin_type}")
        
        try:
            plugin_class = self.plugins[plugin_type]
            plugin = plugin_class(feed_config, feed_config['name'], self.api_manager)
            plugin.validate_config()
            return plugin
            
        except Exception as e:
            raise PluginError(f"Erreur lors de la création du plugin {plugin_type}: {e}")
    
    def get_available_plugins(self) -> List[str]:
        """Retourne la liste des plugins disponibles"""
        return list(self.plugins.keys())

# ===============================
# STOCKAGE ET DÉDUPLICATION
# ===============================

class StorageError(Exception):
    """Erreur de stockage"""
    pass

class IOCStorage:
    """Gestionnaire de stockage des IOCs avec déduplication"""
    
    def __init__(self, output_dir: str = "iocs", max_file_size: int = 10485760):
        self.output_dir = Path(output_dir)
        self.max_file_size = max_file_size
        self.logger = logging.getLogger(f'{__name__}.IOCStorage')
        self._lock = threading.Lock()
        
        # Initialise la structure de stockage
        self._initialize_storage()
        
        # Base de données SQLite pour la déduplication
        self.db_path = self.output_dir / "iocs.db"
        self._initialize_database()
    
    def _initialize_storage(self):
        """Initialise la structure de stockage"""
        try:
            self.output_dir.mkdir(exist_ok=True)
            
            # Crée les répertoires pour chaque bucket
            for bucket in RetentionBucket:
                bucket_dir = self.output_dir / bucket.value
                bucket_dir.mkdir(exist_ok=True)
                
                # Crée un fichier par type d'IOC
                for ioc_type in IOCType:
                    file_path = bucket_dir / f"{ioc_type.value}.txt"
                    if not file_path.exists():
                        file_path.touch()
            
            self.logger.info(f"Structure de stockage initialisée dans {self.output_dir}")
            
        except Exception as e:
            raise StorageError(f"Erreur lors de l'initialisation du stockage: {e}")
    
    def _initialize_database(self):
        """Initialise la base de données de déduplication"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    value TEXT,
                    type TEXT,
                    source TEXT,
                    bucket TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    PRIMARY KEY (value, type)
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_value_type ON iocs(value, type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_bucket ON iocs(bucket)')
            conn.commit()
            conn.close()
            
            self.logger.info("Base de données de déduplication initialisée")
            
        except Exception as e:
            raise StorageError(f"Erreur lors de l'initialisation de la base de données: {e}")
    
    def store_iocs(self, iocs: List[IOC]) -> Dict[str, int]:
        """Stocke les IOCs avec déduplication"""
        if not iocs:
            return {'total': 0, 'new': 0, 'duplicates': 0, 'errors': 0}
        
        with self._lock:
            stats = {'total': len(iocs), 'new': 0, 'duplicates': 0, 'errors': 0}
            
            try:
                conn = sqlite3.connect(self.db_path)
                
                # Groupe les IOCs par type et bucket
                grouped = {}
                for ioc in iocs:
                    key = (ioc.type, ioc.retention)
                    if key not in grouped:
                        grouped[key] = []
                    grouped[key].append(ioc)
                
                # Traite chaque groupe
                for (ioc_type, bucket), ioc_list in grouped.items():
                    try:
                        new_iocs = self._deduplicate_iocs(conn, ioc_list)
                        if new_iocs:
                            self._write_iocs_to_file(ioc_type, bucket, new_iocs)
                            stats['new'] += len(new_iocs)
                        
                        stats['duplicates'] += len(ioc_list) - len(new_iocs)
                        
                    except Exception as e:
                        stats['errors'] += len(ioc_list)
                        self.logger.error(f"Erreur lors du stockage des IOCs {ioc_type.value}/{bucket.value}: {e}")
                
                conn.close()
                
            except Exception as e:
                stats['errors'] = stats['total']
                self.logger.error(f"Erreur lors du stockage des IOCs: {e}")
            
            return stats
    
    def _deduplicate_iocs(self, conn: sqlite3.Connection, iocs: List[IOC]) -> List[IOC]:
        """Déduplique les IOCs contre la base de données"""
        new_iocs = []
        now = datetime.now()
        
        for ioc in iocs:
            # Vérifie si l'IOC existe déjà
            cursor = conn.execute(
                'SELECT last_seen FROM iocs WHERE value = ? AND type = ?',
                (ioc.value, ioc.type.value)
            )
            result = cursor.fetchone()
            
            if result:
                # IOC existant, met à jour la date de dernière observation
                conn.execute(
                    'UPDATE iocs SET last_seen = ?, source = ? WHERE value = ? AND type = ?',
                    (now, ioc.source, ioc.value, ioc.type.value)
                )
            else:
                # Nouvel IOC
                conn.execute(
                    'INSERT INTO iocs (value, type, source, bucket, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)',
                    (ioc.value, ioc.type.value, ioc.source, ioc.retention.value, ioc.first_seen, now)
                )
                new_iocs.append(ioc)
        
        conn.commit()
        return new_iocs
    
    def _write_iocs_to_file(self, ioc_type: IOCType, bucket: RetentionBucket, iocs: List[IOC]):
        """Écrit les IOCs dans le fichier approprié"""
        file_path = self.output_dir / bucket.value / f"{ioc_type.value}.txt"
        
        try:
            # Vérifie la taille du fichier
            if file_path.stat().st_size > self.max_file_size:
                self._rotate_file(file_path)
            
            with open(file_path, 'a', encoding='utf-8') as f:
                for ioc in iocs:
                    f.write(f"{ioc.value}\n")
            
            self.logger.debug(f"Écrit {len(iocs)} IOCs dans {file_path}")
            
        except Exception as e:
            raise StorageError(f"Erreur lors de l'écriture dans {file_path}: {e}")
    
    def _rotate_file(self, file_path: Path):
        """Effectue la rotation d'un fichier trop volumineux"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = file_path.with_suffix(f".{timestamp}.txt")
            shutil.move(str(file_path), str(backup_path))
            file_path.touch()
            
            self.logger.info(f"Rotation du fichier {file_path} vers {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la rotation du fichier {file_path}: {e}")

# ===============================
# EXPORT POUR NGFW/FIREWALL
# ===============================

class NGFWExporter:
    """Exporte les IOCs dans des formats compatibles NGFW/Firewall"""
    
    def __init__(self, storage: IOCStorage, output_dir: str = "ngfw"):
        self.storage = storage
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(f'{__name__}.NGFWExporter')
        
        # Crée les sous-répertoires par bucket
        for bucket in RetentionBucket:
            (self.output_dir / bucket.value).mkdir(exist_ok=True)
    
    def export_all_buckets(self):
        """Exporte tous les buckets vers les formats NGFW"""
        try:
            for bucket in RetentionBucket:
                self.export_bucket(bucket)
            self.logger.info("Export NGFW terminé pour tous les buckets")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'export NGFW: {e}")
    
    def export_bucket(self, bucket: RetentionBucket):
        """Exporte un bucket spécifique"""
        source_dir = self.storage.output_dir / bucket.value
        target_dir = self.output_dir / bucket.value
        
        # Types d'IOCs à exporter pour NGFW
        ngfw_types = {
            IOCType.IPV4: 'malicious-ips.txt',
            IOCType.IPV6: 'malicious-ipv6.txt', 
            IOCType.DOMAIN: 'malicious-domains.txt',
            IOCType.URL: 'malicious-urls.txt'
        }
        
        for ioc_type, filename in ngfw_types.items():
            source_file = source_dir / f"{ioc_type.value}.txt"
            target_file = target_dir / filename
            
            if source_file.exists():
                try:
                    # Copie simple pour NGFW (une IOC par ligne)
                    with open(source_file, 'r') as src, open(target_file, 'w') as dst:
                        # Ajoute un header avec timestamp
                        dst.write(f"# TinyCTI NGFW Export - {datetime.now().isoformat()}\n")
                        dst.write(f"# Bucket: {bucket.value} - Type: {ioc_type.value}\n")
                        dst.write(f"# Format: One IOC per line\n")
                        
                        # Copie les IOCs
                        ioc_count = 0
                        for line in src:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                dst.write(f"{line}\n")
                                ioc_count += 1
                        
                        dst.write(f"# Total IOCs: {ioc_count}\n")
                    
                    self.logger.debug(f"Export NGFW: {source_file} -> {target_file}")
                    
                except Exception as e:
                    self.logger.error(f"Erreur export {source_file}: {e}")
    
    def generate_pfsense_aliases(self, bucket: RetentionBucket = RetentionBucket.LIVE):
        """Génère des alias pfSense"""
        alias_file = self.output_dir / bucket.value / "pfsense-aliases.txt"
        
        try:
            with open(alias_file, 'w') as f:
                f.write("# pfSense Aliases - TinyCTI Export\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
                
                # Alias pour IPs malveillantes
                ip_file = self.storage.output_dir / bucket.value / "ipv4.txt"
                if ip_file.exists():
                    f.write("# Malicious IPs Alias\n")
                    f.write("malicious_ips = {\n")
                    with open(ip_file) as ip_src:
                        for line in ip_src:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                f.write(f"    {line},\n")
                    f.write("}\n\n")
                
                # Alias pour domaines
                domain_file = self.storage.output_dir / bucket.value / "domain.txt"
                if domain_file.exists():
                    f.write("# Malicious Domains Alias\n")
                    f.write("malicious_domains = {\n")
                    with open(domain_file) as domain_src:
                        for line in domain_src:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                f.write(f"    {line},\n")
                    f.write("}\n")
            
            self.logger.info(f"Alias pfSense générés: {alias_file}")
            
        except Exception as e:
            self.logger.error(f"Erreur génération alias pfSense: {e}")
    
    def generate_iptables_rules(self, bucket: RetentionBucket = RetentionBucket.LIVE):
        """Génère des règles iptables"""
        rules_file = self.output_dir / bucket.value / "iptables-rules.sh"
        
        try:
            with open(rules_file, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# iptables rules - TinyCTI Export\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
                f.write("# Drop malicious IPs\n")
                
                ip_file = self.storage.output_dir / bucket.value / "ipv4.txt"
                if ip_file.exists():
                    with open(ip_file) as ip_src:
                        for line in ip_src:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                f.write(f"iptables -A INPUT -s {line} -j DROP\n")
                                f.write(f"iptables -A FORWARD -s {line} -j DROP\n")
            
            # Rend le script exécutable
            os.chmod(rules_file, 0o755)
            self.logger.info(f"Règles iptables générées: {rules_file}")
            
        except Exception as e:
            self.logger.error(f"Erreur génération règles iptables: {e}")

# ===============================
# API REST ET INTERFACE WEB
# ===============================

class TinyCTIAPI:
    """API REST pour TinyCTI avec interface de gestion"""
    
    def __init__(self, tinycti_instance: 'TinyCTI', host: str = "127.0.0.1", port: int = 5000):
        self.tinycti = tinycti_instance
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.app.secret_key = os.urandom(24)
        self.logger = logging.getLogger(f'{__name__}.TinyCTIAPI')
        self.server = None
        
        # Configure les routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Configure les routes de l'API"""
        
        # ===============================
        # ROUTES API JSON
        # ===============================
        
        @self.app.route('/api/status')
        def api_status():
            """Statut général du système"""
            try:
                status = {
                    'status': 'running',
                    'version': '1.0.0',
                    'daemon_running': self.tinycti.is_daemon_running,
                    'feeds_total': len(self.tinycti.config['feeds']),
                    'feeds_enabled': len([f for f in self.tinycti.config['feeds'] if f.get('enabled', True)]),
                    'uptime': str(datetime.now() - getattr(self.tinycti, 'start_time', datetime.now())),
                    'scheduler': None
                }
                
                if self.tinycti.scheduler:
                    status['scheduler'] = self.tinycti.scheduler.get_status()
                
                return jsonify(status)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/feeds')
        def api_feeds():
            """Liste des flux configurés"""
            try:
                feeds = []
                for feed in self.tinycti.config['feeds']:
                    feed_info = {
                        'name': feed['name'],
                        'type': feed['type'],
                        'url': feed['url'],
                        'enabled': feed.get('enabled', True),
                        'retention': feed.get('retention', 'live'),
                        'schedule': feed.get('schedule', '1h'),
                        'priority': feed.get('priority', 5)
                    }
                    feeds.append(feed_info)
                
                return jsonify({'feeds': feeds})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/feeds/<feed_name>/toggle', methods=['POST'])
        def api_toggle_feed(feed_name):
            """Active/désactive un flux"""
            try:
                for feed in self.tinycti.config['feeds']:
                    if feed['name'] == feed_name:
                        feed['enabled'] = not feed.get('enabled', True)
                        
                        # Sauvegarde la configuration
                        self._save_config()
                        
                        return jsonify({
                            'feed': feed_name,
                            'enabled': feed['enabled'],
                            'message': f"Flux {'activé' if feed['enabled'] else 'désactivé'}"
                        })
                
                return jsonify({'error': 'Flux non trouvé'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/feeds/<feed_name>/schedule', methods=['POST'])
        def api_update_schedule(feed_name):
            """Met à jour la planification d'un flux"""
            try:
                data = request.get_json()
                schedule = data.get('schedule')
                priority = data.get('priority')
                
                if not schedule:
                    return jsonify({'error': 'Schedule manquant'}), 400
                
                # Valide le format de schedule
                try:
                    ScheduleParser.parse_duration(schedule)
                except ValueError as e:
                    return jsonify({'error': f'Format de schedule invalide: {e}'}), 400
                
                # Met à jour la config
                for feed in self.tinycti.config['feeds']:
                    if feed['name'] == feed_name:
                        feed['schedule'] = schedule
                        if priority is not None:
                            feed['priority'] = max(1, min(10, int(priority)))
                        
                        # Met à jour le scheduler si actif
                        if self.tinycti.scheduler and feed_name in self.tinycti.scheduler.tasks:
                            task = self.tinycti.scheduler.tasks[feed_name]
                            task.interval = ScheduleParser.parse_duration(schedule)
                            if priority is not None:
                                task.priority = feed['priority']
                        
                        # Sauvegarde la configuration
                        self._save_config()
                        
                        return jsonify({
                            'feed': feed_name,
                            'schedule': schedule,
                            'priority': feed.get('priority'),
                            'message': 'Planification mise à jour'
                        })
                
                return jsonify({'error': 'Flux non trouvé'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/iocs/<ioc_type>')
        def api_get_iocs(ioc_type):
            """Récupère les IOCs d'un type donné"""
            try:
                bucket = request.args.get('bucket', 'live')
                limit = int(request.args.get('limit', 1000))
                
                ioc_file = self.tinycti.storage.output_dir / bucket / f"{ioc_type}.txt"
                
                if not ioc_file.exists():
                    return jsonify({'iocs': [], 'total': 0})
                
                iocs = []
                with open(ioc_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            iocs.append(line)
                            if len(iocs) >= limit:
                                break
                
                return jsonify({
                    'type': ioc_type,
                    'bucket': bucket,
                    'iocs': iocs,
                    'total': len(iocs),
                    'truncated': len(iocs) >= limit
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/iocs/search')
        def api_search_iocs():
            """Recherche un IOC spécifique"""
            try:
                query = request.args.get('q', '').strip()
                if not query:
                    return jsonify({'error': 'Paramètre q manquant'}), 400
                
                results = []
                
                # Recherche dans tous les buckets et types
                for bucket in RetentionBucket:
                    bucket_dir = self.tinycti.storage.output_dir / bucket.value
                    for ioc_file in bucket_dir.glob('*.txt'):
                        ioc_type = ioc_file.stem
                        
                        try:
                            with open(ioc_file, 'r') as f:
                                for line_num, line in enumerate(f, 1):
                                    line = line.strip()
                                    if query.lower() in line.lower():
                                        results.append({
                                            'ioc': line,
                                            'type': ioc_type,
                                            'bucket': bucket.value,
                                            'file': str(ioc_file),
                                            'line': line_num
                                        })
                        except Exception as e:
                            continue
                
                return jsonify({
                    'query': query,
                    'results': results,
                    'total': len(results)
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/export/ngfw')
        def api_export_ngfw():
            """Lance l'export NGFW"""
            try:
                exporter = NGFWExporter(self.tinycti.storage)
                exporter.export_all_buckets()
                
                return jsonify({'message': 'Export NGFW terminé'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        # ===============================
        # INTERFACE WEB DE GESTION
        # ===============================
        
        @self.app.route('/')
        def dashboard():
            """Interface principale de gestion"""
            return render_template_string(DASHBOARD_TEMPLATE)
        
        @self.app.route('/feeds')
        def feeds_page():
            """Page de gestion des flux"""
            return render_template_string(FEEDS_TEMPLATE)
        
        @self.app.route('/iocs')
        def iocs_page():
            """Page de consultation des IOCs"""
            return render_template_string(IOCS_TEMPLATE)
    
    def _save_config(self):
        """Sauvegarde la configuration modifiée"""
        try:
            with open(self.tinycti.config_file, 'w') as f:
                yaml.dump(self.tinycti.config, f, default_flow_style=False, indent=2)
            self.logger.info("Configuration sauvegardée")
        except Exception as e:
            self.logger.error(f"Erreur sauvegarde config: {e}")
    
    def start(self):
        """Démarre le serveur API"""
        try:
            self.server = make_server(self.host, self.port, self.app, threaded=True)
            self.logger.info(f"API TinyCTI démarrée sur http://{self.host}:{self.port}")
            self.server.serve_forever()
        except Exception as e:
            self.logger.error(f"Erreur serveur API: {e}")
    
    def stop(self):
        """Arrête le serveur API"""
        if self.server:
            self.server.shutdown()
            self.logger.info("Serveur API arrêté")

# ===============================
# TEMPLATES HTML POUR L'INTERFACE
# ===============================

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TinyCTI - Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn { padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 4px; display: inline-block; margin: 5px; }
        .btn:hover { background: #2980b9; }
        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .status.running { background: #27ae60; color: white; }
        .status.stopped { background: #e74c3c; color: white; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ TinyCTI Dashboard</h1>
            <p>Framework modulaire de collecte d'IOCs</p>
        </div>
        
        <div class="cards">
            <div class="card">
                <h3>Statut Système</h3>
                <div id="system-status">Chargement...</div>
            </div>
            
            <div class="card">
                <h3>Actions Rapides</h3>
                <a href="/feeds" class="btn">⚙️ Gérer les Flux</a>
                <a href="/iocs" class="btn">🔍 Consulter IOCs</a>
                <a href="#" onclick="exportNGFW()" class="btn">📤 Export NGFW</a>
            </div>
            
            <div class="card">
                <h3>Statistiques Récentes</h3>
                <div id="stats">Chargement...</div>
            </div>
        </div>
        
        <div class="card">
            <h3>Planificateur de Tâches</h3>
            <div id="scheduler">Chargement...</div>
        </div>
    </div>

    <script>
        async function loadStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                document.getElementById('system-status').innerHTML = `
                    <p><strong>État:</strong> <span class="status ${data.daemon_running ? 'running' : 'stopped'}">${data.daemon_running ? 'DAEMON ACTIF' : 'ARRÊTÉ'}</span></p>
                    <p><strong>Flux totaux:</strong> ${data.feeds_total}</p>
                    <p><strong>Flux actifs:</strong> ${data.feeds_enabled}</p>
                    <p><strong>Uptime:</strong> ${data.uptime}</p>
                `;
                
                if (data.scheduler) {
                    const scheduler = data.scheduler;
                    let schedulerHtml = `
                        <p><strong>Tâches totales:</strong> ${scheduler.total_tasks}</p>
                        <p><strong>En cours:</strong> ${scheduler.running_tasks}</p>
                        <p><strong>Prêtes:</strong> ${scheduler.ready_tasks}</p>
                    `;
                    
                    if (scheduler.next_execution) {
                        schedulerHtml += `<p><strong>Prochaine exécution:</strong> ${new Date(scheduler.next_execution).toLocaleString()}</p>`;
                    }
                    
                    document.getElementById('scheduler').innerHTML = schedulerHtml;
                }
                
            } catch (error) {
                console.error('Erreur chargement statut:', error);
            }
        }
        
        async function exportNGFW() {
            try {
                const response = await fetch('/api/export/ngfw');
                const data = await response.json();
                alert(data.message || 'Export terminé');
            } catch (error) {
                alert('Erreur lors de l\'export: ' + error);
            }
        }
        
        // Charge le statut au démarrage et toutes les 30 secondes
        loadStatus();
        setInterval(loadStatus, 30000);
    </script>
</body>
</html>
"""

FEEDS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TinyCTI - Gestion des Flux</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .btn { padding: 6px 12px; margin: 2px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-toggle { background: #3498db; color: white; }
        .btn-edit { background: #f39c12; color: white; }
        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .status.enabled { background: #27ae60; color: white; }
        .status.disabled { background: #e74c3c; color: white; }
        .priority { font-weight: bold; }
        .priority-1, .priority-2 { color: #e74c3c; }
        .priority-3, .priority-4, .priority-5 { color: #f39c12; }
        .priority-6, .priority-7, .priority-8, .priority-9, .priority-10 { color: #95a5a6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚙️ Gestion des Flux TinyCTI</h1>
            <a href="/" style="color: white;">← Retour au Dashboard</a>
        </div>
        
        <div class="card">
            <h3>Flux Configurés</h3>
            <table id="feeds-table">
                <thead>
                    <tr>
                        <th>Nom</th>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Statut</th>
                        <th>Schedule</th>
                        <th>Priorité</th>
                        <th>Rétention</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="feeds-tbody">
                    <tr><td colspan="8">Chargement...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function loadFeeds() {
            try {
                const response = await fetch('/api/feeds');
                const data = await response.json();
                
                const tbody = document.getElementById('feeds-tbody');
                tbody.innerHTML = '';
                
                data.feeds.forEach(feed => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td><strong>${feed.name}</strong></td>
                        <td>${feed.type.toUpperCase()}</td>
                        <td title="${feed.url}">${feed.url.length > 50 ? feed.url.substring(0, 50) + '...' : feed.url}</td>
                        <td><span class="status ${feed.enabled ? 'enabled' : 'disabled'}">${feed.enabled ? 'ACTIF' : 'INACTIF'}</span></td>
                        <td>${feed.schedule}</td>
                        <td><span class="priority priority-${feed.priority}">${feed.priority}</span></td>
                        <td>${feed.retention}</td>
                        <td>
                            <button class="btn btn-toggle" onclick="toggleFeed('${feed.name}')">${feed.enabled ? 'Désactiver' : 'Activer'}</button>
                            <button class="btn btn-edit" onclick="editSchedule('${feed.name}', '${feed.schedule}', ${feed.priority})">Modifier</button>
                        </td>
                    `;
                });
                
            } catch (error) {
                console.error('Erreur chargement flux:', error);
            }
        }
        
        async function toggleFeed(feedName) {
            try {
                const response = await fetch(`/api/feeds/${feedName}/toggle`, { method: 'POST' });
                const data = await response.json();
                
                if (response.ok) {
                    alert(data.message);
                    loadFeeds();
                } else {
                    alert('Erreur: ' + data.error);
                }
            } catch (error) {
                alert('Erreur: ' + error);
            }
        }
        
        function editSchedule(feedName, currentSchedule, currentPriority) {
            const newSchedule = prompt(`Nouvelle planification pour ${feedName}:`, currentSchedule);
            if (!newSchedule) return;
            
            const newPriority = prompt(`Nouvelle priorité (1-10):`, currentPriority);
            if (!newPriority) return;
            
            updateSchedule(feedName, newSchedule, parseInt(newPriority));
        }
        
        async function updateSchedule(feedName, schedule, priority) {
            try {
                const response = await fetch(`/api/feeds/${feedName}/schedule`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ schedule, priority })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    alert(data.message);
                    loadFeeds();
                } else {
                    alert('Erreur: ' + data.error);
                }
            } catch (error) {
                alert('Erreur: ' + error);
            }
        }
        
        // Charge les flux au démarrage
        loadFeeds();
        
        // Actualise toutes les 30 secondes
        setInterval(loadFeeds, 30000);
    </script>
</body>
</html>
"""

IOCS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TinyCTI - Consultation IOCs</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .search-box { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 10px; }
        .btn { padding: 10px 20px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #2980b9; }
        .ioc-list { max-height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; background: #f9f9f9; }
        .ioc-item { padding: 5px; border-bottom: 1px solid #eee; font-family: monospace; }
        select { padding: 8px; border: 1px solid #ddd; border-radius: 4px; margin: 5px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 20px; }
        .stat-card { background: #ecf0f1; padding: 15px; border-radius: 4px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Consultation IOCs TinyCTI</h1>
            <a href="/" style="color: white;">← Retour au Dashboard</a>
        </div>
        
        <div class="card">
            <h3>Recherche d'IOCs</h3>
            <input type="text" id="search-input" class="search-box" placeholder="Rechercher un IOC (IP, domaine, hash...)">
            <button class="btn" onclick="searchIOCs()">🔍 Rechercher</button>
            <button class="btn" onclick="clearSearch()">✕ Effacer</button>
            
            <div id="search-results" style="display: none;">
                <h4>Résultats de recherche</h4>
                <div id="search-content"></div>
            </div>
        </div>
        
        <div class="card">
            <h3>Navigation par Type et Bucket</h3>
            <select id="ioc-type">
                <option value="ipv4">IPv4</option>
                <option value="ipv6">IPv6</option>
                <option value="domain">Domaines</option>
                <option value="url">URLs</option>
                <option value="hash_md5">Hash MD5</option>
                <option value="hash_sha1">Hash SHA1</option>
                <option value="hash_sha256">Hash SHA256</option>
                <option value="email">Emails</option>
            </select>
            
            <select id="bucket">
                <option value="live">Live</option>
                <option value="chaud">Chaud</option>
                <option value="tiede">Tiède</option>
                <option value="froid">Froid</option>
            </select>
            
            <button class="btn" onclick="loadIOCs()">📊 Charger IOCs</button>
            <button class="btn" onclick="exportIOCs()">📤 Exporter</button>
            
            <div id="ioc-stats" class="stats"></div>
            
            <div id="ioc-content">
                <p>Sélectionnez un type et bucket, puis cliquez sur "Charger IOCs"</p>
            </div>
        </div>
    </div>

    <script>
        async function searchIOCs() {
            const query = document.getElementById('search-input').value.trim();
            if (!query) {
                alert('Veuillez saisir une recherche');
                return;
            }
            
            try {
                const response = await fetch(`/api/iocs/search?q=${encodeURIComponent(query)}`);
                const data = await response.json();
                
                const resultsDiv = document.getElementById('search-results');
                const contentDiv = document.getElementById('search-content');
                
                if (data.results.length === 0) {
                    contentDiv.innerHTML = '<p>Aucun résultat trouvé</p>';
                } else {
                    let html = `<p><strong>${data.total} résultat(s) pour "${data.query}"</strong></p>`;
                    html += '<div class="ioc-list">';
                    
                    data.results.forEach(result => {
                        html += `<div class="ioc-item">
                            <strong>${result.ioc}</strong> 
                            <span style="color: #666;">[${result.type}/${result.bucket}]</span>
                        </div>`;
                    });
                    
                    html += '</div>';
                    contentDiv.innerHTML = html;
                }
                
                resultsDiv.style.display = 'block';
                
            } catch (error) {
                alert('Erreur de recherche: ' + error);
            }
        }
        
        function clearSearch() {
            document.getElementById('search-input').value = '';
            document.getElementById('search-results').style.display = 'none';
        }
        
        async function loadIOCs() {
            const type = document.getElementById('ioc-type').value;
            const bucket = document.getElementById('bucket').value;
            
            try {
                const response = await fetch(`/api/iocs/${type}?bucket=${bucket}&limit=500`);
                const data = await response.json();
                
                // Affiche les stats
                const statsDiv = document.getElementById('ioc-stats');
                statsDiv.innerHTML = `
                    <div class="stat-card">
                        <h4>Type</h4>
                        <p>${data.type.toUpperCase()}</p>
                    </div>
                    <div class="stat-card">
                        <h4>Bucket</h4>
                        <p>${data.bucket.toUpperCase()}</p>
                    </div>
                    <div class="stat-card">
                        <h4>Total IOCs</h4>
                        <p>${data.total}</p>
                    </div>
                    <div class="stat-card">
                        <h4>Affichés</h4>
                        <p>${Math.min(data.total, 500)}</p>
                    </div>
                `;
                
                // Affiche les IOCs
                const contentDiv = document.getElementById('ioc-content');
                if (data.iocs.length === 0) {
                    contentDiv.innerHTML = '<p>Aucun IOC trouvé</p>';
                } else {
                    let html = '<div class="ioc-list">';
                    data.iocs.forEach(ioc => {
                        html += `<div class="ioc-item">${ioc}</div>`;
                    });
                    html += '</div>';
                    
                    if (data.truncated) {
                        html += '<p><em>Liste tronquée à 500 éléments</em></p>';
                    }
                    
                    contentDiv.innerHTML = html;
                }
                
            } catch (error) {
                alert('Erreur chargement IOCs: ' + error);
            }
        }
        
        function exportIOCs() {
            const type = document.getElementById('ioc-type').value;
            const bucket = document.getElementById('bucket').value;
            
            // Ouvre le fichier IOC correspondant dans un nouvel onglet
            window.open(`/api/iocs/${type}?bucket=${bucket}&limit=10000`, '_blank');
        }
        
        // Raccourci clavier pour la recherche
        document.getElementById('search-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                searchIOCs();
            }
        });
    </script>
</body>
</html>
"""

# ===============================
# PLANIFICATION ET DAEMON
# ===============================

class ScheduleParser:
    """Parse les expressions de planification"""
    
    @staticmethod
    def parse_duration(duration_str: str) -> int:
        """Convertit une durée en secondes (ex: '30m', '2h', '1d')"""
        if not duration_str:
            return 3600  # 1h par défaut
        
        duration_str = duration_str.lower().strip()
        
        # Patterns de durée
        patterns = {
            r'(\d+)s': 1,           # secondes
            r'(\d+)m': 60,          # minutes  
            r'(\d+)h': 3600,        # heures
            r'(\d+)d': 86400,       # jours
        }
        
        for pattern, multiplier in patterns.items():
            match = re.match(pattern, duration_str)
            if match:
                return int(match.group(1)) * multiplier
        
        # Fallback: si c'est juste un nombre, on assume des secondes
        try:
            return int(duration_str)
        except ValueError:
            raise ValueError(f"Format de durée invalide: {duration_str}")

@dataclass
class ScheduledTask:
    """Représente une tâche planifiée"""
    feed_name: str
    next_run: datetime
    interval: int  # en secondes
    priority: int = 5  # 1=haute, 10=basse
    last_run: Optional[datetime] = None
    consecutive_errors: int = 0
    is_running: bool = False
    
    def should_run(self) -> bool:
        """Vérifie si la tâche doit être exécutée"""
        return datetime.now() >= self.next_run and not self.is_running
    
    def update_next_run(self):
        """Met à jour la prochaine exécution"""
        self.next_run = datetime.now() + timedelta(seconds=self.interval)
        self.last_run = datetime.now()

class FeedScheduler:
    """Planificateur de flux avec gestion des priorités"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tasks: Dict[str, ScheduledTask] = {}
        self.logger = logging.getLogger(f'{__name__}.FeedScheduler')
        self.is_running = False
        self._stop_event = threading.Event()
        
        # Configuration du daemon
        daemon_config = config.get('daemon', {})
        self.check_interval = ScheduleParser.parse_duration(
            daemon_config.get('check_interval', '60s')
        )
        self.max_concurrent = daemon_config.get('max_concurrent_feeds', 3)
        self.default_schedule = daemon_config.get('default_schedule', '1h')
        
        # Semaphore pour limiter les tâches concurrentes
        self._semaphore = threading.Semaphore(self.max_concurrent)
        self._initialize_tasks()
    
    def _initialize_tasks(self):
        """Initialise les tâches depuis la configuration"""
        for feed in self.config['feeds']:
            if not feed.get('enabled', True):
                continue
            
            feed_name = feed['name']
            schedule = feed.get('schedule', self.default_schedule)
            priority = feed.get('priority', 5)
            
            try:
                interval = ScheduleParser.parse_duration(schedule)
                
                # Étale les premières exécutions pour éviter les pics
                initial_delay = random.randint(0, min(interval // 4, 300))  # Max 5min
                next_run = datetime.now() + timedelta(seconds=initial_delay)
                
                task = ScheduledTask(
                    feed_name=feed_name,
                    next_run=next_run,
                    interval=interval,
                    priority=priority
                )
                
                self.tasks[feed_name] = task
                self.logger.info(
                    f"Tâche planifiée: {feed_name} - "
                    f"Intervalle: {schedule} ({interval}s) - "
                    f"Priorité: {priority} - "
                    f"Première exécution: {next_run.strftime('%H:%M:%S')}"
                )
                
            except ValueError as e:
                self.logger.error(f"Erreur de planification pour {feed_name}: {e}")
    
    def get_ready_tasks(self) -> List[ScheduledTask]:
        """Retourne les tâches prêtes à être exécutées, triées par priorité"""
        ready_tasks = [
            task for task in self.tasks.values() 
            if task.should_run()
        ]
        
        # Trie par priorité (1=haute priorité en premier)
        ready_tasks.sort(key=lambda t: (t.priority, t.next_run))
        
        return ready_tasks
    
    def mark_task_running(self, feed_name: str, running: bool = True):
        """Marque une tâche comme en cours d'exécution"""
        if feed_name in self.tasks:
            self.tasks[feed_name].is_running = running
    
    def mark_task_completed(self, feed_name: str, success: bool = True):
        """Marque une tâche comme terminée"""
        if feed_name in self.tasks:
            task = self.tasks[feed_name]
            task.is_running = False
            
            if success:
                task.consecutive_errors = 0
                task.update_next_run()
                self.logger.debug(f"Tâche {feed_name} terminée avec succès, prochaine exécution: {task.next_run.strftime('%H:%M:%S')}")
            else:
                task.consecutive_errors += 1
                # Backoff exponentiel en cas d'erreurs répétées
                delay_multiplier = min(2 ** task.consecutive_errors, 16)  # Max 16x
                delayed_interval = task.interval * delay_multiplier
                task.next_run = datetime.now() + timedelta(seconds=delayed_interval)
                
                self.logger.warning(
                    f"Erreur pour {feed_name} ({task.consecutive_errors} consécutives), "
                    f"report à {task.next_run.strftime('%H:%M:%S')} "
                    f"(délai x{delay_multiplier})"
                )
    
    def get_next_execution_time(self) -> Optional[datetime]:
        """Retourne l'heure de la prochaine exécution"""
        if not self.tasks:
            return None
        
        return min(task.next_run for task in self.tasks.values())
    
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut du planificateur"""
        now = datetime.now()
        
        return {
            'total_tasks': len(self.tasks),
            'running_tasks': sum(1 for t in self.tasks.values() if t.is_running),
            'ready_tasks': len(self.get_ready_tasks()),
            'next_execution': self.get_next_execution_time(),
            'tasks': {
                name: {
                    'next_run': task.next_run,
                    'interval': task.interval,
                    'priority': task.priority,
                    'is_running': task.is_running,
                    'consecutive_errors': task.consecutive_errors,
                    'seconds_until_next': max(0, int((task.next_run - now).total_seconds()))
                }
                for name, task in self.tasks.items()
            }
        }
    
    def stop(self):
        """Arrête le planificateur"""
        self._stop_event.set()
        self.is_running = False

# ===============================
# ORCHESTRATEUR PRINCIPAL
# ===============================

class TinyCTI:
    """Orchestrateur principal du framework TinyCTI"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.logger = logging.getLogger(f'{__name__}.TinyCTI')
        
        # Initialise les composants
        self.config_loader = ConfigurationLoader(config_file)
        self.api_manager = APIKeyManager()
        self.plugin_manager = PluginManager(self.api_manager)
        self.scheduler = None
        
        # État du daemon
        self.is_daemon_running = False
        self._stop_event = threading.Event()
        self.start_time = datetime.now()
        
        # API et export
        self.api_server = None
        self.ngfw_exporter = None
        
        # Charge la configuration
        try:
            self.config = self.config_loader.load_config()
            self.storage = IOCStorage(
                self.config['output_dir'],
                self.config.get('max_file_size', 10485760)
            )
            self._setup_api_keys()
            
            # Initialise le planificateur si mode daemon
            daemon_config = self.config.get('daemon', {})
            if daemon_config.get('enabled', False):
                self.scheduler = FeedScheduler(self.config)
            
            # Initialise l'exporteur NGFW
            self.ngfw_exporter = NGFWExporter(self.storage)
            
            # Initialise l'API si configurée
            api_config = self.config.get('api', {})
            if api_config.get('enabled', False):
                host = api_config.get('host', '127.0.0.1')
                port = api_config.get('port', 5000)
                self.api_server = TinyCTIAPI(self, host, port)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation: {e}")
            raise
    
    def _setup_api_keys(self):
        """Configure les clés API pour chaque flux"""
        for feed in self.config['feeds']:
            api_keys = feed.get('api_keys', [])
            if api_keys:
                self.api_manager.add_keys(feed['name'], api_keys)
    
    def run(self, daemon_mode: bool = None):
        """Lance la collecte (mode one-shot ou daemon)"""
        # Détermine le mode d'exécution
        if daemon_mode is None:
            daemon_mode = self.config.get('daemon', {}).get('enabled', False)
        
        if daemon_mode:
            self.run_daemon()
        else:
            self.run_once()
    
    def run_once(self):
        """Exécution unique de tous les flux activés"""
        start_time = time.time()
        
        # Statistiques globales
        global_stats = {
            'feeds_total': 0,
            'feeds_enabled': 0,
            'feeds_success': 0,
            'feeds_error': 0,
            'total_iocs': 0,
            'new_iocs': 0,
            'duplicates': 0,
            'errors': 0
        }
        
        self.logger.info("=" * 50)
        self.logger.info("Début de la collecte TinyCTI (mode one-shot)")
        self.logger.info("=" * 50)
        
        # Filtre les flux activés
        enabled_feeds = [feed for feed in self.config['feeds'] if feed.get('enabled', True)]
        global_stats['feeds_total'] = len(self.config['feeds'])
        global_stats['feeds_enabled'] = len(enabled_feeds)
        
        if not enabled_feeds:
            self.logger.warning("Aucun flux activé dans la configuration")
            return
        
        self.logger.info(f"Traitement de {len(enabled_feeds)} flux activés")
        
        # Traitement des flux
        if self.config.get('parallel_feeds', False):
            self._process_feeds_parallel(enabled_feeds, global_stats)
        else:
            self._process_feeds_sequential(enabled_feeds, global_stats)
        
        # Statistiques finales
        duration = time.time() - start_time
        self._log_final_stats(global_stats, duration)
        
        # Export NGFW automatique si configuré
        self._auto_export_ngfw()
    
    def run_daemon(self):
        """Mode daemon avec planification automatique"""
        if not self.scheduler:
            self.scheduler = FeedScheduler(self.config)
        
        self.is_daemon_running = True
        self.logger.info("=" * 50)
        self.logger.info("Démarrage du daemon TinyCTI")
        self.logger.info("=" * 50)
        
        # Statistiques du daemon
        daemon_stats = {
            'start_time': datetime.now(),
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'total_iocs_collected': 0
        }
        
        # Affiche la planification initiale
        self._log_scheduler_status()
        
        # Démarre l'API en arrière-plan si configurée
        api_thread = None
        if self.api_server:
            api_thread = threading.Thread(target=self.api_server.start, daemon=True)
            api_thread.start()
            self.logger.info("API TinyCTI démarrée en arrière-plan")
        
        try:
            while not self._stop_event.is_set():
                # Vérifie les tâches prêtes
                ready_tasks = self.scheduler.get_ready_tasks()
                
                if ready_tasks:
                    self.logger.info(f"{len(ready_tasks)} flux prêts pour exécution")
                    
                    # Limite le nombre de tâches concurrentes
                    max_concurrent = self.config.get('daemon', {}).get('max_concurrent_feeds', 3)
                    tasks_to_run = ready_tasks[:max_concurrent]
                    
                    # Lance les tâches
                    if len(tasks_to_run) == 1:
                        # Exécution séquentielle pour une seule tâche
                        task = tasks_to_run[0]
                        success = self._execute_scheduled_task(task)
                        daemon_stats['total_executions'] += 1
                        if success:
                            daemon_stats['successful_executions'] += 1
                        else:
                            daemon_stats['failed_executions'] += 1
                    else:
                        # Exécution parallèle pour plusieurs tâches
                        self._execute_tasks_parallel(tasks_to_run, daemon_stats)
                
                # Attend avant la prochaine vérification
                wait_time = min(self.scheduler.check_interval, 60)  # Max 1 minute
                if self._stop_event.wait(wait_time):
                    break
                
                # Affiche le statut périodiquement
                if daemon_stats['total_executions'] % 10 == 0 and daemon_stats['total_executions'] > 0:
                    self._log_daemon_stats(daemon_stats)
        
        except KeyboardInterrupt:
            self.logger.info("Arrêt du daemon demandé par l'utilisateur")
        
        except Exception as e:
            self.logger.error(f"Erreur fatale dans le daemon: {e}")
            self.logger.debug(traceback.format_exc())
        
        finally:
            self.is_daemon_running = False
            self.logger.info("Daemon TinyCTI arrêté")
            self._log_daemon_stats(daemon_stats)
    
    def _execute_scheduled_task(self, task: ScheduledTask) -> bool:
        """Exécute une tâche planifiée"""
        feed_name = task.feed_name
        
        # Trouve la configuration du flux
        feed_config = None
        for feed in self.config['feeds']:
            if feed['name'] == feed_name:
                feed_config = feed
                break
        
        if not feed_config or not feed_config.get('enabled', True):
            self.logger.warning(f"Flux {feed_name} introuvable ou désactivé")
            self.scheduler.mark_task_completed(feed_name, False)
            return False
        
        # Marque la tâche comme en cours
        self.scheduler.mark_task_running(feed_name, True)
        
        try:
            self.logger.info(f"Exécution planifiée: {feed_name}")
            
            # Rate limiting si configuré
            rate_limit = feed_config.get('rate_limit', 0)
            if rate_limit > 0:
                self.logger.debug(f"Rate limiting: attente {rate_limit}s avant {feed_name}")
                time.sleep(rate_limit)
            
            # Traite le flux
            feed_stats = self._process_single_feed(feed_config, {})
            
            # Détermine le succès
            success = feed_stats.get('feeds_success', 0) > 0
            
            # Met à jour la planification
            self.scheduler.mark_task_completed(feed_name, success)
            
            if success:
                self.logger.info(
                    f"Flux {feed_name} terminé: "
                    f"{feed_stats.get('new_iocs', 0)} nouveaux IOCs"
                )
            
            return success
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'exécution de {feed_name}: {e}")
            self.scheduler.mark_task_completed(feed_name, False)
            return False
    
    def _execute_tasks_parallel(self, tasks: List[ScheduledTask], daemon_stats: Dict):
        """Exécute plusieurs tâches en parallèle"""
        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            future_to_task = {
                executor.submit(self._execute_scheduled_task, task): task
                for task in tasks
            }
            
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                daemon_stats['total_executions'] += 1
                
                try:
                    success = future.result()
                    if success:
                        daemon_stats['successful_executions'] += 1
                    else:
                        daemon_stats['failed_executions'] += 1
                        
                except Exception as e:
                    daemon_stats['failed_executions'] += 1
                    self.logger.error(f"Erreur dans la tâche {task.feed_name}: {e}")
    
    def _log_scheduler_status(self):
        """Affiche le statut du planificateur"""
        if not self.scheduler:
            return
        
        status = self.scheduler.get_status()
        self.logger.info(f"Planificateur initialisé: {status['total_tasks']} tâches")
        
        next_exec = status.get('next_execution')
        if next_exec:
            self.logger.info(f"Prochaine exécution: {next_exec.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Affiche le détail des tâches
        for name, task_info in status['tasks'].items():
            self.logger.info(
                f"  {name}: priorité {task_info['priority']}, "
                f"dans {task_info['seconds_until_next']}s"
            )
    
    def _log_daemon_stats(self, stats: Dict):
        """Affiche les statistiques du daemon"""
        uptime = datetime.now() - stats['start_time']
        success_rate = 0
        if stats['total_executions'] > 0:
            success_rate = (stats['successful_executions'] / stats['total_executions']) * 100
        
        self.logger.info("=" * 40)
        self.logger.info("Statistiques du daemon TinyCTI")
        self.logger.info("=" * 40)
        self.logger.info(f"Uptime: {uptime}")
        self.logger.info(f"Exécutions totales: {stats['total_executions']}")
        self.logger.info(f"Exécutions réussies: {stats['successful_executions']}")
        self.logger.info(f"Exécutions échouées: {stats['failed_executions']}")
        self.logger.info(f"Taux de réussite: {success_rate:.1f}%")
        
        if self.scheduler:
            scheduler_status = self.scheduler.get_status()
            self.logger.info(f"Tâches en cours: {scheduler_status['running_tasks']}")
            self.logger.info(f"Tâches prêtes: {scheduler_status['ready_tasks']}")
    
    def stop_daemon(self):
        """Arrête le daemon proprement"""
        if self.is_daemon_running:
            self.logger.info("Arrêt en cours du daemon...")
            self._stop_event.set()
            if self.scheduler:
                self.scheduler.stop()
            if self.api_server:
                self.api_server.stop()
    
    def _auto_export_ngfw(self):
        """Export automatique NGFW après collecte"""
        try:
            ngfw_config = self.config.get('ngfw_export', {})
            if not ngfw_config.get('enabled', True):
                return
            
            if not ngfw_config.get('auto_export_after_collection', True):
                return
            
            self.logger.info("Début de l'export automatique NGFW")
            
            # Export standard
            self.ngfw_exporter.export_all_buckets()
            
            # Génération des alias pfSense si demandé
            if ngfw_config.get('generate_pfsense_aliases', True):
                self.ngfw_exporter.generate_pfsense_aliases(RetentionBucket.LIVE)
            
            # Génération des règles iptables si demandé
            if ngfw_config.get('generate_iptables_rules', True):
                self.ngfw_exporter.generate_iptables_rules(RetentionBucket.LIVE)
            
            self.logger.info("Export automatique NGFW terminé")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'export automatique NGFW: {e}")
    
    def start_api_server(self, background: bool = True):
        """Démarre le serveur API"""
        if not self.api_server:
            api_config = self.config.get('api', {})
            host = api_config.get('host', '127.0.0.1')
            port = api_config.get('port', 5000)
            self.api_server = TinyCTIAPI(self, host, port)
        
        if background:
            api_thread = threading.Thread(target=self.api_server.start, daemon=True)
            api_thread.start()
            self.logger.info(f"API démarrée en arrière-plan sur http://{self.api_server.host}:{self.api_server.port}")
        else:
            self.api_server.start()
    
    def manual_export_ngfw(self, bucket: str = "live"):
        """Export manuel NGFW"""
        try:
            bucket_enum = RetentionBucket(bucket)
            self.ngfw_exporter.export_bucket(bucket_enum)
            self.ngfw_exporter.generate_pfsense_aliases(bucket_enum)
            self.ngfw_exporter.generate_iptables_rules(bucket_enum)
            self.logger.info(f"Export NGFW manuel terminé pour le bucket {bucket}")
        except Exception as e:
            self.logger.error(f"Erreur export NGFW manuel: {e}")
            raise
    
    def _process_feeds_sequential(self, feeds: List[Dict], global_stats: Dict):
        """Traite les flux de manière séquentielle"""
        for feed_config in feeds:
            self._process_single_feed(feed_config, global_stats)
    
    def _process_feeds_parallel(self, feeds: List[Dict], global_stats: Dict):
        """Traite les flux en parallèle"""
        max_workers = min(self.config.get('max_workers', 4), len(feeds))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_feed = {
                executor.submit(self._process_single_feed, feed, {}): feed
                for feed in feeds
            }
            
            for future in as_completed(future_to_feed):
                feed = future_to_feed[future]
                try:
                    feed_stats = future.result()
                    # Agrège les statistiques
                    for key in ['feeds_success', 'feeds_error', 'total_iocs', 'new_iocs', 'duplicates', 'errors']:
                        if key in feed_stats:
                            global_stats[key] += feed_stats[key]
                except Exception as e:
                    self.logger.error(f"Erreur lors du traitement du flux {feed['name']}: {e}")
                    global_stats['feeds_error'] += 1
    
    def _process_single_feed(self, feed_config: Dict, stats: Dict) -> Dict:
        """Traite un flux unique"""
        feed_name = feed_config['name']
        feed_stats = {'feeds_success': 0, 'feeds_error': 0, 'total_iocs': 0, 'new_iocs': 0, 'duplicates': 0, 'errors': 0}
        
        try:
            self.logger.info(f"Début du traitement: {feed_name}")
            feed_start_time = time.time()
            
            # Crée le plugin
            plugin = self.plugin_manager.create_plugin(feed_config)
            
            # Collecte les données
            self.logger.debug(f"Collecte des données depuis {feed_name}")
            raw_data = plugin.collect()
            
            if not raw_data:
                self.logger.warning(f"Aucune donnée collectée depuis {feed_name}")
                return feed_stats
            
            self.logger.debug(f"Collecté {len(raw_data)} octets depuis {feed_name}")
            
            # Parse les IOCs
            self.logger.debug(f"Parsing des IOCs depuis {feed_name}")
            iocs = plugin.parse(raw_data)
            
            if not iocs:
                self.logger.warning(f"Aucun IOC extrait depuis {feed_name}")
                return feed_stats
            
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {feed_name}")
            
            # Stocke les IOCs
            storage_stats = self.storage.store_iocs(iocs)
            
            # Met à jour les statistiques
            feed_stats.update({
                'feeds_success': 1,
                'total_iocs': storage_stats['total'],
                'new_iocs': storage_stats['new'],
                'duplicates': storage_stats['duplicates'],
                'errors': storage_stats['errors']
            })
            
            # Statistiques du plugin
            plugin_stats = plugin.get_stats()
            
            # Durée de traitement
            duration = time.time() - feed_start_time
            
            self.logger.info(
                f"Flux {feed_name} terminé en {duration:.2f}s: "
                f"{storage_stats['new']} nouveaux IOCs, "
                f"{storage_stats['duplicates']} doublons, "
                f"{storage_stats['errors']} erreurs"
            )
            
            if storage_stats['errors'] > 0:
                self.logger.warning(f"Erreurs lors du stockage pour {feed_name}: {storage_stats['errors']}")
            
        except PluginError as e:
            feed_stats['feeds_error'] = 1
            self.logger.error(f"Erreur de plugin pour {feed_name}: {e}")
            
        except Exception as e:
            feed_stats['feeds_error'] = 1
            self.logger.error(f"Erreur inattendue pour {feed_name}: {e}")
            self.logger.debug(f"Stack trace: {traceback.format_exc()}")
        
        # Met à jour les stats globales
        for key, value in feed_stats.items():
            stats[key] = stats.get(key, 0) + value
        
        return feed_stats
    
    def _log_final_stats(self, stats: Dict, duration: float):
        """Affiche les statistiques finales"""
        self.logger.info("=" * 50)
        self.logger.info("Collecte TinyCTI terminée")
        self.logger.info("=" * 50)
        
        self.logger.info(f"Durée totale: {duration:.2f} secondes")
        self.logger.info(f"Flux totaux: {stats['feeds_total']}")
        self.logger.info(f"Flux activés: {stats['feeds_enabled']}")
        self.logger.info(f"Flux traités avec succès: {stats['feeds_success']}")
        self.logger.info(f"Flux en erreur: {stats['feeds_error']}")
        self.logger.info(f"IOCs totaux traités: {stats['total_iocs']}")
        self.logger.info(f"Nouveaux IOCs ajoutés: {stats['new_iocs']}")
        self.logger.info(f"IOCs dupliqués ignorés: {stats['duplicates']}")
        
        if stats['errors'] > 0:
            self.logger.warning(f"Erreurs de stockage: {stats['errors']}")
        
        # Taux de réussite
        if stats['feeds_enabled'] > 0:
            success_rate = (stats['feeds_success'] / stats['feeds_enabled']) * 100
            self.logger.info(f"Taux de réussite: {success_rate:.1f}%")

def main():
    """Point d'entrée principal"""
    import argparse
    import signal
    
    parser = argparse.ArgumentParser(
        description='TinyCTI - Framework modulaire léger de collecte d\'IOCs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python tinycti.py                    # Exécution one-shot avec config.yaml
  python tinycti.py -c myconfig.yaml   # Configuration spécifique
  python tinycti.py -d                 # Mode daemon (planification automatique)
  python tinycti.py --daemon           # Mode daemon explicite
  python tinycti.py --api              # Démarre uniquement l'API (sans collecte)
  python tinycti.py -d --api           # Mode daemon + API
  python tinycti.py --export-ngfw      # Export NGFW manuel
  python tinycti.py -v                 # Mode verbeux
  python tinycti.py --debug            # Mode debug complet
  python tinycti.py --status           # Affiche le statut du planificateur
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Fichier de configuration YAML (défaut: config.yaml)'
    )
    
    parser.add_argument(
        '-d', '--daemon',
        action='store_true',
        help='Mode daemon avec planification automatique'
    )
    
    parser.add_argument(
        '--once',
        action='store_true',
        help='Force le mode one-shot (ignore la config daemon)'
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='Affiche le statut du planificateur et quitte'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbeux (niveau INFO)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Mode debug complet (niveau DEBUG)'
    )
    
    parser.add_argument(
        '--validate-config',
        action='store_true',
        help='Valide uniquement la configuration et quitte'
    )
    
    parser.add_argument(
        '--api',
        action='store_true',
        help='Démarre uniquement le serveur API (sans collecte)'
    )
    
    parser.add_argument(
        '--export-ngfw',
        action='store_true',
        help='Lance un export NGFW manuel et quitte'
    )
    
    parser.add_argument(
        '--api-host',
        default='127.0.0.1',
        help='Adresse IP pour l\'API (défaut: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--api-port',
        type=int,
        default=5000,
        help='Port pour l\'API (défaut: 5000)'
    )
    
    parser.add_argument(
        '--analyze-csv',
        metavar='FEED_NAME',
        help='Analyse la structure d\'un flux CSV et suggère une configuration'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='TinyCTI 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Configuration des logs
    log_level = logging.WARNING
    if args.debug:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('tinycti.log'),
            logging.StreamHandler()
        ]
    )
    
    # Supprime les logs verbeux des bibliothèques externes
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    # Variable globale pour l'instance TinyCTI (pour les signaux)
    tinycti_instance = None
    
    def signal_handler(signum, frame):
        """Gestionnaire de signaux pour arrêt propre"""
        signal_name = signal.Signals(signum).name
        logging.info(f"Signal {signal_name} reçu, arrêt en cours...")
        
        if tinycti_instance and tinycti_instance.is_daemon_running:
            tinycti_instance.stop_daemon()
        else:
            sys.exit(0)
    
    # Enregistre les gestionnaires de signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        tinycti_instance = TinyCTI(args.config)
        
        # Validation seule de la configuration
        if args.validate_config:
            print("✓ Configuration valide")
            sys.exit(0)
        
        # Export NGFW manuel
        if args.export_ngfw:
            print("Lancement de l'export NGFW...")
            tinycti_instance.manual_export_ngfw()
            print("✓ Export NGFW terminé")
            sys.exit(0)
        
        # Analyse CSV
        if args.analyze_csv:
            print(f"Analyse du flux CSV: {args.analyze_csv}")
            
            # Trouve le flux dans la configuration
            feed_config = None
            for feed in tinycti_instance.config['feeds']:
                if feed['name'] == args.analyze_csv:
                    feed_config = feed
                    break
            
            if not feed_config:
                print(f"Erreur: Flux '{args.analyze_csv}' non trouvé dans la configuration")
                sys.exit(1)
            
            if feed_config['type'] != 'csv':
                print(f"Erreur: Le flux '{args.analyze_csv}' n'est pas de type CSV")
                sys.exit(1)
            
            try:
                # Crée le plugin CSV pour analyse
                csv_plugin = CSVPlugin(feed_config, args.analyze_csv, tinycti_instance.api_manager)
                analysis = csv_plugin.analyze_csv_structure()
                
                print("\n=== Analyse de la Structure CSV ===")
                print(f"Lignes analysées: {analysis.get('total_lines', 'N/A')}")
                print(f"Délimiteur: '{analysis.get('delimiter', 'N/A')}'")
                print(f"En-tête: {analysis.get('has_header', 'N/A')}")
                print(f"Colonnes: {analysis.get('min_columns', 'N/A')}-{analysis.get('max_columns', 'N/A')}")
                print(f"Structure cohérente: {analysis.get('consistent_structure', 'N/A')}")
                
                if 'header' in analysis:
                    print(f"\nEn-têtes détectés:")
                    for i, header in enumerate(analysis['header']):
                        print(f"  {i}: {header}")
                
                print(f"\nAnalyse des colonnes:")
                for col in analysis.get('columns', []):
                    print(f"  Colonne {col['index']} ('{col['name']}'):")
                    print(f"    IOCs détectés: {col['ioc_count']}/{col['total_values']} ({col['ioc_percentage']:.1f}%)")
                    if col['ioc_types']:
                        print(f"    Types: {', '.join(col['ioc_types'])}")
                    if col['sample_values']:
                        print(f"    Échantillon: {col['sample_values'][:3]}")
                    print()
                
                print("=== Recommandations ===")
                for rec in analysis.get('recommendations', []):
                    print(f"• {rec}")
                
                if 'error' in analysis:
                    print(f"Erreur d'analyse: {analysis['error']}")
                
                print("\n=== Configuration Suggérée ===")
                best_col = max(analysis.get('columns', []), key=lambda c: c['ioc_percentage'], default=None)
                if best_col:
                    print(f"column: {best_col['index']}  # ou '{best_col['name']}' par nom")
                    if best_col['ioc_percentage'] > 80:
                        print("auto_detect_column: false  # Colonne clairement identifiée")
                    else:
                        print("auto_detect_column: true   # Utilise l'auto-détection")
                
                if not analysis.get('consistent_structure', True):
                    print("skip_malformed_lines: true  # Ignore les lignes incomplètes")
                    print(f"min_columns: {analysis.get('min_columns', 1)}  # Minimum de colonnes requis")
                
            except Exception as e:
                print(f"Erreur lors de l'analyse: {e}")
                sys.exit(1)
            
            sys.exit(0)
        
        # Mode API uniquement
        if args.api and not args.daemon:
            print(f"Démarrage du serveur API sur http://{args.api_host}:{args.api_port}")
            print("Appuyez sur Ctrl+C pour arrêter")
            
            # Override la config API si arguments fournis
            if not tinycti_instance.api_server:
                tinycti_instance.api_server = TinyCTIAPI(tinycti_instance, args.api_host, args.api_port)
            
            try:
                tinycti_instance.api_server.start()
            except KeyboardInterrupt:
                print("\nServeur API arrêté")
                sys.exit(0)
        
        # Affichage du statut du planificateur
        if args.status:
            if tinycti_instance.scheduler:
                status = tinycti_instance.scheduler.get_status()
                print("\n=== Statut du Planificateur TinyCTI ===")
                print(f"Tâches totales: {status['total_tasks']}")
                print(f"Tâches en cours: {status['running_tasks']}")
                print(f"Tâches prêtes: {status['ready_tasks']}")
                
                if status['next_execution']:
                    print(f"Prochaine exécution: {status['next_execution'].strftime('%Y-%m-%d %H:%M:%S')}")
                
                print("\nDétail des tâches:")
                for name, task_info in status['tasks'].items():
                    status_str = "🔄 EN COURS" if task_info['is_running'] else "⏳ EN ATTENTE"
                    print(f"  {name}: {status_str}")
                    print(f"    Priorité: {task_info['priority']}")
                    print(f"    Prochaine exécution: dans {task_info['seconds_until_next']}s")
                    if task_info['consecutive_errors'] > 0:
                        print(f"    Erreurs consécutives: {task_info['consecutive_errors']}")
            else:
                print("Planificateur non configuré (mode daemon désactivé)")
            
            sys.exit(0)
        
        # Détermine le mode d'exécution
        daemon_mode = args.daemon
        if args.once:
            daemon_mode = False
        
        # Lance l'exécution
        tinycti_instance.run(daemon_mode=daemon_mode)
        
    except ConfigurationError as e:
        logging.error(f"Erreur de configuration: {e}")
        sys.exit(1)
        
    except KeyboardInterrupt:
        logging.info("Arrêt demandé par l'utilisateur")
        sys.exit(0)
        
    except Exception as e:
        logging.error(f"Erreur fatale: {e}")
        logging.debug(f"Stack trace: {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()