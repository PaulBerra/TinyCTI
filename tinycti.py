#!/usr/bin/env python3
"""
TinyCTI - Framework modulaire léger de collecte et publication d'IOCs
"""

from __future__ import annotations

import csv
import gc
import hashlib
import json
import logging
import os
import random
import re
import shutil
import signal
import sqlite3
import sys
import threading
import time
import traceback
import uuid
import weakref
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import psutil
import yaml

# Bibliothèques externes
try:
    import gzip
    import zipfile

    import bcrypt
    import feedparser
    import iocextract
    import jwt
    import requests
    import stix2
    import taxii2client
    from cerberus import Validator
    from flask import (Flask, Response, jsonify, redirect,
                       render_template_string, request, session, url_for)
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    from werkzeug.serving import make_server
except ImportError as e:
    print(f"Erreur d'import: {e}")
    print(
        "Installez les dépendances: pip install requests feedparser iocextract stix2 taxii2-client cerberus flask"
    )
    sys.exit(1)

# ===============================
# UTILITAIRES COMMUNS ET SÉCURITÉ
# ===============================

import hashlib
import hmac
import re
import secrets
from html import escape


class SecurityValidator:
    """Validateur de sécurité pour l'entrée utilisateur"""

    # Patterns de validation sécurisée
    SAFE_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")
    SAFE_PATH_PATTERN = re.compile(r"^[a-zA-Z0-9._/-]+$")
    SAFE_CONFIG_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")

    # Longueurs maximales
    MAX_FILENAME_LENGTH = 255
    MAX_PATH_LENGTH = 4096
    MAX_CONFIG_VALUE_LENGTH = 8192
    MAX_LOG_MESSAGE_LENGTH = 2048

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Nettoie et valide un nom de fichier"""
        if not filename or len(filename) > SecurityValidator.MAX_FILENAME_LENGTH:
            raise ValueError("Nom de fichier invalide ou trop long")

        # Supprime les caractères dangereux
        sanitized = re.sub(r"[^\w\.-]", "_", filename)

        # Vérifie contre les noms réservés
        reserved_names = {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        }
        if sanitized.upper() in reserved_names:
            sanitized = f"safe_{sanitized}"

        return sanitized

    @staticmethod
    def sanitize_path(path: str) -> str:
        """Nettoie et valide un chemin de fichier"""
        if not path or len(path) > SecurityValidator.MAX_PATH_LENGTH:
            raise ValueError("Chemin invalide ou trop long")

        # Normalise le chemin et empêche le directory traversal
        normalized = os.path.normpath(path)
        if ".." in normalized or normalized.startswith("/"):
            raise ValueError("Chemin non autorisé détecté")

        return normalized

    @staticmethod
    def sanitize_log_message(message: str) -> str:
        """Nettoie un message de log pour éviter l'injection"""
        if not message:
            return ""

        # Limite la longueur
        if len(message) > SecurityValidator.MAX_LOG_MESSAGE_LENGTH:
            message = message[: SecurityValidator.MAX_LOG_MESSAGE_LENGTH] + "..."

        # Échappe les caractères HTML et supprime les caractères de contrôle
        sanitized = escape(message)
        sanitized = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", sanitized)

        return sanitized

    @staticmethod
    def validate_ioc_value(value: str, ioc_type: str) -> bool:
        """Valide qu'une valeur IOC est sûre et conforme au type"""
        if not value or len(value) > 2048:  # Limite raisonnable pour les IOCs
            return False

        # Patterns de validation par type d'IOC
        patterns = {
            "ipv4": re.compile(
                r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            ),
            "ipv6": re.compile(
                r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$"
            ),
            "domain": re.compile(
                r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
            ),
            "url": re.compile(r"^https?://[^\s/$.?#].[^\s]*$"),
            "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
            "hash_md5": re.compile(r"^[a-fA-F0-9]{32}$"),
            "hash_sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
            "hash_sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
            "hash_sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
        }

        pattern = patterns.get(ioc_type)
        return pattern.match(value) is not None if pattern else True


class SecureSessionManager:
    """Gestionnaire de sessions sécurisé"""

    def __init__(self, secret_key: str):
        if not secret_key or len(secret_key) < 32:
            raise ValueError("Clé secrète trop faible")
        self.secret_key = (
            secret_key.encode() if isinstance(secret_key, str) else secret_key
        )
        self.sessions = {}  # En production, utiliser Redis ou une base de données

    def create_session(self, user_id: str, user_data: dict) -> str:
        """Crée une session sécurisée"""
        session_id = secrets.token_urlsafe(32)
        timestamp = datetime.now()

        session_data = {
            "user_id": user_id,
            "user_data": user_data,
            "created_at": timestamp,
            "last_accessed": timestamp,
            "csrf_token": secrets.token_urlsafe(32),
        }

        # Signe la session
        session_signature = self._sign_session(session_id, session_data)
        session_data["signature"] = session_signature

        self.sessions[session_id] = session_data
        return session_id

    def validate_session(self, session_id: str) -> Optional[dict]:
        """Valide et récupère une session"""
        if not session_id or session_id not in self.sessions:
            return None

        session_data = self.sessions[session_id]

        # Vérifie la signature
        expected_signature = self._sign_session(
            session_id, {k: v for k, v in session_data.items() if k != "signature"}
        )
        if not hmac.compare_digest(session_data["signature"], expected_signature):
            self.invalidate_session(session_id)
            return None

        # Vérifie l'expiration (24h par défaut)
        if datetime.now() - session_data["created_at"] > timedelta(hours=24):
            self.invalidate_session(session_id)
            return None

        # Met à jour l'accès
        session_data["last_accessed"] = datetime.now()
        return session_data

    def invalidate_session(self, session_id: str):
        """Invalide une session"""
        self.sessions.pop(session_id, None)

    def _sign_session(self, session_id: str, session_data: dict) -> str:
        """Signe une session avec HMAC"""
        data_to_sign = (
            f"{session_id}:{session_data['user_id']}:{session_data['created_at']}"
        )
        return hmac.new(
            self.secret_key, data_to_sign.encode(), hashlib.sha256
        ).hexdigest()


class RateLimiter:
    """Limiteur de débit avancé avec protection DDoS"""

    def __init__(self):
        self.requests = {}  # IP -> [timestamps]
        self.blocked_ips = {}  # IP -> block_until_timestamp
        self.failed_attempts = {}  # IP -> failed_count

    def is_allowed(
        self,
        ip: str,
        endpoint: str = "default",
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> bool:
        """Vérifie si une requête est autorisée"""
        now = datetime.now()

        # Vérifie si l'IP est bloquée
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                return False
            else:
                del self.blocked_ips[ip]

        # Clé unique par IP et endpoint
        key = f"{ip}:{endpoint}"

        # Nettoie les anciennes requêtes
        if key in self.requests:
            self.requests[key] = [
                req_time
                for req_time in self.requests[key]
                if now - req_time < timedelta(seconds=window_seconds)
            ]
        else:
            self.requests[key] = []

        # Vérifie la limite
        if len(self.requests[key]) >= max_requests:
            self._record_failed_attempt(ip)
            return False

        # Enregistre la requête
        self.requests[key].append(now)
        return True

    def _record_failed_attempt(self, ip: str):
        """Enregistre une tentative échouée et bloque si nécessaire"""
        self.failed_attempts[ip] = self.failed_attempts.get(ip, 0) + 1

        # Bloque après 5 tentatives échouées
        if self.failed_attempts[ip] >= 5:
            block_duration = min(
                300 * (2 ** (self.failed_attempts[ip] - 5)), 3600
            )  # Max 1h
            self.blocked_ips[ip] = datetime.now() + timedelta(seconds=block_duration)

    def reset_failed_attempts(self, ip: str):
        """Remet à zéro les tentatives échouées (après connexion réussie)"""
        self.failed_attempts.pop(ip, None)


class MemoryManager:
    """Gestionnaire de mémoire avancé avec monitoring et optimisation"""

    def __init__(self, max_memory_mb: int = 1024, gc_threshold: int = 10000):
        self.max_memory_mb = max_memory_mb
        self.gc_threshold = gc_threshold
        self.object_count = 0
        self.last_gc_time = datetime.now()
        self.memory_alerts = []

        # Pools d'objets réutilisables
        self.string_pool = weakref.WeakValueDictionary()
        self.list_pool = []
        self.dict_pool = []

        # Configuration du garbage collector
        gc.set_threshold(gc_threshold, gc_threshold // 10, gc_threshold // 100)

    def get_memory_usage(self) -> Dict[str, Any]:
        """Retourne les statistiques d'utilisation mémoire"""
        process = psutil.Process()
        memory_info = process.memory_info()

        return {
            "rss_mb": memory_info.rss / (1024 * 1024),  # Resident Set Size
            "vms_mb": memory_info.vms / (1024 * 1024),  # Virtual Memory Size
            "percent": process.memory_percent(),
            "available_mb": psutil.virtual_memory().available / (1024 * 1024),
            "gc_counts": gc.get_count(),
            "object_count": len(gc.get_objects()),
            "max_memory_mb": self.max_memory_mb,
        }

    def check_memory_usage(self) -> bool:
        """Vérifie si l'utilisation mémoire est dans les limites"""
        memory_stats = self.get_memory_usage()

        if memory_stats["rss_mb"] > self.max_memory_mb:
            alert = {
                "timestamp": datetime.now(),
                "memory_mb": memory_stats["rss_mb"],
                "limit_mb": self.max_memory_mb,
                "message": "Memory limit exceeded",
            }
            self.memory_alerts.append(alert)

            # Keep only last 100 alerts to prevent unbounded growth
            if len(self.memory_alerts) > 100:
                self.memory_alerts = self.memory_alerts[-100:]

            return False

        return True

    def force_garbage_collection(self) -> Dict[str, int]:
        """Force le garbage collection et retourne les statistiques"""
        before = len(gc.get_objects())

        # Collecte forcée sur tous les niveaux
        collected_0 = gc.collect(0)
        collected_1 = gc.collect(1)
        collected_2 = gc.collect(2)

        after = len(gc.get_objects())
        self.last_gc_time = datetime.now()

        # Nettoie les pools d'objets
        self._clean_object_pools()

        return {
            "objects_before": before,
            "objects_after": after,
            "objects_freed": before - after,
            "collected_gen0": collected_0,
            "collected_gen1": collected_1,
            "collected_gen2": collected_2,
            "total_collected": collected_0 + collected_1 + collected_2,
        }

    def optimize_memory(self) -> Dict[str, Any]:
        """Optimise l'utilisation mémoire"""
        stats_before = self.get_memory_usage()

        # Garbage collection agressif
        gc_stats = self.force_garbage_collection()

        # Vide les caches si nécessaire
        if stats_before["rss_mb"] > self.max_memory_mb * 0.8:
            self._clear_caches()

        stats_after = self.get_memory_usage()

        return {
            "memory_before_mb": stats_before["rss_mb"],
            "memory_after_mb": stats_after["rss_mb"],
            "memory_freed_mb": stats_before["rss_mb"] - stats_after["rss_mb"],
            "gc_stats": gc_stats,
            "optimization_time": datetime.now(),
        }

    def get_pooled_string(self, value: str) -> str:
        """Récupère une chaîne depuis le pool ou l'ajoute"""
        if value in self.string_pool:
            return self.string_pool[value]

        # Limite la taille du pool
        if len(self.string_pool) > 10000:
            self.string_pool.clear()

        self.string_pool[value] = value
        return value

    def get_pooled_list(self) -> List:
        """Récupère une liste réutilisable depuis le pool"""
        if self.list_pool:
            return self.list_pool.pop()
        return []

    def return_list(self, lst: List):
        """Retourne une liste au pool après utilisation"""
        lst.clear()
        if len(self.list_pool) < 100:  # Limite la taille du pool
            self.list_pool.append(lst)

    def get_pooled_dict(self) -> Dict:
        """Récupère un dictionnaire réutilisable depuis le pool"""
        if self.dict_pool:
            return self.dict_pool.pop()
        return {}

    def return_dict(self, dct: Dict):
        """Retourne un dictionnaire au pool après utilisation"""
        dct.clear()
        if len(self.dict_pool) < 100:  # Limite la taille du pool
            self.dict_pool.append(dct)

    def _clean_object_pools(self):
        """Nettoie les pools d'objets"""
        # Garde seulement les derniers objets utilisés
        if len(self.list_pool) > 50:
            self.list_pool = self.list_pool[-50:]

        if len(self.dict_pool) > 50:
            self.dict_pool = self.dict_pool[-50:]

    def _clear_caches(self):
        """Vide les caches internes pour libérer de la mémoire"""
        self.string_pool.clear()
        self.list_pool.clear()
        self.dict_pool.clear()

    def get_memory_report(self) -> str:
        """Génère un rapport détaillé de l'utilisation mémoire"""
        stats = self.get_memory_usage()

        report = f"""
=== TinyCTI Memory Report ===
RSS Memory: {stats['rss_mb']:.2f} MB
VMS Memory: {stats['vms_mb']:.2f} MB
Memory %: {stats['percent']:.2f}%
Available: {stats['available_mb']:.2f} MB
Max Allowed: {self.max_memory_mb} MB
Objects: {stats['object_count']}
GC Counts: {stats['gc_counts']}
String Pool: {len(self.string_pool)} items
List Pool: {len(self.list_pool)} items
Dict Pool: {len(self.dict_pool)} items
Last GC: {self.last_gc_time}
Memory Alerts: {len(self.memory_alerts)}
"""

        if self.memory_alerts:
            report += "\n=== Recent Memory Alerts ===\n"
            for alert in self.memory_alerts[-5:]:  # Dernières 5 alertes
                report += f"{alert['timestamp']}: {alert['message']} ({alert['memory_mb']:.2f}MB)\n"

        return report


class PerformanceMonitor:
    """Moniteur de performance avec métriques détaillées"""

    def __init__(self):
        self.metrics = {}
        self.start_times = {}
        self.memory_manager = MemoryManager()

    def start_timer(self, operation: str):
        """Démarre un timer pour une opération"""
        self.start_times[operation] = time.time()

    def end_timer(self, operation: str) -> float:
        """Termine un timer et enregistre la métrique"""
        if operation not in self.start_times:
            return 0.0

        duration = time.time() - self.start_times[operation]

        if operation not in self.metrics:
            self.metrics[operation] = {
                "count": 0,
                "total_time": 0.0,
                "min_time": float("inf"),
                "max_time": 0.0,
                "last_time": 0.0,
            }

        metrics = self.metrics[operation]
        metrics["count"] += 1
        metrics["total_time"] += duration
        metrics["min_time"] = min(metrics["min_time"], duration)
        metrics["max_time"] = max(metrics["max_time"], duration)
        metrics["last_time"] = duration

        del self.start_times[operation]
        return duration

    def get_performance_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de performance"""
        stats = {}

        for operation, data in self.metrics.items():
            if data["count"] > 0:
                stats[operation] = {
                    "count": data["count"],
                    "avg_time": data["total_time"] / data["count"],
                    "min_time": data["min_time"],
                    "max_time": data["max_time"],
                    "last_time": data["last_time"],
                    "total_time": data["total_time"],
                }

        # Ajoute les métriques mémoire
        stats["memory"] = self.memory_manager.get_memory_usage()

        return stats

    def optimize_if_needed(self) -> Optional[Dict[str, Any]]:
        """Optimise automatiquement si nécessaire"""
        if not self.memory_manager.check_memory_usage():
            return self.memory_manager.optimize_memory()
        return None


def parse_duration(duration_str: str) -> int:
    """Parse une durée en secondes depuis une chaîne (ex: '1h', '30m', '7d')"""
    if not duration_str or not isinstance(duration_str, str):
        raise ValueError("Duration string is required")

    duration_str = duration_str.strip().lower()

    # Si c'est déjà un nombre, retourne-le
    if duration_str.isdigit():
        value = int(duration_str)
        if value <= 0:
            raise ValueError("Duration must be positive")
        return value

    # Parse les formats avec unités
    import re

    match = re.match(r"^(\d+)([smhd])$", duration_str)
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")

    value, unit = match.groups()
    value = int(value)

    if value <= 0:
        raise ValueError("Duration must be positive")

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}

    # Validation des limites raisonnables
    result = value * multipliers.get(unit, 1)
    if unit == "h" and value > 24:
        raise ValueError("Hours cannot exceed 24")
    if result > 86400 * 365:  # Plus d'un an
        raise ValueError("Duration too large")

    return result


def parse_size(size_str: str) -> int:
    """Parse une taille en bytes depuis une chaîne (ex: '10MB', '1GB')"""
    if not size_str or not isinstance(size_str, str):
        return 0

    size_str = size_str.strip().upper()

    # Si c'est déjà un nombre, retourne-le
    if size_str.isdigit():
        return int(size_str)

    # Parse les formats avec unités
    import re

    match = re.match(r"^(\d+(?:\.\d+)?)(KB|MB|GB|TB)$", size_str)
    if not match:
        return 0

    value, unit = match.groups()
    value = float(value)

    multipliers = {
        "KB": 1024,
        "MB": 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
        "TB": 1024 * 1024 * 1024 * 1024,
    }

    return int(value * multipliers.get(unit, 1))


# ===============================
# ENUMS ET TYPES
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


class ThreatLevel(Enum):
    """Niveaux de menace pour classification"""

    HIGH = "high"  # Menace confirmée, impact élevé
    MEDIUM = "medium"  # Menace probable, impact modéré
    LOW = "low"  # Menace potentielle, impact faible
    INFO = "info"  # Information, pas de menace directe


class ConfidenceLevel(Enum):
    """Niveaux de confiance pour les IOCs"""

    CONFIRMED = "confirmed"  # IOC confirmé par multiple sources
    HIGH = "high"  # IOC de source fiable
    MEDIUM = "medium"  # IOC de source modérément fiable
    LOW = "low"  # IOC de source peu fiable
    UNKNOWN = "unknown"  # Confiance non évaluée


class ThreatBucket(Enum):
    """Buckets de threat intelligence optimisés"""

    # Buckets opérationnels (priorité élevée)
    CRITICAL = "critical"  # IOCs critiques - Blocking immédiat
    ACTIVE = "active"  # IOCs actifs - Monitoring renforcé
    WATCH = "watch"  # IOCs à surveiller - Alerting

    # Buckets d'analyse (priorité moyenne)
    INTEL = "intel"  # IOCs d'intelligence - Enrichissement
    EMERGING = "emerging"  # IOCs émergents - Validation en cours

    # Buckets de stockage (priorité faible)
    ARCHIVE = "archive"  # IOCs archivés - Recherche historique
    DEPRECATED = "deprecated"  # IOCs obsolètes - Prêts pour suppression


# Alias pour compatibilité ascendante
class RetentionBucket(Enum):
    """Buckets de rétention (legacy - utiliser ThreatBucket)"""

    LIVE = "critical"  # Mapping vers CRITICAL
    CHAUD = "active"  # Mapping vers ACTIVE
    TIEDE = "watch"  # Mapping vers WATCH
    FROID = "archive"  # Mapping vers ARCHIVE


# ===============================
# CONFIGURATION ET VALIDATION
# ===============================


class ConfigurationError(Exception):
    """Erreur de configuration"""

    def __init__(self, message, config_key=None):
        super().__init__(message)
        self.config_key = config_key


class PluginError(Exception):
    """Erreur de plugin"""

    pass


class APIError(Exception):
    """Erreur API"""

    pass


class StorageError(Exception):
    """Erreur de stockage"""

    pass


class RetentionError(Exception):
    """Erreur de rétention"""

    pass


class ErrorHandler:
    """Gestionnaire centralisé des erreurs avec logging et récupération"""

    def __init__(self, logger: logging.Logger, max_error_history: int = 100):
        self.logger = logger
        self.error_counts = {}
        self.last_errors = []
        self.max_error_history = max_error_history

    def handle_error(
        self,
        error: Exception,
        context: str = "",
        critical: bool = False,
        user_message: str = None,
    ) -> dict:
        """Gère une erreur de manière centralisée

        Args:
            error: L'exception à gérer
            context: Contexte où l'erreur s'est produite
            critical: Si True, l'erreur est considérée comme critique
            user_message: Message personnalisé pour l'utilisateur

        Returns:
            dict: Informations sur l'erreur pour les APIs
        """
        try:
            error_type = type(error).__name__
            error_msg = str(error)

            # Comptabilise les erreurs
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

            # Stocke l'erreur dans l'historique
            tb = traceback.format_exc()
            error_info = {
                "timestamp": datetime.now().isoformat(),
                "type": error_type,
                "message": error_msg,
                "error": error_msg,
                "context": context,
                "critical": critical,
                "traceback": tb if tb != "NoneType: None\n" else None,
            }

            self.last_errors.append(error_info)
            if len(self.last_errors) > self.max_error_history:
                self.last_errors.pop(0)

            # Log selon la criticité
            try:
                if critical:
                    self.logger.critical(
                        f"Erreur critique dans {context}: {error_type}: {error_msg}\nTraceback: {tb}"
                    )
                else:
                    self.logger.error(
                        f"Erreur dans {context}: {error_type}: {error_msg}"
                    )
            except Exception:
                # Ignore les erreurs de logging pour éviter les cascades
                pass

            # Retourne une réponse formatée pour les APIs
            result = {
                "error": user_message or error_msg,
                "error_type": error_type,
                "context": context,
                "timestamp": error_info["timestamp"],
                "critical": critical,
            }

            # Ajoute traceback si disponible
            if error_info.get("traceback"):
                result["traceback"] = error_info["traceback"]

            return result

        except (AttributeError, TypeError, ValueError) as internal_error:
            # En cas d'erreur interne, retourne une structure minimale
            return {
                "error": str(error),
                "error_type": type(error).__name__,
                "context": context,
                "timestamp": datetime.now().isoformat(),
                "critical": critical,
                "internal_error": str(internal_error),
            }

    def get_error_stats(self, recent_limit: int = 10) -> Dict[str, Any]:
        """Retourne les statistiques d'erreurs"""
        return {
            "error_counts": self.error_counts.copy(),
            "total_errors": sum(self.error_counts.values()),
            "recent_errors": self.last_errors[-recent_limit:],  # Dernières erreurs
            "critical_errors": [e for e in self.last_errors if e["critical"]],
        }

    def clear_error_history(self):
        """Vide l'historique des erreurs"""
        self.last_errors.clear()
        self.error_counts.clear()
        self.logger.info("Historique des erreurs vidé")


class CircuitBreaker:
    """Implémentation d'un circuit breaker pour éviter les cascades d'erreurs"""

    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout  # en secondes
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def call(self, func, *args, **kwargs):
        """Exécute une fonction avec protection circuit breaker"""
        if self.state == "OPEN":
            if (
                self.last_failure_time
                and (datetime.now() - self.last_failure_time).total_seconds()
                > self.timeout
            ):
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN - operation blocked")

        try:
            result = func(*args, **kwargs)

            # Succès - reset le circuit breaker
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
            self.failure_count = 0  # Reset le compteur à chaque succès

            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = datetime.now()

            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"

            raise e

    def reset(self):
        """Reset manuel du circuit breaker"""
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"


class ConfigurationLoader:
    """Gestionnaire de configuration centralisé"""

    SCHEMA = {
        "feeds": {
            "type": "list",
            "required": True,
            "schema": {
                "type": "dict",
                "schema": {
                    "name": {"type": "string", "required": True},
                    "type": {
                        "type": "string",
                        "required": True,
                        "allowed": ["text", "csv", "json", "stix", "taxii", "rss"],
                    },
                    "url": {"type": "string", "required": True},
                    "enabled": {"type": "boolean", "default": True},
                    "retention": {
                        "type": "string",
                        "default": "active",
                        "allowed": ["active", "critical", "watch", "archive", "live", "chaud", "tiede", "froid"],
                    },
                    "api_keys": {"type": "list", "default": []},
                    "delimiter": {"type": "string", "default": ","},
                    "encoding": {"type": "string", "default": "utf-8"},
                    "column": {"type": ["string", "integer"], "default": 0},
                    "has_header": {"type": "boolean", "default": True},
                    "json_path": {"type": "list", "default": []},
                    "timeout": {"type": "integer", "default": 30},
                    "max_retries": {"type": "integer", "default": 3},
                    # Champs TAXII
                    "collection_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 100},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    # Champs RSS
                    "max_entries": {"type": "integer", "default": 100},
                    # Planification par flux
                    "schedule": {
                        "type": "string",
                        "default": "1h",
                    },  # Ex: "30m", "2h", "1d"
                    "priority": {
                        "type": "integer",
                        "default": 5,
                        "min": 1,
                        "max": 10,
                    },  # 1=haute, 10=basse
                    "rate_limit": {
                        "type": "integer",
                        "default": 0,
                    },  # Secondes entre requêtes
                    # Options CSV avancées
                    "auto_detect_column": {
                        "type": "boolean",
                        "default": False,
                    },  # Auto-détection de la meilleure colonne
                    "skip_malformed_lines": {
                        "type": "boolean",
                        "default": True,
                    },  # Ignore les lignes malformées
                    "min_columns": {
                        "type": "integer",
                        "default": 0,
                    },  # Nombre minimum de colonnes requis
                },
            },
        },
        "output_dir": {"type": "string", "default": "iocs"},
        "max_file_size": {"type": "integer", "default": 10485760},
        "parallel_feeds": {"type": "boolean", "default": False},
        "max_workers": {"type": "integer", "default": 4},
        "daemon": {
            "type": "dict",
            "default": {
                "enabled": False,
                "default_schedule": "1h",
                "check_interval": "60s",
                "max_concurrent_feeds": 3,
            },
        },
        "retention_policy": {
            "type": "dict",
            "default": {
                "live_to_chaud": "24h",
                "chaud_to_tiede": "7d",
                "tiede_to_froid": "30d",
                "froid_retention": "365d",
            },
        },
        "logging": {
            "type": "dict",
            "default": {
                "level": "INFO",
                "file": "tinycti.log",
                "max_size": "10MB",
                "backup_count": 5,
                "compression": False,
                "compress_after": "24h",
                "retention_days": 30,
                "audit_enabled": False,
                "audit_file": "audit.log",
            },
            "schema": {
                "level": {
                    "type": "string",
                    "default": "INFO",
                    "allowed": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                },
                "file": {"type": "string", "default": "tinycti.log"},
                "max_size": {"type": "string", "default": "10MB"},
                "backup_count": {"type": "integer", "default": 5, "min": 0},
                "compression": {"type": "boolean", "default": False},
                "compress_after": {"type": "string", "default": "24h"},
                "retention_days": {"type": "integer", "default": 30, "min": 1},
                "audit_enabled": {"type": "boolean", "default": False},
                "audit_file": {"type": "string", "default": "audit.log"},
            },
        },
        "security": {
            "type": "dict",
            "default": {
                "max_file_size": 52428800,
                "max_json_depth": 10,
                "validate_ssl": True,
                "user_agent": "TinyCTI/1.0",
            },
        },
        "api": {
            "type": "dict",
            "default": {
                "enabled": False,
                "host": "127.0.0.1",
                "port": 5000,
                "auto_export_ngfw": True,
                "auth": {
                    "enabled": False,
                    "password": "",
                    "rate_limit": {
                        "enabled": True,
                        "requests_per_minute": 60,
                        "burst": 10,
                    },
                },
            },
            "schema": {
                "enabled": {"type": "boolean", "default": False},
                "host": {"type": "string", "default": "127.0.0.1"},
                "port": {"type": "integer", "default": 5000, "min": 1, "max": 65535},
                "auto_export_ngfw": {"type": "boolean", "default": True},
                "auth": {
                    "type": "dict",
                    "default": {
                        "enabled": False,
                        "password": "",
                        "rate_limit": {
                            "enabled": True,
                            "requests_per_minute": 60,
                            "burst": 10,
                        },
                    },
                    "schema": {
                        "enabled": {"type": "boolean", "default": False},
                        "password": {"type": "string", "default": ""},
                        "rate_limit": {
                            "type": "dict",
                            "schema": {
                                "enabled": {"type": "boolean", "default": True},
                                "requests_per_minute": {
                                    "type": "integer",
                                    "default": 60,
                                    "min": 1,
                                },
                                "burst": {"type": "integer", "default": 10, "min": 1},
                            },
                        },
                    },
                },
                "export": {
                    "type": "dict",
                    "default": {
                        "csv_enabled": True,
                        "json_enabled": True,
                        "text_enabled": True,
                        "max_records": 10000,
                    },
                    "schema": {
                        "csv_enabled": {"type": "boolean", "default": True},
                        "json_enabled": {"type": "boolean", "default": True},
                        "text_enabled": {"type": "boolean", "default": True},
                        "max_records": {"type": "integer", "default": 10000, "min": 1},
                    },
                },
            },
        },
        "ngfw_export": {
            "type": "dict",
            "default": {
                "enabled": True,
                "output_dir": "ngfw",
                "auto_export_after_collection": True,
                "generate_pfsense_aliases": True,
                "generate_iptables_rules": True,
            },
        },
        "authentication": {
            "type": "dict",
            "default": {
                "users": {},
                "saml": {
                    "enabled": False,
                    "sp_entity_id": "tinycti",
                    "sp_assertion_consumer_service_url": "http://localhost:5000/saml/acs",
                    "idp_metadata_url": "",
                    "idp_sso_service_url": "",
                    "idp_x509_cert": "",
                },
                "openid": {
                    "enabled": False,
                    "client_id": "",
                    "client_secret": "",
                    "discovery_url": "",
                    "redirect_uri": "http://localhost:5000/openid/callback",
                },
            },
            "schema": {
                "users": {
                    "type": "dict",
                    "valueschema": {
                        "type": "dict",
                        "schema": {
                            "password_hash": {"type": "string"},
                            "role": {
                                "type": "string",
                                "default": "user",
                                "allowed": ["admin", "user", "readonly"],
                            },
                        },
                    },
                },
                "saml": {
                    "type": "dict",
                    "default": {
                        "enabled": False,
                        "sp_entity_id": "tinycti",
                        "sp_assertion_consumer_service_url": "http://localhost:5000/saml/acs",
                        "idp_metadata_url": "",
                        "idp_sso_service_url": "",
                        "idp_x509_cert": "",
                    },
                    "schema": {
                        "enabled": {"type": "boolean", "default": False},
                        "sp_entity_id": {"type": "string", "default": "tinycti"},
                        "sp_assertion_consumer_service_url": {
                            "type": "string",
                            "default": "http://localhost:5000/saml/acs",
                        },
                        "idp_metadata_url": {"type": "string", "default": ""},
                        "idp_sso_service_url": {"type": "string", "default": ""},
                        "idp_x509_cert": {"type": "string", "default": ""},
                    },
                },
                "openid": {
                    "type": "dict",
                    "default": {
                        "enabled": False,
                        "client_id": "",
                        "client_secret": "",
                        "discovery_url": "",
                        "redirect_uri": "http://localhost:5000/openid/callback",
                    },
                    "schema": {
                        "enabled": {"type": "boolean", "default": False},
                        "client_id": {"type": "string", "default": ""},
                        "client_secret": {"type": "string", "default": ""},
                        "discovery_url": {"type": "string", "default": ""},
                        "redirect_uri": {
                            "type": "string",
                            "default": "http://localhost:5000/openid/callback",
                        },
                    },
                },
            },
        },
        "retention": {
            "type": "dict",
            "default": {"enabled": False, "rules": []},
            "schema": {
                "enabled": {"type": "boolean", "default": False},
                "rules": {
                    "type": "list",
                    "schema": {
                        "type": "dict",
                        "schema": {
                            "from_bucket": {
                                "type": "string",
                                "required": True,
                                "allowed": ["active", "critical", "watch", "archive", "live", "chaud", "tiede", "froid"],
                            },
                            "to_bucket": {
                                "type": "string",
                                "required": True,
                                "allowed": ["active", "critical", "watch", "archive", "live", "chaud", "tiede", "froid"],
                            },
                            "after_days": {
                                "type": "integer",
                                "required": True,
                                "min": 1,
                            },
                        },
                    },
                },
            },
        },
        "internal_api": {
            "type": "dict",
            "default": {
                "enabled": False,
                "host": "127.0.0.1",
                "port": 8080,
                "auth_token": "",
                "rate_limit": 100,
            },
            "schema": {
                "enabled": {"type": "boolean", "default": False},
                "host": {"type": "string", "default": "127.0.0.1"},
                "port": {"type": "integer", "default": 8080, "min": 1, "max": 65535},
                "auth_token": {"type": "string", "default": ""},
                "rate_limit": {"type": "integer", "default": 100, "min": 1},
            },
        },
        "ssl_config_example": {"type": "dict", "default": {}, "allow_unknown": True},
    }

    def __init__(self, config_file: str):
        self.config_file = Path(config_file)
        self.config = None
        self.logger = logging.getLogger(f"{__name__}.ConfigLoader")

    def load_config(self) -> Dict[str, Any]:
        """Charge et valide la configuration"""
        try:
            if not self.config_file.exists():
                raise ConfigurationError(
                    f"Fichier de configuration non trouvé: {self.config_file}"
                )

            with open(self.config_file, "r", encoding="utf-8") as f:
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

            self.logger.info(
                f"Configuration chargée: {len(self.config['feeds'])} flux définis"
            )
            return self.config

        except yaml.YAMLError as e:
            raise ConfigurationError(f"Erreur de syntaxe YAML: {e}")
        except Exception as e:
            raise ConfigurationError(
                f"Erreur lors du chargement de la configuration: {e}"
            )

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
        feed_names = [feed["name"] for feed in self.config["feeds"]]
        if len(feed_names) != len(set(feed_names)):
            raise ConfigurationError("Les noms de flux doivent être uniques")

        # Vérifier les URLs
        for feed in self.config["feeds"]:
            url = feed["url"]
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ConfigurationError(
                    f"URL invalide pour le flux '{feed['name']}': {url}"
                )


# ===============================
# CONFIGURATION DU LOGGING
# ===============================


class LoggingConfigurator:
    """Gestionnaire de configuration avancée du logging avec rotation et compression"""

    def __init__(self, config: Dict[str, Any], override_level: Optional[int] = None):
        self.config = config.get("logging", {})
        # Utilise le niveau override si fourni, sinon prend celui de la config
        if override_level is not None:
            self.log_level = override_level
        else:
            level_name = self.config.get("level", "INFO").upper()
            try:
                self.log_level = getattr(logging, level_name)
            except AttributeError:
                print(f"Warning: Invalid log level '{level_name}', using INFO")
                self.log_level = logging.INFO
        self.log_file = self.config.get("file", "tinycti.log")
        self.max_size = self._parse_size(self.config.get("max_size", "10MB"))
        self.backup_count = self.config.get("backup_count", 5)
        self.compression = self.config.get("compression", True)
        self.compress_after = self.config.get("compress_after", "24h")
        self.retention_days = self.config.get("retention_days", 30)
        self.audit_enabled = self.config.get("audit_enabled", False)
        self.audit_file = self.config.get("audit_file", "tinycti-audit.log")

    def _parse_size(self, size_str: str) -> int:
        """Parse une taille au format '10MB', '1GB', etc."""
        return parse_size(size_str)

    def _parse_duration(self, duration_str: str) -> int:
        """Parse une durée au format '24h', '7d', etc. et retourne en secondes"""
        try:
            return parse_duration(duration_str)
        except ValueError:
            # Valeur par défaut en cas d'erreur
            return 3600  # 1 heure

    def setup_main_logger(self):
        """Configure le logger principal avec rotation et compression"""
        # Supprime les handlers existants
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Handler rotatif pour le fichier principal
        file_handler = RotatingFileHandler(
            self.log_file, maxBytes=self.max_size, backupCount=self.backup_count
        )

        # Handler pour la console
        console_handler = logging.StreamHandler()

        # Format des messages
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Configuration du logger root
        logging.root.setLevel(self.log_level)
        logging.root.addHandler(file_handler)
        logging.root.addHandler(console_handler)

        # Setup compression automatique si activée
        if self.compression:
            self._setup_log_compression()

    def _setup_log_compression(self):
        """Configure la compression automatique des logs"""

        def compress_old_logs():
            """Compresse les anciens logs"""
            import glob
            import time

            while True:
                try:
                    # Recherche les fichiers de log à compresser
                    log_pattern = f"{self.log_file}.*"
                    for log_file in glob.glob(log_pattern):
                        if not log_file.endswith(".gz") and log_file != self.log_file:
                            # Vérifie l'âge du fichier
                            file_age = time.time() - os.path.getmtime(log_file)
                            compress_after_seconds = self._parse_duration(
                                self.compress_after
                            )

                            if file_age > compress_after_seconds:
                                try:
                                    with open(log_file, "rb") as f_in:
                                        with gzip.open(f"{log_file}.gz", "wb") as f_out:
                                            f_out.write(f_in.read())
                                    os.remove(log_file)
                                    logging.info(f"Log compressé: {log_file}")
                                except Exception as e:
                                    logging.error(
                                        f"Erreur compression log {log_file}: {e}"
                                    )

                    # Nettoyage des anciens logs selon retention_days
                    retention_seconds = self.retention_days * 86400
                    for log_file in glob.glob(f"{log_pattern}.gz"):
                        file_age = time.time() - os.path.getmtime(log_file)
                        if file_age > retention_seconds:
                            try:
                                os.remove(log_file)
                                logging.info(f"Log ancien supprimé: {log_file}")
                            except Exception as e:
                                logging.error(f"Erreur suppression log {log_file}: {e}")

                except Exception as e:
                    logging.error(f"Erreur dans la compression automatique: {e}")

                # Attendre une heure avant le prochain cycle
                time.sleep(3600)

        # Lance le thread de compression en arrière-plan
        compression_thread = threading.Thread(target=compress_old_logs, daemon=True)
        compression_thread.start()

    def setup_audit_logger(self) -> Optional[logging.Logger]:
        """Configure le logger d'audit avec rotation"""
        if not self.audit_enabled:
            return None

        audit_logger = logging.getLogger("tinycti.audit")
        audit_logger.setLevel(logging.INFO)

        # Handler rotatif pour l'audit
        audit_handler = RotatingFileHandler(
            self.audit_file, maxBytes=self.max_size, backupCount=self.backup_count
        )

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        audit_handler.setFormatter(formatter)
        audit_logger.addHandler(audit_handler)

        return audit_logger


# ===============================
# GESTION DE LA RÉTENTION ET TRANSITIONS
# ===============================


class RetentionManager:
    """Gestionnaire intelligent des transitions entre buckets selon la politique de rétention"""

    def __init__(
        self, config: Dict[str, Any], storage: "IOCStorage", logger: logging.Logger
    ):
        self.config = config
        self.storage = storage
        self.logger = logger
        self.policy = config.get("retention", {})

        # Nouveau gestionnaire de buckets intelligent
        self.threat_bucket_manager = ThreatBucketManager()

        # Compatibilité ascendante avec l'ancien système
        self.bucket_priorities = {
            RetentionBucket.LIVE: 1,
            RetentionBucket.CHAUD: 2,
            RetentionBucket.TIEDE: 3,
            RetentionBucket.FROID: 4,
        }

        # Configuration des règles de source pour classification automatique
        source_config = config.get(
            "source_confidence",
            {
                # Sources très fiables
                "alienvault": ConfidenceLevel.HIGH,
                "malwaredomainlist": ConfidenceLevel.HIGH,
                "abuse.ch": ConfidenceLevel.HIGH,
                "spamhaus": ConfidenceLevel.CONFIRMED,
                # Sources modérément fiables
                "openphish": ConfidenceLevel.MEDIUM,
                "phishtank": ConfidenceLevel.MEDIUM,
                "urlhaus": ConfidenceLevel.MEDIUM,
                # Sources expérimentales
                "emerging": ConfidenceLevel.LOW,
                "experimental": ConfidenceLevel.UNKNOWN,
            },
        )

        # Convertit les chaînes en enums si nécessaire
        self.source_confidence_mapping = {}
        for source, confidence in source_config.items():
            if isinstance(confidence, str):
                # Mapping des chaînes vers les enums
                confidence_mapping = {
                    "confirmed": ConfidenceLevel.CONFIRMED,
                    "high": ConfidenceLevel.HIGH,
                    "medium": ConfidenceLevel.MEDIUM,
                    "low": ConfidenceLevel.LOW,
                    "unknown": ConfidenceLevel.UNKNOWN,
                }
                self.source_confidence_mapping[source] = confidence_mapping.get(
                    confidence, ConfidenceLevel.UNKNOWN
                )
            else:
                self.source_confidence_mapping[source] = confidence

        # Configuration des niveaux de menace par type d'IOC
        ioc_threat_config = config.get(
            "ioc_threats",
            {
                IOCType.HASH_SHA256: ThreatLevel.HIGH,  # Malware signatures
                IOCType.HASH_MD5: ThreatLevel.HIGH,  # Malware signatures
                IOCType.IPV4: ThreatLevel.MEDIUM,  # C&C servers, scanners
                IOCType.DOMAIN: ThreatLevel.MEDIUM,  # Malicious domains
                IOCType.URL: ThreatLevel.MEDIUM,  # Phishing, malware download
                IOCType.EMAIL: ThreatLevel.LOW,  # Spam, phishing emails
            },
        )

        # Convertit les chaînes en enums si nécessaire
        self.ioc_threat_mapping = {}
        for ioc_type, threat_level in ioc_threat_config.items():
            # Convertit les chaînes IOC types en enums
            if isinstance(ioc_type, str):
                ioc_type_mapping = {
                    "hash_sha256": IOCType.HASH_SHA256,
                    "hash_md5": IOCType.HASH_MD5,
                    "ipv4": IOCType.IPV4,
                    "domain": IOCType.DOMAIN,
                    "url": IOCType.URL,
                    "email": IOCType.EMAIL,
                }
                enum_ioc_type = ioc_type_mapping.get(ioc_type, IOCType.DOMAIN)
            else:
                enum_ioc_type = ioc_type

            # Convertit les chaînes threat levels en enums
            if isinstance(threat_level, str):
                threat_level_mapping = {
                    "high": ThreatLevel.HIGH,
                    "medium": ThreatLevel.MEDIUM,
                    "low": ThreatLevel.LOW,
                    "info": ThreatLevel.INFO,
                }
                enum_threat_level = threat_level_mapping.get(
                    threat_level, ThreatLevel.MEDIUM
                )
            else:
                enum_threat_level = threat_level

            self.ioc_threat_mapping[enum_ioc_type] = enum_threat_level

    def _parse_duration(self, duration_str: str) -> int:
        """Parse une durée au format '24h', '7d', etc. et retourne en secondes"""
        try:
            return parse_duration(duration_str)
        except ValueError:
            # Valeur par défaut en cas d'erreur
            return 3600  # 1 heure

    def enrich_ioc_metadata(self, ioc: IOC) -> IOC:
        """Enrichit automatiquement les métadonnées d'un IOC"""

        # Classification automatique selon la source
        source_lower = ioc.source.lower()
        for source_pattern, confidence in self.source_confidence_mapping.items():
            if source_pattern in source_lower:
                ioc.confidence_level = confidence
                break

        # Classification du niveau de menace selon le type
        if ioc.threat_level == ThreatLevel.INFO:  # Seulement si pas déjà défini
            ioc.threat_level = self.ioc_threat_mapping.get(ioc.type, ThreatLevel.INFO)

        # Détermination du bucket optimal
        current_bucket = getattr(ioc, "bucket", None)
        if hasattr(ioc, "bucket"):
            current_threat_bucket = ioc.bucket
        else:
            # Conversion depuis l'ancien système
            retention_to_threat = {
                RetentionBucket.LIVE: ThreatBucket.CRITICAL,
                RetentionBucket.CHAUD: ThreatBucket.ACTIVE,
                RetentionBucket.TIEDE: ThreatBucket.WATCH,
                RetentionBucket.FROID: ThreatBucket.ARCHIVE,
            }
            current_threat_bucket = retention_to_threat.get(
                ioc.retention, ThreatBucket.EMERGING
            )

        optimal_bucket = self.threat_bucket_manager.determine_bucket(
            ioc, current_threat_bucket
        )
        ioc.bucket = optimal_bucket

        # Tags automatiques selon le contexte
        auto_tags = []

        # Tags selon le niveau de confiance
        if ioc.confidence_level == ConfidenceLevel.CONFIRMED:
            auto_tags.append("verified")
        elif ioc.confidence_level == ConfidenceLevel.LOW:
            auto_tags.append("low-confidence")

        # Tags selon le niveau de menace
        if ioc.threat_level == ThreatLevel.HIGH:
            auto_tags.append("high-threat")
        elif ioc.threat_level == ThreatLevel.LOW:
            auto_tags.append("low-threat")

        # Tags selon le type d'IOC
        if ioc.type in [IOCType.HASH_MD5, IOCType.HASH_SHA256, IOCType.HASH_SHA1]:
            auto_tags.append("malware-signature")
        elif ioc.type in [IOCType.IPV4, IOCType.IPV6]:
            auto_tags.append("network-ioc")
        elif ioc.type in [IOCType.DOMAIN, IOCType.URL]:
            auto_tags.append("web-ioc")

        # Tags selon la source
        if "phish" in source_lower:
            auto_tags.append("phishing")
        elif "malware" in source_lower:
            auto_tags.append("malware")
        elif "spam" in source_lower:
            auto_tags.append("spam")

        # Fusion avec les tags existants
        if hasattr(ioc, "tags") and ioc.tags:
            ioc.tags = list(set(ioc.tags + auto_tags))
        else:
            ioc.tags = auto_tags

        # TTL automatique selon le bucket
        if not ioc.ttl_hours:
            ttl_mapping = {
                ThreatBucket.CRITICAL: 24 * 7,  # 1 semaine
                ThreatBucket.ACTIVE: 24 * 14,  # 2 semaines
                ThreatBucket.WATCH: 24 * 30,  # 1 mois
                ThreatBucket.INTEL: 24 * 90,  # 3 mois
                ThreatBucket.EMERGING: 24 * 3,  # 3 jours
                ThreatBucket.ARCHIVE: 24 * 365,  # 1 an
                ThreatBucket.DEPRECATED: 24 * 7,  # 1 semaine avant suppression
            }
            ioc.ttl_hours = ttl_mapping.get(ioc.bucket, 24 * 30)

        return ioc

    def process_intelligent_transitions(self):
        """Traite les transitions intelligentes selon la nouvelle logique"""
        conn = None
        try:
            conn = sqlite3.connect(self.storage.db_path)

            # Récupère tous les IOCs pour évaluation
            cursor = conn.execute(
                """
                SELECT value, type, source, bucket, first_seen, last_seen 
                FROM iocs
            """
            )

            transitions_made = 0
            promotions_made = 0
            archived_count = 0

            for row in cursor.fetchall():
                value, ioc_type, source, bucket, first_seen, last_seen = row

                # Reconstitue l'IOC (simulation)
                ioc = IOC(
                    value=value,
                    type=IOCType(ioc_type),
                    source=source,
                    first_seen=(
                        datetime.fromisoformat(first_seen)
                        if isinstance(first_seen, str)
                        else first_seen
                    ),
                    last_seen=(
                        datetime.fromisoformat(last_seen)
                        if isinstance(last_seen, str)
                        else last_seen
                    ),
                )

                # Conversion bucket legacy vers nouveau système
                if hasattr(ThreatBucket, bucket.upper()):
                    current_bucket = ThreatBucket(bucket)
                else:
                    # Mappage legacy
                    legacy_mapping = {
                        "live": ThreatBucket.CRITICAL,
                        "chaud": ThreatBucket.ACTIVE,
                        "tiede": ThreatBucket.WATCH,
                        "froid": ThreatBucket.ARCHIVE,
                    }
                    current_bucket = legacy_mapping.get(bucket, ThreatBucket.EMERGING)

                ioc.bucket = current_bucket

                # Enrichissement automatique
                ioc = self.enrich_ioc_metadata(ioc)

                # Vérification des transitions
                if self.threat_bucket_manager.should_transition(ioc, current_bucket):
                    new_bucket = self.threat_bucket_manager.get_next_bucket(
                        ioc, current_bucket
                    )

                    if new_bucket:
                        # Mise à jour en base
                        conn.execute(
                            """
                            UPDATE iocs 
                            SET bucket = ?, last_seen = ?
                            WHERE value = ? AND type = ?
                        """,
                            (new_bucket.value, datetime.now(), value, ioc_type),
                        )

                        # Déplacement des fichiers
                        self._move_ioc_between_buckets(
                            value, ioc_type, bucket, new_bucket.value
                        )

                        if self.threat_bucket_manager.get_bucket_priority(
                            new_bucket
                        ) < self.threat_bucket_manager.get_bucket_priority(
                            current_bucket
                        ):
                            promotions_made += 1
                        elif new_bucket == ThreatBucket.ARCHIVE:
                            archived_count += 1

                        transitions_made += 1

                        self.logger.info(
                            f"IOC {value} transitionné de {current_bucket.value} vers {new_bucket.value}"
                        )

            conn.commit()

            self.logger.info(
                f"Traitement intelligent terminé: {transitions_made} transitions, {promotions_made} promotions, {archived_count} archivages"
            )

        except Exception as e:
            self.logger.error(
                f"Erreur lors du traitement intelligent des transitions: {e}"
            )
            raise RetentionError(
                f"Échec du traitement intelligent des transitions: {e}"
            ) from e
        finally:
            if conn:
                conn.close()

    def process_transitions(self):
        """Traite toutes les transitions selon la politique (nouveau système intelligent)"""

        # Utilise le nouveau système intelligent par défaut
        if self.config.get("use_intelligent_buckets", True):
            return self.process_intelligent_transitions()

        # Fallback vers l'ancien système pour compatibilité
        return self._process_legacy_transitions()

    def _process_legacy_transitions(self):
        """Traite les transitions selon l'ancien système (compatibilité)"""
        conn = None
        try:
            conn = sqlite3.connect(self.storage.db_path)

            # Live → Chaud
            live_to_chaud = self.policy.get("live_to_chaud", "24h")
            self._transition_bucket(
                conn, "live", "chaud", self._parse_duration(live_to_chaud)
            )

            # Chaud → Tiede
            chaud_to_tiede = self.policy.get("chaud_to_tiede", "7d")
            self._transition_bucket(
                conn, "chaud", "tiede", self._parse_duration(chaud_to_tiede)
            )

            # Tiede → Froid
            tiede_to_froid = self.policy.get("tiede_to_froid", "30d")
            self._transition_bucket(
                conn, "tiede", "froid", self._parse_duration(tiede_to_froid)
            )

            # Suppression des anciens IOCs du bucket froid
            froid_retention = self.policy.get("froid_retention", "365d")
            self._cleanup_old_iocs(conn, self._parse_duration(froid_retention))

            self.logger.info("Cycle de rétention terminé avec succès")

        except Exception as e:
            self.logger.error(f"Erreur lors du traitement des transitions: {e}")
            raise RetentionError(f"Échec du traitement des transitions: {e}") from e
        finally:
            if conn:
                conn.close()

    def _transition_bucket(
        self,
        conn: sqlite3.Connection,
        from_bucket: str,
        to_bucket: str,
        max_age_seconds: int,
    ):
        """Effectue la transition d'un bucket vers un autre"""
        cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)

        cursor = conn.execute(
            """
            SELECT value, type FROM iocs 
            WHERE bucket = ? AND last_seen < ?
        """,
            (from_bucket, cutoff_time),
        )

        candidates = cursor.fetchall()

        if not candidates:
            self.logger.debug(
                f"Aucun IOC à transitionner de {from_bucket} vers {to_bucket}"
            )
            return

        transitioned_count = 0

        for value, ioc_type in candidates:
            try:
                # Supprime des anciens fichiers
                self._remove_from_file(from_bucket, ioc_type, value)

                # Ajoute aux nouveaux fichiers
                self._add_to_file(to_bucket, ioc_type, value)

                # Met à jour la DB
                conn.execute(
                    """
                    UPDATE iocs SET bucket = ? WHERE value = ? AND type = ?
                """,
                    (to_bucket, value, ioc_type),
                )

                transitioned_count += 1

            except Exception as e:
                self.logger.error(f"Erreur transition IOC {value} ({ioc_type}): {e}")

        conn.commit()
        self.logger.info(
            f"Transitionné {transitioned_count}/{len(candidates)} IOCs de {from_bucket} vers {to_bucket}"
        )

    def _remove_from_file(self, bucket: str, ioc_type: str, value: str):
        """Supprime un IOC d'un fichier de bucket (utilise les opérations atomiques)"""
        try:
            self.storage._atomic_remove_from_file(bucket, ioc_type, value)
        except Exception as e:
            self.logger.error(f"Erreur lors de la suppression atomique de {value}: {e}")
            raise RetentionError(f"Échec de suppression d'IOC: {e}") from e

    def _add_to_file(self, bucket: str, ioc_type: str, value: str):
        """Ajoute un IOC à un fichier de bucket (utilise les opérations atomiques)"""
        try:
            self.storage._atomic_add_to_file(bucket, ioc_type, value)
        except Exception as e:
            self.logger.error(f"Erreur lors de l'ajout atomique de {value}: {e}")
            raise RetentionError(f"Échec d'ajout d'IOC: {e}") from e

    def _cleanup_old_iocs(self, conn: sqlite3.Connection, max_age_seconds: int):
        """Supprime les IOCs trop anciens du bucket froid"""
        cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)

        cursor = conn.execute(
            """
            SELECT value, type FROM iocs 
            WHERE bucket = 'froid' AND last_seen < ?
        """,
            (cutoff_time,),
        )

        candidates = cursor.fetchall()

        if not candidates:
            self.logger.debug("Aucun IOC ancien à supprimer du bucket froid")
            return

        deleted_count = 0

        for value, ioc_type in candidates:
            try:
                # Supprime du fichier
                self._remove_from_file("froid", ioc_type, value)

                # Supprime de la DB
                conn.execute(
                    """
                    DELETE FROM iocs WHERE value = ? AND type = ?
                """,
                    (value, ioc_type),
                )

                deleted_count += 1

            except Exception as e:
                self.logger.error(f"Erreur suppression IOC {value} ({ioc_type}): {e}")

        conn.commit()
        self.logger.info(
            f"Supprimé {deleted_count}/{len(candidates)} IOCs anciens du stockage"
        )

    def audit_duplicates_across_buckets(self) -> Dict[str, Any]:
        """Audit des doublons potentiels entre buckets"""
        try:
            duplicates = {}
            total_duplicates = 0

            for ioc_type in IOCType:
                type_duplicates = []
                iocs_by_bucket = {}

                # Charge tous les IOCs de ce type depuis les fichiers
                for bucket in RetentionBucket:
                    file_path = (
                        self.storage.output_dir / bucket.value / f"{ioc_type.value}.txt"
                    )
                    if file_path.exists():
                        with open(file_path, "r") as f:
                            iocs_by_bucket[bucket.value] = set(
                                line.strip()
                                for line in f
                                if line.strip() and not line.startswith("#")
                            )

                # Détecte les intersections
                buckets = list(iocs_by_bucket.keys())
                for i, bucket1 in enumerate(buckets):
                    for bucket2 in buckets[i + 1 :]:
                        common_iocs = iocs_by_bucket[bucket1].intersection(
                            iocs_by_bucket[bucket2]
                        )
                        if common_iocs:
                            type_duplicates.append(
                                {
                                    "bucket_1": bucket1,
                                    "bucket_2": bucket2,
                                    "duplicates": list(common_iocs)[
                                        :10
                                    ],  # Limite l'affichage
                                    "count": len(common_iocs),
                                }
                            )
                            total_duplicates += len(common_iocs)

                if type_duplicates:
                    duplicates[ioc_type.value] = type_duplicates

            return {
                "duplicates_by_type": duplicates,
                "total_duplicates": total_duplicates,
                "audit_time": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Erreur lors de l'audit des doublons: {e}")
            return {"error": str(e), "error_type": "RetentionError"}

    def fix_duplicates(self) -> Dict[str, Any]:
        """Corrige les doublons en conservant les IOCs dans le bucket le plus prioritaire"""
        try:
            # Hiérarchie des priorités (live > chaud > tiede > froid)
            bucket_priority = {"live": 0, "chaud": 1, "tiede": 2, "froid": 3}
            fixed_count = 0

            conn = sqlite3.connect(self.storage.db_path)

            for ioc_type in IOCType:
                iocs_by_bucket = {}

                # Charge tous les IOCs de ce type
                for bucket in RetentionBucket:
                    file_path = (
                        self.storage.output_dir / bucket.value / f"{ioc_type.value}.txt"
                    )
                    if file_path.exists():
                        with open(file_path, "r") as f:
                            iocs_by_bucket[bucket.value] = set(
                                line.strip()
                                for line in f
                                if line.strip() and not line.startswith("#")
                            )

                # Trouve tous les IOCs uniques
                all_iocs = set()
                for bucket_iocs in iocs_by_bucket.values():
                    all_iocs.update(bucket_iocs)

                # Pour chaque IOC, trouve le bucket le plus prioritaire
                for ioc_value in all_iocs:
                    buckets_containing = [
                        bucket
                        for bucket, iocs in iocs_by_bucket.items()
                        if ioc_value in iocs
                    ]

                    if len(buckets_containing) > 1:
                        # Trouve le bucket le plus prioritaire
                        priority_bucket = min(
                            buckets_containing, key=lambda b: bucket_priority[b]
                        )

                        # Supprime des autres buckets
                        for bucket in buckets_containing:
                            if bucket != priority_bucket:
                                self._remove_from_file(
                                    bucket, ioc_type.value, ioc_value
                                )
                                fixed_count += 1

                        # Met à jour la DB
                        conn.execute(
                            """
                            UPDATE iocs SET bucket = ? 
                            WHERE value = ? AND type = ?
                        """,
                            (priority_bucket, ioc_value, ioc_type.value),
                        )

            conn.commit()
            conn.close()

            self.logger.info(f"Corrigé {fixed_count} doublons")
            return {
                "fixed_duplicates": fixed_count,
                "status": "success",
                "fix_time": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Erreur lors de la correction des doublons: {e}")
            return {"error": str(e), "error_type": "RetentionError"}

    def _get_bucket_priority(self, bucket: RetentionBucket) -> int:
        """Retourne la priorité numérique d'un bucket"""
        return self.bucket_priorities.get(bucket, 999)

    def _should_promote_ioc(
        self, existing_bucket: RetentionBucket, new_bucket: RetentionBucket
    ) -> bool:
        """Détermine si un IOC doit être promu vers un bucket de priorité plus élevée"""
        return self._get_bucket_priority(new_bucket) < self._get_bucket_priority(
            existing_bucket
        )

    def check_duplicate_iocs(self) -> List[Dict[str, Any]]:
        """Vérifie la présence de doublons dans la base de données"""
        try:
            return self._find_duplicates_in_db()
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification des doublons: {e}")
            return []

    def _find_duplicates_in_db(self) -> List[Dict[str, Any]]:
        """Trouve les doublons dans la base de données"""
        try:
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.execute(
                """
                SELECT value, type, GROUP_CONCAT(bucket) as buckets
                FROM iocs 
                GROUP BY value, type 
                HAVING COUNT(*) > 1
            """
            )

            duplicates = []
            for row in cursor.fetchall():
                value, ioc_type, buckets_str = row
                buckets = buckets_str.split(",") if buckets_str else []
                duplicates.append(
                    {"value": value, "type": ioc_type, "buckets": buckets}
                )

            conn.close()
            return duplicates
        except Exception as e:
            self.logger.error(f"Erreur lors de la recherche de doublons: {e}")
            return []

    def fix_duplicate_iocs(self) -> Dict[str, Any]:
        """Corrige les IOCs dupliqués en gardant la priorité la plus élevée"""
        try:
            duplicates = self.check_duplicate_iocs()
            fixed_count = 0
            failed_count = 0

            for duplicate in duplicates:
                try:
                    if self._resolve_duplicate(duplicate):
                        fixed_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    self.logger.error(
                        f"Erreur lors de la résolution du doublon {duplicate['value']}: {e}"
                    )
                    failed_count += 1

            return {
                "total_duplicates": len(duplicates),
                "fixed_count": fixed_count,
                "failed_count": failed_count,
                "status": "success" if failed_count == 0 else "partial",
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la correction des doublons: {e}")
            return {"error": str(e), "status": "error"}

    def _resolve_duplicate(self, duplicate: Dict[str, Any]) -> bool:
        """Résout un doublon en gardant la priorité la plus élevée"""
        try:
            value = duplicate["value"]
            ioc_type = duplicate["type"]
            buckets = duplicate["buckets"]

            # Trouve le bucket de plus haute priorité
            # Convertit les chaînes en enums
            bucket_enums = []
            for b in buckets:
                if isinstance(b, str):
                    # Mapping des chaînes vers les enums (ancien + nouveau)
                    mapping = {
                        # Nouveaux noms
                        "active": RetentionBucket.CHAUD,
                        "critical": RetentionBucket.LIVE,
                        "watch": RetentionBucket.TIEDE,
                        "archive": RetentionBucket.FROID,
                        # Anciens noms (compatibilité)
                        "live": RetentionBucket.LIVE,
                        "chaud": RetentionBucket.CHAUD,
                        "tiede": RetentionBucket.TIEDE,
                        "froid": RetentionBucket.FROID,
                    }
                    bucket_enums.append(mapping.get(b, RetentionBucket.FROID))
                else:
                    bucket_enums.append(b)

            priority_bucket_enum = min(
                bucket_enums, key=lambda b: self._get_bucket_priority(b)
            )
            priority_bucket = priority_bucket_enum.value

            # Supprime des autres buckets
            conn = sqlite3.connect(self.storage.db_path)
            conn.execute(
                """
                DELETE FROM iocs 
                WHERE value = ? AND type = ? AND bucket != ?
            """,
                (value, ioc_type, priority_bucket),
            )
            conn.commit()
            conn.close()

            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la résolution du doublon: {e}")
            return False

    def get_retention_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de rétention"""
        try:
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.execute(
                """
                SELECT bucket, COUNT(*) as count
                FROM iocs
                GROUP BY bucket
            """
            )

            stats = {}
            for row in cursor.fetchall():
                bucket, count = row
                stats[bucket] = count

            conn.close()
            return {
                "bucket_counts": stats,
                "total_iocs": sum(stats.values()),
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des stats: {e}")
            return {"error": str(e)}

    def audit_retention_system(self) -> Dict[str, Any]:
        """Effectue un audit complet du système de rétention"""
        try:
            stats = self.get_retention_stats()
            duplicates = self.check_duplicate_iocs()

            return {
                "stats": stats,
                "duplicates_found": len(duplicates),
                "duplicates": duplicates[:10],  # Limite l'affichage
                "audit_timestamp": datetime.now().isoformat(),
                "status": "success",
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de l'audit: {e}")
            return {"error": str(e), "status": "error"}

    def process_retentions(self) -> Dict[str, Any]:
        """Lance le processus de rétention"""
        try:
            self.process_transitions()
            return {"status": "success", "timestamp": datetime.now().isoformat()}
        except Exception as e:
            self.logger.error(f"Erreur lors du processus de rétention: {e}")
            return {"error": str(e), "status": "error"}

    def process_bucket_transitions(self) -> Dict[str, Any]:
        """Traite les transitions entre buckets"""
        return self.process_retentions()

    def find_iocs_for_transition(
        self, from_bucket: str, to_bucket: str, max_age_seconds: int
    ) -> List[Dict[str, Any]]:
        """Trouve les IOCs candidats pour une transition"""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)
            conn = sqlite3.connect(self.storage.db_path)
            cursor = conn.execute(
                """
                SELECT value, type, last_seen FROM iocs 
                WHERE bucket = ? AND last_seen < ?
            """,
                (from_bucket, cutoff_time),
            )

            candidates = []
            for row in cursor.fetchall():
                value, ioc_type, last_seen = row
                candidates.append(
                    {"value": value, "type": ioc_type, "last_seen": last_seen}
                )

            conn.close()
            return candidates
        except Exception as e:
            self.logger.error(
                f"Erreur lors de la recherche d'IOCs pour transition: {e}"
            )
            return []

    def check_bucket_integrity(self) -> Dict[str, Any]:
        """Vérifie l'intégrité des buckets"""
        try:
            issues = []
            conn = sqlite3.connect(self.storage.db_path)

            # Vérifie que tous les buckets existent
            for bucket in RetentionBucket:
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM iocs WHERE bucket = ?", (bucket.value,)
                )
                count = cursor.fetchone()[0]
                if count == 0:
                    issues.append(f"Bucket {bucket.value} is empty")

            conn.close()

            return {
                "issues": issues,
                "status": "success" if not issues else "issues_found",
                "check_timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification d'intégrité: {e}")
            return {"error": str(e), "status": "error"}

    def check_retention_rules_compliance(self) -> Dict[str, Any]:
        """Vérifie la conformité aux règles de rétention"""
        try:
            compliance_issues = []

            # Vérifications de base
            if not self.policy:
                compliance_issues.append("No retention policy configured")

            return {
                "compliance_issues": compliance_issues,
                "status": "compliant" if not compliance_issues else "non_compliant",
                "check_timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification de conformité: {e}")
            return {"error": str(e), "status": "error"}


# ===============================
# GESTION DES CLÉS API
# ===============================


class APIKeyManager:
    """Gestionnaire des clés API avec rotation automatique"""

    def __init__(self):
        self.key_status: Dict[str, Dict] = {}
        self.key_usage: Dict[str, int] = {}
        self.logger = logging.getLogger(f"{__name__}.APIKeyManager")
        self._lock = threading.Lock()

    def add_keys(self, feed_name: str, keys: List[str]):
        """Ajoute des clés API pour un flux"""
        with self._lock:
            for key in keys:
                key_id = self._get_key_id(key)
                self.key_status[key_id] = {
                    "key": key,
                    "feed": feed_name,
                    "active": True,
                    "last_used": None,
                    "error_count": 0,
                    "rate_limited_until": None,
                }
                self.key_usage[key_id] = 0

    def get_key(self, feed_name: str) -> Optional[str]:
        """Récupère une clé API disponible pour un flux"""
        with self._lock:
            available_keys = []

            for key_id, status in self.key_status.items():
                if (
                    status["feed"] == feed_name
                    and status["active"]
                    and self._is_key_available(status)
                ):
                    available_keys.append((key_id, status))

            if not available_keys:
                self.logger.warning(
                    f"Aucune clé API disponible pour le flux {feed_name}"
                )
                return None

            # Sélectionne la clé la moins utilisée
            key_id, status = min(available_keys, key=lambda x: self.key_usage[x[0]])
            self.key_usage[key_id] += 1
            status["last_used"] = datetime.now()

            self.logger.debug(
                f"Clé API sélectionnée pour {feed_name}: {self._get_key_id(status['key'])}"
            )
            return status["key"]

    def report_key_error(
        self, key: str, error_type: str, retry_after: Optional[int] = None
    ):
        """Signale une erreur pour une clé API"""
        key_id = self._get_key_id(key)

        with self._lock:
            if key_id in self.key_status:
                status = self.key_status[key_id]
                status["error_count"] += 1

                if error_type == "rate_limit" and retry_after:
                    status["rate_limited_until"] = datetime.now() + timedelta(
                        seconds=retry_after
                    )
                    self.logger.warning(
                        f"Clé API {key_id} limitée jusqu'à {status['rate_limited_until']}"
                    )

                elif error_type == "invalid":
                    status["active"] = False
                    self.logger.error(f"Clé API {key_id} désactivée (invalide)")

                elif status["error_count"] >= 5:
                    status["active"] = False
                    self.logger.error(f"Clé API {key_id} désactivée (trop d'erreurs)")

    def _get_key_id(self, key: str) -> str:
        """Génère un ID anonymisé pour une clé"""
        return f"key_{hashlib.md5(key.encode()).hexdigest()[:8]}"

    def _is_key_available(self, status: Dict) -> bool:
        """Vérifie si une clé est disponible"""
        if status["rate_limited_until"]:
            return datetime.now() > status["rate_limited_until"]
        return True


# ===============================
# GESTION DES IOCs
# ===============================


@dataclass
class IOC:
    """Représente un IOC avec ses métadonnées enrichies"""

    value: str
    type: IOCType
    source: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    # Nouvelle logique de buckets intelligents
    bucket: ThreatBucket = ThreatBucket.EMERGING
    threat_level: ThreatLevel = ThreatLevel.INFO
    confidence_level: ConfidenceLevel = ConfidenceLevel.UNKNOWN

    # Métadonnées avancées
    tags: list = field(default_factory=list)
    ttl_hours: Optional[int] = None  # Time-to-live spécifique
    verified: bool = False  # IOC vérifié manuellement
    false_positive: bool = False  # Marqué comme faux positif

    # Compatibilité ascendante (pour les tests)
    retention: Optional[RetentionBucket] = None  # Paramètre legacy
    confidence: float = field(init=False)

    def __post_init__(self):
        """Assure la compatibilité ascendante et valide les données"""
        # Validation des données d'entrée
        if not self.value or not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("IOC value must be a non-empty string")

        if not isinstance(self.type, IOCType):
            raise ValueError("IOC type must be a valid IOCType")

        if (
            not self.source
            or not isinstance(self.source, str)
            or not self.source.strip()
        ):
            raise ValueError("IOC source must be a non-empty string")

        # Normalize values
        self.value = self.value.strip()
        self.source = self.source.strip()

        # Si retention est fourni (legacy), l'utiliser pour déterminer le bucket
        if self.retention is not None:
            # Mappage inverse: de l'ancien vers le nouveau
            retention_to_bucket = {
                RetentionBucket.LIVE: ThreatBucket.CRITICAL,
                RetentionBucket.CHAUD: ThreatBucket.ACTIVE,
                RetentionBucket.TIEDE: ThreatBucket.WATCH,
                RetentionBucket.FROID: ThreatBucket.ARCHIVE,
            }
            self.bucket = retention_to_bucket.get(self.retention, ThreatBucket.EMERGING)
        else:
            # Mappage du nouveau bucket vers l'ancien
            bucket_mapping = {
                ThreatBucket.CRITICAL: RetentionBucket.LIVE,
                ThreatBucket.ACTIVE: RetentionBucket.CHAUD,
                ThreatBucket.WATCH: RetentionBucket.TIEDE,
                ThreatBucket.INTEL: RetentionBucket.TIEDE,
                ThreatBucket.EMERGING: RetentionBucket.CHAUD,
                ThreatBucket.ARCHIVE: RetentionBucket.FROID,
                ThreatBucket.DEPRECATED: RetentionBucket.FROID,
            }
            self.retention = bucket_mapping.get(self.bucket, RetentionBucket.LIVE)

        # Mappage de confidence_level vers confidence (float)
        confidence_mapping = {
            ConfidenceLevel.CONFIRMED: 1.0,
            ConfidenceLevel.HIGH: 0.8,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.LOW: 0.4,
            ConfidenceLevel.UNKNOWN: 0.2,
        }
        self.confidence = confidence_mapping.get(self.confidence_level, 0.5)

    def __hash__(self):
        return hash((self.value, self.type))

    def __eq__(self, other):
        if not isinstance(other, IOC):
            return False
        return self.value == other.value and self.type == other.type

    def is_operational(self) -> bool:
        """Vérifie si l'IOC est dans un bucket opérationnel"""
        return self.bucket in [
            ThreatBucket.CRITICAL,
            ThreatBucket.ACTIVE,
            ThreatBucket.WATCH,
        ]

    def is_expired(self) -> bool:
        """Vérifie si l'IOC a expiré selon son TTL"""
        if not self.ttl_hours:
            return False
        expiry_time = self.last_seen + timedelta(hours=self.ttl_hours)
        return datetime.now() > expiry_time

    def should_be_archived(self) -> bool:
        """Détermine si l'IOC devrait être archivé"""
        if self.false_positive:
            return True
        if self.is_expired():
            return True
        # Logique métier : IOCs de confiance faible et anciens
        if (
            self.confidence_level == ConfidenceLevel.LOW
            and (datetime.now() - self.last_seen).days > 30
        ):
            return True
        return False


class ThreatBucketManager:
    """Gestionnaire intelligent des buckets de threat intelligence"""

    def __init__(self):
        # Priorités des buckets (plus faible = plus prioritaire)
        self.bucket_priorities = {
            ThreatBucket.CRITICAL: 1,
            ThreatBucket.ACTIVE: 2,
            ThreatBucket.WATCH: 3,
            ThreatBucket.INTEL: 4,
            ThreatBucket.EMERGING: 5,
            ThreatBucket.ARCHIVE: 6,
            ThreatBucket.DEPRECATED: 7,
        }

        # Règles de transition automatique
        self.transition_rules = {
            # IOCs critiques restent critiques mais peuvent être rétrogradés
            ThreatBucket.CRITICAL: {
                "max_age_days": 30,
                "fallback_bucket": ThreatBucket.ACTIVE,
                "conditions": ["not verified", "low confidence"],
            },
            # IOCs actifs peuvent être promus ou rétrogradés
            ThreatBucket.ACTIVE: {
                "max_age_days": 14,
                "fallback_bucket": ThreatBucket.WATCH,
                "promotion_bucket": ThreatBucket.CRITICAL,
                "conditions": ["multiple sources", "high confidence"],
            },
            # IOCs surveillés évoluent selon l'activité
            ThreatBucket.WATCH: {
                "max_age_days": 7,
                "fallback_bucket": ThreatBucket.INTEL,
                "promotion_bucket": ThreatBucket.ACTIVE,
                "conditions": ["recent activity", "confirmed threats"],
            },
            # IOCs émergents nécessitent validation
            ThreatBucket.EMERGING: {
                "max_age_days": 3,
                "fallback_bucket": ThreatBucket.ARCHIVE,
                "promotion_bucket": ThreatBucket.WATCH,
                "conditions": ["manual verification", "source reputation"],
            },
            # Intelligence générale moins prioritaire
            ThreatBucket.INTEL: {
                "max_age_days": 60,
                "fallback_bucket": ThreatBucket.ARCHIVE,
                "conditions": ["research value", "correlation potential"],
            },
            # Archive pour recherche historique
            ThreatBucket.ARCHIVE: {
                "max_age_days": 365,
                "fallback_bucket": ThreatBucket.DEPRECATED,
                "conditions": ["storage optimization"],
            },
            # Prêts pour suppression
            ThreatBucket.DEPRECATED: {
                "max_age_days": 30,
                "fallback_bucket": None,  # Suppression
                "conditions": ["cleanup process"],
            },
        }

    def determine_bucket(
        self, ioc: IOC, existing_bucket: Optional[ThreatBucket] = None
    ) -> ThreatBucket:
        """Détermine le bucket optimal pour un IOC selon sa contexte"""

        # IOCs marqués comme faux positifs
        if ioc.false_positive:
            return ThreatBucket.DEPRECATED

        # IOCs expirés
        if ioc.is_expired():
            return ThreatBucket.ARCHIVE

        # IOCs vérifiés manuellement avec haute confiance
        if ioc.verified and ioc.confidence_level in [
            ConfidenceLevel.CONFIRMED,
            ConfidenceLevel.HIGH,
        ]:
            if ioc.threat_level == ThreatLevel.HIGH:
                return ThreatBucket.CRITICAL
            elif ioc.threat_level == ThreatLevel.MEDIUM:
                return ThreatBucket.ACTIVE
            else:
                return ThreatBucket.WATCH

        # Nouveaux IOCs de sources fiables
        if not existing_bucket and ioc.confidence_level in [
            ConfidenceLevel.HIGH,
            ConfidenceLevel.CONFIRMED,
        ]:
            return (
                ThreatBucket.ACTIVE
                if ioc.threat_level == ThreatLevel.HIGH
                else ThreatBucket.WATCH
            )

        # IOCs de sources peu fiables ou inconnues
        if ioc.confidence_level in [ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN]:
            return ThreatBucket.EMERGING

        # Maintenir le bucket existant si approprié
        if existing_bucket and not self.should_transition(ioc, existing_bucket):
            return existing_bucket

        # Par défaut : bucket émergent pour nouveaux IOCs
        return ThreatBucket.EMERGING

    def should_transition(self, ioc: IOC, current_bucket: ThreatBucket) -> bool:
        """Détermine si un IOC doit changer de bucket"""
        rules = self.transition_rules.get(current_bucket, {})
        max_age_days = rules.get("max_age_days", float("inf"))

        # Vérification de l'âge
        age_days = (datetime.now() - ioc.last_seen).days
        if age_days >= max_age_days:
            return True

        # Conditions spéciales pour promotion
        if ioc.verified and ioc.confidence_level == ConfidenceLevel.CONFIRMED:
            return True

        # Conditions pour rétrogradation
        if ioc.false_positive or ioc.is_expired():
            return True

        return False

    def get_next_bucket(
        self, ioc: IOC, current_bucket: ThreatBucket
    ) -> Optional[ThreatBucket]:
        """Retourne le prochain bucket pour un IOC selon les règles"""
        if not self.should_transition(ioc, current_bucket):
            return None

        rules = self.transition_rules.get(current_bucket, {})

        # Promotion si conditions remplies
        if (
            ioc.verified
            and ioc.confidence_level
            in [ConfidenceLevel.CONFIRMED, ConfidenceLevel.HIGH]
            and "promotion_bucket" in rules
        ):
            return ThreatBucket(rules["promotion_bucket"])

        # Fallback normal
        fallback = rules.get("fallback_bucket")
        return ThreatBucket(fallback) if fallback else None

    def get_bucket_priority(self, bucket: ThreatBucket) -> int:
        """Retourne la priorité numérique d'un bucket"""
        return self.bucket_priorities.get(bucket, 999)

    def should_promote(
        self, existing_bucket: ThreatBucket, new_bucket: ThreatBucket
    ) -> bool:
        """Détermine si un IOC doit être promu vers un bucket plus prioritaire"""
        return self.get_bucket_priority(new_bucket) < self.get_bucket_priority(
            existing_bucket
        )


class IOCClassificationError(Exception):
    """Erreur de classification d'IOC"""

    pass


class IOCClassifier:
    """Classificateur d'IOCs avec validation avancée et extraction de patterns"""

    # Patterns regex stricts pour éviter les faux positifs
    PATTERNS = {
        IOCType.IPV4: re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ),
        IOCType.IPV6: re.compile(
            r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
        ),
        IOCType.DOMAIN: re.compile(
            r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$"
        ),
        IOCType.URL: re.compile(r'^(https?|ftp)://[^\s<>"\']+$'),
        IOCType.HASH_MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
        IOCType.HASH_SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
        IOCType.HASH_SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
        IOCType.HASH_SHA512: re.compile(r"^[a-fA-F0-9]{128}$"),
        IOCType.EMAIL: re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    }

    # IPs privées à exclure
    PRIVATE_IP_PATTERNS = [
        re.compile(r"^10\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
        re.compile(r"^127\."),
        re.compile(r"^169\.254\."),
        re.compile(r"^224\."),  # Multicast
        re.compile(r"^0\.0\.0\.0$"),
        re.compile(r"^255\.255\.255\.255$"),
    ]

    def __init__(self, whitelist_file: str = "ip_whitelist.yaml"):
        self.logger = logging.getLogger(f"{__name__}.IOCClassifier")
        self.stats = {"classified": 0, "rejected": 0, "errors": 0}
        self.whitelist = self._load_whitelist(whitelist_file)

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
                    if ioc_type == IOCType.IPV4 and (self._is_private_ip(value) or self._is_whitelisted_ip(value)):
                        continue
                    if ioc_type == IOCType.DOMAIN and self._is_whitelisted_domain(value):
                        continue
                    self.stats["classified"] += 1
                    return ioc_type

            self.stats["rejected"] += 1
            return None

        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Erreur lors de la classification de '{value}': {e}")
            return None

    def _classify_with_iocextract(self, value: str) -> Optional[IOCType]:
        """Classification avec iocextract (si disponible)"""
        try:
            import iocextract

            # Test chaque type d'IOC
            if list(iocextract.extract_ipv4s([value])):
                return IOCType.IPV4 if not (self._is_private_ip(value) or self._is_whitelisted_ip(value)) else None

            if list(iocextract.extract_ipv6s([value])):
                return IOCType.IPV6

            if list(iocextract.extract_domains([value])):
                return IOCType.DOMAIN if not self._is_whitelisted_domain(value) else None

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

        except (Exception, ImportError, ModuleNotFoundError):
            # iocextract n'est pas disponible ou erreur, utilise les regex
            pass

        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée"""
        for pattern in self.PRIVATE_IP_PATTERNS:
            if pattern.match(ip):
                return True
        return False

    def _load_whitelist(self, whitelist_file: str) -> Dict[str, List[str]]:
        """Charge la liste blanche depuis le fichier YAML"""
        try:
            whitelist_path = Path(whitelist_file)
            if not whitelist_path.exists():
                self.logger.warning(f"Fichier whitelist non trouvé: {whitelist_file}")
                return {"public_whitelist": [], "domain_whitelist": []}
            
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                whitelist_data = yaml.safe_load(f)
                
            return {
                "public_whitelist": whitelist_data.get("public_whitelist", []),
                "domain_whitelist": whitelist_data.get("domain_whitelist", [])
            }
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement de la whitelist: {e}")
            return {"public_whitelist": [], "domain_whitelist": []}

    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Vérifie si une IP est dans la whitelist"""
        return ip in self.whitelist["public_whitelist"]

    def _is_whitelisted_domain(self, domain: str) -> bool:
        """Vérifie si un domaine est dans la whitelist"""
        domain_lower = domain.lower()
        for whitelisted in self.whitelist["domain_whitelist"]:
            if domain_lower == whitelisted.lower() or domain_lower.endswith(f".{whitelisted.lower()}"):
                return True
        return False

    def extract_iocs_from_url(self, url: str) -> Dict[str, List[str]]:
        """Extrait et nettoie les IOCs depuis une URL complète
        Ex: http://122.56.54.121/test.exe -> {
            'url': ['http://122.56.54.121/'],
            'ipv4': ['122.56.54.121'],
            'domain': []
        }
        """
        extracted_iocs = {
            'url': [],
            'ipv4': [],
            'ipv6': [],
            'domain': []
        }
        
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            
            # Crée l'URL propre (sans path)
            if parsed.port:
                netloc = f"{parsed.netloc}"
            else:
                netloc = parsed.netloc
                
            clean_url = f"{parsed.scheme}://{netloc}/"
            extracted_iocs['url'].append(clean_url)
            
            # Extrait le hostname/IP (sans port)
            hostname = parsed.netloc.split(':')[0]
            
            # Vérifie si c'est une IP
            if self.PATTERNS[IOCType.IPV4].match(hostname):
                if not self._is_private_ip(hostname) and not self._is_whitelisted_ip(hostname):
                    extracted_iocs['ipv4'].append(hostname)
            elif self.PATTERNS[IOCType.IPV6].match(hostname):
                extracted_iocs['ipv6'].append(hostname)
            # Vérifie si c'est un domaine
            elif self.PATTERNS[IOCType.DOMAIN].match(hostname):
                if not self._is_whitelisted_domain(hostname):
                    extracted_iocs['domain'].append(hostname)
                    
        except Exception as e:
            self.logger.error(f"Erreur lors de l'extraction d'IOCs depuis l'URL {url}: {e}")
            
        return extracted_iocs

    def extract_iocs_from_text(self, text: str) -> List[str]:
        """Extrait tous les IOCs d'un texte avec extraction de patterns URL"""
        if not text:
            return []

        iocs = set()

        try:
            # Limite la taille du texte pour éviter les problèmes de mémoire
            if len(text) > 1024 * 1024:  # 1MB
                self.logger.warning("Texte trop long, troncature à 1MB")
                text = text[: 1024 * 1024]

            # Extraction avec iocextract
            extracted_urls = list(iocextract.extract_urls([text]))
            extracted_ipv4s = list(iocextract.extract_ipv4s([text]))
            extracted_ipv6s = list(iocextract.extract_ipv6s([text]))
            extracted_domains = list(iocextract.extract_domains([text]))
            
            # Traite les URLs pour extraire domaines/IPs supplémentaires et nettoyer les paths
            for url in extracted_urls:
                # Extrait les composants (URL nettoyée + IP/domaine)
                extracted_components = self.extract_iocs_from_url(url)
                # Ajoute l'URL nettoyée (sans path)
                if extracted_components['url']:
                    iocs.add(extracted_components['url'][0])
                # Ajoute les IPs et domaines extraits
                for ip in extracted_components['ipv4']:
                    iocs.add(ip)
                for ip in extracted_components['ipv6']:
                    iocs.add(ip)
                for domain in extracted_components['domain']:
                    iocs.add(domain)
            
            # Filtre les IPs
            for ip in extracted_ipv4s:
                if not self._is_private_ip(ip) and not self._is_whitelisted_ip(ip):
                    iocs.add(ip)
                    
            for ip in extracted_ipv6s:
                iocs.add(ip)  # Les IPv6 sont généralement OK
                
            # Filtre les domaines
            for domain in extracted_domains:
                if not self._is_whitelisted_domain(domain):
                    iocs.add(domain)
            
            # Ajoute les autres types sans filtrage spécial
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


class BasePlugin(ABC):
    """Classe de base pour tous les plugins"""

    def __init__(self, config: Dict[str, Any], name: str, api_manager: APIKeyManager):
        self.config = config
        self.name = name
        self.api_manager = api_manager
        self.logger = logging.getLogger(f"{__name__}.Plugin.{name}")
        self.session = self._create_session()

        # Statistiques du plugin
        self.stats = {
            "requests_made": 0,
            "bytes_downloaded": 0,
            "iocs_extracted": 0,
            "errors": 0,
            "retries": 0,
        }

    def _create_session(self) -> requests.Session:
        """Crée une session HTTP avec retry automatique"""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.config.get("max_retries", 3),
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
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
        required_fields = ["url"]
        for fieldw in required_fields:
            if fieldw not in self.config:
                raise PluginError(f"Champ obligatoire manquant: {fieldw}")
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du plugin"""
        return self.stats.copy()


class HTTPPlugin(BasePlugin):
    """Plugin de base pour les sources HTTP"""

    def _make_request(self, url: str, **kwargs) -> requests.Response:
        """Effectue une requête HTTP avec gestion d'erreurs avancée"""
        try:
            # Utilise ExternalAPIClient pour une gestion SSL/auth robuste
            client_config = self.config.copy()
            client_config["url"] = url

            # Ajoute une clé API si disponible
            api_key = self.api_manager.get_key(self.name)
            if api_key:
                # Configure l'authentification API key
                if "auth" not in client_config:
                    client_config["auth"] = {}
                client_config["auth"].update({"type": "bearer", "token": api_key})

            client = ExternalAPIClient(client_config)

            self.stats["requests_made"] += 1
            content = client.fetch_data()

            # Crée un objet response-like pour compatibilité
            mock_response = type(
                "MockResponse",
                (),
                {
                    "text": content,
                    "content": content.encode("utf-8"),
                    "status_code": 200,
                    "headers": {"Content-Type": "text/plain"},
                },
            )()

            self.stats["bytes_downloaded"] += len(content.encode("utf-8"))
            return mock_response

        except ExternalAPIError as e:
            self.stats["errors"] += 1

            # Gestion spécifique des erreurs d'API key
            if "Unauthorized" in str(e) or "401" in str(e):
                if api_key:
                    self.api_manager.report_key_error(api_key, "invalid")
                raise PluginError(f"Clé API invalide pour {self.name}: {e}")
            elif "Too Many Requests" in str(e) or "429" in str(e):
                if api_key:
                    self.api_manager.report_key_error(api_key, "rate_limit", 60)
                raise PluginError(f"Limite de taux atteinte pour {self.name}: {e}")
            elif "SSL" in str(e):
                raise PluginError(f"Erreur SSL pour {self.name}: {e}")
            elif "Timeout" in str(e):
                raise PluginError(f"Timeout pour {self.name}: {e}")
            else:
                raise PluginError(f"Erreur API externe pour {self.name}: {e}")

        except Exception as e:
            self.stats["errors"] += 1
            raise PluginError(
                f"Erreur inattendue lors de la requête vers {self.name}: {e}"
            )


class TextPlugin(HTTPPlugin):
    """Plugin pour les flux texte brut"""

    def collect(self) -> str:
        """Collecte depuis une URL texte"""
        url = self.config["url"]
        response = self._make_request(url)
        return response.text

    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le texte brut et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier("ip_whitelist.yaml")

        try:
            lines = raw_data.split("\n")
            self.logger.debug(f"Traitement de {len(lines)} lignes")

            for line_num, line in enumerate(lines, 1):
                line = line.strip()

                # Ignore les lignes vides et les commentaires
                if not line or line.startswith("#") or line.startswith("//"):
                    continue

                # Limite la longueur des lignes
                if len(line) > 2048:
                    self.logger.warning(f"Ligne {line_num} trop longue, ignorée")
                    continue

                # Classification directe de la ligne
                ioc_type = classifier.classify_ioc(line)
                if ioc_type:
                    # Pour les URLs, utilise l'extraction pour nettoyer les paths et extraire IPs
                    if ioc_type == IOCType.URL:
                        extracted_components = classifier.extract_iocs_from_url(line)
                        # Ajoute l'URL nettoyée
                        if extracted_components['url']:
                            ioc = IOC(
                                value=extracted_components['url'][0].lower(),
                                type=IOCType.URL,
                                source=self.name,
                                retention=RetentionBucket(self.config.get("retention", "active")),
                            )
                            iocs.append(ioc)
                        # Ajoute les IPs extraites
                        for ip in extracted_components['ipv4']:
                            ioc = IOC(
                                value=ip.lower(),
                                type=IOCType.IPV4,
                                source=self.name,
                                retention=RetentionBucket(self.config.get("retention", "active")),
                            )
                            iocs.append(ioc)
                        # Ajoute les domaines extraits
                        for domain in extracted_components['domain']:
                            ioc = IOC(
                                value=domain.lower(),
                                type=IOCType.DOMAIN,
                                source=self.name,
                                retention=RetentionBucket(self.config.get("retention", "active")),
                            )
                            iocs.append(ioc)
                    else:
                        ioc = IOC(
                            value=line.lower(),
                            type=ioc_type,
                            source=self.name,
                            retention=RetentionBucket(self.config.get("retention", "live")),
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
                                retention=RetentionBucket(
                                    self.config.get("retention", "live")
                                ),
                            )
                            iocs.append(ioc)

            self.stats["iocs_extracted"] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")

        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Erreur lors du parsing texte: {e}")
            raise PluginError(f"Erreur de parsing: {e}")

        return iocs


class CSVPlugin(HTTPPlugin):
    """Plugin pour les flux CSV avec gestion robuste des erreurs"""

    def collect(self) -> str:
        """Collecte depuis une URL CSV"""
        url = self.config["url"]
        response = self._make_request(url)
        return response.text

    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le CSV et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier("ip_whitelist.yaml")

        try:
            # Configuration CSV
            delimiter = self.config.get("delimiter", ",")
            encoding = self.config.get("encoding", "utf-8")
            column = self.config.get("column", 0)
            has_header = self.config.get("has_header", True)

            # Validation des paramètres
            if delimiter not in [",", ";", "\t", "|"]:
                raise PluginError(f"Délimiteur CSV non supporté: {delimiter}")

            lines = raw_data.splitlines()
            if not lines:
                raise PluginError("Fichier CSV vide")

            # Protection contre les fichiers trop gros
            if len(lines) > 100000:
                self.logger.warning(
                    f"Fichier CSV très volumineux ({len(lines)} lignes), traitement des 100000 premières"
                )
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
            if self.config.get("auto_detect_column", False):
                col_index = self._auto_detect_best_column(
                    lines[:50], delimiter, has_header, classifier
                )
                self.logger.info(
                    f"Auto-détection: utilisation de la colonne {col_index}"
                )

            # Option pour ignorer les lignes malformées
            skip_malformed = self.config.get("skip_malformed_lines", True)
            min_columns = self.config.get("min_columns", 0)

            # Statistiques d'erreurs pour éviter le spam de logs
            error_stats = {
                "lines_processed": 0,
                "lines_skipped": 0,
                "column_missing": 0,
                "empty_values": 0,
                "invalid_iocs": 0,
                "last_error_line": 0,
            }

            for row_num, row in enumerate(reader, 2 if has_header else 1):
                error_stats["lines_processed"] += 1

                if not row:
                    error_stats["lines_skipped"] += 1
                    continue

                try:
                    # Sécurité: vérifie la longueur des cellules
                    for i, cell in enumerate(row):
                        if len(cell) > 2048:
                            self.logger.warning(
                                f"Cellule trop longue ligne {row_num}, colonne {i}, troncature"
                            )
                            row[i] = cell[:2048]

                    # Vérifie si la colonne existe
                    if col_index >= len(row):
                        error_stats["column_missing"] += 1
                        error_stats["last_error_line"] = row_num

                        # Log groupé seulement pour les premières erreurs
                        if error_stats["column_missing"] <= 5:
                            self.logger.warning(
                                f"Ligne {row_num}: colonne {col_index} inexistante (ligne a {len(row)} colonnes)"
                            )
                        elif error_stats["column_missing"] == 6:
                            self.logger.warning(
                                "Trop d'erreurs de colonnes manquantes, suppression des logs suivants..."
                            )

                        # Ignore la ligne si skip_malformed est activé
                        if skip_malformed:
                            continue
                        else:
                            # Essaie avec une colonne alternative (dernière colonne disponible)
                            if len(row) > 0:
                                col_index_alt = len(row) - 1
                                ioc_value = row[col_index_alt].strip()
                                if ioc_value:
                                    self.logger.debug(
                                        f"Utilisation colonne alternative {col_index_alt} pour ligne {row_num}"
                                    )
                                else:
                                    continue
                            else:
                                continue
                    else:
                        # Récupère la valeur IOC normalement
                        ioc_value = row[col_index].strip()

                    # Vérifie le nombre minimum de colonnes si spécifié
                    if min_columns > 0 and len(row) < min_columns:
                        error_stats["lines_skipped"] += 1
                        continue
                    if not ioc_value:
                        error_stats["empty_values"] += 1
                        continue

                    # Classifie l'IOC
                    ioc_type = classifier.classify_ioc(ioc_value)
                    if ioc_type:
                        ioc = IOC(
                            value=ioc_value.lower(),
                            type=ioc_type,
                            source=self.name,
                            retention=RetentionBucket(
                                self.config.get("retention", "live")
                            ),
                        )
                        iocs.append(ioc)
                    else:
                        error_stats["invalid_iocs"] += 1

                except Exception as e:
                    error_stats["lines_skipped"] += 1
                    if error_stats["lines_skipped"] <= 3:
                        self.logger.warning(f"Erreur ligne {row_num}: {e}")
                    continue

            # Log final des statistiques d'erreurs
            self._log_csv_statistics(error_stats)

            self.stats["iocs_extracted"] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")

        except csv.Error as e:
            self.stats["errors"] += 1
            raise PluginError(f"Erreur de format CSV: {e}")

        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Erreur lors du parsing CSV: {e}")
            raise PluginError(f"Erreur de parsing: {e}")

        return iocs

    def _analyze_csv_structure(
        self, header: List[str], sample_lines: List[str], delimiter: str
    ):
        """Analyse la structure du CSV pour détecter les problèmes"""
        try:
            self.logger.debug(
                f"Analyse de la structure CSV avec délimiteur '{delimiter}'"
            )

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
                    except Exception:
                        continue

            if column_counts:
                min_cols = min(column_counts)
                max_cols = max(column_counts)
                avg_cols = sum(column_counts) / len(column_counts)

                self.logger.debug(
                    f"Analyse des colonnes - Min: {min_cols}, Max: {max_cols}, Moyenne: {avg_cols:.1f}"
                )

                # Avertissement si structure incohérente
                if max_cols - min_cols > 2:
                    self.logger.warning(
                        f"Structure CSV incohérente: {min_cols}-{max_cols} colonnes par ligne"
                    )

                # Recommandation pour la colonne cible
                target_column = self.config.get("column", 0)
                if isinstance(target_column, int) and target_column >= min_cols:
                    self.logger.warning(
                        f"Colonne cible {target_column} peut être absente de certaines lignes (min colonnes: {min_cols})"
                    )

                    # Suggère une colonne alternative si possible
                    if min_cols > 0:
                        suggested_col = min(target_column, min_cols - 1)
                        if suggested_col != target_column:
                            self.logger.info(
                                f"Suggestion: utiliser la colonne {suggested_col} pour plus de compatibilité"
                            )

        except Exception as e:
            self.logger.warning(f"Impossible d'analyser la structure CSV: {e}")

    def _auto_detect_best_column(
        self,
        sample_lines: List[str],
        delimiter: str,
        has_header: bool,
        classifier: IOCClassifier,
    ) -> int:
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
                self.logger.warning(
                    "Pas assez de données pour l'auto-détection, utilisation colonne 0"
                )
                return 0

            # Détermine le nombre max de colonnes
            max_columns = max(len(row) for row in sample_rows if row)

            for col_idx in range(max_columns):
                valid_iocs = 0
                total_values = 0

                for row in sample_rows:
                    if col_idx < len(row):
                        value = row[col_idx].strip()
                        if value and not value.startswith("#"):
                            total_values += 1
                            if classifier.classify_ioc(value):
                                valid_iocs += 1

                # Score = pourcentage d'IOCs valides
                if total_values > 0:
                    score = (valid_iocs / total_values) * 100
                    column_scores[col_idx] = {
                        "score": score,
                        "valid_iocs": valid_iocs,
                        "total_values": total_values,
                    }

                    self.logger.debug(
                        f"Colonne {col_idx}: {valid_iocs}/{total_values} IOCs valides ({score:.1f}%)"
                    )

            if not column_scores:
                self.logger.warning(
                    "Aucune colonne avec des IOCs détectée, utilisation colonne 0"
                )
                return 0

            # Sélectionne la colonne avec le meilleur score
            best_col = max(
                column_scores.keys(), key=lambda k: column_scores[k]["score"]
            )
            best_score = column_scores[best_col]

            self.logger.info(
                f"Meilleure colonne détectée: {best_col} ({best_score['valid_iocs']}/{best_score['total_values']} IOCs, {best_score['score']:.1f}%)"
            )

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

            delimiter = self.config.get("delimiter", ",")
            has_header = self.config.get("has_header", True)

            reader = csv.reader(lines, delimiter=delimiter)

            analysis = {
                "total_lines": len(lines),
                "delimiter": delimiter,
                "has_header": has_header,
                "columns": [],
                "recommendations": [],
            }

            # Analyse l'en-tête
            if has_header:
                header = next(reader, None)
                if header:
                    analysis["header"] = header
                    analysis["num_columns"] = len(header)

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

                analysis["min_columns"] = min_cols
                analysis["max_columns"] = max_cols
                analysis["consistent_structure"] = max_cols == min_cols

                # Analyse chaque colonne
                classifier = IOCClassifier("ip_whitelist.yaml")
                for col_idx in range(max_cols):
                    col_analysis = {
                        "index": col_idx,
                        "name": (
                            header[col_idx]
                            if has_header and col_idx < len(header)
                            else f"Column_{col_idx}"
                        ),
                        "sample_values": [],
                        "ioc_count": 0,
                        "total_values": 0,
                        "ioc_types": set(),
                    }

                    for row in data_rows[:10]:  # Échantillon de 10 lignes
                        if col_idx < len(row):
                            value = row[col_idx].strip()
                            if value:
                                col_analysis["sample_values"].append(value)
                                col_analysis["total_values"] += 1

                                ioc_type = classifier.classify_ioc(value)
                                if ioc_type:
                                    col_analysis["ioc_count"] += 1
                                    col_analysis["ioc_types"].add(ioc_type.value)

                    col_analysis["ioc_types"] = list(col_analysis["ioc_types"])
                    col_analysis["ioc_percentage"] = (
                        (col_analysis["ioc_count"] / col_analysis["total_values"] * 100)
                        if col_analysis["total_values"] > 0
                        else 0
                    )

                    analysis["columns"].append(col_analysis)

                # Génère des recommandations
                best_ioc_column = (
                    max(analysis["columns"], key=lambda c: c["ioc_percentage"])
                    if analysis["columns"]
                    else None
                )

                if best_ioc_column and best_ioc_column["ioc_percentage"] > 50:
                    analysis["recommendations"].append(
                        f"Colonne recommandée: {best_ioc_column['index']} ('{best_ioc_column['name']}') - {best_ioc_column['ioc_percentage']:.1f}% d'IOCs"
                    )

                if not analysis["consistent_structure"]:
                    analysis["recommendations"].append(
                        f"Structure incohérente: {min_cols}-{max_cols} colonnes par ligne. Considérez skip_malformed_lines: true"
                    )

                if min_cols > 0:
                    analysis["recommendations"].append(
                        f"Définir min_columns: {min_cols} pour filtrer les lignes incomplètes"
                    )

            return analysis

        except Exception as e:
            return {"error": f"Erreur d'analyse: {e}"}

    def _log_csv_statistics(self, error_stats: Dict[str, int]):
        """Log les statistiques d'erreurs de façon groupée"""
        total_processed = error_stats["lines_processed"]

        if total_processed == 0:
            return

        self.logger.info(f"Statistiques de parsing CSV pour {self.name}:")
        self.logger.info(f"  Lignes traitées: {total_processed}")

        if error_stats["lines_skipped"] > 0:
            skip_percent = (error_stats["lines_skipped"] / total_processed) * 100
            self.logger.warning(
                f"  Lignes ignorées: {error_stats['lines_skipped']} ({skip_percent:.1f}%)"
            )

        if error_stats["column_missing"] > 0:
            col_percent = (error_stats["column_missing"] / total_processed) * 100
            self.logger.warning(
                f"  Colonnes manquantes: {error_stats['column_missing']} ({col_percent:.1f}%) - Dernière ligne: {error_stats['last_error_line']}"
            )

        if error_stats["empty_values"] > 0:
            empty_percent = (error_stats["empty_values"] / total_processed) * 100
            self.logger.info(
                f"  Valeurs vides ignorées: {error_stats['empty_values']} ({empty_percent:.1f}%)"
            )

        if error_stats["invalid_iocs"] > 0:
            invalid_percent = (error_stats["invalid_iocs"] / total_processed) * 100
            self.logger.info(
                f"  IOCs invalides: {error_stats['invalid_iocs']} ({invalid_percent:.1f}%)"
            )

    def _get_column_index(
        self, column: Union[str, int], header: Optional[List[str]]
    ) -> int:
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
                        self.logger.info(
                            f"Colonne trouvée avec correspondance insensible à la casse: '{column}' -> index {i}"
                        )
                        return i

                # Recherche partielle
                for i, col_name in enumerate(header):
                    if column.lower() in col_name.lower():
                        self.logger.info(
                            f"Colonne trouvée avec correspondance partielle: '{column}' dans '{col_name}' -> index {i}"
                        )
                        return i

                raise PluginError(
                    f"Colonne '{column}' non trouvée dans l'en-tête. Colonnes disponibles: {header}"
                )

        else:
            raise PluginError("Impossible de déterminer l'index de la colonne")


class JSONPlugin(HTTPPlugin):
    """Plugin pour les flux JSON"""

    def collect(self) -> str:
        """Collecte depuis une API JSON"""
        url = self.config["url"]
        response = self._make_request(url)
        return response.text

    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le JSON et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier("ip_whitelist.yaml")

        try:
            # Limite la taille des données JSON
            if len(raw_data) > 50 * 1024 * 1024:  # 50MB
                raise PluginError("Fichier JSON trop volumineux (> 50MB)")

            data = json.loads(raw_data)

            # Chemin d'accès aux IOCs dans le JSON
            json_path = self.config.get("json_path", [])

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

            self.stats["iocs_extracted"] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")

        except json.JSONDecodeError as e:
            self.stats["errors"] += 1
            raise PluginError(f"JSON invalide: {e}")

        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Erreur lors du parsing JSON: {e}")
            raise PluginError(f"Erreur de parsing: {e}")

        return iocs

    def _extract_iocs_from_json(
        self, data: Any, classifier: IOCClassifier, iocs: List[IOC], depth: int = 0
    ):
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
                    retention=RetentionBucket(self.config.get("retention", "live")),
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
                            retention=RetentionBucket(
                                self.config.get("retention", "live")
                            ),
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
        url = self.config["url"]
        response = self._make_request(url)
        return response.text

    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le STIX et extrait les IOCs"""
        iocs = []
        classifier = IOCClassifier("ip_whitelist.yaml")

        try:
            # Parse le bundle STIX
            bundle = stix2.parse(raw_data)

            if not hasattr(bundle, "objects"):
                raise PluginError("Bundle STIX invalide: pas d'objets")

            for obj in bundle.objects:
                if obj.type == "indicator" and hasattr(obj, "pattern"):
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
                                    retention=RetentionBucket(
                                        self.config.get("retention", "live")
                                    ),
                                )
                                iocs.append(ioc)

                    except Exception as e:
                        self.logger.warning(
                            f"Erreur lors du parsing du pattern STIX: {e}"
                        )
                        continue

            self.stats["iocs_extracted"] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")

        except Exception as e:
            self.stats["errors"] += 1
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
        url = self.config["url"]
        response = self._make_request(url)
        return response.text

    def parse(self, raw_data: str) -> List[IOC]:
        """Parse le RSS et extrait les IOCs du contenu"""
        iocs = []
        classifier = IOCClassifier("ip_whitelist.yaml")

        try:
            feed = feedparser.parse(raw_data)

            if feed.bozo and feed.bozo_exception:
                self.logger.warning(f"RSS mal formé: {feed.bozo_exception}")

            if not hasattr(feed, "entries") or not feed.entries:
                raise PluginError("Flux RSS vide ou invalide")

            # Limite le nombre d'entrées à traiter
            max_entries = self.config.get("max_entries", 100)
            entries_to_process = feed.entries[:max_entries]

            for entry in entries_to_process:
                # Extrait le contenu textuel
                text_content = []

                if hasattr(entry, "title") and entry.title:
                    text_content.append(entry.title)

                if hasattr(entry, "description") and entry.description:
                    text_content.append(entry.description)

                if hasattr(entry, "summary") and entry.summary:
                    text_content.append(entry.summary)

                # Combine tout le texte
                combined_text = " ".join(text_content)

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
                                retention=RetentionBucket(
                                    self.config.get("retention", "live")
                                ),
                            )
                            iocs.append(ioc)

            self.stats["iocs_extracted"] = len(iocs)
            self.logger.info(f"Extrait {len(iocs)} IOCs depuis {self.name}")

        except Exception as e:
            self.stats["errors"] += 1
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
        required_fields = ["url", "collection_id"]
        for fieldw in required_fields:
            if fieldw not in self.config:
                raise PluginError(f"Champ TAXII obligatoire manquant: {fieldw}")
        return True

    def collect(self) -> str:
        """Collecte depuis un serveur TAXII"""
        try:
            # Initialise le client TAXII
            api_root_url = self.config["url"]

            # Authentification
            username = self.config.get("username")
            password = self.config.get("password")
            api_key = self.api_manager.get_key(self.name)

            if api_key:
                # Authentification par clé API
                server = taxii2client.Server(
                    api_root_url, headers={"Authorization": f"Bearer {api_key}"}
                )
            elif username and password:
                # Authentification par login/password
                server = taxii2client.Server(
                    api_root_url, user=username, password=password
                )
            else:
                # Pas d'authentification
                server = taxii2client.Server(api_root_url)

            # Récupère l'API root
            api_root = server.api_roots[0] if server.api_roots else server.default

            # Récupère la collection
            collection_id = self.config["collection_id"]
            collection = None

            for coll in api_root.collections:
                if coll.id == collection_id:
                    collection = coll
                    break

            if not collection:
                raise PluginError(f"Collection TAXII non trouvée: {collection_id}")

            # Récupère les objets
            limit = self.config.get("limit", 100)
            objects = collection.get_objects(limit=limit)

            self.stats["requests_made"] += 1

            # Retourne les objets sous forme de bundle STIX
            if objects.get("objects"):
                bundle_data = {
                    "type": "bundle",
                    "id": f"bundle--{time.time()}",
                    "objects": objects["objects"],
                }
                return json.dumps(bundle_data)
            else:
                return '{"type": "bundle", "objects": []}'

        except Exception as e:
            self.stats["errors"] += 1
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
        self.logger = logging.getLogger(f"{__name__}.PluginManager")
        self._register_builtin_plugins()

    def _register_builtin_plugins(self):
        """Enregistre les plugins intégrés"""
        self.plugins = {
            "text": TextPlugin,
            "csv": CSVPlugin,
            "json": JSONPlugin,
            "stix": STIXPlugin,
            "rss": RSSPlugin,
            "taxii": TAXIIPlugin,
        }
        self.logger.info(f"Plugins enregistrés: {list(self.plugins.keys())}")

    def create_plugin(self, feed_config: Dict[str, Any]) -> BasePlugin:
        """Crée une instance de plugin selon la configuration"""
        plugin_type = feed_config.get("type")

        if plugin_type not in self.plugins:
            raise PluginError(f"Type de plugin non supporté: {plugin_type}")

        try:
            plugin_class = self.plugins[plugin_type]
            plugin = plugin_class(feed_config, feed_config["name"], self.api_manager)
            plugin.validate_config()
            return plugin

        except Exception as e:
            raise PluginError(
                f"Erreur lors de la création du plugin {plugin_type}: {e}"
            )

    def get_available_plugins(self) -> List[str]:
        """Retourne la liste des plugins disponibles"""
        return list(self.plugins.keys())


# ===============================
# STOCKAGE ET DÉDUPLICATION
# ===============================


class IOCStorage:
    """Gestionnaire de stockage des IOCs avec déduplication"""

    def __init__(self, output_dir: str = "iocs", max_file_size: int = 10485760):
        self.output_dir = Path(output_dir)
        self.max_file_size = max_file_size
        self.logger = logging.getLogger(f"{__name__}.IOCStorage")
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

            self.logger.info(
                f"Structure de stockage initialisée dans {self.output_dir}"
            )

        except Exception as e:
            raise StorageError(f"Erreur lors de l'initialisation du stockage: {e}")

    def _initialize_database(self):
        """Initialise la base de données de déduplication"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    value TEXT,
                    type TEXT,
                    source TEXT,
                    bucket TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    PRIMARY KEY (value, type)
                )
            """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_value_type ON iocs(value, type)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bucket ON iocs(bucket)")
            conn.commit()
            conn.close()

            self.logger.info("Base de données de déduplication initialisée")

        except Exception as e:
            raise StorageError(
                f"Erreur lors de l'initialisation de la base de données: {e}"
            )

    def store_iocs(self, iocs: List[IOC]) -> Dict[str, int]:
        """Stocke les IOCs avec déduplication"""
        if not iocs:
            return {"total": 0, "new": 0, "updated": 0, "duplicates": 0, "errors": 0}

        with self._lock:
            stats = {
                "total": len(iocs),
                "new": 0,
                "updated": 0,
                "duplicates": 0,
                "errors": 0,
            }

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
                        dedup_result = self._deduplicate_iocs(conn, ioc_list)
                        new_iocs = dedup_result["new"]
                        updated_iocs = dedup_result["updated"]

                        if new_iocs:
                            self._write_iocs_to_file(ioc_type, bucket, new_iocs)
                            stats["new"] += len(new_iocs)

                        stats["updated"] += len(updated_iocs)
                        stats["duplicates"] += (
                            len(ioc_list) - len(new_iocs) - len(updated_iocs)
                        )

                    except Exception as e:
                        stats["errors"] += len(ioc_list)
                        self.logger.error(
                            f"Erreur lors du stockage des IOCs {ioc_type.value}/{bucket.value}: {e}"
                        )

                conn.close()

            except Exception as e:
                stats["errors"] = stats["total"]
                self.logger.error(f"Erreur lors du stockage des IOCs: {e}")

            return stats

    def _deduplicate_iocs(
        self, conn: sqlite3.Connection, iocs: List[IOC]
    ) -> Dict[str, List[IOC]]:
        """Déduplique les IOCs contre la base de données avec gestion des transitions entre buckets"""
        new_iocs = []
        updated_iocs = []
        transitioned_iocs = []
        now = datetime.now()

        # Hiérarchie des priorités des buckets (live > chaud > tiede > froid)
        bucket_priority = {"live": 0, "chaud": 1, "tiede": 2, "froid": 3}

        for ioc in iocs:
            # Vérifie si l'IOC existe déjà avec son bucket actuel
            cursor = conn.execute(
                "SELECT bucket, last_seen, first_seen FROM iocs WHERE value = ? AND type = ?",
                (ioc.value, ioc.type.value),
            )
            result = cursor.fetchone()

            if result:
                existing_bucket, last_seen, first_seen = result

                # Gestion des transitions entre buckets
                if existing_bucket != ioc.retention.value:
                    current_priority = bucket_priority.get(existing_bucket, 999)
                    new_priority = bucket_priority.get(ioc.retention.value, 999)

                    # Si le nouveau bucket est plus prioritaire (priorité plus faible)
                    if new_priority < current_priority:
                        # Promotion vers un bucket plus prioritaire
                        self._move_ioc_between_buckets(
                            ioc.value,
                            ioc.type.value,
                            existing_bucket,
                            ioc.retention.value,
                        )

                        # Met à jour la base de données
                        conn.execute(
                            "UPDATE iocs SET bucket = ?, last_seen = ?, source = ? WHERE value = ? AND type = ?",
                            (
                                ioc.retention.value,
                                now,
                                ioc.source,
                                ioc.value,
                                ioc.type.value,
                            ),
                        )

                        transitioned_iocs.append(
                            {
                                "value": ioc.value,
                                "type": ioc.type.value,
                                "from_bucket": existing_bucket,
                                "to_bucket": ioc.retention.value,
                                "reason": "promotion",
                            }
                        )

                        updated_iocs.append(ioc)

                        self.logger.info(
                            f"IOC {ioc.value} promu de {existing_bucket} vers {ioc.retention.value}"
                        )

                    else:
                        # Conserve dans le bucket existant (plus prioritaire ou même priorité)
                        conn.execute(
                            "UPDATE iocs SET last_seen = ?, source = ? WHERE value = ? AND type = ?",
                            (now, ioc.source, ioc.value, ioc.type.value),
                        )

                        if new_priority > current_priority:
                            self.logger.debug(
                                f"IOC {ioc.value} conservé dans {existing_bucket} (priorité supérieure à {ioc.retention.value})"
                            )
                        updated_iocs.append(ioc)
                else:
                    # Même bucket, simple mise à jour
                    conn.execute(
                        "UPDATE iocs SET last_seen = ?, source = ? WHERE value = ? AND type = ?",
                        (now, ioc.source, ioc.value, ioc.type.value),
                    )
                    updated_iocs.append(ioc)

            else:
                # Nouvel IOC
                conn.execute(
                    "INSERT INTO iocs (value, type, source, bucket, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        ioc.value,
                        ioc.type.value,
                        ioc.source,
                        ioc.retention.value,
                        ioc.first_seen,
                        now,
                    ),
                )
                new_iocs.append(ioc)

        conn.commit()

        # Log des statistiques
        if transitioned_iocs:
            self.logger.info(f"Transitions effectuées: {len(transitioned_iocs)}")

        return {"new": new_iocs, "updated": updated_iocs}

    def _move_ioc_between_buckets(
        self, value: str, ioc_type: str, from_bucket: str, to_bucket: str
    ):
        """Déplace un IOC entre buckets avec opérations atomiques"""
        try:
            # Atomic removal from old bucket
            self._atomic_remove_from_file(from_bucket, ioc_type, value)

            # Atomic addition to new bucket
            self._atomic_add_to_file(to_bucket, ioc_type, value)

        except Exception as e:
            self.logger.error(
                f"Erreur lors du déplacement de l'IOC {value} de {from_bucket} vers {to_bucket}: {e}"
            )
            raise StorageError(f"Échec du déplacement d'IOC entre buckets: {e}") from e

    def _write_iocs_to_file(
        self, ioc_type: IOCType, bucket: RetentionBucket, iocs: List[IOC]
    ):
        """Écrit les IOCs dans le fichier approprié avec format brut pour live"""
        file_path = self.output_dir / bucket.value / f"{ioc_type.value}.txt"

        try:
            # Vérifie la taille du fichier et effectue la rotation/compression si nécessaire
            if file_path.exists() and file_path.stat().st_size > self.max_file_size:
                self._rotate_and_compress_file(file_path, bucket)

            # Utilise atomic write pour éviter les corruptions
            self._atomic_write_iocs(file_path, iocs, bucket)

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

    def _rotate_and_compress_file(self, file_path: Path, bucket: RetentionBucket):
        """Effectue la rotation avec compression selon la politique du bucket"""
        import gzip

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # Compression automatique pour buckets non-live
            if bucket != RetentionBucket.LIVE:
                backup_path = file_path.with_suffix(f".{timestamp}.txt.gz")

                # Compresse le fichier existant
                with open(file_path, "rb") as f_in:
                    with gzip.open(backup_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)

                self.logger.info(f"Fichier compressé: {file_path} -> {backup_path}")
            else:
                # Bucket live reste non compressé
                backup_path = file_path.with_suffix(f".{timestamp}.txt")
                shutil.move(str(file_path), str(backup_path))
                self.logger.info(
                    f"Rotation sans compression: {file_path} -> {backup_path}"
                )

            # Recrée le fichier vide
            file_path.touch()

        except Exception as e:
            self.logger.error(
                f"Erreur lors de la rotation/compression du fichier {file_path}: {e}"
            )

    def _atomic_write_iocs(
        self, file_path: Path, iocs: List[IOC], bucket: RetentionBucket
    ):
        """Écrit les IOCs de manière atomique avec format approprié selon le bucket"""
        import os

        # Crée le répertoire parent si nécessaire
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Utilise un fichier temporaire pour écriture atomique
        temp_file = file_path.with_suffix(".tmp")

        try:
            # Charge le contenu existant
            existing_content = ""
            if file_path.exists():
                with open(file_path, "r", encoding="utf-8") as f:
                    existing_content = f.read()

            # Prepare le nouveau contenu
            new_lines = []
            for ioc in iocs:
                # Bucket LIVE doit être brut (pas de commentaires)
                if bucket == RetentionBucket.LIVE:
                    new_lines.append(f"{ioc.value}\n")
                else:
                    # Autres buckets peuvent avoir des métadonnées optionnelles
                    new_lines.append(f"{ioc.value}\n")

            # Écrit atomiquement
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(existing_content)
                f.writelines(new_lines)
                f.flush()
                os.fsync(f.fileno())  # Force l'écriture sur disque

            # Déplacement atomique
            os.replace(str(temp_file), str(file_path))

        except Exception as e:
            # Nettoie le fichier temporaire en cas d'erreur
            if temp_file.exists():
                temp_file.unlink()
            raise StorageError(f"Échec de l'écriture atomique: {e}") from e

    def _atomic_remove_from_file(self, bucket: str, ioc_type: str, value: str):
        """Supprime un IOC d'un fichier de manière atomique"""
        import os

        file_path = self.output_dir / bucket / f"{ioc_type}.txt"

        if not file_path.exists():
            return

        temp_file = file_path.with_suffix(".tmp")
        found = False

        try:
            with open(file_path, "r", encoding="utf-8") as f_in:
                with open(temp_file, "w", encoding="utf-8") as f_out:
                    for line in f_in:
                        line_value = line.strip()
                        if line_value == value:
                            found = True
                            continue
                        f_out.write(line)
                    f_out.flush()
                    os.fsync(f_out.fileno())

            if found:
                # Déplacement atomique seulement si modification effectuée
                os.replace(str(temp_file), str(file_path))
            else:
                # Supprime le fichier temporaire si aucune modification
                temp_file.unlink()

        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise StorageError(f"Échec de la suppression atomique: {e}") from e

    def _atomic_add_to_file(self, bucket: str, ioc_type: str, value: str):
        """Ajoute un IOC à un fichier de manière atomique avec vérification de doublon"""
        import os

        file_path = self.output_dir / bucket / f"{ioc_type}.txt"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Vérifie d'abord si l'IOC existe déjà
        if file_path.exists():
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() == value:
                        return  # Déjà présent

        # Ajoute atomiquement
        temp_file = file_path.with_suffix(".tmp")

        try:
            # Copie le contenu existant + nouveau IOC
            with open(temp_file, "w", encoding="utf-8") as f_out:
                if file_path.exists():
                    with open(file_path, "r", encoding="utf-8") as f_in:
                        f_out.write(f_in.read())

                # Ajoute le nouvel IOC (format brut)
                f_out.write(f"{value}\n")
                f_out.flush()
                os.fsync(f_out.fileno())

            # Déplacement atomique
            os.replace(str(temp_file), str(file_path))

        except Exception as e:
            if temp_file.exists():
                temp_file.unlink()
            raise StorageError(f"Échec de l'ajout atomique: {e}") from e


# ===============================
# API EXTERNE - RÉCUPÉRATION DEPUIS APIS TIERCES
# ===============================


class ExternalAPIClient:
    """Client pour récupérer des IOCs depuis des APIs externes"""

    def __init__(self, feed_config: Dict[str, Any]):
        self.config = feed_config
        self.name = feed_config["name"]
        self.url = feed_config["url"]
        self.logger = logging.getLogger(f"{__name__}.ExternalAPIClient.{self.name}")

        # Configuration SSL/TLS
        self.verify_ssl = feed_config.get("ssl", {}).get("verify", True)
        self.ssl_cert = feed_config.get("ssl", {}).get("cert_file")
        self.ssl_key = feed_config.get("ssl", {}).get("key_file")
        self.ca_bundle = feed_config.get("ssl", {}).get("ca_bundle")

        # Configuration authentification
        self.auth_config = feed_config.get("auth", {})
        self.timeout = feed_config.get("timeout", 30)
        self.max_retries = feed_config.get("max_retries", 3)
        self.user_agent = feed_config.get("user_agent", "TinyCTI/1.0")

        # Headers personnalisés
        self.custom_headers = feed_config.get("headers", {})

    def fetch_data(self) -> Optional[str]:
        """Récupère les données depuis l'API externe avec gestion SSL et auth"""
        session = requests.Session()

        try:
            # Configuration SSL/TLS de production
            if not self.verify_ssl:
                session.verify = False
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                self.logger.warning(f"SSL verification disabled for {self.name}")
            elif self.ca_bundle:
                session.verify = self.ca_bundle
                self.logger.debug(f"Using CA bundle: {self.ca_bundle}")
            else:
                session.verify = True  # Verification SSL par défaut

            # Certificats client
            if self.ssl_cert and self.ssl_key:
                session.cert = (self.ssl_cert, self.ssl_key)
            elif self.ssl_cert:
                session.cert = self.ssl_cert

            # Configuration des tentatives
            retry_strategy = Retry(
                total=self.max_retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            # Headers de base
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate",
            }
            headers.update(self.custom_headers)

            # Authentification
            auth = self._setup_authentication(session)

            # Requête
            self.logger.info(f"Récupération depuis {self.url}")
            response = session.get(
                self.url, headers=headers, auth=auth, timeout=self.timeout, stream=True
            )

            response.raise_for_status()

            # Gestion du contenu compressé
            content = response.text
            self.logger.info(f"Récupéré {len(content)} caractères depuis {self.name}")

            return content

        except requests.exceptions.SSLError as e:
            self.logger.error(
                f"Erreur SSL lors de la récupération depuis {self.name}: {e}"
            )
            raise ExternalAPIError(f"Erreur SSL: {e}") from e
        except requests.exceptions.Timeout as e:
            self.logger.error(
                f"Timeout lors de la récupération depuis {self.name}: {e}"
            )
            raise ExternalAPIError(f"Timeout: {e}") from e
        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Erreur réseau lors de la récupération depuis {self.name}: {e}"
            )
            raise ExternalAPIError(f"Erreur réseau: {e}") from e
        except Exception as e:
            self.logger.error(
                f"Erreur inattendue lors de la récupération depuis {self.name}: {e}"
            )
            raise ExternalAPIError(f"Erreur inattendue: {e}") from e
        finally:
            session.close()

    def _setup_authentication(self, session: requests.Session) -> Optional[Any]:
        """Configure l'authentification selon le type"""
        auth_type = self.auth_config.get("type", "none")

        if auth_type == "none":
            return None
        elif auth_type == "basic":
            username = self.auth_config.get("username")
            password = self.auth_config.get("password")
            if username and password:
                from requests.auth import HTTPBasicAuth

                return HTTPBasicAuth(username, password)
        elif auth_type == "bearer":
            token = self.auth_config.get("token")
            if token:
                session.headers.update({"Authorization": f"Bearer {token}"})
        elif auth_type == "api_key":
            key = self.auth_config.get("key")
            header_name = self.auth_config.get("header", "X-API-Key")
            if key:
                session.headers.update({header_name: key})
        elif auth_type == "oauth2":
            # Gestion OAuth2 simplifiée
            access_token = self._get_oauth2_token()
            if access_token:
                session.headers.update({"Authorization": f"Bearer {access_token}"})

        return None

    def _get_oauth2_token(self) -> Optional[str]:
        """Obtient un token OAuth2"""
        try:
            client_id = self.auth_config.get("client_id")
            client_secret = self.auth_config.get("client_secret")
            token_url = self.auth_config.get("token_url")

            if not all([client_id, client_secret, token_url]):
                return None

            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }

            response = requests.post(token_url, data=data, timeout=self.timeout)
            response.raise_for_status()

            token_data = response.json()
            return token_data.get("access_token")

        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération du token OAuth2: {e}")
            return None


class ExternalAPIError(Exception):
    """Erreur spécifique aux APIs externes"""

    pass


# ===============================
# API INTERNE - EXPOSITION FICHIERS TXT
# ===============================


class InternalFileAPI:
    """API interne pour exposer les fichiers .txt des buckets"""

    def __init__(
        self, storage: "IOCStorage", config: Dict[str, Any], api_id: str = "default"
    ):
        self.storage = storage
        self.api_id = api_id
        self.config = config
        self.enabled = self.config.get("enabled", False)
        self.host = self.config.get("host", "127.0.0.1")
        self.port = self.config.get("port", 8080)
        self.auth_token = self.config.get("auth_token")
        self.rate_limit = self.config.get("rate_limit", 100)
        self.buckets_filter = self.config.get(
            "buckets", ["live", "chaud", "tiede", "froid"]
        )
        self.types_filter = self.config.get(
            "types",
            ["ipv4", "ipv6", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"],
        )
        self.logger = logging.getLogger(f"{__name__}.InternalFileAPI.{api_id}")

        if self.enabled:
            self.app = Flask(__name__)
            self._setup_routes()

    def _setup_routes(self):
        """Configure les routes de l'API interne"""

        @self.app.before_request
        def check_auth():
            """Vérifie l'authentification si configurée"""
            if self.auth_token:
                auth_header = request.headers.get("Authorization")
                if not auth_header or auth_header != f"Bearer {self.auth_token}":
                    return jsonify({"error": "Unauthorized"}), 401

        @self.app.route("/buckets")
        def list_buckets():
            """Liste les buckets disponibles"""
            return jsonify(
                {
                    "buckets": ["live", "chaud", "tiede", "froid"],
                    "description": "Buckets d'IOCs disponibles",
                }
            )

        @self.app.route("/bucket/<bucket_name>/<ioc_type>.txt")
        def get_bucket_file(bucket_name: str, ioc_type: str):
            """Récupère le fichier .txt d'un bucket/type"""
            # Sanitize inputs to prevent path traversal
            from tinycti import SecurityValidator

            bucket_name = SecurityValidator.sanitize_path(bucket_name)
            ioc_type = SecurityValidator.sanitize_path(ioc_type)

            if not bucket_name or not ioc_type:
                return "Invalid path parameters", 400

            if bucket_name not in self.buckets_filter:
                return f"Bucket {bucket_name} non autorisé sur cette API", 404

            if ioc_type not in self.types_filter:
                return f"Type {ioc_type} non autorisé sur cette API", 404

            file_path = self.storage.output_dir / bucket_name / f"{ioc_type}.txt"

            # Ensure the resolved path is still within the expected directory
            if not str(file_path.resolve()).startswith(
                str(self.storage.output_dir.resolve())
            ):
                return "Invalid file path", 400

            if not file_path.exists():
                return "Fichier non trouvé", 404

            try:
                with open(file_path, "r") as f:
                    content = f.read()

                return Response(
                    content,
                    mimetype="text/plain",
                    headers={
                        "Content-Disposition": f'attachment; filename="{bucket_name}_{ioc_type}.txt"',
                        "X-Bucket": bucket_name,
                        "X-IOC-Type": ioc_type,
                        "X-Line-Count": str(len(content.splitlines())),
                    },
                )
            except Exception as e:
                self.logger.error(f"Erreur lecture fichier {file_path}: {e}")
                return "Erreur interne", 500

        @self.app.route("/bucket/<bucket_name>/stats")
        def get_bucket_stats(bucket_name: str):
            """Statistiques d'un bucket"""
            if bucket_name not in ["live", "chaud", "tiede", "froid"]:
                return jsonify({"error": "Bucket non trouvé"}), 404

            bucket_dir = self.storage.output_dir / bucket_name
            stats = {"bucket": bucket_name, "files": {}}

            if bucket_dir.exists():
                for file_path in bucket_dir.glob("*.txt"):
                    ioc_type = file_path.stem
                    try:
                        with open(file_path, "r") as f:
                            line_count = sum(1 for line in f if line.strip())
                        stats["files"][ioc_type] = {
                            "count": line_count,
                            "size": file_path.stat().st_size,
                            "modified": file_path.stat().st_mtime,
                        }
                    except Exception as e:
                        stats["files"][ioc_type] = {"error": str(e)}

            return jsonify(stats)

    def start(self):
        """Démarre l'API interne"""
        if not self.enabled:
            return

        try:
            self.logger.info(f"Démarrage API interne sur {self.host}:{self.port}")
            self.app.run(host=self.host, port=self.port, threaded=True, debug=False)
        except Exception as e:
            self.logger.error(f"Erreur démarrage API interne: {e}")


class MultipleInternalAPIManager:
    """Gestionnaire pour plusieurs APIs internes simultanées"""

    def __init__(self, storage: "IOCStorage", config: Dict[str, Any]):
        self.storage = storage
        self.config = config
        self.apis = {}
        self.threads = {}
        self.logger = logging.getLogger(f"{__name__}.MultipleInternalAPIManager")

        # Configuration des APIs multiples
        apis_config = config.get("internal_apis", {})

        # API par défaut pour compatibilité
        if config.get("internal_api", {}).get("enabled", False):
            self.apis["default"] = InternalFileAPI(
                storage, config.get("internal_api"), "default"
            )

        # APIs additionnelles
        for api_name, api_config in apis_config.items():
            if api_config.get("enabled", False):
                self.apis[api_name] = InternalFileAPI(storage, api_config, api_name)

    def start_all(self, background: bool = True):
        """Démarre toutes les APIs configurées"""
        for api_name, api in self.apis.items():
            if api.enabled:
                if background:
                    thread = threading.Thread(target=api.start, daemon=True)
                    thread.start()
                    self.threads[api_name] = thread
                    self.logger.info(
                        f"API interne '{api_name}' démarrée sur {api.host}:{api.port}"
                    )
                else:
                    api.start()

    def get_status(self):
        """Retourne le statut de toutes les APIs"""
        status = {}
        for api_name, api in self.apis.items():
            status[api_name] = {
                "enabled": api.enabled,
                "host": api.host,
                "port": api.port,
                "buckets": api.buckets_filter,
                "types": api.types_filter,
                "auth_protected": bool(api.auth_token),
            }
        return status


# ===============================
# ÉMISSION D'IOCS - STIX/RSS/JSON/TAXII
# ===============================


class IOCEmissionAPI:
    """API pour émettre des IOCs dans différents formats (STIX, RSS, JSON, TAXII)"""

    def __init__(self, storage: "IOCStorage", config: Dict[str, Any]):
        self.storage = storage
        self.config = config.get("emission_api", {})
        self.enabled = self.config.get("enabled", False)
        self.host = self.config.get("host", "127.0.0.1")
        self.port = self.config.get("port", 9000)
        self.auth_token = self.config.get("auth_token")
        self.formats = self.config.get("formats", ["json", "stix", "rss", "taxii"])
        self.logger = logging.getLogger(f"{__name__}.IOCEmissionAPI")

        if self.enabled:
            self.app = Flask(__name__)
            self._setup_emission_routes()

    def _setup_emission_routes(self):
        """Configure les routes d'émission"""

        @self.app.before_request
        def check_emission_auth():
            """Vérifie l'authentification si configurée"""
            if self.auth_token:
                auth_header = request.headers.get("Authorization")
                if not auth_header or auth_header != f"Bearer {self.auth_token}":
                    return jsonify({"error": "Unauthorized"}), 401

        @self.app.route("/formats")
        def list_emission_formats():
            """Liste les formats d'émission disponibles"""
            return jsonify(
                {
                    "formats": self.formats,
                    "endpoints": {
                        "json": "/emit/json/<bucket>/<ioc_type>",
                        "stix": "/emit/stix/<bucket>",
                        "rss": "/emit/rss/<bucket>",
                        "taxii": "/taxii/collections/<collection_id>/objects",
                    },
                }
            )

        @self.app.route("/emit/json/<bucket>/<ioc_type>")
        def emit_json(bucket: str, ioc_type: str):
            """Émet les IOCs au format JSON structuré"""
            if "json" not in self.formats:
                return jsonify({"error": "Format JSON non activé"}), 403

            try:
                file_path = self.storage.output_dir / bucket / f"{ioc_type}.txt"
                if not file_path.exists():
                    return jsonify({"error": "Données non trouvées"}), 404

                iocs = []
                with open(file_path, "r") as f:
                    for line in f:
                        ioc_value = line.strip()
                        if ioc_value:
                            iocs.append(
                                {
                                    "value": ioc_value,
                                    "type": ioc_type,
                                    "bucket": bucket,
                                    "timestamp": datetime.now().isoformat(),
                                    "source": "TinyCTI",
                                }
                            )

                return jsonify(
                    {
                        "indicators": iocs,
                        "metadata": {
                            "count": len(iocs),
                            "bucket": bucket,
                            "type": ioc_type,
                            "generated": datetime.now().isoformat(),
                            "format": "json",
                        },
                    }
                )
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/emit/stix/<bucket>")
        def emit_stix(bucket: str):
            """Émet les IOCs au format STIX 2.1"""
            if "stix" not in self.formats:
                return jsonify({"error": "Format STIX non activé"}), 403

            try:
                stix_objects = []

                # Crée un bundle STIX
                bundle_id = f"bundle--{uuid.uuid4()}"

                for ioc_type in [
                    "ipv4",
                    "ipv6",
                    "domain",
                    "url",
                    "hash_md5",
                    "hash_sha1",
                    "hash_sha256",
                ]:
                    file_path = self.storage.output_dir / bucket / f"{ioc_type}.txt"
                    if file_path.exists():
                        with open(file_path, "r") as f:
                            for line in f:
                                ioc_value = line.strip()
                                if ioc_value:
                                    # Crée un objet STIX Indicator
                                    indicator = {
                                        "type": "indicator",
                                        "spec_version": "2.1",
                                        "id": f"indicator--{uuid.uuid4()}",
                                        "created": datetime.now().isoformat() + "Z",
                                        "modified": datetime.now().isoformat() + "Z",
                                        "labels": ["malicious-activity"],
                                        "pattern": self._create_stix_pattern(
                                            ioc_type, ioc_value
                                        ),
                                        "valid_from": datetime.now().isoformat() + "Z",
                                    }
                                    stix_objects.append(indicator)

                # Crée le bundle STIX
                bundle = {"type": "bundle", "id": bundle_id, "objects": stix_objects}

                return jsonify(bundle)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/emit/rss/<bucket>")
        def emit_rss(bucket: str):
            """Émet les IOCs au format RSS"""
            if "rss" not in self.formats:
                return "Format RSS non activé", 403

            try:
                # Génère un flux RSS avec les derniers IOCs
                rss_template = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>TinyCTI IOC Feed - {bucket}</title>
        <link>http://{host}:{port}/emit/rss/{bucket}</link>
        <description>Flux RSS des IOCs du bucket {bucket}</description>
        <lastBuildDate>{timestamp}</lastBuildDate>
        <generator>TinyCTI</generator>
        {items}
    </channel>
</rss>"""

                items = []
                for ioc_type in ["ipv4", "ipv6", "domain", "url"]:
                    file_path = self.storage.output_dir / bucket / f"{ioc_type}.txt"
                    if file_path.exists():
                        with open(file_path, "r") as f:
                            for line in f:
                                ioc_value = line.strip()
                                if ioc_value:
                                    item = f"""
        <item>
            <title>{ioc_type.upper()}: {ioc_value}</title>
            <description>IOC de type {ioc_type} dans le bucket {bucket}</description>
                                    <pubDate>{datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")}</pubDate>
            <guid>{ioc_value}</guid>
        </item>"""
                                    items.append(item)

                rss_content = rss_template.format(
                    bucket=bucket,
                    host=self.host,
                    port=self.port,
                    timestamp=datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"),
                    items="".join(items),
                )

                return Response(rss_content, mimetype="application/rss+xml")
            except Exception as e:
                return f"Erreur: {e}", 500

        @self.app.route("/taxii/collections")
        def list_taxii_collections():
            """Liste les collections TAXII disponibles"""
            if "taxii" not in self.formats:
                return jsonify({"error": "Format TAXII non activé"}), 403

            collections = []
            for bucket in ["live", "chaud", "tiede", "froid"]:
                collections.append(
                    {
                        "id": f"tinycti-{bucket}",
                        "title": f"TinyCTI {bucket.title()} IOCs",
                        "description": f"Collection d'IOCs du bucket {bucket}",
                        "can_read": True,
                        "can_write": False,
                        "media_types": ["application/stix+json;version=2.1"],
                    }
                )

            return jsonify({"collections": collections})

        @self.app.route("/taxii/collections/<collection_id>/objects")
        def get_taxii_objects(collection_id: str):
            """Récupère les objets STIX d'une collection TAXII"""
            if "taxii" not in self.formats:
                return jsonify({"error": "Format TAXII non activé"}), 403

            # Extrait le bucket du collection_id
            if collection_id.startswith("tinycti-"):
                bucket = collection_id.replace("tinycti-", "")
                if bucket in ["live", "chaud", "tiede", "froid"]:
                    # Redirige vers l'endpoint STIX
                    return emit_stix(bucket)

            return jsonify({"error": "Collection non trouvée"}), 404

    def _create_stix_pattern(self, ioc_type: str, value: str) -> str:
        """Crée un pattern STIX selon le type d'IOC"""
        patterns = {
            "ipv4": f"[ipv4-addr:value = '{value}']",
            "ipv6": f"[ipv6-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "hash_md5": f"[file:hashes.MD5 = '{value}']",
            "hash_sha1": f"[file:hashes.SHA-1 = '{value}']",
            "hash_sha256": f"[file:hashes.SHA-256 = '{value}']",
        }
        return patterns.get(ioc_type, f"[x-custom:value = '{value}']")

    def start(self):
        """Démarre l'API d'émission"""
        if not self.enabled:
            return

        try:
            self.logger.info(f"Démarrage API d'émission sur {self.host}:{self.port}")
            self.app.run(host=self.host, port=self.port, threaded=True, debug=False)
        except Exception as e:
            self.logger.error(f"Erreur démarrage API d'émission: {e}")


# ===============================
# EXPORT POUR NGFW/FIREWALL (Legacy)
# ===============================


class NGFWExporter:
    """Exporte les IOCs dans des formats compatibles NGFW/Firewall"""

    def __init__(self, storage: IOCStorage, output_dir: str = "ngfw"):
        self.storage = storage
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(f"{__name__}.NGFWExporter")

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
            IOCType.IPV4: "malicious-ips.txt",
            IOCType.IPV6: "malicious-ipv6.txt",
            IOCType.DOMAIN: "malicious-domains.txt",
            IOCType.URL: "malicious-urls.txt",
        }

        for ioc_type, filename in ngfw_types.items():
            source_file = source_dir / f"{ioc_type.value}.txt"
            target_file = target_dir / filename

            if source_file.exists():
                try:
                    # Export NGFW: format brut sans headers (firewalls lisent ligne par ligne)
                    with open(source_file, "r") as src, open(target_file, "w") as dst:
                        ioc_count = 0
                        for line in src:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                dst.write(f"{line}\n")
                                ioc_count += 1

                    self.logger.debug(f"Export NGFW: {source_file} -> {target_file}")

                except Exception as e:
                    self.logger.error(f"Erreur export {source_file}: {e}")

    def generate_pfsense_aliases(self, bucket: RetentionBucket = RetentionBucket.LIVE):
        """Génère des alias pfSense"""
        alias_file = self.output_dir / bucket.value / "pfsense-aliases.txt"

        try:
            with open(alias_file, "w") as f:
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
                            if line and not line.startswith("#"):
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
                            if line and not line.startswith("#"):
                                f.write(f"    {line},\n")
                    f.write("}\n")

            self.logger.info(f"Alias pfSense générés: {alias_file}")

        except Exception as e:
            self.logger.error(f"Erreur génération alias pfSense: {e}")

    def generate_iptables_rules(self, bucket: RetentionBucket = RetentionBucket.LIVE):
        """Génère des règles iptables"""
        rules_file = self.output_dir / bucket.value / "iptables-rules.sh"

        try:
            with open(rules_file, "w") as f:
                f.write("#!/bin/bash\n")
                f.write("# iptables rules - TinyCTI Export\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
                f.write("# Drop malicious IPs\n")

                ip_file = self.storage.output_dir / bucket.value / "ipv4.txt"
                if ip_file.exists():
                    with open(ip_file) as ip_src:
                        for line in ip_src:
                            line = line.strip()
                            if line and not line.startswith("#"):
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

    def __init__(
        self, tinycti_instance: "TinyCTI", host: str = "127.0.0.1", port: int = 5000
    ):
        self.tinycti = tinycti_instance
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.app.secret_key = os.urandom(24)
        self.logger = logging.getLogger(f"{__name__}.TinyCTIAPI")
        self.server = None

        # Configuration d'authentification et rate limiting
        self.auth_config = self.tinycti.config.get("authentication", {})
        self.api_config = self.tinycti.config.get("api", {})

        # Setup rate limiting
        if self.api_config.get("auth", {}).get("rate_limit", {}).get("enabled", True):
            self.limiter = Limiter(
                app=self.app,
                key_func=get_remote_address,
                default_limits=[
                    f"{self.api_config.get('auth', {}).get('rate_limit', {}).get('requests_per_minute', 60)}/minute"
                ],
            )
        else:
            self.limiter = None

        # Audit logger - utilise celui configuré par LoggingConfigurator
        if hasattr(self.tinycti, "logging_configurator"):
            self.audit_logger = self.tinycti.logging_configurator.setup_audit_logger()
        else:
            self.audit_logger = None

        # Configure les routes
        self._setup_routes()

    def _log_audit(self, action: str, user: str = "anonymous", details: str = ""):
        """Log une action d'audit"""
        if self.audit_logger:
            client_ip = request.remote_addr if request else "unknown"
            message = (
                f"User: {user}, IP: {client_ip}, Action: {action}, Details: {details}"
            )
            self.audit_logger.info(message)

    def _verify_password(self, username: str, password: str) -> bool:
        """Vérifie un mot de passe utilisateur"""
        users = self.auth_config.get("users", {})
        if username not in users:
            return False

        stored_hash = users[username].get("password_hash", "")
        if not stored_hash:
            return False

        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except:
            return False

    def _require_auth(self, f):
        """Décorateur pour exiger l'authentification"""

        def decorated_function(*args, **kwargs):
            if not self.api_config.get("auth", {}).get("enabled", False):
                return f(*args, **kwargs)

            # Vérification de l'authentification par token ou session
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                if self._verify_token(token):
                    return f(*args, **kwargs)

            # Vérification de l'authentification par session
            if "authenticated" in session and session["authenticated"]:
                return f(*args, **kwargs)

            # Vérification de l'authentification par API password
            api_password = self.api_config.get("auth", {}).get("password", "")
            if api_password and request.headers.get("X-API-Password") == api_password:
                return f(*args, **kwargs)

            self._log_audit("AUTH_FAILED", details=f"Endpoint: {request.endpoint}")
            return jsonify({"error": "Authentication required"}), 401

        decorated_function.__name__ = f.__name__
        return decorated_function

    def _verify_token(self, token: str) -> bool:
        """Vérifie un token JWT"""
        try:
            jwt.decode(token, self.app.secret_key, algorithms=["HS256"])
            return True
        except:
            return False

    def _generate_token(self, username: str) -> str:
        """Génère un token JWT"""
        payload = {"username": username, "exp": datetime.now() + timedelta(hours=24)}
        return jwt.encode(payload, self.app.secret_key, algorithm="HS256")

    def _setup_routes(self):
        """Configure les routes de l'API"""

        # ===============================
        # ROUTES API JSON
        # ===============================

        @self.app.route("/api/status")
        def api_status():
            """Statut général du système"""
            try:
                status = {
                    "status": "running",
                    "version": "1.0.0",
                    "daemon_running": self.tinycti.is_daemon_running,
                    "feeds_total": len(self.tinycti.config["feeds"]),
                    "feeds_enabled": len(
                        [
                            f
                            for f in self.tinycti.config["feeds"]
                            if f.get("enabled", True)
                        ]
                    ),
                    "uptime": str(
                        datetime.now()
                        - getattr(self.tinycti, "start_time", datetime.now())
                    ),
                    "scheduler": None,
                }

                if self.tinycti.scheduler:
                    status["scheduler"] = self.tinycti.scheduler.get_status()

                return jsonify(status)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # Routes d'authentification
        @self.app.route("/api/login", methods=["POST"])
        def api_login():
            """Authentification utilisateur"""
            try:
                data = request.get_json()
                username = data.get("username", "")
                password = data.get("password", "")

                if not username or not password:
                    self._log_audit("LOGIN_FAILED", details="Missing credentials")
                    return jsonify({"error": "Username and password required"}), 400

                if self._verify_password(username, password):
                    token = self._generate_token(username)
                    session["authenticated"] = True
                    session["username"] = username
                    self._log_audit("LOGIN_SUCCESS", user=username)
                    return jsonify({"token": token, "message": "Login successful"})
                else:
                    self._log_audit(
                        "LOGIN_FAILED", user=username, details="Invalid credentials"
                    )
                    return jsonify({"error": "Invalid credentials"}), 401

            except Exception as e:
                self._log_audit("LOGIN_ERROR", details=str(e))
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/logout", methods=["POST"])
        def api_logout():
            """Déconnexion utilisateur"""
            username = session.get("username", "unknown")
            session.clear()
            self._log_audit("LOGOUT", user=username)
            return jsonify({"message": "Logout successful"})

        # Routes d'export avec authentification
        @self.app.route("/api/export/<export_type>/<ioc_type>")
        def api_export_iocs(export_type, ioc_type):
            """Export des IOCs dans différents formats"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                bucket = request.args.get("bucket", "active")

                # Validation du bucket
                valid_buckets = ["active", "critical", "watch", "archive"]
                if bucket not in valid_buckets:
                    return (
                        jsonify(
                            {
                                "error": f"Invalid bucket. Must be one of: {valid_buckets}"
                            }
                        ),
                        400,
                    )

                # Validation et parsing de la limite
                try:
                    limit = int(
                        request.args.get(
                            "limit",
                            self.api_config.get("export", {}).get("max_records", 10000),
                        )
                    )
                    if limit < 0:
                        return jsonify({"error": "Limit must be non-negative"}), 400
                    if limit > 100000:  # Limite maximale raisonnable
                        return jsonify({"error": "Limit too large"}), 400
                except ValueError:
                    return jsonify({"error": "Limit must be an integer"}), 400

                # Vérification du format d'export
                export_config = self.api_config.get("export", {})
                if export_type == "csv" and not export_config.get("csv_enabled", True):
                    return jsonify({"error": "CSV export disabled"}), 403
                elif export_type == "json" and not export_config.get(
                    "json_enabled", True
                ):
                    return jsonify({"error": "JSON export disabled"}), 403
                elif export_type == "text" and not export_config.get(
                    "text_enabled", True
                ):
                    return jsonify({"error": "Text export disabled"}), 403
                elif export_type not in ["csv", "json", "text"]:
                    return jsonify({"error": "Invalid export type"}), 400

                # Lecture des IOCs
                ioc_file = self.tinycti.storage.output_dir / bucket / f"{ioc_type}.txt"
                if not ioc_file.exists():
                    return jsonify({"error": "IOC file not found"}), 404

                iocs = []
                with open(ioc_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            iocs.append(line)
                            if len(iocs) >= limit:
                                break

                username = session.get("username", "api_user")
                self._log_audit(
                    "EXPORT",
                    user=username,
                    details=f"Type: {export_type}, IOC: {ioc_type}, Count: {len(iocs)}",
                )

                # Export selon le format demandé
                if export_type == "json":
                    return jsonify(
                        {
                            "type": ioc_type,
                            "bucket": bucket,
                            "export_format": "json",
                            "count": len(iocs),
                            "exported_at": datetime.now().isoformat(),
                            "data": iocs,
                        }
                    )

                elif export_type == "csv":
                    import io

                    from flask import make_response

                    output = io.StringIO()
                    output.write(f"# TinyCTI Export - {ioc_type} - {bucket}\n")
                    output.write(f"# Exported at: {datetime.now().isoformat()}\n")
                    output.write(f"# Count: {len(iocs)}\n")
                    output.write("ioc_value\n")

                    for ioc in iocs:
                        output.write(f"{ioc}\n")

                    response = make_response(output.getvalue())
                    response.headers["Content-Type"] = "text/csv"
                    response.headers["Content-Disposition"] = (
                        f"attachment; filename={ioc_type}_{bucket}.csv"
                    )
                    return response

                elif export_type == "text":
                    from flask import make_response

                    content = f"# TinyCTI Export - {ioc_type} - {bucket}\n"
                    content += f"# Exported at: {datetime.now().isoformat()}\n"
                    content += f"# Count: {len(iocs)}\n\n"
                    content += "\n".join(iocs)

                    response = make_response(content)
                    response.headers["Content-Type"] = "text/plain"
                    response.headers["Content-Disposition"] = (
                        f"attachment; filename={ioc_type}_{bucket}.txt"
                    )
                    return response

            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/feeds")
        def api_feeds():
            """Liste des flux configurés"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                feeds = []
                for feed in self.tinycti.config["feeds"]:
                    feed_info = {
                        "name": feed["name"],
                        "type": feed["type"],
                        "url": feed["url"],
                        "enabled": feed.get("enabled", True),
                        "retention": feed.get("retention", "live"),
                        "schedule": feed.get("schedule", "1h"),
                        "priority": feed.get("priority", 5),
                    }
                    feeds.append(feed_info)

                username = session.get("username", "api_user")
                self._log_audit("VIEW_FEEDS", user=username)
                return jsonify({"feeds": feeds})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/feeds/<feed_name>/toggle", methods=["POST"])
        def api_toggle_feed(feed_name):
            """Active/désactive un flux"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                for feed in self.tinycti.config["feeds"]:
                    if feed["name"] == feed_name:
                        old_state = feed.get("enabled", True)
                        feed["enabled"] = not old_state

                        # Sauvegarde la configuration
                        self._save_config()

                        username = session.get("username", "api_user")
                        self._log_audit(
                            "TOGGLE_FEED",
                            user=username,
                            details=f"Feed: {feed_name}, Enabled: {feed['enabled']}",
                        )

                        return jsonify(
                            {
                                "feed": feed_name,
                                "enabled": feed["enabled"],
                                "message": f"Flux {'activé' if feed['enabled'] else 'désactivé'}",
                            }
                        )

                return jsonify({"error": "Flux non trouvé"}), 404
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/feeds/<feed_name>/schedule", methods=["POST"])
        def api_update_schedule(feed_name):
            """Met à jour la planification d'un flux"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                data = request.get_json()
                schedule = data.get("schedule")
                priority = data.get("priority")

                if not schedule:
                    return jsonify({"error": "Schedule manquant"}), 400

                # Valide le format de schedule
                try:
                    parsed_duration = parse_duration(schedule)
                    if parsed_duration <= 0:
                        return jsonify({"error": "Schedule must be positive"}), 400
                except ValueError as e:
                    return jsonify({"error": f"Format de schedule invalide: {e}"}), 400

                # Met à jour la config
                for feed in self.tinycti.config["feeds"]:
                    if feed["name"] == feed_name:
                        old_schedule = feed.get("schedule", "1h")
                        old_priority = feed.get("priority", 5)

                        feed["schedule"] = schedule
                        if priority is not None:
                            try:
                                priority_int = int(priority)
                                if priority_int < 1 or priority_int > 10:
                                    return (
                                        jsonify(
                                            {
                                                "error": "Priority must be between 1 and 10"
                                            }
                                        ),
                                        400,
                                    )
                                feed["priority"] = priority_int
                            except (ValueError, TypeError):
                                return (
                                    jsonify({"error": "Priority must be an integer"}),
                                    400,
                                )

                        # Met à jour le scheduler si actif
                        if (
                            self.tinycti.scheduler
                            and feed_name in self.tinycti.scheduler.tasks
                        ):
                            task = self.tinycti.scheduler.tasks[feed_name]
                            task.interval = parse_duration(schedule)
                            if priority is not None:
                                task.priority = feed["priority"]

                        # Sauvegarde la configuration
                        self._save_config()

                        username = session.get("username", "api_user")
                        self._log_audit(
                            "UPDATE_SCHEDULE",
                            user=username,
                            details=f"Feed: {feed_name}, Schedule: {old_schedule}->{schedule}, Priority: {old_priority}->{feed.get('priority')}",
                        )

                        return jsonify(
                            {
                                "feed": feed_name,
                                "schedule": schedule,
                                "priority": feed.get("priority"),
                                "message": "Planification mise à jour",
                            }
                        )

                return jsonify({"error": "Flux non trouvé"}), 404
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/iocs/<ioc_type>")
        def api_get_iocs(ioc_type):
            """Récupère les IOCs d'un type donné"""
            try:
                bucket = request.args.get("bucket", "active")
                limit = int(request.args.get("limit", 1000))

                ioc_file = self.tinycti.storage.output_dir / bucket / f"{ioc_type}.txt"

                if not ioc_file.exists():
                    return jsonify({"iocs": [], "total": 0})

                iocs = []
                with open(ioc_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            iocs.append(line)
                            if len(iocs) >= limit:
                                break

                return jsonify(
                    {
                        "type": ioc_type,
                        "bucket": bucket,
                        "iocs": iocs,
                        "total": len(iocs),
                        "truncated": len(iocs) >= limit,
                    }
                )
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/iocs/search")
        def api_search_iocs():
            """Recherche un IOC spécifique"""
            try:
                query = request.args.get("q", "").strip()
                if not query:
                    return jsonify({"error": "Paramètre q manquant"}), 400

                results = []

                # Recherche dans tous les buckets et types
                for bucket in RetentionBucket:
                    bucket_dir = self.tinycti.storage.output_dir / bucket.value
                    for ioc_file in bucket_dir.glob("*.txt"):
                        ioc_type = ioc_file.stem

                        try:
                            with open(ioc_file, "r") as f:
                                for line_num, line in enumerate(f, 1):
                                    line = line.strip()
                                    if query.lower() in line.lower():
                                        results.append(
                                            {
                                                "ioc": line,
                                                "type": ioc_type,
                                                "bucket": bucket.value,
                                                "file": str(ioc_file),
                                                "line": line_num,
                                            }
                                        )
                        except Exception:
                            continue

                return jsonify(
                    {"query": query, "results": results, "total": len(results)}
                )
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/export/ngfw")
        def api_export_ngfw():
            """Lance l'export NGFW"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                exporter = NGFWExporter(self.tinycti.storage)
                exporter.export_all_buckets()

                username = session.get("username", "api_user")
                self._log_audit("EXPORT_NGFW", user=username)

                return jsonify({"message": "Export NGFW terminé"})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # Routes de gestion de la rétention et des doublons
        @self.app.route("/api/retention/process", methods=["POST"])
        def api_process_retention():
            """Lance le traitement de la rétention des IOCs"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                if not hasattr(self.tinycti, "retention_manager"):
                    return (
                        jsonify({"error": "Gestionnaire de rétention non disponible"}),
                        500,
                    )

                self.tinycti.retention_manager.process_transitions()

                username = session.get("username", "api_user")
                self._log_audit("RETENTION_PROCESS", user=username)

                return jsonify(
                    {"message": "Traitement de la rétention terminé avec succès"}
                )
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/retention/audit")
        def api_audit_duplicates():
            """Audit des doublons entre buckets"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                if not hasattr(self.tinycti, "retention_manager"):
                    return (
                        jsonify({"error": "Gestionnaire de rétention non disponible"}),
                        500,
                    )

                audit_result = (
                    self.tinycti.retention_manager.audit_duplicates_across_buckets()
                )

                username = session.get("username", "api_user")
                self._log_audit(
                    "RETENTION_AUDIT",
                    user=username,
                    details=f"Total doublons: {audit_result.get('total_duplicates', 0)}",
                )

                return jsonify(audit_result)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/retention/fix-duplicates", methods=["POST"])
        def api_fix_duplicates():
            """Corrige les doublons entre buckets"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                if not hasattr(self.tinycti, "retention_manager"):
                    return (
                        jsonify({"error": "Gestionnaire de rétention non disponible"}),
                        500,
                    )

                fix_result = self.tinycti.retention_manager.fix_duplicate_iocs()

                username = session.get("username", "api_user")
                self._log_audit(
                    "RETENTION_FIX",
                    user=username,
                    details=f"Doublons corrigés: {fix_result.get('fixed_count', 0)}",
                )

                return jsonify(fix_result)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route("/api/retention/stats")
        def api_retention_stats():
            """Statistiques de rétention des IOCs par bucket"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                stats = {}
                total_iocs = 0

                for bucket in RetentionBucket:
                    bucket_stats = {"types": {}, "total": 0}

                    for ioc_type in IOCType:
                        file_path = (
                            self.tinycti.storage.output_dir
                            / bucket.value
                            / f"{ioc_type.value}.txt"
                        )
                        if file_path.exists():
                            with open(file_path, "r") as f:
                                count = sum(
                                    1
                                    for line in f
                                    if line.strip() and not line.startswith("#")
                                )
                                bucket_stats["types"][ioc_type.value] = count
                                bucket_stats["total"] += count

                    stats[bucket.value] = bucket_stats
                    total_iocs += bucket_stats["total"]

                username = session.get("username", "api_user")
                self._log_audit("RETENTION_STATS", user=username)

                return jsonify(
                    {
                        "buckets": stats,
                        "total_iocs": total_iocs,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # Routes de gestion des erreurs
        @self.app.route("/api/errors/stats")
        def api_error_stats():
            """Statistiques des erreurs système"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                if (
                    not hasattr(self.tinycti, "error_handler")
                    or not self.tinycti.error_handler
                ):
                    return (
                        jsonify({"error": "Gestionnaire d'erreurs non disponible"}),
                        500,
                    )

                stats = self.tinycti.error_handler.get_error_stats()

                username = session.get("username", "api_user")
                self._log_audit("VIEW_ERROR_STATS", user=username)

                return jsonify(stats)
            except Exception as e:
                error_response = {
                    "error": "Erreur lors de la récupération des statistiques d'erreurs",
                    "details": str(e),
                }
                return jsonify(error_response), 500

        @self.app.route("/api/errors/clear", methods=["POST"])
        def api_clear_errors():
            """Vide l'historique des erreurs"""
            auth_func = self._require_auth(lambda: None)
            auth_result = auth_func()
            if auth_result is not None:
                return auth_result

            try:
                if (
                    not hasattr(self.tinycti, "error_handler")
                    or not self.tinycti.error_handler
                ):
                    return (
                        jsonify({"error": "Gestionnaire d'erreurs non disponible"}),
                        500,
                    )

                self.tinycti.error_handler.clear_error_history()

                username = session.get("username", "api_user")
                self._log_audit("CLEAR_ERROR_HISTORY", user=username)

                return jsonify({"message": "Historique des erreurs vidé avec succès"})
            except Exception as e:
                error_response = {
                    "error": "Erreur lors du vidage de l'historique",
                    "details": str(e),
                }
                return jsonify(error_response), 500

        @self.app.route("/api/health")
        def api_health_check():
            """Vérification de santé du système (endpoint public)"""
            try:
                health_status = {
                    "status": "healthy",
                    "timestamp": datetime.now().isoformat(),
                    "version": "1.0.0",
                    "uptime_seconds": int(
                        (
                            datetime.now()
                            - getattr(self.tinycti, "start_time", datetime.now())
                        ).total_seconds()
                    ),
                    "components": {},
                }

                # Vérification du storage
                try:
                    if self.tinycti.storage and self.tinycti.storage.db_path.exists():
                        health_status["components"]["storage"] = "healthy"
                    else:
                        health_status["components"]["storage"] = "unhealthy"
                        health_status["status"] = "degraded"
                except Exception:
                    health_status["components"]["storage"] = "unhealthy"
                    health_status["status"] = "degraded"

                # Vérification du scheduler
                try:
                    if self.tinycti.scheduler:
                        health_status["components"]["scheduler"] = "healthy"
                    else:
                        health_status["components"]["scheduler"] = "inactive"
                except Exception:
                    health_status["components"]["scheduler"] = "unhealthy"
                    health_status["status"] = "degraded"

                # Vérification de l'exporteur NGFW
                try:
                    if self.tinycti.ngfw_exporter:
                        health_status["components"]["ngfw_exporter"] = "healthy"
                    else:
                        health_status["components"]["ngfw_exporter"] = "inactive"
                except Exception:
                    health_status["components"]["ngfw_exporter"] = "unhealthy"
                    health_status["status"] = "degraded"

                # Ajoute les statistiques d'erreurs si disponibles
                if (
                    hasattr(self.tinycti, "error_handler")
                    and self.tinycti.error_handler
                ):
                    try:
                        error_stats = self.tinycti.error_handler.get_error_stats()
                        health_status["error_summary"] = {
                            "total_errors": error_stats.get("total_errors", 0),
                            "critical_errors": len(
                                error_stats.get("critical_errors", [])
                            ),
                        }
                    except Exception as e:
                        self.logger.warning(
                            f"Erreur lors de la récupération des stats d'erreur: {e}"
                        )
                        health_status["error_summary"] = {
                            "total_errors": 0,
                            "critical_errors": 0,
                        }

                    # Marque comme dégradé s'il y a des erreurs critiques récentes
                    try:
                        critical_errors = error_stats.get("critical_errors", [])
                        recent_critical = [
                            e
                            for e in critical_errors
                            if (
                                datetime.now() - datetime.fromisoformat(e["timestamp"])
                            ).seconds
                            < 300
                        ]  # 5 min
                        if recent_critical:
                            health_status["status"] = "degraded"
                    except Exception:
                        # Ignore les erreurs lors de l'analyse des erreurs critiques récentes
                        pass

                # Détermine le code de statut HTTP selon l'état
                status_code = 200 if health_status["status"] == "healthy" else 503

                return jsonify(health_status), status_code

            except Exception as e:
                return (
                    jsonify(
                        {
                            "status": "unhealthy",
                            "error": "Health check failed",
                            "details": str(e),
                            "timestamp": datetime.now().isoformat(),
                        }
                    ),
                    503,
                )

        # ===============================
        # INTERFACE WEB DE GESTION
        # ===============================

        @self.app.route("/")
        def dashboard():
            """Interface principale de gestion"""
            return render_template_string(DASHBOARD_TEMPLATE)

        @self.app.route("/feeds")
        def feeds_page():
            """Page de gestion des flux"""
            return render_template_string(FEEDS_TEMPLATE)

        @self.app.route("/iocs")
        def iocs_page():
            """Page de consultation des IOCs"""
            return render_template_string(IOCS_TEMPLATE)

    def _save_config(self):
        """Sauvegarde la configuration modifiée"""
        try:
            with open(self.tinycti.config_file, "w") as f:
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
            <h1> TinyCTI Dashboard</h1>
            <p>Framework modulaire de collecte d'IOCs</p>
        </div>
        
        <div class="cards">
            <div class="card">
                <h3>Statut Système</h3>
                <div id="system-status">Chargement...</div>
            </div>
            
            <div class="card">
                <h3>Actions Rapides</h3>
                <a href="/feeds" class="btn">Gérer les Flux</a>
                <a href="/iocs" class="btn">Consulter IOCs</a>
                <a href="#" onclick="exportNGFW()" class="btn">Export NGFW</a>
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
                <option value="active">Active</option>
                <option value="critical">Critical</option>
                <option value="watch">Watch</option>
                <option value="archive">Archive</option>
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
                
                if (data.error) {
                    throw new Error(data.error);
                }
                
                // Affiche les stats
                const statsDiv = document.getElementById('ioc-stats');
                statsDiv.innerHTML = `
                    <div class="stat-card">
                        <h4>Type</h4>
                        <p>${data.type ? data.type.toUpperCase() : 'N/A'}</p>
                    </div>
                    <div class="stat-card">
                        <h4>Bucket</h4>
                        <p>${data.bucket ? data.bucket.toUpperCase() : 'N/A'}</p>
                    </div>
                    <div class="stat-card">
                        <h4>Total IOCs</h4>
                        <p>${data.total || 0}</p>
                    </div>
                    <div class="stat-card">
                        <h4>Affichés</h4>
                        <p>${Math.min(data.total || 0, 500)}</p>
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
                console.error('Erreur chargement IOCs:', error);
                const statsDiv = document.getElementById('ioc-stats');
                const contentDiv = document.getElementById('ioc-content');
                statsDiv.innerHTML = '<div class="stat-card error"><h4>Erreur</h4><p>Échec du chargement</p></div>';
                contentDiv.innerHTML = `<p class="error">Erreur: ${error.message}</p>`;
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
    def parse_duration_legacy(duration_str: str) -> int:
        """Convertit une durée en secondes (ex: '30m', '2h', '1d')"""
        if not duration_str:
            return 3600  # 1h par défaut

        duration_str = duration_str.lower().strip()

        # Patterns de durée
        patterns = {
            r"(\d+)s": 1,  # secondes
            r"(\d+)m": 60,  # minutes
            r"(\d+)h": 3600,  # heures
            r"(\d+)d": 86400,  # jours
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
        self.logger = logging.getLogger(f"{__name__}.FeedScheduler")
        self.is_running = False
        self._stop_event = threading.Event()

        # Configuration du daemon
        daemon_config = config.get("daemon", {})
        try:
            self.check_interval = parse_duration(
                daemon_config.get("check_interval", "60s")
            )
        except ValueError:
            self.check_interval = 60  # 60 secondes par défaut
        max_concurrent_raw = daemon_config.get("max_concurrent_feeds", 3)
        try:
            self.max_concurrent = int(max_concurrent_raw)
            if self.max_concurrent < 1:
                self.max_concurrent = 1
        except (ValueError, TypeError):
            self.logger.warning(
                f"Invalid max_concurrent_feeds value: {max_concurrent_raw}, using default 3"
            )
            self.max_concurrent = 3
        self.default_schedule = daemon_config.get("default_schedule", "1h")

        # Semaphore pour limiter les tâches concurrentes
        self._semaphore = threading.Semaphore(self.max_concurrent)
        self._initialize_tasks()

    def _initialize_tasks(self):
        """Initialise les tâches depuis la configuration"""
        for feed in self.config["feeds"]:
            if not feed.get("enabled", True):
                continue

            feed_name = feed["name"]
            schedule = feed.get("schedule", self.default_schedule)
            priority = feed.get("priority", 5)

            try:
                interval = parse_duration(schedule)
            except ValueError:
                interval = 3600  # 1 heure par défaut
                self.logger.warning(f"Schedule invalide pour {feed_name}: {schedule}, utilisation de 1h par défaut")

            # Étale les premières exécutions pour éviter les pics
            initial_delay = random.randint(0, min(interval // 4, 300))  # Max 5min
            next_run = datetime.now() + timedelta(seconds=initial_delay)

            task = ScheduledTask(
                feed_name=feed_name,
                next_run=next_run,
                interval=interval,
                priority=priority,
            )

            self.tasks[feed_name] = task
            self.logger.info(
                f"Tâche planifiée: {feed_name} - "
                f"Intervalle: {schedule} ({interval}s) - "
                f"Priorité: {priority} - "
                f"Première exécution: {next_run.strftime('%H:%M:%S')}"
            )

    def get_ready_tasks(self) -> List[ScheduledTask]:
        """Retourne les tâches prêtes à être exécutées, triées par priorité"""
        ready_tasks = [task for task in self.tasks.values() if task.should_run()]

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
                self.logger.debug(
                    f"Tâche {feed_name} terminée avec succès, prochaine exécution: {task.next_run.strftime('%H:%M:%S')}"
                )
            else:
                task.consecutive_errors += 1
                # Backoff exponentiel en cas d'erreurs répétées
                delay_multiplier = min(2**task.consecutive_errors, 16)  # Max 16x
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
            "total_tasks": len(self.tasks),
            "running_tasks": sum(1 for t in self.tasks.values() if t.is_running),
            "ready_tasks": len(self.get_ready_tasks()),
            "next_execution": self.get_next_execution_time(),
            "tasks": {
                name: {
                    "next_run": task.next_run,
                    "interval": task.interval,
                    "priority": task.priority,
                    "is_running": task.is_running,
                    "consecutive_errors": task.consecutive_errors,
                    "seconds_until_next": max(
                        0, int((task.next_run - now).total_seconds())
                    ),
                }
                for name, task in self.tasks.items()
            },
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

    def __init__(
        self,
        config_file: Union[str, Dict] = "config.yaml",
        log_level: Optional[int] = None,
    ):
        self.log_level = log_level
        self.logger = logging.getLogger(f"{__name__}.TinyCTI")

        # Gère les deux types de configuration: fichier ou dictionnaire
        if isinstance(config_file, dict):
            # Configuration directe depuis dictionnaire (pour les tests)
            self.config_file = None
            self.config = config_file
            self.config_loader = None
        else:
            # Configuration depuis fichier (mode normal)
            self.config_file = config_file
            self.config_loader = ConfigurationLoader(config_file)
            try:
                self.config = self.config_loader.load_config()
            except Exception as e:
                self.logger.error(f"Erreur lors du chargement de la configuration: {e}")
                raise ConfigurationError(
                    f"Échec du chargement de la configuration: {e}"
                ) from e

        # Initialise les composants de sécurité et performance
        self.security_validator = SecurityValidator()
        self.performance_monitor = PerformanceMonitor()
        self.rate_limiter = RateLimiter()
        self.session_manager = None  # Initialisé plus tard avec la clé secrète

        # Configuration sécurisée
        self._setup_security()

        # Initialise les composants
        self.api_manager = APIKeyManager()
        self.plugin_manager = PluginManager(self.api_manager)
        self.scheduler = None

        # Initialise le gestionnaire d'erreurs (sera configuré après le logging)
        self.error_handler = None

        # État du daemon
        self._daemon_lock = threading.Lock()
        self._is_daemon_running = False
        self._stop_event = threading.Event()
        self.start_time = datetime.now()

        # API et export
        self.api_server = None
        self.ngfw_exporter = None

        try:
            # Configure le système de logging avancé
            self.logging_configurator = LoggingConfigurator(self.config, self.log_level)
            self.logging_configurator.setup_main_logger()

            # Re-configure le logger de cette classe avec le nouveau système
            self.logger = logging.getLogger(f"{__name__}.TinyCTI")
            self.logger.info(
                "Système de logging avancé configuré avec rotation et compression"
            )

            # Initialise le gestionnaire d'erreurs avec le nouveau logger
            self.error_handler = ErrorHandler(self.logger)
            self.logger.info("Gestionnaire d'erreurs centralisé initialisé")

            self.storage = IOCStorage(
                self.config["output_dir"], self.config.get("max_file_size", 10485760)
            )
            self._setup_api_keys()

            # Initialise le gestionnaire de rétention
            retention_policy = self.config.get("retention_policy", {})
            self.retention_manager = RetentionManager(
                retention_policy, self.storage, self.logger
            )
            self.logger.info("Gestionnaire de rétention initialisé")

            # Initialise le planificateur si mode daemon
            daemon_config = self.config.get("daemon", {})
            if daemon_config.get("enabled", False):
                self.scheduler = FeedScheduler(self.config)

            # Initialise l'exporteur NGFW
            self.ngfw_exporter = NGFWExporter(self.storage)

            # Initialise l'API de gestion web si configurée
            api_config = self.config.get("api", {})
            if api_config.get("enabled", False):
                host = api_config.get("host", "127.0.0.1")
                port = api_config.get("port", 5000)
                self.api_server = TinyCTIAPI(self, host, port)

            # Initialise l'API interne d'exposition de fichiers
            self.internal_api = InternalFileAPI(self.storage, self.config)
            if self.internal_api.enabled:
                self.logger.info(
                    f"API interne configurée sur {self.internal_api.host}:{self.internal_api.port}"
                )

        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation: {e}")
            raise

    @property
    def is_daemon_running(self) -> bool:
        """Thread-safe getter for daemon running status"""
        with self._daemon_lock:
            return self._is_daemon_running

    @is_daemon_running.setter
    def is_daemon_running(self, value: bool):
        """Thread-safe setter for daemon running status"""
        with self._daemon_lock:
            self._is_daemon_running = value

    def _setup_security(self):
        """Configure les composants de sécurité"""
        try:
            # Configuration du gestionnaire de sessions sécurisées
            secret_key = os.environ.get("SECRET_KEY") or self.config.get("api", {}).get(
                "secret_key"
            )
            if secret_key and len(secret_key) >= 32:
                self.session_manager = SecureSessionManager(secret_key)
                self.logger.info("Gestionnaire de sessions sécurisées initialisé")
            else:
                self.logger.warning(
                    "Clé secrète faible ou manquante - génération automatique"
                )
                auto_key = secrets.token_urlsafe(64)
                self.session_manager = SecureSessionManager(auto_key)

            # Configuration des limites de mémoire
            max_memory = self.config.get("performance", {}).get("memory_limit", "1GB")
            if isinstance(max_memory, str):
                if max_memory.endswith("GB"):
                    max_memory_mb = int(max_memory[:-2]) * 1024
                elif max_memory.endswith("MB"):
                    max_memory_mb = int(max_memory[:-2])
                else:
                    max_memory_mb = 1024  # Default 1GB
            else:
                max_memory_mb = int(max_memory)

            self.performance_monitor.memory_manager.max_memory_mb = max_memory_mb

            # Configuration des seuils GC
            gc_threshold = self.config.get("performance", {}).get("gc_threshold", 10000)
            self.performance_monitor.memory_manager.gc_threshold = gc_threshold

            self.logger.info(
                f"Sécurité configurée - Limite mémoire: {max_memory_mb}MB, Seuil GC: {gc_threshold}"
            )

        except Exception as e:
            self.logger.error(f"Erreur lors de la configuration sécurisée: {e}")
            # Continue avec les valeurs par défaut
            self.session_manager = SecureSessionManager(secrets.token_urlsafe(64))

    def _setup_api_keys(self):
        """Configure les clés API pour chaque flux"""
        for feed in self.config["feeds"]:
            api_keys = feed.get("api_keys", [])
            if api_keys:
                self.api_manager.add_keys(feed["name"], api_keys)

    def run(self, daemon_mode: bool = None):
        """Lance la collecte (mode one-shot ou daemon)"""
        # Détermine le mode d'exécution
        if daemon_mode is None:
            daemon_mode = self.config.get("daemon", {}).get("enabled", False)

        if daemon_mode:
            self.run_daemon()
        else:
            self.run_once()

    def run_once(self):
        """Exécution unique de tous les flux activés"""
        start_time = time.time()

        # Statistiques globales
        global_stats = {
            "feeds_total": 0,
            "feeds_enabled": 0,
            "feeds_success": 0,
            "feeds_error": 0,
            "total_iocs": 0,
            "new_iocs": 0,
            "duplicates": 0,
            "errors": 0,
        }

        self.logger.info("=" * 50)
        self.logger.info("Début de la collecte TinyCTI (mode one-shot)")
        self.logger.info("=" * 50)

        # Filtre les flux activés
        enabled_feeds = [
            feed for feed in self.config["feeds"] if feed.get("enabled", True)
        ]
        global_stats["feeds_total"] = len(self.config["feeds"])
        global_stats["feeds_enabled"] = len(enabled_feeds)

        if not enabled_feeds:
            self.logger.warning("Aucun flux activé dans la configuration")
            return

        self.logger.info(f"Traitement de {len(enabled_feeds)} flux activés")

        # Traitement des flux
        if self.config.get("parallel_feeds", False):
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
            "start_time": datetime.now(),
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "total_iocs_collected": 0,
        }

        # Affiche la planification initiale
        self._log_scheduler_status()

        # Démarre l'API de gestion en arrière-plan si configurée
        api_thread = None
        if self.api_server:
            api_thread = threading.Thread(target=self.api_server.start, daemon=True)
            api_thread.start()
            self.logger.info("API de gestion TinyCTI démarrée en arrière-plan")

        # Démarre l'API interne d'exposition de fichiers si configurée
        internal_api_thread = None
        if hasattr(self, "internal_api") and self.internal_api.enabled:
            internal_api_thread = threading.Thread(
                target=self.internal_api.start, daemon=True
            )
            internal_api_thread.start()
            self.logger.info("API interne d'exposition démarrée en arrière-plan")

        try:
            while not self._stop_event.is_set():
                # Vérifie les tâches prêtes
                ready_tasks = self.scheduler.get_ready_tasks()

                if ready_tasks:
                    self.logger.info(f"{len(ready_tasks)} flux prêts pour exécution")

                    # Limite le nombre de tâches concurrentes
                    max_concurrent = self.config.get("daemon", {}).get(
                        "max_concurrent_feeds", 3
                    )
                    tasks_to_run = ready_tasks[:max_concurrent]

                    # Lance les tâches
                    if len(tasks_to_run) == 1:
                        # Exécution séquentielle pour une seule tâche
                        task = tasks_to_run[0]
                        success = self._execute_scheduled_task(task)
                        daemon_stats["total_executions"] += 1
                        if success:
                            daemon_stats["successful_executions"] += 1
                        else:
                            daemon_stats["failed_executions"] += 1
                    else:
                        # Exécution parallèle pour plusieurs tâches
                        self._execute_tasks_parallel(tasks_to_run, daemon_stats)

                # Attend avant la prochaine vérification
                wait_time = min(self.scheduler.check_interval, 60)  # Max 1 minute
                if self._stop_event.wait(wait_time):
                    break

                # Affiche le statut périodiquement
                if (
                    daemon_stats["total_executions"] % 10 == 0
                    and daemon_stats["total_executions"] > 0
                ):
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
        for feed in self.config["feeds"]:
            if feed["name"] == feed_name:
                feed_config = feed
                break

        if not feed_config or not feed_config.get("enabled", True):
            self.logger.warning(f"Flux {feed_name} introuvable ou désactivé")
            self.scheduler.mark_task_completed(feed_name, False)
            return False

        # Marque la tâche comme en cours
        self.scheduler.mark_task_running(feed_name, True)

        try:
            self.logger.info(f"Exécution planifiée: {feed_name}")

            # Rate limiting si configuré
            rate_limit = feed_config.get("rate_limit", 0)
            if rate_limit > 0:
                self.logger.debug(
                    f"Rate limiting: attente {rate_limit}s avant {feed_name}"
                )
                time.sleep(rate_limit)

            # Traite le flux
            feed_stats = self._process_single_feed(feed_config, {})

            # Détermine le succès
            success = feed_stats.get("feeds_success", 0) > 0

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
                daemon_stats["total_executions"] += 1

                try:
                    success = future.result()
                    if success:
                        daemon_stats["successful_executions"] += 1
                    else:
                        daemon_stats["failed_executions"] += 1

                except Exception as e:
                    daemon_stats["failed_executions"] += 1
                    self.logger.error(f"Erreur dans la tâche {task.feed_name}: {e}")

    def _log_scheduler_status(self):
        """Affiche le statut du planificateur"""
        if not self.scheduler:
            return

        status = self.scheduler.get_status()
        self.logger.info(f"Planificateur initialisé: {status['total_tasks']} tâches")

        next_exec = status.get("next_execution")
        if next_exec:
            self.logger.info(
                f"Prochaine exécution: {next_exec.strftime('%Y-%m-%d %H:%M:%S')}"
            )

        # Affiche le détail des tâches
        for name, task_info in status["tasks"].items():
            self.logger.info(
                f"  {name}: priorité {task_info['priority']}, "
                f"dans {task_info['seconds_until_next']}s"
            )

    def _log_daemon_stats(self, stats: Dict):
        """Affiche les statistiques du daemon"""
        uptime = datetime.now() - stats["start_time"]
        success_rate = 0
        if stats["total_executions"] > 0:
            success_rate = (
                stats["successful_executions"] / stats["total_executions"]
            ) * 100

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
            ngfw_config = self.config.get("ngfw_export", {})
            if not ngfw_config.get("enabled", True):
                return

            if not ngfw_config.get("auto_export_after_collection", True):
                return

            self.logger.info("Début de l'export automatique NGFW")

            # Export standard
            self.ngfw_exporter.export_all_buckets()

            # Génération des alias pfSense si demandé
            if ngfw_config.get("generate_pfsense_aliases", True):
                self.ngfw_exporter.generate_pfsense_aliases(RetentionBucket.LIVE)

            # Génération des règles iptables si demandé
            if ngfw_config.get("generate_iptables_rules", True):
                self.ngfw_exporter.generate_iptables_rules(RetentionBucket.LIVE)

            self.logger.info("Export automatique NGFW terminé")

        except Exception as e:
            self.logger.error(f"Erreur lors de l'export automatique NGFW: {e}")

    def start_api_server(self, background: bool = True):
        """Démarre le serveur API de gestion web"""
        if not self.api_server:
            api_config = self.config.get("api", {})
            host = api_config.get("host", "127.0.0.1")
            port = api_config.get("port", 5000)
            self.api_server = TinyCTIAPI(self, host, port)

        if background:
            api_thread = threading.Thread(target=self.api_server.start, daemon=True)
            api_thread.start()
            self.logger.info(
                f"API de gestion démarrée en arrière-plan sur http://{self.api_server.host}:{self.api_server.port}"
            )
        else:
            self.api_server.start()

    def start_internal_api(self, background: bool = True):
        """Démarre l'API interne d'exposition de fichiers"""
        if not hasattr(self, "internal_api") or not self.internal_api.enabled:
            return

        if background:
            internal_api_thread = threading.Thread(
                target=self.internal_api.start, daemon=True
            )
            internal_api_thread.start()
            self.logger.info(
                f"API interne démarrée en arrière-plan sur http://{self.internal_api.host}:{self.internal_api.port}"
            )
        else:
            self.internal_api.start()

    def manual_export_ngfw(self, bucket: str = "critical"):
        """Export manuel NGFW"""
        try:
            # Conversion string vers enum avec mapping
            bucket_mapping = {
                "active": RetentionBucket.CHAUD,
                "critical": RetentionBucket.LIVE,
                "watch": RetentionBucket.TIEDE,
                "archive": RetentionBucket.FROID,
                "live": RetentionBucket.LIVE,
                "chaud": RetentionBucket.CHAUD,
                "tiede": RetentionBucket.TIEDE,
                "froid": RetentionBucket.FROID,
            }
            bucket_enum = bucket_mapping.get(bucket, RetentionBucket.LIVE)
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
        max_workers = min(self.config.get("max_workers", 4), len(feeds))

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
                    for key in [
                        "feeds_success",
                        "feeds_error",
                        "total_iocs",
                        "new_iocs",
                        "duplicates",
                        "errors",
                    ]:
                        if key in feed_stats:
                            global_stats[key] += feed_stats[key]
                except Exception as e:
                    self.logger.error(
                        f"Erreur lors du traitement du flux {feed['name']}: {e}"
                    )
                    global_stats["feeds_error"] += 1

    def _process_single_feed(self, feed_config: Dict, stats: Dict) -> Dict:
        """Traite un flux unique"""
        feed_name = feed_config["name"]
        feed_stats = {
            "feeds_success": 0,
            "feeds_error": 0,
            "total_iocs": 0,
            "new_iocs": 0,
            "duplicates": 0,
            "errors": 0,
        }

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
            feed_stats.update(
                {
                    "feeds_success": 1,
                    "total_iocs": storage_stats["total"],
                    "new_iocs": storage_stats["new"],
                    "duplicates": storage_stats["duplicates"],
                    "errors": storage_stats["errors"],
                }
            )

            # Statistiques du plugin
            plugin_stats = plugin.get_stats()

            # Durée de traitement
            duration = time.time() - feed_start_time

            self.logger.info(
                f"Flux {feed_name} terminé en {duration:.2f}s: "
                f"{storage_stats['new']} nouveaux IOCs, "
                f"{storage_stats['duplicates']} doublons, "
                f"{storage_stats['errors']} erreurs"
                f"{plugin_stats} 'plugin_stats'"
            )

            if storage_stats["errors"] > 0:
                self.logger.warning(
                    f"Erreurs lors du stockage pour {feed_name}: {storage_stats['errors']}"
                )

        except PluginError as e:
            feed_stats["feeds_error"] = 1
            self.logger.error(f"Erreur de plugin pour {feed_name}: {e}")

        except Exception as e:
            feed_stats["feeds_error"] = 1
            self.logger.error(f"Erreur inattendue pour {feed_name}: {e}")
            self.logger.debug(f"Stack trace: {traceback.format_exc()}")

        # Met à jour les stats globales
        for key, value in feed_stats.items():
            stats[key] = stats.get(key, 0) + value

        return feed_stats

    def get_security_status(self) -> Dict[str, Any]:
        """Retourne le statut de sécurité du système"""
        try:
            memory_stats = self.performance_monitor.memory_manager.get_memory_usage()

            security_status = {
                "session_manager_active": self.session_manager is not None,
                "rate_limiter_active": self.rate_limiter is not None,
                "security_validator_active": self.security_validator is not None,
                "memory_usage_mb": memory_stats["rss_mb"],
                "memory_limit_mb": self.performance_monitor.memory_manager.max_memory_mb,
                "memory_within_limits": memory_stats["rss_mb"]
                < self.performance_monitor.memory_manager.max_memory_mb,
                "active_sessions": (
                    len(self.session_manager.sessions) if self.session_manager else 0
                ),
                "blocked_ips": len(self.rate_limiter.blocked_ips),
                "failed_attempts": len(self.rate_limiter.failed_attempts),
                "last_security_check": datetime.now().isoformat(),
            }

            return security_status

        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération du statut sécurité: {e}")
            return {"error": str(e)}

    def get_performance_status(self) -> Dict[str, Any]:
        """Retourne le statut de performance du système"""
        try:
            return self.performance_monitor.get_performance_stats()
        except Exception as e:
            self.logger.error(
                f"Erreur lors de la récupération du statut performance: {e}"
            )
            return {"error": str(e)}

    def optimize_memory(self) -> Dict[str, Any]:
        """Optimise la mémoire manuellement"""
        try:
            self.logger.info("Optimisation mémoire démarrée")
            result = self.performance_monitor.memory_manager.optimize_memory()
            self.logger.info(
                f"Optimisation terminée - {result.get('memory_freed_mb', 0):.2f}MB libérés"
            )
            return result
        except Exception as e:
            self.logger.error(f"Erreur lors de l'optimisation mémoire: {e}")
            return {"error": str(e)}

    def validate_ioc_security(self, value: str, ioc_type: str) -> bool:
        """Valide la sécurité d'un IOC avant traitement"""
        try:
            # Validation de base
            if not self.security_validator.validate_ioc_value(value, ioc_type):
                self.logger.warning(f"IOC invalide détecté: {value} (type: {ioc_type})")
                return False

            # Vérifications de sécurité supplémentaires
            if len(value) > 2048:  # Limite de sécurité
                self.logger.warning(f"IOC trop long détecté: {len(value)} caractères")
                return False

            # Détection de patterns suspects
            suspicious_patterns = [
                r"<script.*?>",  # Scripts potentiels
                r"javascript:",  # URLs JavaScript
                r"data:.*base64",  # Data URLs base64
                r"\\x[0-9a-fA-F]{2}",  # Encodage hexadécimal
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    self.logger.warning(
                        f"Pattern suspect détecté dans l'IOC: {pattern}"
                    )
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Erreur lors de la validation sécurité IOC: {e}")
            return False

    def get_memory_report(self) -> str:
        """Génère un rapport détaillé de mémoire"""
        try:
            return self.performance_monitor.memory_manager.get_memory_report()
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du rapport mémoire: {e}")
            return f"Erreur: {e}"

    def check_rate_limit(self, ip: str, endpoint: str = "default") -> bool:
        """Vérifie les limites de débit pour une IP"""
        try:
            return self.rate_limiter.is_allowed(ip, endpoint)
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification rate limit: {e}")
            return False  # Bloque en cas d'erreur par sécurité

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

        if stats["errors"] > 0:
            self.logger.warning(f"Erreurs de stockage: {stats['errors']}")

        # Taux de réussite
        if stats["feeds_enabled"] > 0:
            success_rate = (stats["feeds_success"] / stats["feeds_enabled"]) * 100
            self.logger.info(f"Taux de réussite: {success_rate:.1f}%")


def main():
    """Point d'entrée principal"""
    import argparse

    parser = argparse.ArgumentParser(
        description="TinyCTI - Framework modulaire léger de collecte d'IOCs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python tinycti.py                    # Exécution selon config.yaml (daemon/oneshot)
  python tinycti.py -c myconfig.yaml   # Configuration spécifique
  python tinycti.py --once             # Force mode one-shot (ignore config daemon)
  python tinycti.py --export-ngfw      # Export NGFW manuel
  python tinycti.py --validate-config  # Valide la configuration
  python tinycti.py --analyze-csv FEED # Analyse structure d'un flux CSV
  python tinycti.py --status           # Affiche le statut
  python tinycti.py --debug            # Mode debug complet

Note: Les modes daemon et API sont configurés dans config.yaml
        """,
    )

    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Fichier de configuration YAML (défaut: config.yaml)",
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Force le mode one-shot (ignore la config daemon)",
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Affiche le statut du système et quitte",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Mode verbeux (niveau INFO)"
    )

    parser.add_argument(
        "--debug", action="store_true", help="Mode debug complet (niveau DEBUG)"
    )

    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Valide uniquement la configuration et quitte",
    )

    parser.add_argument(
        "--export-ngfw",
        action="store_true",
        help="Lance un export NGFW manuel et quitte",
    )

    parser.add_argument(
        "--analyze-csv",
        metavar="FEED_NAME",
        help="Analyse la structure d'un flux CSV et suggère une configuration",
    )

    parser.add_argument("--version", action="version", version="TinyCTI 1.0.0")

    args = parser.parse_args()

    # Validation des arguments CLI
    def validate_cli_args(args):
        """Valide la cohérence des arguments CLI"""
        errors = []
        
        # Vérifier les conflits d'arguments
        if args.status and args.once:
            errors.append("--status ne peut pas être combiné avec --once")
            
        if args.export_ngfw and args.once:
            errors.append("--export-ngfw ne peut pas être combiné avec --once")
            
        if args.validate_config and args.once:
            errors.append("--validate-config ne peut pas être combiné avec --once")
        
        if errors:
            print("❌ Erreurs de validation des arguments:")
            for error in errors:
                print(f"   • {error}")
            print("\nUtilisez --help pour voir les combinaisons valides.")
            sys.exit(1)
    
    validate_cli_args(args)

    # Configuration des logs - sera remplacée par LoggingConfigurator lors de l'initialisation TinyCTI
    # Configuration temporaire pour les messages d'initialisation
    log_level = logging.WARNING
    if args.debug:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO

    # Configuration basique temporaire
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Supprime les logs verbeux des bibliothèques externes
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

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
        tinycti_instance = TinyCTI(args.config, log_level)

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
            for feed in tinycti_instance.config["feeds"]:
                if feed["name"] == args.analyze_csv:
                    feed_config = feed
                    break

            if not feed_config:
                print(
                    f"Erreur: Flux '{args.analyze_csv}' non trouvé dans la configuration"
                )
                sys.exit(1)

            if feed_config["type"] != "csv":
                print(f"Erreur: Le flux '{args.analyze_csv}' n'est pas de type CSV")
                sys.exit(1)

            try:
                # Crée le plugin CSV pour analyse
                csv_plugin = CSVPlugin(
                    feed_config, args.analyze_csv, tinycti_instance.api_manager
                )
                analysis = csv_plugin.analyze_csv_structure()

                print("\n=== Analyse de la Structure CSV ===")
                print(f"Lignes analysées: {analysis.get('total_lines', 'N/A')}")
                print(f"Délimiteur: '{analysis.get('delimiter', 'N/A')}'")
                print(f"En-tête: {analysis.get('has_header', 'N/A')}")
                print(
                    f"Colonnes: {analysis.get('min_columns', 'N/A')}-{analysis.get('max_columns', 'N/A')}"
                )
                print(
                    f"Structure cohérente: {analysis.get('consistent_structure', 'N/A')}"
                )

                if "header" in analysis:
                    print("\nEn-têtes détectés:")
                    for i, header in enumerate(analysis["header"]):
                        print(f"  {i}: {header}")

                print("\nAnalyse des colonnes:")
                for col in analysis.get("columns", []):
                    print(f"  Colonne {col['index']} ('{col['name']}'):")
                    print(
                        f"    IOCs détectés: {col['ioc_count']}/{col['total_values']} ({col['ioc_percentage']:.1f}%)"
                    )
                    if col["ioc_types"]:
                        print(f"    Types: {', '.join(col['ioc_types'])}")
                    if col["sample_values"]:
                        print(f"    Échantillon: {col['sample_values'][:3]}")
                    print()

                print("=== Recommandations ===")
                for rec in analysis.get("recommendations", []):
                    print(f"• {rec}")

                if "error" in analysis:
                    print(f"Erreur d'analyse: {analysis['error']}")

                print("\n=== Configuration Suggérée ===")
                best_col = max(
                    analysis.get("columns", []),
                    key=lambda c: c["ioc_percentage"],
                    default=None,
                )
                if best_col:
                    print(
                        f"column: {best_col['index']}  # ou '{best_col['name']}' par nom"
                    )
                    if best_col["ioc_percentage"] > 80:
                        print(
                            "auto_detect_column: false  # Colonne clairement identifiée"
                        )
                    else:
                        print("auto_detect_column: true   # Utilise l'auto-détection")

                if not analysis.get("consistent_structure", True):
                    print("skip_malformed_lines: true  # Ignore les lignes incomplètes")
                    print(
                        f"min_columns: {analysis.get('min_columns', 1)}  # Minimum de colonnes requis"
                    )

            except Exception as e:
                print(f"Erreur lors de l'analyse: {e}")
                sys.exit(1)

            sys.exit(0)


        # Affichage du statut du planificateur
        if args.status:
            if tinycti_instance.scheduler:
                status = tinycti_instance.scheduler.get_status()
                print("\n=== Statut du Planificateur TinyCTI ===")
                print(f"Tâches totales: {status['total_tasks']}")
                print(f"Tâches en cours: {status['running_tasks']}")
                print(f"Tâches prêtes: {status['ready_tasks']}")

                if status["next_execution"]:
                    print(
                        f"Prochaine exécution: {status['next_execution'].strftime('%Y-%m-%d %H:%M:%S')}"
                    )

                print("\nDétail des tâches:")
                for name, task_info in status["tasks"].items():
                    status_str = (
                        "🔄 EN COURS" if task_info["is_running"] else "⏳ EN ATTENTE"
                    )
                    print(f"  {name}: {status_str}")
                    print(f"    Priorité: {task_info['priority']}")
                    print(
                        f"    Prochaine exécution: dans {task_info['seconds_until_next']}s"
                    )
                    if task_info["consecutive_errors"] > 0:
                        print(
                            f"    Erreurs consécutives: {task_info['consecutive_errors']}"
                        )
            else:
                print("Planificateur non configuré (mode daemon désactivé)")

            sys.exit(0)

        # Détermine le mode d'exécution basé sur la config et les arguments
        daemon_config = tinycti_instance.config.get("daemon", {})
        api_config = tinycti_instance.config.get("api", {})
        
        # --once force le mode one-shot même si daemon est configuré
        if args.once:
            daemon_mode = False
            print("🔄 Mode one-shot forcé (--once)")
        else:
            # Utilise la configuration
            daemon_mode = daemon_config.get("enabled", False)
            
        # Affiche le mode déterminé
        if daemon_mode and api_config.get("enabled", False):
            api_host = api_config.get("host", "127.0.0.1")
            api_port = api_config.get("port", 5000)
            print(f"🚀 Mode daemon + API selon config - http://{api_host}:{api_port}")
        elif daemon_mode:
            print("🔄 Mode daemon selon config")
        elif api_config.get("enabled", False):
            api_host = api_config.get("host", "127.0.0.1")
            api_port = api_config.get("port", 5000)
            print(f"🌐 Mode API seul selon config - http://{api_host}:{api_port}")
        else:
            print("⚡ Mode one-shot selon config")
            
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
