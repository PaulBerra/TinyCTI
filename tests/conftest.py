"""
Configuration pytest et fixtures partagées pour TinyCTI
"""

import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

# Ajoute le répertoire racine au PYTHONPATH pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tinycti import (IOC, ConfigurationLoader, ErrorHandler, IOCStorage,
                     IOCType, RetentionBucket, RetentionManager, TinyCTIAPI)


@pytest.fixture(scope="session")
def temp_directory():
    """Crée un répertoire temporaire pour les tests"""
    temp_dir = tempfile.mkdtemp(prefix="tinycti_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_config_minimal():
    """Configuration minimale pour les tests"""
    return {
        "feeds": [
            {
                "name": "test_feed",
                "type": "text",
                "url": "http://test.example.com/feed.txt",
                "enabled": True,
                "retention": "live",
                "schedule": "1h",
                "priority": 5,
                "timeout": 30,
                "max_retries": 3,
            }
        ],
        "output_dir": "test_iocs",
        "max_file_size": 1048576,
        "daemon": {
            "enabled": False,
            "check_interval": "60s",
            "max_concurrent_feeds": 3,
        },
        "api": {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 5000,
            "auth": {
                "enabled": False,
                "password": "",
                "rate_limit": {"enabled": True, "requests_per_minute": 60},
            },
            "export": {
                "csv_enabled": True,
                "json_enabled": True,
                "text_enabled": True,
                "max_records": 1000,
            },
        },
        "logging": {
            "level": "INFO",
            "file": "test.log",
            "max_size": "1MB",
            "backup_count": 3,
            "compression": False,
            "audit_enabled": False,
        },
        "retention_policy": {
            "live_to_chaud": "24h",
            "chaud_to_tiede": "7d",
            "tiede_to_froid": "30d",
            "froid_retention": "365d",
        },
        "authentication": {
            "users": {
                "test_user": {"password_hash": "$2b$12$test_hash", "role": "admin"}
            }
        },
        "security": {
            "validate_ssl": True,
            "max_file_size": 52428800,
            "user_agent": "TinyCTI-Test/1.0",
        },
    }


@pytest.fixture
def test_config_file(temp_directory, test_config_minimal):
    """Crée un fichier de configuration temporaire"""
    config_path = temp_directory / "test_config.yaml"

    with open(config_path, "w") as f:
        yaml.dump(test_config_minimal, f)

    return config_path


@pytest.fixture
def mock_ioc_live():
    """IOC de test pour le bucket live"""
    return IOC(
        value="192.168.1.100",
        type=IOCType.IPV4,
        source="test_source",
        retention=RetentionBucket.LIVE,
        first_seen=datetime.now(),
    )


@pytest.fixture
def mock_ioc_chaud():
    """IOC de test pour le bucket chaud"""
    return IOC(
        value="malicious.example.com",
        type=IOCType.DOMAIN,
        source="test_source",
        retention=RetentionBucket.CHAUD,
        first_seen=datetime.now(),
    )


@pytest.fixture
def sample_iocs():
    """Liste d'IOCs de test"""
    return [
        IOC("192.168.1.1", IOCType.IPV4, "test_feed", retention=RetentionBucket.LIVE),
        IOC("evil.com", IOCType.DOMAIN, "test_feed", retention=RetentionBucket.LIVE),
        IOC(
            "http://malicious.com/path",
            IOCType.URL,
            "test_feed",
            retention=RetentionBucket.LIVE,
        ),
        IOC(
            "a1b2c3d4e5f6",
            IOCType.HASH_MD5,
            "test_feed",
            retention=RetentionBucket.CHAUD,
        ),
    ]


@pytest.fixture
def mock_requests_session():
    """Session requests mockée"""
    mock_session = Mock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "192.168.1.1\n192.168.1.2\nevil.com"
    mock_response.raise_for_status.return_value = None
    mock_session.get.return_value = mock_response
    return mock_session


@pytest.fixture
def temp_database(temp_directory):
    """Base de données SQLite temporaire"""
    import uuid

    db_path = temp_directory / f"test_{uuid.uuid4().hex[:8]}.db"

    # Crée la base de données avec le schéma IOC
    conn = sqlite3.connect(str(db_path))
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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bucket ON iocs(bucket)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON iocs(last_seen)")
    conn.commit()
    conn.close()

    return db_path


@pytest.fixture
def temp_storage(temp_directory, temp_database):
    """Instance IOCStorage temporaire"""
    storage = IOCStorage(str(temp_directory), max_file_size=1048576)
    storage.db_path = temp_database

    # Crée les répertoires de buckets
    for bucket in RetentionBucket:
        bucket_dir = temp_directory / bucket.value
        bucket_dir.mkdir(exist_ok=True)

    return storage


@pytest.fixture
def mock_logger():
    """Logger mocké"""
    logger = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    logger.critical = Mock()
    return logger


@pytest.fixture
def configuration_loader(test_config_file):
    """Instance ConfigurationLoader avec fichier de test"""
    return ConfigurationLoader(str(test_config_file))


@pytest.fixture
def error_handler(mock_logger):
    """Instance ErrorHandler avec logger mocké"""
    return ErrorHandler(mock_logger)


@pytest.fixture
def retention_manager(temp_storage, test_config_minimal):
    """Instance RetentionManager avec storage temporaire"""
    return RetentionManager(temp_storage, test_config_minimal["retention_policy"])


@pytest.fixture
def flask_app(temp_directory, test_config_minimal):
    """Application Flask de test"""
    # Mock de l'instance TinyCTI
    mock_tinycti = Mock()
    mock_tinycti.config = test_config_minimal
    mock_tinycti.start_time = datetime.now()

    # Mock storage avec db_path et structure de fichiers
    mock_storage = Mock()
    mock_db_path = Mock()
    mock_db_path.exists.return_value = True
    mock_storage.db_path = mock_db_path
    mock_storage.output_dir = temp_directory
    mock_storage.get_iocs_by_type.return_value = []
    mock_storage.get_bucket_stats.return_value = {
        "active": 0,
        "critical": 0,
        "watch": 0,
        "archive": 0,
    }

    # Crée la structure de fichiers de test
    for bucket in ["active", "critical", "watch", "archive"]:
        bucket_dir = temp_directory / bucket
        bucket_dir.mkdir(exist_ok=True)
        for ioc_type in [
            "ipv4",
            "ipv6",
            "domain",
            "url",
            "hash_md5",
            "hash_sha1",
            "hash_sha256",
            "hash_sha512",
            "email",
        ]:
            ioc_file = bucket_dir / f"{ioc_type}.txt"
            with open(ioc_file, "w") as f:
                f.write("# Test IOC file\n")
                if ioc_type == "ipv4":
                    f.write("192.168.1.1\n")
                    f.write("10.0.0.1\n")
                elif ioc_type == "domain":
                    f.write("example.com\n")
                    f.write("test.org\n")

    mock_tinycti.storage = mock_storage

    mock_tinycti.scheduler = None
    mock_tinycti.is_daemon_running = False

    # Mock NGFW exporter
    mock_ngfw_exporter = Mock()
    mock_tinycti.ngfw_exporter = mock_ngfw_exporter

    # Mock error handler
    mock_error_handler = Mock()
    mock_error_handler.get_error_stats.return_value = {
        "total_errors": 0,
        "recent_errors": [],
    }
    mock_tinycti.error_handler = mock_error_handler

    # Mock retention manager
    mock_retention_manager = Mock()
    mock_retention_manager.get_retention_stats.return_value = {
        "buckets": {},
        "transitions": 0,
    }
    mock_retention_manager.audit_duplicates_across_buckets.return_value = {
        "duplicates": []
    }
    mock_retention_manager.fix_duplicates.return_value = {
        "fixed_duplicates": 0,
        "status": "success",
    }
    mock_retention_manager.fix_duplicate_iocs.return_value = {
        "total_duplicates": 0,
        "fixed_count": 0,
        "status": "success",
    }
    mock_retention_manager.process_retentions.return_value = {"status": "success"}
    mock_tinycti.retention_manager = mock_retention_manager

    # Crée l'instance API
    api = TinyCTIAPI(mock_tinycti, "127.0.0.1", 5000)
    api.app.config["TESTING"] = True

    # Mock des méthodes API
    api._save_config = Mock()
    api._log_audit = Mock()

    return api.app


@pytest.fixture
def flask_client(flask_app):
    """Client de test Flask"""
    return flask_app.test_client()


# Fixtures pour les données de test spécialisées


@pytest.fixture
def malformed_config():
    """Configuration malformée pour tester la validation"""
    return {
        "feeds": [
            {
                "name": "bad_feed",
                "type": "invalid_type",  # Type invalide
                "url": "not_a_url",  # URL invalide
                "enabled": "yes",  # Devrait être boolean
                "retention": "invalid_bucket",  # Bucket invalide
            }
        ]
    }


@pytest.fixture
def network_error_mock():
    """Mock pour simuler des erreurs réseau"""

    def side_effect(*args, **kwargs):
        from requests.exceptions import ConnectionError

        raise ConnectionError("Connection failed")

    return side_effect


@pytest.fixture
def csv_test_data():
    """Données CSV de test"""
    return """# Test CSV Data
url,date_added,threat_type,malware_family
http://evil.com/malware,2023-01-01,malware,trojan
http://phishing.com/login,2023-01-02,phishing,phishing
"""


@pytest.fixture
def json_test_data():
    """Données JSON de test"""
    return {
        "indicators": [
            {
                "value": "192.168.1.100",
                "type": "ipv4",
                "confidence": 80,
                "tags": ["malware", "botnet"],
            },
            {
                "value": "evil-domain.com",
                "type": "domain",
                "confidence": 90,
                "tags": ["phishing"],
            },
        ]
    }


# Markers personnalisés pour pytest
def pytest_configure(config):
    """Configuration des markers pytest"""
    config.addinivalue_line("markers", "unit: Tests unitaires rapides")
    config.addinivalue_line("markers", "integration: Tests d'intégration")
    config.addinivalue_line("markers", "slow: Tests lents nécessitant des ressources")
    config.addinivalue_line(
        "markers", "network: Tests nécessitant une connexion réseau"
    )
    config.addinivalue_line("markers", "security: Tests de sécurité")


# Hooks pytest pour la collecte de tests
def pytest_collection_modifyitems(config, items):
    """Modifie la collecte des tests pour ajouter des markers automatiques"""
    for item in items:
        # Ajoute automatiquement le marker 'unit' aux tests dans le dossier unit/
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)

        # Ajoute automatiquement le marker 'integration' aux tests dans le dossier integration/
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


# Fixture de session pour la configuration globale
@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Configuration globale de l'environnement de test"""
    # Désactive les logs durant les tests pour éviter le spam
    import logging

    logging.disable(logging.CRITICAL)

    yield

    # Réactive les logs après les tests
    logging.disable(logging.NOTSET)
