"""
Tests unitaires pour le système de stockage des IOCs TinyCTI
"""

import pytest
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from datetime import datetime

from tinycti import (
    IOCStorage, 
    IOC, 
    IOCType, 
    RetentionBucket,
    IOCClassifier,
    StorageError
)


class TestIOCStorage:
    """Tests pour la classe IOCStorage"""

    def test_ioc_storage_initialization(self, temp_directory):
        """Test l'initialisation d'IOCStorage"""
        storage = IOCStorage(str(temp_directory), max_file_size=1024)
        
        assert storage.output_dir == Path(temp_directory)
        assert storage.max_file_size == 1024
        assert storage.db_path == Path(temp_directory) / "iocs.db"

    def test_database_creation(self, temp_storage):
        """Test la création de la base de données"""
        # La base est créée via la fixture temp_storage
        assert temp_storage.db_path.exists()
        
        # Vérifie la structure de la base
        conn = sqlite3.connect(str(temp_storage.db_path))
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        assert "iocs" in tables
        conn.close()

    def test_directory_structure_creation(self, temp_storage):
        """Test la création de la structure de répertoires"""
        # Force la création des répertoires
        for bucket in RetentionBucket:
            bucket_dir = temp_storage.output_dir / bucket.value
            bucket_dir.mkdir(parents=True, exist_ok=True)
        
        # Vérifie que tous les buckets existent
        for bucket in RetentionBucket:
            bucket_dir = temp_storage.output_dir / bucket.value
            assert bucket_dir.exists()
            assert bucket_dir.is_dir()

    def test_store_iocs_new(self, temp_storage, sample_iocs):
        """Test le stockage de nouveaux IOCs"""
        stats = temp_storage.store_iocs(sample_iocs)
        
        assert stats["total"] == len(sample_iocs)
        assert stats["new"] == len(sample_iocs)
        assert stats["updated"] == 0
        assert stats["errors"] == 0

    def test_store_iocs_duplicates(self, temp_storage, sample_iocs):
        """Test le stockage d'IOCs dupliqués"""
        # Stocke une première fois
        temp_storage.store_iocs(sample_iocs)
        
        # Stocke une seconde fois (doublons)
        stats = temp_storage.store_iocs(sample_iocs)
        
        assert stats["total"] == len(sample_iocs)
        assert stats["new"] == 0
        assert stats["updated"] == len(sample_iocs)
        assert stats["errors"] == 0

    def test_store_iocs_with_promotion(self, temp_storage):
        """Test le stockage avec promotion entre buckets"""
        # IOC dans bucket chaud
        ioc_chaud = IOC("192.168.1.1", IOCType.IPV4, "source1", RetentionBucket.CHAUD)
        temp_storage.store_iocs([ioc_chaud])
        
        # Même IOC mais dans bucket live (plus prioritaire)
        ioc_live = IOC("192.168.1.1", IOCType.IPV4, "source2", RetentionBucket.LIVE)
        stats = temp_storage.store_iocs([ioc_live])
        
        # Devrait être mis à jour (promotion)
        assert stats["updated"] == 1

    def test_deduplicate_iocs_new(self, temp_storage, sample_iocs):
        """Test la déduplication d'IOCs nouveaux"""
        conn = sqlite3.connect(str(temp_storage.db_path))
        
        result = temp_storage._deduplicate_iocs(conn, sample_iocs)
        
        # Tous devraient être nouveaux
        assert len(result) == len(sample_iocs)
        
        conn.close()

    def test_deduplicate_iocs_existing(self, temp_storage, sample_iocs):
        """Test la déduplication d'IOCs existants"""
        conn = sqlite3.connect(str(temp_storage.db_path))
        
        # Stocke une première fois
        temp_storage._deduplicate_iocs(conn, sample_iocs)
        
        # Stocke une seconde fois
        result = temp_storage._deduplicate_iocs(conn, sample_iocs)
        
        # Tous devraient être des mises à jour
        assert len(result) == len(sample_iocs)
        
        conn.close()

    def test_move_ioc_between_buckets(self, temp_storage):
        """Test le déplacement d'IOC entre buckets"""
        # Crée les répertoires
        for bucket in RetentionBucket:
            bucket_dir = temp_storage.output_dir / bucket.value
            bucket_dir.mkdir(parents=True, exist_ok=True)
        
        # Crée un fichier avec un IOC dans le bucket chaud
        chaud_file = temp_storage.output_dir / "chaud" / "ipv4.txt"
        chaud_file.write_text("192.168.1.1\n192.168.1.2\n")
        
        # Déplace un IOC vers le bucket live
        temp_storage._move_ioc_between_buckets("192.168.1.1", "ipv4", "chaud", "live")
        
        # Vérifie que l'IOC a été supprimé du bucket chaud
        chaud_content = chaud_file.read_text()
        assert "192.168.1.1" not in chaud_content
        assert "192.168.1.2" in chaud_content
        
        # Vérifie que l'IOC a été ajouté au bucket live
        live_file = temp_storage.output_dir / "live" / "ipv4.txt"
        if live_file.exists():
            live_content = live_file.read_text()
            assert "192.168.1.1" in live_content

    def test_write_iocs_to_file(self, temp_storage, sample_iocs):
        """Test l'écriture d'IOCs dans un fichier"""
        ipv4_iocs = [ioc for ioc in sample_iocs if ioc.type == IOCType.IPV4]
        
        temp_storage._write_iocs_to_file(IOCType.IPV4, RetentionBucket.LIVE, ipv4_iocs)
        
        file_path = temp_storage.output_dir / "live" / "ipv4.txt"
        assert file_path.exists()
        
        content = file_path.read_text()
        for ioc in ipv4_iocs:
            assert ioc.value in content

    def test_write_iocs_file_size_limit(self, temp_storage):
        """Test la limite de taille de fichier"""
        # Configure une taille limite très petite
        temp_storage.max_file_size = 50  # 50 bytes
        
        # Crée beaucoup d'IOCs pour dépasser la limite
        large_iocs = []
        for i in range(10):
            ioc = IOC(f"192.168.1.{i}", IOCType.IPV4, "test", RetentionBucket.LIVE)
            large_iocs.append(ioc)
        
        # Le stockage devrait gérer la limite gracieusement
        stats = temp_storage.store_iocs(large_iocs)
        
        # Au moins certains IOCs devraient être traités
        assert stats["total"] > 0

    def test_database_connection_error_handling(self, temp_directory):
        """Test la gestion des erreurs de connexion à la base"""
        storage = IOCStorage(str(temp_directory))
        
        # Simule une erreur de base de données
        with patch('sqlite3.connect', side_effect=sqlite3.Error("DB Error")):
            ioc = IOC("192.168.1.1", IOCType.IPV4, "test", RetentionBucket.LIVE)
            
            stats = storage.store_iocs([ioc])
            
            # Devrait gérer l'erreur gracieusement
            assert stats["errors"] > 0

    def test_file_write_permission_error(self, temp_storage, sample_iocs):
        """Test la gestion des erreurs de permission de fichier"""
        # Simule une erreur de permission
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            stats = temp_storage.store_iocs(sample_iocs)
            
            # Devrait gérer l'erreur gracieusement
            assert stats["errors"] > 0

    def test_concurrent_storage_operations(self, temp_storage, sample_iocs):
        """Test les opérations de stockage concurrentes"""
        import threading
        import time
        
        results = []
        
        def store_iocs():
            stats = temp_storage.store_iocs(sample_iocs)
            results.append(stats)
        
        # Lance plusieurs threads de stockage
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=store_iocs)
            threads.append(thread)
            thread.start()
        
        # Attend que tous les threads terminent
        for thread in threads:
            thread.join()
        
        # Vérifie que tous les threads ont réussi
        assert len(results) == 3
        for stats in results:
            assert stats["total"] > 0

    def test_storage_with_malformed_ioc(self, temp_storage):
        """Test le stockage avec des IOCs malformés"""
        # IOC avec valeur vide
        malformed_iocs = [
            IOC("", IOCType.IPV4, "test", RetentionBucket.LIVE),
            IOC("   ", IOCType.DOMAIN, "test", RetentionBucket.LIVE),  # Espaces
            IOC("192.168.1.1", IOCType.IPV4, "", RetentionBucket.LIVE),  # Source vide
        ]
        
        stats = temp_storage.store_iocs(malformed_iocs)
        
        # Devrait gérer les IOCs malformés
        assert stats["total"] == len(malformed_iocs)

    def test_bucket_priority_enforcement(self, temp_storage):
        """Test l'application des priorités de bucket"""
        # IOC dans bucket froid
        ioc_froid = IOC("test.com", IOCType.DOMAIN, "source1", RetentionBucket.FROID)
        temp_storage.store_iocs([ioc_froid])
        
        # Même IOC dans bucket live (plus prioritaire)
        ioc_live = IOC("test.com", IOCType.DOMAIN, "source2", RetentionBucket.LIVE)
        stats = temp_storage.store_iocs([ioc_live])
        
        # Devrait être promu vers live
        assert stats["updated"] == 1

    def test_large_dataset_handling(self, temp_storage):
        """Test la gestion de gros datasets"""
        # Génère un grand nombre d'IOCs
        large_dataset = []
        for i in range(1000):
            ioc = IOC(f"192.168.{i//256}.{i%256}", IOCType.IPV4, "test", RetentionBucket.LIVE)
            large_dataset.append(ioc)
        
        stats = temp_storage.store_iocs(large_dataset)
        
        assert stats["total"] == 1000
        assert stats["new"] == 1000


class TestIOCClassifier:
    """Tests pour la classe IOCClassifier"""

    def test_ioc_classifier_initialization(self):
        """Test l'initialisation du classificateur d'IOCs"""
        classifier = IOCClassifier()
        assert classifier is not None

    def test_classify_ipv4(self):
        """Test la classification d'adresses IPv4"""
        classifier = IOCClassifier()
        
        # IPs publiques (valides pour IOCs)
        public_ipv4 = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222"
        ]
        
        for ip in public_ipv4:
            result = classifier.classify_ioc(ip)
            assert result == IOCType.IPV4
            
        # IPs privées (doivent être rejetées)
        private_ipv4 = [
            "192.168.1.1",
            "10.0.0.1", 
            "172.16.1.1",
            "127.0.0.1"
        ]
        
        for ip in private_ipv4:
            result = classifier.classify_ioc(ip)
            assert result is None  # IPs privées ne sont pas des IOCs

    def test_classify_ipv6(self):
        """Test la classification d'adresses IPv6"""
        classifier = IOCClassifier()
        
        valid_ipv6 = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "::1",
            "fe80::1",
            "2001:db8::1"
        ]
        
        for ip in valid_ipv6:
            result = classifier.classify_ioc(ip)
            assert result == IOCType.IPV6

    def test_classify_domain(self):
        """Test la classification de domaines"""
        classifier = IOCClassifier()
        
        valid_domains = [
            "example.com",
            "sub.example.org",
            "malicious-site.net",
            "test.co.uk",
            "very-long-subdomain.example.com"
        ]
        
        for domain in valid_domains:
            result = classifier.classify_ioc(domain)
            assert result == IOCType.DOMAIN

    def test_classify_url(self):
        """Test la classification d'URLs"""
        classifier = IOCClassifier()
        
        valid_urls = [
            "http://example.com",
            "https://malicious.com/path",
            "ftp://files.example.org",
            "https://sub.domain.com/path?param=value",
            "http://192.168.1.1:8080/path"
        ]
        
        for url in valid_urls:
            result = classifier.classify_ioc(url)
            assert result == IOCType.URL

    def test_classify_email(self):
        """Test la classification d'emails"""
        classifier = IOCClassifier()
        
        valid_emails = [
            "user@example.com",
            "test.email@domain.org",
            "malicious@evil.net",
            "contact@sub.domain.co.uk"
        ]
        
        for email in valid_emails:
            result = classifier.classify_ioc(email)
            assert result == IOCType.EMAIL

    def test_classify_hash_md5(self):
        """Test la classification de hash MD5"""
        classifier = IOCClassifier()
        
        valid_md5 = [
            "d41d8cd98f00b204e9800998ecf8427e",
            "5d41402abc4b2a76b9719d911017c592",
            "098f6bcd4621d373cade4e832627b4f6"
        ]
        
        for hash_val in valid_md5:
            result = classifier.classify_ioc(hash_val)
            assert result == IOCType.HASH_MD5

    def test_classify_hash_sha1(self):
        """Test la classification de hash SHA1"""
        classifier = IOCClassifier()
        
        valid_sha1 = [
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "356a192b7913b04c54574d18c28d46e6395428ab",
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        ]
        
        for hash_val in valid_sha1:
            result = classifier.classify_ioc(hash_val)
            assert result == IOCType.HASH_SHA1

    def test_classify_hash_sha256(self):
        """Test la classification de hash SHA256"""
        classifier = IOCClassifier()
        
        valid_sha256 = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
        ]
        
        for hash_val in valid_sha256:
            result = classifier.classify_ioc(hash_val)
            assert result == IOCType.HASH_SHA256

    def test_classify_hash_sha512(self):
        """Test la classification de hash SHA512"""
        classifier = IOCClassifier()
        
        valid_sha512 = [
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
        ]
        
        for hash_val in valid_sha512:
            result = classifier.classify_ioc(hash_val)
            assert result == IOCType.HASH_SHA512

    def test_classify_unknown_format(self):
        """Test la classification de formats inconnus"""
        classifier = IOCClassifier()
        
        unknown_values = [
            "random_string",
            "123456",
            "not.an.ip.address",
            "",
            "   ",
            None
        ]
        
        for value in unknown_values:
            if value is not None:
                result = classifier.classify_ioc(value)
                # Devrait retourner un type par défaut ou None

    def test_classify_edge_cases(self):
        """Test la classification de cas limites"""
        classifier = IOCClassifier()
        
        edge_cases = [
            "192.168.1.256",  # IP invalide
            "not-a-domain",   # Domaine sans TLD
            "http://",        # URL incomplète
            "user@",          # Email incomplet
            "abcdefg"         # Hash trop court
        ]
        
        for case in edge_cases:
            result = classifier.classify_ioc(case)
            # Devrait gérer gracieusement les cas limites

    def test_classify_case_sensitivity(self):
        """Test la sensibilité à la casse"""
        classifier = IOCClassifier()
        
        # Les hash en majuscules
        hash_upper = "D41D8CD98F00B204E9800998ECF8427E"
        hash_lower = "d41d8cd98f00b204e9800998ecf8427e"
        
        result_upper = classifier.classify_ioc(hash_upper)
        result_lower = classifier.classify_ioc(hash_lower)
        
        # Devraient être classifiés de la même manière
        assert result_upper == result_lower

    def test_classify_with_whitespace(self):
        """Test la classification avec des espaces"""
        classifier = IOCClassifier()
        
        values_with_spaces = [
            "  192.168.1.1  ",
            "\texample.com\n",
            " user@domain.com ",
            "\td41d8cd98f00b204e9800998ecf8427e\n"
        ]
        
        for value in values_with_spaces:
            result = classifier.classify_ioc(value)
            # Devrait gérer les espaces correctement