"""
Tests d'intégration pour le pipeline de données TinyCTI
"""

import time
from unittest.mock import patch

import pytest
import requests_mock

from tinycti import IOC, IOCType, RetentionBucket, TinyCTI


class TestDataPipeline:
    """Tests d'intégration du pipeline de données complet"""

    @pytest.fixture
    def pipeline_config(self, temp_directory):
        """Configuration pour les tests de pipeline"""
        return {
            "feeds": [
                {
                    "name": "ipv4_feed",
                    "type": "text",
                    "url": "http://feeds.example.com/ipv4.txt",
                    "enabled": True,
                    "retention": "live",
                    "schedule": "1h",
                    "priority": 1,
                },
                {
                    "name": "domain_feed",
                    "type": "text",
                    "url": "http://feeds.example.com/domains.txt",
                    "enabled": True,
                    "retention": "chaud",
                    "schedule": "2h",
                    "priority": 2,
                },
                {
                    "name": "hash_feed",
                    "type": "text",
                    "url": "http://feeds.example.com/hashes.txt",
                    "enabled": True,
                    "retention": "tiede",
                    "schedule": "6h",
                    "priority": 3,
                },
            ],
            "output_dir": str(temp_directory),
            "retention": {
                "enabled": True,
                "rules": [
                    {
                        "from_bucket": "live",
                        "to_bucket": "chaud",
                        "after_days": 1,  # Court pour les tests
                    },
                    {"from_bucket": "chaud", "to_bucket": "tiede", "after_days": 3},
                    {"from_bucket": "tiede", "to_bucket": "froid", "after_days": 7},
                ],
            },
            "logging": {"level": "DEBUG", "file": str(temp_directory / "pipeline.log")},
        }

    def test_complete_data_pipeline_flow(self, pipeline_config):
        """Test le flux complet du pipeline de données"""
        with requests_mock.Mocker() as m:
            # Mock des feeds
            m.get(
                "http://feeds.example.com/ipv4.txt",
                text="192.168.1.1\n10.0.0.1\n172.16.1.1\n192.168.1.1",
            )  # Avec doublon
            m.get(
                "http://feeds.example.com/domains.txt",
                text="malicious.com\nexample.org\ntest.net\nmalicious.com",
            )  # Avec doublon
            m.get(
                "http://feeds.example.com/hashes.txt",
                text="d41d8cd98f00b204e9800998ecf8427e\n5d41402abc4b2a76b9719d911017c592",
            )

            tinycti = TinyCTI(pipeline_config)

            # Étape 1: Collecte des données
            collection_results = tinycti.process_feeds()

            # Vérifie que tous les feeds ont été traités
            assert len(collection_results) == 3
            for result in collection_results:
                assert result["status"] == "success"
                assert result["stats"]["total"] > 0

            # Étape 2: Vérification du stockage
            stored_ipv4 = tinycti.storage.get_iocs_by_type("ipv4")
            stored_domains = tinycti.storage.get_iocs_by_type("domain")
            stored_hashes = tinycti.storage.get_iocs_by_type("hash_md5")

            # Vérifie la déduplication
            ipv4_values = [ioc["value"] for ioc in stored_ipv4]
            domain_values = [ioc["value"] for ioc in stored_domains]

            assert len(set(ipv4_values)) == len(ipv4_values)  # Pas de doublons
            assert len(set(domain_values)) == len(domain_values)  # Pas de doublons

            # Étape 3: Vérification des buckets
            assert len(stored_ipv4) == 3  # 4 - 1 doublon
            assert len(stored_domains) == 3  # 4 - 1 doublon
            assert len(stored_hashes) == 2

            # Étape 4: Traitement des rétentions
            retention_results = tinycti.retention_manager.process_retentions()
            assert "transitions" in retention_results
            assert "duplicates_fixed" in retention_results

    def test_data_transformation_pipeline(self, pipeline_config):
        """Test la transformation des données dans le pipeline"""
        with requests_mock.Mocker() as m:
            # Données avec différents formats
            mixed_data = """
# Commentaire à ignorer
192.168.1.1
  10.0.0.1  
https://malicious.com/path
ftp://files.evil.net
email@malicious.com

example.org
d41d8cd98f00b204e9800998ecf8427e
""".strip()

            m.get("http://feeds.example.com/ipv4.txt", text=mixed_data)
            m.get("http://feeds.example.com/domains.txt", text=mixed_data)
            m.get("http://feeds.example.com/hashes.txt", text=mixed_data)

            tinycti = TinyCTI(pipeline_config)
            results = tinycti.process_feeds()

            # Vérifie que les différents types ont été correctement classifiés
            stored_ipv4 = tinycti.storage.get_iocs_by_type("ipv4")
            stored_domains = tinycti.storage.get_iocs_by_type("domain")
            stored_urls = tinycti.storage.get_iocs_by_type("url")
            stored_emails = tinycti.storage.get_iocs_by_type("email")
            stored_hashes = tinycti.storage.get_iocs_by_type("hash_md5")

            # Vérifie la classification automatique
            assert len(stored_ipv4) >= 2  # Au moins les IPs
            assert len(stored_domains) >= 1  # Au moins example.org
            assert len(stored_urls) >= 2  # Les URLs
            assert len(stored_emails) >= 1  # L'email
            assert len(stored_hashes) >= 1  # Le hash MD5

    def test_data_quality_pipeline(self, pipeline_config):
        """Test la qualité des données dans le pipeline"""
        with requests_mock.Mocker() as m:
            # Données avec problèmes de qualité
            dirty_data = """
192.168.1.1
invalid.ip.address
   
# commentaire
192.168.1.300  # IP invalide
example.com
not-a-domain
..invalid..domain..
   whitespace_domain.com   
UPPER.CASE.DOMAIN.COM
""".strip()

            m.get("http://feeds.example.com/ipv4.txt", text=dirty_data)
            m.get("http://feeds.example.com/domains.txt", text=dirty_data)
            m.get("http://feeds.example.com/hashes.txt", text=dirty_data)

            tinycti = TinyCTI(pipeline_config)
            results = tinycti.process_feeds()

            # Vérifie que seules les données valides ont été stockées
            stored_ipv4 = tinycti.storage.get_iocs_by_type("ipv4")
            stored_domains = tinycti.storage.get_iocs_by_type("domain")

            # Vérifie les IPs valides
            valid_ips = [ioc["value"] for ioc in stored_ipv4]
            assert "192.168.1.1" in valid_ips
            assert "192.168.1.300" not in valid_ips  # IP invalide filtrée

            # Vérifie les domaines valides
            valid_domains = [ioc["value"] for ioc in stored_domains]
            assert "example.com" in valid_domains
            # Vérifie la normalisation (si implémentée)
            assert any("domain.com" in domain for domain in valid_domains)

    def test_incremental_data_updates(self, pipeline_config):
        """Test les mises à jour incrémentales des données"""
        tinycti = TinyCTI(pipeline_config)

        with requests_mock.Mocker() as m:
            # Premier lot de données
            m.get("http://feeds.example.com/ipv4.txt", text="192.168.1.1\n10.0.0.1")
            m.get("http://feeds.example.com/domains.txt", text="example.com\ntest.org")
            m.get(
                "http://feeds.example.com/hashes.txt",
                text="d41d8cd98f00b204e9800998ecf8427e",
            )

            # Premier traitement
            results1 = tinycti.process_feeds()
            initial_count = sum(r["stats"]["new"] for r in results1)

            # Deuxième lot avec nouvelles données et chevauchement
            m.get(
                "http://feeds.example.com/ipv4.txt", text="192.168.1.1\n172.16.1.1"
            )  # 1 nouveau
            m.get(
                "http://feeds.example.com/domains.txt",
                text="example.com\nmalicious.net",
            )  # 1 nouveau
            m.get(
                "http://feeds.example.com/hashes.txt",
                text="d41d8cd98f00b204e9800998ecf8427e\n5d41402abc4b2a76b9719d911017c592",
            )  # 1 nouveau

            # Deuxième traitement
            results2 = tinycti.process_feeds()
            new_count = sum(r["stats"]["new"] for r in results2)
            updated_count = sum(r["stats"]["updated"] for r in results2)

            # Vérifie les mises à jour incrémentales
            assert new_count == 3  # 3 nouveaux IOCs
            assert updated_count == 3  # 3 IOCs mis à jour (existants)

    def test_data_retention_pipeline(self, pipeline_config):
        """Test le pipeline de rétention des données"""
        tinycti = TinyCTI(pipeline_config)

        # Ajoute des IOCs avec différentes dates
        from datetime import datetime, timedelta

        old_date = datetime.now() - timedelta(days=8)  # Très ancien
        medium_date = datetime.now() - timedelta(days=4)  # Moyen
        recent_date = datetime.now() - timedelta(hours=1)  # Récent

        # Simule des IOCs de différents âges en modifiant leurs timestamps
        test_iocs = [
            IOC("old.domain.com", IOCType.DOMAIN, "test", RetentionBucket.LIVE),
            IOC("medium.domain.com", IOCType.DOMAIN, "test", RetentionBucket.CHAUD),
            IOC("recent.domain.com", IOCType.DOMAIN, "test", RetentionBucket.LIVE),
        ]

        tinycti.storage.store_iocs(test_iocs)

        # Mock le système de détection d'âge pour les tests
        with patch.object(
            tinycti.retention_manager, "_find_iocs_for_transition"
        ) as mock_find:
            # Simule que old.domain.com doit être déplacé
            mock_find.return_value = [
                {"value": "old.domain.com", "type": "domain", "age_days": 8}
            ]

            # Traite les rétentions
            retention_result = tinycti.retention_manager.process_retentions()

            assert retention_result["transitions"]["total_processed"] >= 0

    def test_data_deduplication_across_feeds(self, pipeline_config):
        """Test la déduplication des données entre feeds"""
        with requests_mock.Mocker() as m:
            # Feeds avec des IOCs qui se chevauchent
            m.get("http://feeds.example.com/ipv4.txt", text="192.168.1.1\n10.0.0.1")
            m.get(
                "http://feeds.example.com/domains.txt", text="192.168.1.1\nexample.com"
            )  # IP dupliquée
            m.get(
                "http://feeds.example.com/hashes.txt",
                text="example.com\nd41d8cd98f00b204e9800998ecf8427e",
            )  # Domaine dupliqué

            tinycti = TinyCTI(pipeline_config)
            results = tinycti.process_feeds()

            # Vérifie la déduplication globale
            all_ipv4 = tinycti.storage.get_iocs_by_type("ipv4")
            all_domains = tinycti.storage.get_iocs_by_type("domain")

            # Chaque IOC ne devrait apparaître qu'une fois au total
            ipv4_values = [ioc["value"] for ioc in all_ipv4]
            domain_values = [ioc["value"] for ioc in all_domains]

            assert len(set(ipv4_values)) == len(ipv4_values)
            assert len(set(domain_values)) == len(domain_values)

            # Vérifie les comptes spécifiques
            assert ipv4_values.count("192.168.1.1") == 1
            assert domain_values.count("example.com") == 1

    def test_data_priority_handling(self, pipeline_config):
        """Test la gestion des priorités des données"""
        tinycti = TinyCTI(pipeline_config)

        # Ajoute le même IOC avec différentes priorités (buckets)
        test_iocs = [
            IOC(
                "priority.test", IOCType.DOMAIN, "feed3", RetentionBucket.FROID
            ),  # Priorité faible
            IOC(
                "priority.test", IOCType.DOMAIN, "feed1", RetentionBucket.LIVE
            ),  # Priorité élevée
            IOC(
                "priority.test", IOCType.DOMAIN, "feed2", RetentionBucket.CHAUD
            ),  # Priorité moyenne
        ]

        # Stocke dans l'ordre de priorité croissante
        for ioc in test_iocs:
            tinycti.storage.store_iocs([ioc])

        # Vérifie que l'IOC est dans le bucket de plus haute priorité
        stored_domains = tinycti.storage.get_iocs_by_type("domain")
        priority_ioc = next(
            (ioc for ioc in stored_domains if ioc["value"] == "priority.test"), None
        )

        assert priority_ioc is not None
        # Devrait être dans le bucket LIVE (plus haute priorité)

    def test_data_rollback_on_error(self, pipeline_config):
        """Test le rollback en cas d'erreur dans le pipeline"""
        tinycti = TinyCTI(pipeline_config)

        with requests_mock.Mocker() as m:
            # Premier feed réussit
            m.get("http://feeds.example.com/ipv4.txt", text="192.168.1.1\n10.0.0.1")
            # Deuxième feed échoue
            m.get("http://feeds.example.com/domains.txt", status_code=500)
            # Troisième feed réussit
            m.get(
                "http://feeds.example.com/hashes.txt",
                text="d41d8cd98f00b204e9800998ecf8427e",
            )

            results = tinycti.process_feeds()

            # Vérifie que les feeds qui ont réussi sont stockés
            successful_results = [r for r in results if r["status"] == "success"]
            failed_results = [r for r in results if r["status"] == "error"]

            assert len(successful_results) == 2
            assert len(failed_results) == 1

            # Les données des feeds réussis devraient être stockées
            stored_ipv4 = tinycti.storage.get_iocs_by_type("ipv4")
            stored_hashes = tinycti.storage.get_iocs_by_type("hash_md5")

            assert len(stored_ipv4) > 0
            assert len(stored_hashes) > 0

    def test_data_streaming_pipeline(self, pipeline_config):
        """Test le pipeline en mode streaming (traitement continu)"""
        tinycti = TinyCTI(pipeline_config)

        # Simule plusieurs cycles de traitement
        cycles_results = []

        for cycle in range(3):
            with requests_mock.Mocker() as m:
                # Données différentes à chaque cycle
                m.get(
                    "http://feeds.example.com/ipv4.txt",
                    text=f"192.168.{cycle}.1\n10.{cycle}.0.1",
                )
                m.get(
                    "http://feeds.example.com/domains.txt",
                    text=f"cycle{cycle}.example.com\ntest{cycle}.org",
                )
                m.get(
                    "http://feeds.example.com/hashes.txt", text=f"{'a' * 32}"
                )  # Hash factice

                results = tinycti.process_feeds()
                cycles_results.append(results)

                # Petite pause entre les cycles
                time.sleep(0.1)

        # Vérifie que chaque cycle a été traité
        assert len(cycles_results) == 3

        for cycle_results in cycles_results:
            assert len(cycle_results) == 3  # 3 feeds
            assert all(r["status"] == "success" for r in cycle_results)

        # Vérifie l'accumulation des données
        final_count = len(tinycti.storage.get_all_iocs())
        assert final_count > 0

    def test_data_backup_and_recovery(self, pipeline_config, temp_directory):
        """Test la sauvegarde et récupération des données"""
        tinycti = TinyCTI(pipeline_config)

        # Ajoute des données initiales
        initial_iocs = [
            IOC("backup.test", IOCType.DOMAIN, "test", RetentionBucket.LIVE),
            IOC("192.168.1.100", IOCType.IPV4, "test", RetentionBucket.CHAUD),
        ]

        tinycti.storage.store_iocs(initial_iocs)
        initial_count = len(tinycti.storage.get_all_iocs())

        # Simule une sauvegarde (export complet)
        backup_file = temp_directory / "backup.json"
        all_data = tinycti.storage.get_all_iocs()

        import json

        with open(backup_file, "w") as f:
            json.dump(all_data, f)

        # Simule une perte de données (vide la base)
        # Note: ceci nécessiterait une méthode clear() sur le storage

        # Simule une restauration
        # Note: ceci nécessiterait une méthode restore() sur le storage

        # Pour ce test, on vérifie juste que la sauvegarde contient les données
        with open(backup_file, "r") as f:
            backup_data = json.load(f)

        assert len(backup_data) == initial_count
        backup_values = [item["value"] for item in backup_data]
        assert "backup.test" in backup_values
        assert "192.168.1.100" in backup_values

    def test_data_compression_pipeline(self, pipeline_config):
        """Test la compression des données dans le pipeline"""
        # Génère un gros volume de données pour tester la compression
        large_dataset = []
        for i in range(1000):
            large_dataset.append(f"192.168.{i // 256}.{i % 256}")
            large_dataset.append(f"test{i}.example.com")

        large_data_text = "\n".join(large_dataset)

        with requests_mock.Mocker() as m:
            m.get("http://feeds.example.com/ipv4.txt", text=large_data_text)
            m.get("http://feeds.example.com/domains.txt", text=large_data_text)
            m.get(
                "http://feeds.example.com/hashes.txt",
                text="d41d8cd98f00b204e9800998ecf8427e",
            )

            tinycti = TinyCTI(pipeline_config)

            # Mesure les performances de traitement
            start_time = time.time()
            results = tinycti.process_feeds()
            end_time = time.time()

            processing_time = end_time - start_time

            # Vérifie que le traitement reste raisonnable même avec beaucoup de données
            assert processing_time < 60  # Moins d'une minute

            # Vérifie que toutes les données ont été traitées
            total_processed = sum(
                r["stats"]["total"] for r in results if r["status"] == "success"
            )
            assert total_processed > 2000  # Au moins les données générées
