"""
Tests unitaires pour le RetentionManager TinyCTI
"""

import sqlite3
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from tinycti import RetentionBucket, RetentionManager


class TestRetentionManager:
    """Tests pour la classe RetentionManager"""

    def test_retention_manager_initialization(
        self, test_config_minimal, temp_directory
    ):
        """Test l'initialisation du RetentionManager"""
        mock_storage = Mock()
        mock_logger = Mock()

        manager = RetentionManager(test_config_minimal, mock_storage, mock_logger)

        assert manager.config == test_config_minimal
        assert manager.storage == mock_storage
        assert manager.logger == mock_logger
        assert manager.bucket_priorities == {
            RetentionBucket.LIVE: 1,
            RetentionBucket.CHAUD: 2,
            RetentionBucket.TIEDE: 3,
            RetentionBucket.FROID: 4,
        }

    def test_bucket_priority_comparison(self, temp_storage, test_config_minimal):
        """Test la comparaison des priorités de buckets"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # LIVE a la priorité la plus élevée (valeur la plus faible)
        assert manager._get_bucket_priority(
            RetentionBucket.LIVE
        ) < manager._get_bucket_priority(RetentionBucket.CHAUD)
        assert manager._get_bucket_priority(
            RetentionBucket.CHAUD
        ) < manager._get_bucket_priority(RetentionBucket.TIEDE)
        assert manager._get_bucket_priority(
            RetentionBucket.TIEDE
        ) < manager._get_bucket_priority(RetentionBucket.FROID)

    def test_should_promote_ioc_higher_priority(
        self, temp_storage, test_config_minimal
    ):
        """Test la promotion d'IOC vers un bucket de priorité plus élevée"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # IOC existant dans FROID, nouveau dans LIVE
        should_promote = manager._should_promote_ioc(
            RetentionBucket.FROID, RetentionBucket.LIVE
        )
        assert should_promote is True

    def test_should_promote_ioc_same_priority(self, temp_storage, test_config_minimal):
        """Test qu'aucune promotion n'est nécessaire pour la même priorité"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # Même bucket
        should_promote = manager._should_promote_ioc(
            RetentionBucket.LIVE, RetentionBucket.LIVE
        )
        assert should_promote is False

    def test_should_promote_ioc_lower_priority(self, temp_storage, test_config_minimal):
        """Test qu'aucune promotion n'est nécessaire vers un bucket de priorité plus faible"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # IOC existant dans LIVE, nouveau dans FROID
        should_promote = manager._should_promote_ioc(
            RetentionBucket.LIVE, RetentionBucket.FROID
        )
        assert should_promote is False

    def test_check_duplicate_iocs_none_found(self, temp_storage, test_config_minimal):
        """Test la vérification de doublons quand aucun n'est trouvé"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # Mock pour retourner aucun doublon
        with patch.object(manager, "_find_duplicates_in_db", return_value=[]):
            duplicates = manager.check_duplicate_iocs()

            assert duplicates == []

    def test_check_duplicate_iocs_found(self, temp_storage, test_config_minimal):
        """Test la vérification de doublons quand des doublons sont trouvés"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        mock_logger = Mock()
        manager.logger = mock_logger

        # Mock pour retourner des doublons
        mock_duplicates = [
            {"value": "192.168.1.1", "type": "ipv4", "buckets": ["live", "chaud"]},
            {"value": "example.com", "type": "domain", "buckets": ["chaud", "froid"]},
        ]

        with patch.object(
            manager, "_find_duplicates_in_db", return_value=mock_duplicates
        ):
            duplicates = manager.check_duplicate_iocs()

            assert len(duplicates) == 2
            assert duplicates[0]["value"] == "192.168.1.1"
            assert duplicates[0]["type"] == "ipv4"
            assert duplicates[0]["buckets"] == ["live", "chaud"]

    def test_fix_duplicate_iocs_success(self, temp_storage, test_config_minimal):
        """Test la correction réussie des doublons"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        mock_logger = Mock()
        manager.logger = mock_logger

        # Mock des doublons à corriger
        mock_duplicates = [
            {"value": "192.168.1.1", "type": "ipv4", "buckets": ["live", "chaud"]},
            {"value": "example.com", "type": "domain", "buckets": ["chaud", "froid"]},
        ]

        with patch.object(
            manager, "check_duplicate_iocs", return_value=mock_duplicates
        ):
            with patch.object(
                manager, "_resolve_duplicate", return_value=True
            ) as mock_resolve:
                result = manager.fix_duplicate_iocs()

                assert result["total_duplicates"] == 2
                assert result["fixed_count"] == 2
                assert result["failed_count"] == 0
                assert mock_resolve.call_count == 2

    def test_fix_duplicate_iocs_with_errors(self, temp_storage, test_config_minimal):
        """Test la correction de doublons avec des erreurs"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        mock_logger = Mock()
        manager.logger = mock_logger

        mock_duplicates = [
            {"value": "192.168.1.1", "type": "ipv4", "buckets": ["live", "chaud"]},
            {"value": "example.com", "type": "domain", "buckets": ["chaud", "froid"]},
        ]

        with patch.object(
            manager, "check_duplicate_iocs", return_value=mock_duplicates
        ):
            # Premier resolve réussit, second échoue
            with patch.object(manager, "_resolve_duplicate", side_effect=[True, False]):
                result = manager.fix_duplicate_iocs()

                assert result["total_duplicates"] == 2
                assert result["fixed_count"] == 1
                assert result["failed_count"] == 1

    def test_resolve_duplicate_promotion_needed(
        self, temp_storage, test_config_minimal
    ):
        """Test la résolution d'un doublon nécessitant une promotion"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        duplicate = {
            "value": "192.168.1.1",
            "type": "ipv4",
            "buckets": ["chaud", "froid"],
        }

        # Mock la connexion sqlite pour simuler la suppression
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor

        with patch("sqlite3.connect", return_value=mock_connection):
            result = manager._resolve_duplicate(duplicate)

            assert result is True
            # Vérifie que la requête SQL a été exécutée
            assert mock_connection.execute.called
            assert mock_connection.commit.called
            assert mock_connection.close.called

    def test_resolve_duplicate_no_promotion_needed(
        self, temp_storage, test_config_minimal
    ):
        """Test la résolution d'un doublon sans promotion nécessaire"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        duplicate = {
            "value": "192.168.1.1",
            "type": "ipv4",
            "buckets": ["live", "chaud"],
        }

        # Mock la connexion sqlite pour simuler la suppression
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor

        with patch("sqlite3.connect", return_value=mock_connection):
            result = manager._resolve_duplicate(duplicate)

            assert result is True
            # Vérifie que la requête SQL a été exécutée
            assert mock_connection.execute.called
            assert mock_connection.commit.called
            assert mock_connection.close.called

    def test_process_retentions_success(self, temp_storage, test_config_minimal):
        """Test le traitement réussi des rétentions"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        mock_logger = Mock()
        manager.logger = mock_logger

        result = manager.process_retentions()

        assert result["status"] == "success"
        assert "timestamp" in result

    def test_process_bucket_transitions(self, temp_storage, test_config_minimal):
        """Test le traitement des transitions entre buckets"""
        # Configuration avec règles de transition
        config = test_config_minimal.copy()
        config["retention"] = {
            "rules": [
                {"from_bucket": "live", "to_bucket": "chaud", "after_days": 7},
                {"from_bucket": "chaud", "to_bucket": "tiede", "after_days": 30},
            ]
        }

        manager = RetentionManager(config, temp_storage, Mock())

        # Mock des IOCs à transférer
        mock_iocs_to_transfer = [
            {"value": "192.168.1.1", "type": "ipv4", "age_days": 10},
            {"value": "example.com", "type": "domain", "age_days": 35},
        ]

        with patch.object(
            manager, "find_iocs_for_transition", return_value=mock_iocs_to_transfer
        ):
            with patch.object(
                temp_storage, "_move_ioc_between_buckets", return_value=True
            ) as mock_move:
                result = manager.process_bucket_transitions()

                assert result["status"] == "success"
                assert "timestamp" in result

    def test_find_iocs_for_transition(self, temp_storage, test_config_minimal):
        """Test la recherche d'IOCs à transférer"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        rule = {"from_bucket": "live", "to_bucket": "chaud", "after_days": 7}

        # Mock de la base de données
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor

        # IOCs anciens (>7 jours)
        mock_cursor.fetchall.return_value = [
            ("192.168.1.1", "ipv4", "2024-01-01 00:00:00"),
            ("example.com", "domain", "2024-01-02 00:00:00"),
        ]

        with patch("sqlite3.connect", return_value=mock_connection):
            max_age_seconds = 7 * 24 * 3600  # 7 days in seconds
            iocs = manager.find_iocs_for_transition("live", "chaud", max_age_seconds)

            assert len(iocs) == 2
            assert iocs[0]["value"] == "192.168.1.1"
            assert iocs[0]["type"] == "ipv4"

    def test_get_retention_stats(self, temp_storage, test_config_minimal):
        """Test la récupération des statistiques de rétention"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # Mock de la base de données avec des statistiques
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor

        # Mock des résultats par bucket
        mock_cursor.fetchall.side_effect = [
            [("live", 100)],  # Première requête: count par bucket
            [
                ("ipv4", 50),
                ("domain", 30),
                ("url", 20),
            ],  # Seconde requête: count par type
            [
                (datetime.now() - timedelta(days=1),)
            ],  # Troisième requête: dernière mise à jour
        ]

        with patch("sqlite3.connect", return_value=mock_connection):
            stats = manager.get_retention_stats()

            assert "total_iocs" in stats
            assert "bucket_counts" in stats
            assert "timestamp" in stats

    def test_audit_retention_system(self, temp_storage, test_config_minimal):
        """Test de l'audit du système de rétention"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        with patch.object(manager, "check_duplicate_iocs", return_value=[]):
            with patch.object(
                manager, "get_retention_stats", return_value={"total_iocs": 100}
            ):
                audit_result = manager.audit_retention_system()

                assert "duplicates_found" in audit_result
                assert "duplicates" in audit_result
                assert "stats" in audit_result
                assert "audit_timestamp" in audit_result
                assert audit_result["status"] == "success"

    def test_check_bucket_integrity_success(self, temp_storage, test_config_minimal):
        """Test la vérification d'intégrité des buckets sans problème"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # Mock d'une base cohérente
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (1,)  # Chaque bucket a au moins 1 IOC

        with patch("sqlite3.connect", return_value=mock_connection):
            result = manager.check_bucket_integrity()

            assert "issues" in result
            assert len(result["issues"]) == 0

    def test_check_bucket_integrity_with_issues(
        self, temp_storage, test_config_minimal
    ):
        """Test la vérification d'intégrité avec des problèmes détectés"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # Mock avec des incohérences (buckets vides)
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (0,)  # Buckets vides

        with patch("sqlite3.connect", return_value=mock_connection):
            result = manager.check_bucket_integrity()

            assert "issues" in result
            assert (
                len(result["issues"]) == 4
            )  # Un pour chaque bucket RetentionBucket (4 buckets vides)

    def test_check_retention_rules_compliance(self, temp_storage, test_config_minimal):
        """Test la vérification du respect des règles de rétention"""
        # Configuration avec règles de rétention
        config = test_config_minimal.copy()
        config["retention"] = {
            "rules": [{"from_bucket": "live", "to_bucket": "chaud", "after_days": 7}]
        }

        manager = RetentionManager(config, temp_storage, Mock())

        # Mock des violations
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            ("192.168.1.1", "ipv4", "live", "2024-01-01 00:00:00")  # IOC trop ancien
        ]

        with patch("sqlite3.connect", return_value=mock_connection):
            result = manager.check_retention_rules_compliance()

            assert "compliance_issues" in result
            assert "status" in result

    def test_error_handling_database_connection(
        self, temp_storage, test_config_minimal
    ):
        """Test la gestion d'erreur de connexion à la base"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        with patch("sqlite3.connect", side_effect=sqlite3.Error("Connection failed")):
            result = manager.check_duplicate_iocs()

            # Devrait retourner une liste vide et logger l'erreur
            assert result == []

    def test_error_handling_file_operations(self, temp_storage, test_config_minimal):
        """Test la gestion d'erreur des opérations fichier"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        duplicate = {
            "value": "192.168.1.1",
            "type": "ipv4",
            "buckets": ["live", "chaud"],
        }

        # Mock d'erreur lors de l'opération base de données
        with patch("sqlite3.connect", side_effect=Exception("Database error")):
            result = manager._resolve_duplicate(duplicate)

            assert result is False

    def test_concurrent_retention_processing(self, temp_storage, test_config_minimal):
        """Test le traitement concurrent des rétentions"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        import threading

        results = []

        def process_retentions():
            with patch.object(
                manager,
                "process_transitions",
                return_value=None,
            ):
                result = manager.process_retentions()
                results.append(result)

        # Lance plusieurs threads de traitement
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=process_retentions)
            threads.append(thread)
            thread.start()

        # Attend que tous les threads terminent
        for thread in threads:
            thread.join()

        # Tous devraient avoir réussi
        assert len(results) == 3
        for result in results:
            assert result["status"] == "success"

    def test_large_dataset_retention_processing(
        self, temp_storage, test_config_minimal
    ):
        """Test le traitement de rétention sur un gros dataset"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())

        # Mock d'un grand nombre de doublons
        large_duplicates = []
        for i in range(1000):
            large_duplicates.append(
                {
                    "value": f"192.168.1.{i}",
                    "type": "ipv4",
                    "buckets": ["live", "chaud"],
                }
            )

        with patch.object(
            manager, "check_duplicate_iocs", return_value=large_duplicates
        ):
            with patch.object(manager, "_resolve_duplicate", return_value=True):
                result = manager.fix_duplicate_iocs()

                assert result["total_duplicates"] == 1000
                assert result["fixed_count"] == 1000

    def test_retention_manager_configuration_validation(self, temp_directory):
        """Test la validation de la configuration du RetentionManager"""
        invalid_config = {
            "retention": {
                "rules": [
                    {
                        "from_bucket": "invalid_bucket",  # Bucket invalide
                        "to_bucket": "chaud",
                        "after_days": 7,
                    }
                ]
            }
        }

        mock_storage = Mock()
        mock_logger = Mock()

        # Devrait gérer gracieusement les configurations invalides
        manager = RetentionManager(invalid_config, mock_storage, mock_logger)

        # Le manager devrait être créé mais les règles invalides ignorées
        assert manager is not None
