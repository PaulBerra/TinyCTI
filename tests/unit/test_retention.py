"""
Tests unitaires pour le RetentionManager TinyCTI
"""

import pytest
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from tinycti import (
    RetentionManager, 
    IOC, 
    IOCType, 
    RetentionBucket,
    IOCStorage
)


class TestRetentionManager:
    """Tests pour la classe RetentionManager"""

    def test_retention_manager_initialization(self, test_config_minimal, temp_directory):
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
            RetentionBucket.FROID: 4
        }

    def test_bucket_priority_comparison(self, temp_storage, test_config_minimal):
        """Test la comparaison des priorités de buckets"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # LIVE a la priorité la plus élevée (valeur la plus faible)
        assert manager._get_bucket_priority(RetentionBucket.LIVE) < manager._get_bucket_priority(RetentionBucket.CHAUD)
        assert manager._get_bucket_priority(RetentionBucket.CHAUD) < manager._get_bucket_priority(RetentionBucket.TIEDE)
        assert manager._get_bucket_priority(RetentionBucket.TIEDE) < manager._get_bucket_priority(RetentionBucket.FROID)

    def test_should_promote_ioc_higher_priority(self, temp_storage, test_config_minimal):
        """Test la promotion d'IOC vers un bucket de priorité plus élevée"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # IOC existant dans FROID, nouveau dans LIVE
        should_promote = manager._should_promote_ioc(RetentionBucket.FROID, RetentionBucket.LIVE)
        assert should_promote is True

    def test_should_promote_ioc_same_priority(self, temp_storage, test_config_minimal):
        """Test qu'aucune promotion n'est nécessaire pour la même priorité"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # Même bucket
        should_promote = manager._should_promote_ioc(RetentionBucket.LIVE, RetentionBucket.LIVE)
        assert should_promote is False

    def test_should_promote_ioc_lower_priority(self, temp_storage, test_config_minimal):
        """Test qu'aucune promotion n'est nécessaire vers un bucket de priorité plus faible"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # IOC existant dans LIVE, nouveau dans FROID
        should_promote = manager._should_promote_ioc(RetentionBucket.LIVE, RetentionBucket.FROID)
        assert should_promote is False

    def test_check_duplicate_iocs_none_found(self, temp_storage, test_config_minimal):
        """Test la vérification de doublons quand aucun n'est trouvé"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # Mock pour retourner aucun doublon
        with patch.object(manager, '_find_duplicates_in_db', return_value=[]):
            duplicates = manager.check_duplicate_iocs()
            
            assert duplicates == []

    def test_check_duplicate_iocs_found(self, temp_storage, test_config_minimal):
        """Test la vérification de doublons quand des doublons sont trouvés"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        mock_logger = Mock()
        manager.logger = mock_logger
        
        # Mock pour retourner des doublons
        mock_duplicates = [
            ("192.168.1.1", "ipv4", "live,chaud"),
            ("example.com", "domain", "chaud,froid")
        ]
        
        with patch.object(manager, '_find_duplicates_in_db', return_value=mock_duplicates):
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
            {"value": "example.com", "type": "domain", "buckets": ["chaud", "froid"]}
        ]
        
        with patch.object(manager, 'check_duplicate_iocs', return_value=mock_duplicates):
            with patch.object(manager, '_resolve_duplicate', return_value=True) as mock_resolve:
                result = manager.fix_duplicate_iocs()
                
                assert result["total_duplicates"] == 2
                assert result["fixed"] == 2
                assert result["errors"] == 0
                assert mock_resolve.call_count == 2

    def test_fix_duplicate_iocs_with_errors(self, temp_storage, test_config_minimal):
        """Test la correction de doublons avec des erreurs"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        mock_logger = Mock()
        manager.logger = mock_logger
        
        mock_duplicates = [
            {"value": "192.168.1.1", "type": "ipv4", "buckets": ["live", "chaud"]},
            {"value": "example.com", "type": "domain", "buckets": ["chaud", "froid"]}
        ]
        
        with patch.object(manager, 'check_duplicate_iocs', return_value=mock_duplicates):
            # Premier resolve réussit, second échoue
            with patch.object(manager, '_resolve_duplicate', side_effect=[True, False]):
                result = manager.fix_duplicate_iocs()
                
                assert result["total_duplicates"] == 2
                assert result["fixed"] == 1
                assert result["errors"] == 1

    def test_resolve_duplicate_promotion_needed(self, temp_storage, test_config_minimal):
        """Test la résolution d'un doublon nécessitant une promotion"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        duplicate = {
            "value": "192.168.1.1",
            "type": "ipv4", 
            "buckets": ["chaud", "froid"]
        }
        
        # Mock pour indiquer qu'une promotion est nécessaire vers CHAUD
        with patch.object(manager, '_should_promote_ioc', return_value=True):
            with patch.object(temp_storage, '_move_ioc_between_buckets', return_value=True) as mock_move:
                result = manager._resolve_duplicate(duplicate)
                
                assert result is True
                mock_move.assert_called_once_with("192.168.1.1", "ipv4", "froid", "chaud")

    def test_resolve_duplicate_no_promotion_needed(self, temp_storage, test_config_minimal):
        """Test la résolution d'un doublon sans promotion nécessaire"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        duplicate = {
            "value": "192.168.1.1",
            "type": "ipv4",
            "buckets": ["live", "chaud"]
        }
        
        # Mock pour indiquer qu'aucune promotion n'est nécessaire
        with patch.object(manager, '_should_promote_ioc', return_value=False):
            with patch.object(temp_storage, '_move_ioc_between_buckets', return_value=True) as mock_move:
                result = manager._resolve_duplicate(duplicate)
                
                assert result is True
                # Devrait supprimer de CHAUD (priorité plus faible)
                mock_move.assert_called_once_with("192.168.1.1", "ipv4", "chaud", "live")

    def test_process_retentions_success(self, temp_storage, test_config_minimal):
        """Test le traitement réussi des rétentions"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        mock_logger = Mock()
        manager.logger = mock_logger
        
        with patch.object(manager, '_process_bucket_transitions') as mock_transitions:
            with patch.object(manager, 'check_duplicate_iocs', return_value=[]):
                result = manager.process_retentions()
                
                assert "transitions" in result
                assert "duplicates_fixed" in result
                assert "errors" in result
                mock_transitions.assert_called()

    def test_process_bucket_transitions(self, temp_storage, test_config_minimal):
        """Test le traitement des transitions entre buckets"""
        # Configuration avec règles de transition
        config = test_config_minimal.copy()
        config["retention"] = {
            "rules": [
                {
                    "from_bucket": "live",
                    "to_bucket": "chaud", 
                    "after_days": 7
                },
                {
                    "from_bucket": "chaud",
                    "to_bucket": "tiede",
                    "after_days": 30
                }
            ]
        }
        
        manager = RetentionManager(config, temp_storage, Mock())
        
        # Mock des IOCs à transférer
        mock_iocs_to_transfer = [
            {"value": "192.168.1.1", "type": "ipv4", "age_days": 10},
            {"value": "example.com", "type": "domain", "age_days": 35}
        ]
        
        with patch.object(manager, '_find_iocs_for_transition', return_value=mock_iocs_to_transfer):
            with patch.object(temp_storage, '_move_ioc_between_buckets', return_value=True) as mock_move:
                result = manager._process_bucket_transitions()
                
                assert result["total_processed"] == 2
                assert result["moved"] == 2
                assert mock_move.call_count == 2

    def test_find_iocs_for_transition(self, temp_storage, test_config_minimal):
        """Test la recherche d'IOCs à transférer"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        rule = {
            "from_bucket": "live",
            "to_bucket": "chaud",
            "after_days": 7
        }
        
        # Mock de la base de données
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor
        
        # IOCs anciens (>7 jours)
        mock_cursor.fetchall.return_value = [
            ("192.168.1.1", "ipv4", "2024-01-01 00:00:00"),
            ("example.com", "domain", "2024-01-02 00:00:00")
        ]
        
        with patch('sqlite3.connect', return_value=mock_connection):
            iocs = manager._find_iocs_for_transition(rule)
            
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
            [("live", 100)],     # Première requête: count par bucket
            [("ipv4", 50), ("domain", 30), ("url", 20)],  # Seconde requête: count par type
            [(datetime.now() - timedelta(days=1),)],  # Troisième requête: dernière mise à jour
        ]
        
        with patch('sqlite3.connect', return_value=mock_connection):
            stats = manager.get_retention_stats()
            
            assert "total_iocs" in stats
            assert "by_bucket" in stats
            assert "by_type" in stats
            assert "last_update" in stats

    def test_audit_retention_system(self, temp_storage, test_config_minimal):
        """Test de l'audit du système de rétention"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        with patch.object(manager, 'check_duplicate_iocs', return_value=[]):
            with patch.object(manager, '_check_bucket_integrity', return_value={"issues": []}):
                with patch.object(manager, '_check_retention_rules', return_value={"violations": []}):
                    audit_result = manager.audit_retention_system()
                    
                    assert "duplicates" in audit_result
                    assert "integrity" in audit_result
                    assert "rule_violations" in audit_result
                    assert "timestamp" in audit_result

    def test_check_bucket_integrity_success(self, temp_storage, test_config_minimal):
        """Test la vérification d'intégrité des buckets sans problème"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # Mock d'une base cohérente
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []  # Aucune incohérence
        
        with patch('sqlite3.connect', return_value=mock_connection):
            result = manager._check_bucket_integrity()
            
            assert "issues" in result
            assert len(result["issues"]) == 0

    def test_check_bucket_integrity_with_issues(self, temp_storage, test_config_minimal):
        """Test la vérification d'intégrité avec des problèmes détectés"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # Mock avec des incohérences
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            ("192.168.1.1", "ipv4", "missing_file"),
            ("example.com", "domain", "orphaned_db_entry")
        ]
        
        with patch('sqlite3.connect', return_value=mock_connection):
            result = manager._check_bucket_integrity()
            
            assert "issues" in result
            assert len(result["issues"]) == 2

    def test_check_retention_rules_compliance(self, temp_storage, test_config_minimal):
        """Test la vérification du respect des règles de rétention"""
        # Configuration avec règles de rétention
        config = test_config_minimal.copy()
        config["retention"] = {
            "rules": [
                {"from_bucket": "live", "to_bucket": "chaud", "after_days": 7}
            ]
        }
        
        manager = RetentionManager(config, temp_storage, Mock())
        
        # Mock des violations
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            ("192.168.1.1", "ipv4", "live", "2024-01-01 00:00:00")  # IOC trop ancien
        ]
        
        with patch('sqlite3.connect', return_value=mock_connection):
            result = manager._check_retention_rules()
            
            assert "violations" in result
            assert len(result["violations"]) == 1

    def test_error_handling_database_connection(self, temp_storage, test_config_minimal):
        """Test la gestion d'erreur de connexion à la base"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        with patch('sqlite3.connect', side_effect=sqlite3.Error("Connection failed")):
            result = manager.check_duplicate_iocs()
            
            # Devrait retourner une liste vide et logger l'erreur
            assert result == []

    def test_error_handling_file_operations(self, temp_storage, test_config_minimal):
        """Test la gestion d'erreur des opérations fichier"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        duplicate = {
            "value": "192.168.1.1",
            "type": "ipv4",
            "buckets": ["live", "chaud"]
        }
        
        # Mock d'erreur lors du déplacement de fichier
        with patch.object(temp_storage, '_move_ioc_between_buckets', side_effect=Exception("File error")):
            result = manager._resolve_duplicate(duplicate)
            
            assert result is False

    def test_concurrent_retention_processing(self, temp_storage, test_config_minimal):
        """Test le traitement concurrent des rétentions"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        import threading
        import time
        
        results = []
        
        def process_retentions():
            with patch.object(manager, '_process_bucket_transitions', return_value={"total_processed": 0, "moved": 0}):
                with patch.object(manager, 'check_duplicate_iocs', return_value=[]):
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
            assert "transitions" in result
            assert "duplicates_fixed" in result

    def test_large_dataset_retention_processing(self, temp_storage, test_config_minimal):
        """Test le traitement de rétention sur un gros dataset"""
        manager = RetentionManager(test_config_minimal, temp_storage, Mock())
        
        # Mock d'un grand nombre de doublons
        large_duplicates = []
        for i in range(1000):
            large_duplicates.append({
                "value": f"192.168.1.{i}",
                "type": "ipv4",
                "buckets": ["live", "chaud"]
            })
        
        with patch.object(manager, 'check_duplicate_iocs', return_value=large_duplicates):
            with patch.object(manager, '_resolve_duplicate', return_value=True):
                result = manager.fix_duplicate_iocs()
                
                assert result["total_duplicates"] == 1000
                assert result["fixed"] == 1000

    def test_retention_manager_configuration_validation(self, temp_directory):
        """Test la validation de la configuration du RetentionManager"""
        invalid_config = {
            "retention": {
                "rules": [
                    {
                        "from_bucket": "invalid_bucket",  # Bucket invalide
                        "to_bucket": "chaud",
                        "after_days": 7
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