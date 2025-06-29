"""
Tests d'intégration pour le workflow complet TinyCTI
"""

import pytest
import tempfile
import time
import requests_mock
from pathlib import Path
from unittest.mock import patch, Mock

from tinycti import TinyCTI, TinyCTIAPI, IOCStorage, RetentionManager


class TestFullWorkflow:
    """Tests d'intégration du workflow complet"""

    @pytest.fixture
    def integration_config(self, temp_directory):
        """Configuration complète pour les tests d'intégration"""
        return {
            "feeds": [
                {
                    "name": "test_ipv4_feed",
                    "type": "text",
                    "url": "http://example.com/ipv4.txt",
                    "enabled": True,
                    "retention": "live",
                    "schedule": "1h",
                    "timeout": 30
                },
                {
                    "name": "test_domain_feed", 
                    "type": "text",
                    "url": "http://example.com/domains.txt",
                    "enabled": True,
                    "retention": "chaud",
                    "schedule": "2h",
                    "timeout": 30
                }
            ],
            "output_dir": str(temp_directory),
            "logging": {
                "level": "DEBUG",
                "file": str(temp_directory / "tinycti.log"),
                "max_size": "1MB",
                "backup_count": 3,
                "compression": False,
                "audit_enabled": True,
                "audit_file": str(temp_directory / "audit.log")
            },
            "api": {
                "host": "127.0.0.1",
                "port": 5000,
                "auth": {
                    "enabled": False,
                    "password": "test_password",
                    "rate_limit": {
                        "enabled": True,
                        "requests_per_minute": 60,
                        "burst": 10
                    }
                }
            },
            "authentication": {
                "users": {
                    "admin": {
                        "password_hash": "$2b$12$LQv9YB.JcTiWJ9L8JSUQie7KwKy7W3aEJJIr3k9KtKcvFfK6Dt5o2",
                        "role": "admin"
                    }
                }
            },
            "retention": {
                "enabled": True,
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
        }

    def test_tinycti_initialization_complete(self, integration_config):
        """Test l'initialisation complète de TinyCTI"""
        tinycti = TinyCTI(integration_config)
        
        assert tinycti.config == integration_config
        assert tinycti.storage is not None
        assert tinycti.retention_manager is not None
        assert tinycti.error_handler is not None
        assert len(tinycti.feeds) == 2

    def test_feed_processing_workflow(self, integration_config):
        """Test le workflow complet de traitement des feeds"""
        with requests_mock.Mocker() as m:
            # Mock des réponses des feeds
            m.get("http://example.com/ipv4.txt", text="192.168.1.1\n10.0.0.1\n172.16.1.1")
            m.get("http://example.com/domains.txt", text="malicious.com\nexample.org\ntest.net")
            
            tinycti = TinyCTI(integration_config)
            
            # Traite les feeds
            results = tinycti.process_feeds()
            
            # Vérifie que les feeds ont été traités
            assert len(results) == 2
            
            # Vérifie que les IOCs ont été stockés
            for result in results:
                assert result["status"] == "success"
                assert result["stats"]["total"] > 0

    def test_api_integration_with_storage(self, integration_config):
        """Test l'intégration API avec le système de stockage"""
        tinycti = TinyCTI(integration_config)
        api = TinyCTIAPI(tinycti)
        
        # Ajoute quelques IOCs au stockage
        test_iocs = [
            {"value": "192.168.1.1", "type": "ipv4"},
            {"value": "example.com", "type": "domain"},
            {"value": "malicious.com", "type": "domain"}
        ]
        
        # Simule l'ajout d'IOCs
        with patch.object(tinycti.storage, 'get_iocs_by_type') as mock_get_iocs:
            mock_get_iocs.return_value = test_iocs
            
            # Test l'API client
            with api.app.test_client() as client:
                response = client.get('/api/export/json/ipv4')
                assert response.status_code == 200
                
                response = client.get('/api/export/json/domain')
                assert response.status_code == 200

    def test_retention_integration_workflow(self, integration_config):
        """Test l'intégration du système de rétention"""
        tinycti = TinyCTI(integration_config)
        
        # Ajoute des IOCs de test avec différents buckets
        from tinycti import IOC, IOCType, RetentionBucket
        test_iocs = [
            IOC("192.168.1.1", IOCType.IPV4, "test_feed", RetentionBucket.LIVE),
            IOC("10.0.0.1", IOCType.IPV4, "test_feed", RetentionBucket.CHAUD),
            IOC("example.com", IOCType.DOMAIN, "test_feed", RetentionBucket.FROID)
        ]
        
        # Stocke les IOCs
        tinycti.storage.store_iocs(test_iocs)
        
        # Traite les rétentions
        retention_result = tinycti.retention_manager.process_retentions()
        
        assert "transitions" in retention_result
        assert "duplicates_fixed" in retention_result

    def test_error_handling_integration(self, integration_config):
        """Test l'intégration de la gestion d'erreurs"""
        tinycti = TinyCTI(integration_config)
        
        # Simule une erreur dans le traitement des feeds
        with requests_mock.Mocker() as m:
            # Mock qui retourne une erreur 500
            m.get("http://example.com/ipv4.txt", status_code=500)
            m.get("http://example.com/domains.txt", text="valid.com\ntest.org")
            
            results = tinycti.process_feeds()
            
            # Un feed devrait échouer, l'autre réussir
            failed_feeds = [r for r in results if r["status"] == "error"]
            successful_feeds = [r for r in results if r["status"] == "success"]
            
            assert len(failed_feeds) == 1
            assert len(successful_feeds) == 1
            
            # Vérifie les statistiques d'erreurs
            error_stats = tinycti.error_handler.get_error_stats()
            assert error_stats["total_errors"] > 0

    def test_concurrent_operations(self, integration_config):
        """Test les opérations concurrentes"""
        import threading
        import time
        
        tinycti = TinyCTI(integration_config)
        results = []
        
        def process_feeds_worker():
            with requests_mock.Mocker() as m:
                m.get("http://example.com/ipv4.txt", text="192.168.1.1\n10.0.0.1")
                m.get("http://example.com/domains.txt", text="test.com\nexample.org")
                
                result = tinycti.process_feeds()
                results.append(result)
        
        def retention_worker():
            result = tinycti.retention_manager.process_retentions()
            results.append(result)
        
        # Lance les workers en parallèle
        threads = [
            threading.Thread(target=process_feeds_worker),
            threading.Thread(target=retention_worker)
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Vérifie que les opérations ont réussi
        assert len(results) == 2

    def test_configuration_reload(self, integration_config, temp_directory):
        """Test le rechargement de configuration"""
        tinycti = TinyCTI(integration_config)
        
        # Modifie la configuration
        new_config = integration_config.copy()
        new_config["feeds"].append({
            "name": "new_feed",
            "type": "text",
            "url": "http://example.com/new.txt",
            "enabled": True,
            "retention": "live"
        })
        
        # Recharge la configuration
        tinycti.reload_config(new_config)
        
        # Vérifie que les nouveaux feeds sont pris en compte
        assert len(tinycti.feeds) == 3
        assert any(feed.name == "new_feed" for feed in tinycti.feeds)

    def test_data_persistence(self, integration_config):
        """Test la persistance des données"""
        # Premier instance TinyCTI
        tinycti1 = TinyCTI(integration_config)
        
        # Ajoute des IOCs
        from tinycti import IOC, IOCType, RetentionBucket
        test_iocs = [
            IOC("persistent.test", IOCType.DOMAIN, "test", RetentionBucket.LIVE),
            IOC("192.168.100.1", IOCType.IPV4, "test", RetentionBucket.CHAUD)
        ]
        
        tinycti1.storage.store_iocs(test_iocs)
        
        # Nouvelle instance TinyCTI (simule redémarrage)
        tinycti2 = TinyCTI(integration_config)
        
        # Vérifie que les données sont persistées
        stored_data = tinycti2.storage.get_all_iocs()
        stored_values = [ioc["value"] for ioc in stored_data]
        
        assert "persistent.test" in stored_values
        assert "192.168.100.1" in stored_values

    def test_large_dataset_processing(self, integration_config):
        """Test le traitement de gros datasets"""
        # Génère un gros dataset
        large_ipv4_list = "\n".join([f"192.168.{i//256}.{i%256}" for i in range(1000)])
        large_domain_list = "\n".join([f"test{i}.example.com" for i in range(500)])
        
        with requests_mock.Mocker() as m:
            m.get("http://example.com/ipv4.txt", text=large_ipv4_list)
            m.get("http://example.com/domains.txt", text=large_domain_list)
            
            tinycti = TinyCTI(integration_config)
            
            # Mesure le temps de traitement
            start_time = time.time()
            results = tinycti.process_feeds()
            end_time = time.time()
            
            processing_time = end_time - start_time
            
            # Vérifie que le traitement est raisonnable (moins de 30 secondes)
            assert processing_time < 30
            
            # Vérifie que tous les IOCs ont été traités
            total_processed = sum(r["stats"]["total"] for r in results if r["status"] == "success")
            assert total_processed == 1500

    def test_api_performance_under_load(self, integration_config):
        """Test les performances de l'API sous charge"""
        tinycti = TinyCTI(integration_config)
        api = TinyCTIAPI(tinycti)
        
        # Ajoute des données de test
        test_data = [{"value": f"test{i}.com", "type": "domain"} for i in range(100)]
        
        with patch.object(tinycti.storage, 'get_iocs_by_type', return_value=test_data):
            with api.app.test_client() as client:
                # Fait plusieurs requêtes simultanées
                import threading
                import time
                
                response_times = []
                
                def make_request():
                    start = time.time()
                    response = client.get('/api/export/json/domain')
                    end = time.time()
                    response_times.append(end - start)
                    assert response.status_code == 200
                
                # Lance 10 requêtes simultanées
                threads = []
                for _ in range(10):
                    thread = threading.Thread(target=make_request)
                    threads.append(thread)
                    thread.start()
                
                for thread in threads:
                    thread.join()
                
                # Vérifie que les temps de réponse sont acceptables
                avg_response_time = sum(response_times) / len(response_times)
                assert avg_response_time < 1.0  # Moins d'une seconde en moyenne

    def test_graceful_shutdown(self, integration_config):
        """Test l'arrêt gracieux du système"""
        tinycti = TinyCTI(integration_config)
        api = TinyCTIAPI(tinycti)
        
        # Simule des opérations en cours
        with requests_mock.Mocker() as m:
            m.get("http://example.com/ipv4.txt", text="192.168.1.1")
            m.get("http://example.com/domains.txt", text="test.com")
            
            # Lance le traitement
            results = tinycti.process_feeds()
            
            # Simule l'arrêt
            tinycti.shutdown()
            
            # Vérifie que les données ont été sauvegardées
            assert all(r["status"] in ["success", "error"] for r in results)

    @pytest.mark.slow
    def test_long_running_operations(self, integration_config):
        """Test les opérations de longue durée"""
        tinycti = TinyCTI(integration_config)
        
        # Simule une opération longue avec des feeds lents
        with requests_mock.Mocker() as m:
            def slow_response(request, context):
                time.sleep(2)  # Simule une réponse lente
                return "192.168.1.1\n10.0.0.1"
            
            m.get("http://example.com/ipv4.txt", text=slow_response)
            m.get("http://example.com/domains.txt", text="test.com")
            
            start_time = time.time()
            results = tinycti.process_feeds()
            end_time = time.time()
            
            # Vérifie que l'opération a pris du temps mais s'est terminée
            assert end_time - start_time >= 2
            assert all(r["status"] in ["success", "error"] for r in results)

    def test_memory_usage_stability(self, integration_config):
        """Test la stabilité de l'utilisation mémoire"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        tinycti = TinyCTI(integration_config)
        
        # Traite plusieurs cycles de données
        for cycle in range(5):
            with requests_mock.Mocker() as m:
                large_data = "\n".join([f"test{i}_{cycle}.com" for i in range(100)])
                m.get("http://example.com/ipv4.txt", text="192.168.1.1")
                m.get("http://example.com/domains.txt", text=large_data)
                
                tinycti.process_feeds()
                
                # Force le garbage collection
                import gc
                gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # L'augmentation mémoire ne devrait pas être excessive (< 100MB)
        assert memory_increase < 100 * 1024 * 1024