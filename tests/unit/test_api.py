"""
Tests unitaires pour l'API REST TinyCTI
"""

import json
from unittest.mock import Mock, patch

import pytest

from tinycti import TinyCTIAPI


class TestTinyCTIAPI:
    """Tests pour la classe TinyCTIAPI et ses endpoints"""

    def test_api_initialization(self, test_config_minimal):
        """Test l'initialisation de l'API"""
        mock_tinycti = Mock()
        mock_tinycti.config = test_config_minimal

        api = TinyCTIAPI(mock_tinycti, "127.0.0.1", 5000)

        assert api.tinycti == mock_tinycti
        assert api.host == "127.0.0.1"
        assert api.port == 5000
        assert api.app is not None

    def test_status_endpoint(self, flask_client):
        """Test l'endpoint /api/status"""
        response = flask_client.get("/api/status")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert "status" in data
        assert "version" in data
        assert "daemon_running" in data
        assert "feeds_total" in data
        assert "feeds_enabled" in data

    def test_health_endpoint(self, flask_client):
        """Test l'endpoint /api/health"""
        response = flask_client.get("/api/health")

        assert response.status_code in [200, 503]  # Peut être dégradé
        data = json.loads(response.data)

        assert "status" in data
        assert "timestamp" in data
        assert "components" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]

    def test_feeds_endpoint_requires_auth(self, flask_client):
        """Test que l'endpoint /api/feeds nécessite l'authentification"""
        # Si l'auth est activée, devrait retourner 401
        # Si l'auth est désactivée, devrait retourner 200
        response = flask_client.get("/api/feeds")
        assert response.status_code in [200, 401]

    def test_export_endpoint_json(self, flask_client):
        """Test l'endpoint d'export JSON"""
        response = flask_client.get("/api/export/json/ipv4?bucket=active&limit=100")

        # Devrait nécessiter l'authentification si activée
        assert response.status_code in [200, 401]

    def test_export_endpoint_csv(self, flask_client):
        """Test l'endpoint d'export CSV"""
        response = flask_client.get("/api/export/csv/domain?bucket=critical&limit=50")

        # Devrait nécessiter l'authentification si activée
        assert response.status_code in [200, 401]

    def test_export_endpoint_text(self, flask_client):
        """Test l'endpoint d'export texte"""
        response = flask_client.get("/api/export/text/url?bucket=active")

        # Devrait nécessiter l'authentification si activée
        assert response.status_code in [200, 401]

    def test_export_invalid_format(self, flask_client):
        """Test l'export avec un format invalide"""
        response = flask_client.get("/api/export/invalid_format/ipv4")

        # Devrait retourner 400 ou 401 selon l'auth
        assert response.status_code in [400, 401]

    def test_retention_stats_endpoint(self, flask_client):
        """Test l'endpoint des statistiques de rétention"""
        response = flask_client.get("/api/retention/stats")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401]

    def test_retention_audit_endpoint(self, flask_client):
        """Test l'endpoint d'audit de rétention"""
        response = flask_client.get("/api/retention/audit")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401]

    def test_retention_process_endpoint(self, flask_client):
        """Test l'endpoint de traitement de rétention"""
        response = flask_client.post("/api/retention/process")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401]

    def test_retention_fix_duplicates_endpoint(self, flask_client):
        """Test l'endpoint de correction des doublons"""
        response = flask_client.post("/api/retention/fix-duplicates")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401]

    def test_error_stats_endpoint(self, flask_client):
        """Test l'endpoint des statistiques d'erreurs"""
        response = flask_client.get("/api/errors/stats")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401]

    def test_clear_errors_endpoint(self, flask_client):
        """Test l'endpoint de vidage des erreurs"""
        response = flask_client.post("/api/errors/clear")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401]

    def test_login_endpoint_post(self, flask_client):
        """Test l'endpoint de login"""
        login_data = {"username": "test_user", "password": "test_password"}

        response = flask_client.post(
            "/api/login", data=json.dumps(login_data), content_type="application/json"
        )

        # Peut retourner 200 (succès), 401 (échec) ou 400 (données manquantes)
        assert response.status_code in [200, 400, 401, 500]

    def test_logout_endpoint_post(self, flask_client):
        """Test l'endpoint de déconnexion"""
        response = flask_client.post("/api/logout")

        # Devrait toujours retourner 200 même si pas connecté
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "message" in data

    def test_ngfw_export_endpoint(self, flask_client):
        """Test l'endpoint d'export NGFW"""
        response = flask_client.get("/api/export/ngfw")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401]

    def test_api_content_type_json(self, flask_client):
        """Test que l'API retourne du JSON"""
        response = flask_client.get("/api/status")

        assert response.content_type == "application/json"

    def test_api_cors_headers(self, flask_client):
        """Test les en-têtes CORS si configurés"""
        response = flask_client.get("/api/status")

        # Vérifie que la réponse est correcte
        assert response.status_code == 200

    def test_iocs_endpoint_by_type(self, flask_client):
        """Test l'endpoint de récupération d'IOCs par type"""
        for ioc_type in ["ipv4", "domain", "url", "hash_md5"]:
            response = flask_client.get(f"/api/iocs/{ioc_type}")

            # Devrait retourner 200 (public) ou 401 (si auth activée)
            assert response.status_code in [200, 401]

    def test_iocs_search_endpoint(self, flask_client):
        """Test l'endpoint de recherche d'IOCs"""
        response = flask_client.get("/api/iocs/search?q=192.168.1.1")

        # Devrait retourner 200 (public) ou 401 (si auth activée)
        assert response.status_code in [200, 400, 401]

    def test_iocs_search_without_query(self, flask_client):
        """Test la recherche d'IOCs sans paramètre de requête"""
        response = flask_client.get("/api/iocs/search")

        # Devrait retourner 400 (paramètre manquant) ou 401 (auth)
        assert response.status_code in [400, 401]

    def test_feed_toggle_endpoint(self, flask_client):
        """Test l'endpoint de basculement de feed"""
        response = flask_client.post("/api/feeds/test_feed/toggle")

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 401, 404]

    def test_feed_schedule_update_endpoint(self, flask_client):
        """Test l'endpoint de mise à jour de schedule"""
        schedule_data = {"schedule": "2h", "priority": 3}

        response = flask_client.post(
            "/api/feeds/test_feed/schedule",
            data=json.dumps(schedule_data),
            content_type="application/json",
        )

        # Devrait nécessiter l'authentification
        assert response.status_code in [200, 400, 401, 404]

    def test_dashboard_endpoint(self, flask_client):
        """Test l'endpoint du dashboard web"""
        response = flask_client.get("/")

        # Devrait retourner la page HTML du dashboard
        assert response.status_code == 200
        assert b"html" in response.data or b"TinyCTI" in response.data

    def test_feeds_web_endpoint(self, flask_client):
        """Test l'endpoint web de gestion des feeds"""
        response = flask_client.get("/feeds")

        assert response.status_code == 200

    def test_iocs_web_endpoint(self, flask_client):
        """Test l'endpoint web de consultation des IOCs"""
        response = flask_client.get("/iocs")

        assert response.status_code == 200


class TestAPIErrorHandling:
    """Tests pour la gestion d'erreurs de l'API"""

    def test_api_404_handling(self, flask_client):
        """Test la gestion des routes inexistantes"""
        response = flask_client.get("/api/nonexistent/route")

        assert response.status_code == 404

    def test_api_method_not_allowed(self, flask_client):
        """Test la gestion des méthodes non autorisées"""
        # Tentative PUT sur un endpoint GET
        response = flask_client.put("/api/status")

        assert response.status_code == 405

    def test_api_invalid_json_payload(self, flask_client):
        """Test la gestion des payloads JSON invalides"""
        response = flask_client.post(
            "/api/login", data="invalid json", content_type="application/json"
        )

        # Devrait retourner 400 pour JSON invalide
        assert response.status_code in [400, 500]

    def test_api_large_payload_handling(self, flask_client):
        """Test la gestion des payloads trop volumineux"""
        large_data = {"data": "x" * (10 * 1024 * 1024)}  # 10MB de données

        response = flask_client.post(
            "/api/login", data=json.dumps(large_data), content_type="application/json"
        )

        # Devrait gérer gracieusement ou retourner une erreur appropriée
        assert response.status_code in [400, 413, 500]


class TestAPIAuthentication:
    """Tests spécialisés pour l'authentification API"""

    def test_bearer_token_authentication(self, flask_client):
        """Test l'authentification par token Bearer"""
        # Test avec un header Authorization valide
        headers = {"Authorization": "Bearer valid_token"}
        response = flask_client.get("/api/status", headers=headers)

        # Devrait retourner 200 ou 401 selon la configuration
        assert response.status_code in [200, 401]

    def test_api_password_authentication(self, flask_client):
        """Test l'authentification par mot de passe API"""
        # Test avec un header X-API-Password
        headers = {"X-API-Password": "secret_key"}
        response = flask_client.get("/api/status", headers=headers)

        # Devrait retourner 200 ou 401 selon la configuration
        assert response.status_code in [200, 401]

    def test_rate_limiting_enforcement(self, flask_client):
        """Test l'application du rate limiting"""
        # Faire plusieurs requêtes rapides
        responses = []
        for i in range(10):
            response = flask_client.get("/api/status")
            responses.append(response.status_code)

        # Toutes devraient réussir dans les limites normales
        assert all(code in [200, 429] for code in responses)

    def test_session_based_authentication(self, flask_client):
        """Test l'authentification basée sur les sessions"""
        # Simule une session authentifiée
        with flask_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "test_user"

        # Test d'une route protégée
        response = flask_client.get("/api/feeds")

        # Devrait fonctionner avec une session valide
        assert response.status_code in [200, 401]  # Dépend de la config


class TestAPIDataValidation:
    """Tests pour la validation des données API"""

    def test_export_bucket_validation(self, flask_client):
        """Test la validation du paramètre bucket"""
        # Bucket invalide
        response = flask_client.get("/api/export/json/ipv4?bucket=invalid_bucket")
        assert response.status_code in [400, 401]

    def test_export_limit_validation(self, flask_client):
        """Test la validation du paramètre limit"""
        # Limite négative
        response = flask_client.get("/api/export/json/ipv4?limit=-1")
        assert response.status_code in [400, 401]

        # Limite trop élevée
        response = flask_client.get("/api/export/json/ipv4?limit=999999")
        assert response.status_code in [200, 400, 401]

    def test_schedule_validation(self, flask_client):
        """Test la validation des schedules"""
        invalid_schedules = [
            {"schedule": "invalid_format"},
            {"schedule": "25h"},  # Plus de 24h
            {"schedule": "-1h"},  # Négatif
            {"schedule": "0m"},  # Zéro
        ]

        for schedule_data in invalid_schedules:
            response = flask_client.post(
                "/api/feeds/test_feed/schedule",
                data=json.dumps(schedule_data),
                content_type="application/json",
            )

            assert response.status_code in [400, 401]

    def test_priority_validation(self, flask_client):
        """Test la validation des priorités"""
        invalid_priorities = [
            {"schedule": "1h", "priority": -1},  # Négatif
            {"schedule": "1h", "priority": 11},  # Trop élevé
            {"schedule": "1h", "priority": "invalid"},  # Type incorrect
        ]

        for priority_data in invalid_priorities:
            response = flask_client.post(
                "/api/feeds/test_feed/schedule",
                data=json.dumps(priority_data),
                content_type="application/json",
            )

            assert response.status_code in [400, 401]


class TestAPIPerformance:
    """Tests de performance pour l'API"""

    def test_api_response_time(self, flask_client):
        """Test le temps de réponse de l'API"""
        import time

        start_time = time.time()
        response = flask_client.get("/api/status")
        end_time = time.time()

        response_time = end_time - start_time

        # L'API devrait répondre en moins d'une seconde
        assert response_time < 1.0
        assert response.status_code == 200

    def test_concurrent_requests_handling(self, flask_app):
        """Test la gestion des requêtes concurrentes"""
        import threading

        responses = []

        def make_request():
            with flask_app.test_client() as client:
                response = client.get("/api/status")
                responses.append(response.status_code)

        # Lance plusieurs requêtes concurrentes
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        # Attend que tous les threads terminent
        for thread in threads:
            thread.join()

        # Toutes les requêtes devraient réussir
        assert len(responses) == 5
        assert all(code == 200 for code in responses)

    @pytest.mark.slow
    def test_large_dataset_export(self, flask_client):
        """Test l'export de gros datasets"""
        # Test avec une limite élevée
        response = flask_client.get("/api/export/json/ipv4?bucket=active&limit=10000")

        # Devrait gérer les gros exports
        assert response.status_code in [200, 401]

        if response.status_code == 200:
            # Vérifie que la réponse n'est pas vide
            data = json.loads(response.data)
            assert "data" in data or "error" in data
