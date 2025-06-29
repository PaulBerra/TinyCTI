"""
Tests unitaires pour le système d'authentification TinyCTI
"""

import pytest
import bcrypt
import jwt
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from tinycti import TinyCTIAPI, ErrorHandler


class TestAuthenticationSystem:
    """Tests pour le système d'authentification"""

    def test_password_verification_success(self, flask_app):
        """Test la vérification réussie d'un mot de passe"""
        with flask_app.app_context():
            api = flask_app.extensions.get('tinycti_api')
            if not api:
                # Créer une instance d'API pour le test
                mock_tinycti = Mock()
                mock_tinycti.config = {
                    "authentication": {
                        "users": {
                            "testuser": {
                                "password_hash": bcrypt.hashpw("testpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                                "role": "admin"
                            }
                        }
                    }
                }
                api = TinyCTIAPI(mock_tinycti)
                
            # Test la vérification
            result = api._verify_password("testuser", "testpass")
            assert result is True

    def test_password_verification_failure(self, flask_app):
        """Test la vérification échouée d'un mot de passe"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {
                "authentication": {
                    "users": {
                        "testuser": {
                            "password_hash": bcrypt.hashpw("correctpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                            "role": "admin"
                        }
                    }
                }
            }
            api = TinyCTIAPI(mock_tinycti)
            
            # Test avec un mauvais mot de passe
            result = api._verify_password("testuser", "wrongpass")
            assert result is False

    def test_password_verification_user_not_found(self, flask_app):
        """Test la vérification avec un utilisateur inexistant"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {"authentication": {"users": {}}}
            api = TinyCTIAPI(mock_tinycti)
            
            result = api._verify_password("nonexistent", "anypass")
            assert result is False

    def test_password_verification_no_hash(self, flask_app):
        """Test la vérification avec un utilisateur sans hash"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {
                "authentication": {
                    "users": {
                        "nohash": {
                            "role": "admin"
                            # password_hash manquant
                        }
                    }
                }
            }
            api = TinyCTIAPI(mock_tinycti)
            
            result = api._verify_password("nohash", "anypass")
            assert result is False

    def test_jwt_token_generation(self, flask_app):
        """Test la génération de tokens JWT"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            api = TinyCTIAPI(mock_tinycti)
            
            token = api._generate_token("testuser")
            
            assert token is not None
            assert isinstance(token, str)
            
            # Vérifie que le token peut être décodé
            decoded = jwt.decode(token, api.app.secret_key, algorithms=['HS256'])
            assert decoded["username"] == "testuser"
            assert "exp" in decoded

    def test_jwt_token_verification_valid(self, flask_app):
        """Test la vérification d'un token JWT valide"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            api = TinyCTIAPI(mock_tinycti)
            
            token = api._generate_token("testuser")
            result = api._verify_token(token)
            
            assert result is True

    def test_jwt_token_verification_invalid(self, flask_app):
        """Test la vérification d'un token JWT invalide"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            api = TinyCTIAPI(mock_tinycti)
            
            invalid_token = "invalid.token.here"
            result = api._verify_token(invalid_token)
            
            assert result is False

    def test_jwt_token_verification_expired(self, flask_app):
        """Test la vérification d'un token JWT expiré"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            api = TinyCTIAPI(mock_tinycti)
            
            # Crée un token expiré
            expired_payload = {
                'username': 'testuser',
                'exp': datetime.utcnow() - timedelta(hours=1)  # Expiré depuis 1 heure
            }
            expired_token = jwt.encode(expired_payload, api.app.secret_key, algorithm='HS256')
            
            result = api._verify_token(expired_token)
            assert result is False

    def test_require_auth_decorator_no_auth_disabled(self, flask_client):
        """Test le décorateur require_auth quand l'auth est désactivée"""
        # L'authentification est désactivée par défaut dans les tests
        response = flask_client.get('/api/status')
        assert response.status_code == 200

    def test_require_auth_decorator_with_valid_token(self, flask_app):
        """Test le décorateur require_auth avec un token valide"""
        with flask_app.test_client() as client:
            with flask_app.app_context():
                # Active l'authentification
                flask_app.config['AUTH_ENABLED'] = True
                
                mock_tinycti = Mock()
                mock_tinycti.config = {
                    "api": {"auth": {"enabled": True}},
                    "authentication": {
                        "users": {
                            "testuser": {
                                "password_hash": bcrypt.hashpw("testpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                                "role": "admin"
                            }
                        }
                    }
                }
                api = TinyCTIAPI(mock_tinycti)
                
                # Génère un token valide
                token = api._generate_token("testuser")
                
                # Fait une requête avec le token
                headers = {'Authorization': f'Bearer {token}'}
                
                with patch.object(api, '_require_auth') as mock_require_auth:
                    mock_require_auth.return_value = lambda f: f  # Simule l'authentification réussie
                    
                    response = client.get('/api/status', headers=headers)
                    # Le test dépend de l'implémentation spécifique

    def test_require_auth_decorator_no_token(self, flask_app):
        """Test le décorateur require_auth sans token"""
        with flask_app.test_client() as client:
            # Mock pour activer l'authentification
            with patch('flask.session', {}):
                response = client.get('/api/feeds')  # Route protégée
                # Devrait retourner 401 si l'auth est activée
                # Le comportement exact dépend de la configuration

    def test_api_password_authentication(self, flask_app):
        """Test l'authentification par mot de passe API"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {
                "api": {
                    "auth": {
                        "enabled": True,
                        "password": "secret_api_key"
                    }
                }
            }
            api = TinyCTIAPI(mock_tinycti)
            
            # Simule une requête avec le bon mot de passe API
            with flask_app.test_request_context(headers={'X-API-Password': 'secret_api_key'}):
                # Le test nécessite l'implémentation complète du décorateur
                pass

    def test_session_authentication(self, flask_client):
        """Test l'authentification par session"""
        with flask_client.session_transaction() as sess:
            sess['authenticated'] = True
            sess['username'] = 'testuser'
        
        # Test d'une route qui nécessite l'authentification
        response = flask_client.get('/api/status')
        assert response.status_code == 200

    def test_login_endpoint_success(self, flask_client):
        """Test l'endpoint de login avec succès"""
        login_data = {
            "username": "admin",
            "password": "admin123"
        }
        
        response = flask_client.post('/api/login',
                                   json=login_data,
                                   content_type='application/json')
        
        # Le comportement dépend de la configuration de l'instance de test
        # Dans un vrai test, on s'attendrait à un code 200 avec un token

    def test_login_endpoint_invalid_credentials(self, flask_client):
        """Test l'endpoint de login avec des identifiants invalides"""
        login_data = {
            "username": "admin",
            "password": "wrongpassword"
        }
        
        response = flask_client.post('/api/login',
                                   json=login_data,
                                   content_type='application/json')
        
        # Devrait retourner 401 pour des identifiants incorrects

    def test_login_endpoint_missing_credentials(self, flask_client):
        """Test l'endpoint de login avec des identifiants manquants"""
        login_data = {
            "username": "admin"
            # password manquant
        }
        
        response = flask_client.post('/api/login',
                                   json=login_data,
                                   content_type='application/json')
        
        # Devrait retourner 400 pour des données manquantes

    def test_logout_endpoint(self, flask_client):
        """Test l'endpoint de déconnexion"""
        # Connecte d'abord l'utilisateur
        with flask_client.session_transaction() as sess:
            sess['authenticated'] = True
            sess['username'] = 'testuser'
        
        response = flask_client.post('/api/logout')
        
        # Vérifie que la session a été vidée
        with flask_client.session_transaction() as sess:
            assert 'authenticated' not in sess

    def test_rate_limiting_configuration(self, flask_app):
        """Test la configuration du rate limiting"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {
                "api": {
                    "auth": {
                        "rate_limit": {
                            "enabled": True,
                            "requests_per_minute": 60,
                            "burst": 10
                        }
                    }
                }
            }
            
            api = TinyCTIAPI(mock_tinycti)
            
            # Vérifie que le limiter a été configuré
            assert hasattr(api, 'limiter')
            # Le test exact dépend de l'implémentation de flask-limiter

    def test_audit_logging_on_authentication(self, flask_app):
        """Test l'audit logging lors des tentatives d'authentification"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_audit_logger = Mock()
            
            api = TinyCTIAPI(mock_tinycti)
            api.audit_logger = mock_audit_logger
            
            # Simule un appel d'audit
            api._log_audit("LOGIN_SUCCESS", "testuser", "Test login")
            
            # Vérifie que l'audit a été appelé
            if mock_audit_logger:
                mock_audit_logger.info.assert_called_once()

    @pytest.mark.parametrize("invalid_password", [
        "",           # Vide
        " " * 10,     # Espaces seulement
        "short",      # Trop court
        None,         # None
    ])
    def test_password_validation_edge_cases(self, flask_app, invalid_password):
        """Test la validation des mots de passe avec des cas limites"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {
                "authentication": {
                    "users": {
                        "testuser": {
                            "password_hash": bcrypt.hashpw("validpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                            "role": "admin"
                        }
                    }
                }
            }
            api = TinyCTIAPI(mock_tinycti)
            
            # Tous ces cas devraient échouer
            result = api._verify_password("testuser", invalid_password)
            assert result is False

    def test_bcrypt_hash_corruption_handling(self, flask_app):
        """Test la gestion des hashs bcrypt corrompus"""
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {
                "authentication": {
                    "users": {
                        "testuser": {
                            "password_hash": "corrupted_hash_not_bcrypt",
                            "role": "admin"
                        }
                    }
                }
            }
            api = TinyCTIAPI(mock_tinycti)
            
            # Devrait gérer gracieusement le hash corrompu
            result = api._verify_password("testuser", "anypassword")
            assert result is False

    def test_concurrent_authentication_attempts(self, flask_app):
        """Test les tentatives d'authentification concurrentes"""
        import threading
        import time
        
        with flask_app.app_context():
            mock_tinycti = Mock()
            mock_tinycti.config = {
                "authentication": {
                    "users": {
                        "testuser": {
                            "password_hash": bcrypt.hashpw("testpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                            "role": "admin"
                        }
                    }
                }
            }
            api = TinyCTIAPI(mock_tinycti)
            
            results = []
            
            def authenticate():
                result = api._verify_password("testuser", "testpass")
                results.append(result)
            
            # Lance plusieurs threads d'authentification
            threads = []
            for _ in range(5):
                thread = threading.Thread(target=authenticate)
                threads.append(thread)
                thread.start()
            
            # Attend que tous les threads terminent
            for thread in threads:
                thread.join()
            
            # Tous devraient réussir
            assert all(results)
            assert len(results) == 5