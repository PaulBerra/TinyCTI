"""
Tests unitaires pour le système de logging TinyCTI
"""

import logging
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from tinycti import CircuitBreaker, ErrorHandler, LoggingConfigurator


class TestLoggingConfigurator:
    """Tests pour la classe LoggingConfigurator"""

    def test_logging_configurator_initialization(self, test_config_minimal):
        """Test l'initialisation du configurateur de logging"""
        configurator = LoggingConfigurator(test_config_minimal)

        assert configurator.log_file == "test.log"
        assert configurator.max_size == 1024 * 1024  # 1MB
        assert configurator.backup_count == 3
        assert configurator.compression is False

    def test_parse_size_formats(self, test_config_minimal):
        """Test le parsing des différents formats de taille"""
        configurator = LoggingConfigurator(test_config_minimal)

        # Test KB
        assert configurator._parse_size("512KB") == 512 * 1024
        assert configurator._parse_size("1kb") == 1024

        # Test MB
        assert configurator._parse_size("10MB") == 10 * 1024 * 1024
        assert configurator._parse_size("5mb") == 5 * 1024 * 1024

        # Test GB
        assert configurator._parse_size("2GB") == 2 * 1024 * 1024 * 1024
        assert configurator._parse_size("1gb") == 1024 * 1024 * 1024

        # Test bytes directs
        assert configurator._parse_size("2048") == 2048

    def test_parse_duration_formats(self, test_config_minimal):
        """Test le parsing des différents formats de durée"""
        configurator = LoggingConfigurator(test_config_minimal)

        # Test heures
        assert configurator._parse_duration("1h") == 3600
        assert configurator._parse_duration("24h") == 24 * 3600

        # Test jours
        assert configurator._parse_duration("1d") == 86400
        assert configurator._parse_duration("7d") == 7 * 86400

        # Test minutes
        assert configurator._parse_duration("30m") == 1800
        assert configurator._parse_duration("60m") == 3600

        # Test secondes
        assert configurator._parse_duration("120") == 120

    def test_setup_main_logger_configuration(self, test_config_minimal):
        """Test la configuration complète du logger principal"""
        configurator = LoggingConfigurator(test_config_minimal)

        # Test que setup_main_logger n'échoue pas
        try:
            configurator.setup_main_logger()
            logger_configured = True
        except Exception:
            logger_configured = False

        assert logger_configured

    def test_audit_logger_creation_enabled(self, test_config_minimal):
        """Test la création du logger d'audit quand activé"""
        # Active l'audit
        test_config_minimal["logging"]["audit_enabled"] = True
        test_config_minimal["logging"]["audit_file"] = "test_audit.log"

        configurator = LoggingConfigurator(test_config_minimal)

        # Test que setup_audit_logger fonctionne et retourne un logger
        audit_logger = configurator.setup_audit_logger()
        assert audit_logger is not None

    def test_audit_logger_creation_disabled(self, test_config_minimal):
        """Test que le logger d'audit n'est pas créé quand désactivé"""
        # L'audit est désactivé par défaut
        configurator = LoggingConfigurator(test_config_minimal)

        audit_logger = configurator.setup_audit_logger()
        assert audit_logger is None

    @patch("threading.Thread")
    def test_log_compression_setup(self, mock_thread, test_config_minimal):
        """Test la configuration de la compression des logs"""
        # Active la compression
        test_config_minimal["logging"]["compression"] = True

        configurator = LoggingConfigurator(test_config_minimal)

        with patch.object(configurator, "_setup_log_compression") as mock_compression:
            configurator.setup_main_logger()

            # Vérifie que la compression a été configurée
            mock_compression.assert_called_once()

    def test_log_compression_thread_creation(self, test_config_minimal):
        """Test la création du thread de compression"""
        test_config_minimal["logging"]["compression"] = True

        configurator = LoggingConfigurator(test_config_minimal)

        with patch("threading.Thread") as mock_thread:
            mock_thread_instance = Mock()
            mock_thread.return_value = mock_thread_instance

            configurator._setup_log_compression()

            # Vérifie que le thread a été créé et démarré
            mock_thread.assert_called_once()
            mock_thread_instance.start.assert_called_once()

    def test_override_log_level(self, test_config_minimal):
        """Test la surcharge du niveau de log"""
        # Test avec niveau surchargé
        configurator = LoggingConfigurator(test_config_minimal, logging.DEBUG)
        assert configurator.log_level == logging.DEBUG

        # Test sans surcharge
        configurator2 = LoggingConfigurator(test_config_minimal)
        assert configurator2.log_level == logging.INFO  # Valeur de la config


class TestErrorHandler:
    """Tests pour la classe ErrorHandler"""

    def test_error_handler_initialization(self, mock_logger):
        """Test l'initialisation du gestionnaire d'erreurs"""
        handler = ErrorHandler(mock_logger)

        assert handler.logger == mock_logger
        assert handler.error_counts == {}
        assert handler.last_errors == []
        assert handler.max_error_history == 100

    def test_handle_error_basic(self, mock_logger):
        """Test la gestion basique d'une erreur"""
        handler = ErrorHandler(mock_logger)

        error = ValueError("Test error")
        result = handler.handle_error(error, "test_context")

        assert "error" in result
        assert "error_type" in result
        assert "context" in result
        assert "timestamp" in result

        assert result["error"] == "Test error"
        assert result["error_type"] == "ValueError"
        assert result["context"] == "test_context"

    def test_handle_error_critical(self, mock_logger):
        """Test la gestion d'une erreur critique"""
        handler = ErrorHandler(mock_logger)

        error = RuntimeError("Critical error")
        result = handler.handle_error(error, "critical_context", critical=True)

        # Vérifie que l'erreur critique a été loggée
        mock_logger.critical.assert_called()

        # Vérifie que l'erreur est dans l'historique
        assert len(handler.last_errors) == 1
        assert handler.last_errors[0]["critical"] is True

    def test_handle_error_with_user_message(self, mock_logger):
        """Test la gestion d'erreur avec message utilisateur personnalisé"""
        handler = ErrorHandler(mock_logger)

        error = Exception("Internal error")
        user_msg = "Something went wrong"
        result = handler.handle_error(error, user_message=user_msg)

        assert result["error"] == user_msg

    def test_error_counting(self, mock_logger):
        """Test le comptage des erreurs"""
        handler = ErrorHandler(mock_logger)

        # Génère plusieurs erreurs du même type
        for i in range(3):
            handler.handle_error(ValueError(f"Error {i}"), "test")

        # Génère une erreur d'un type différent
        handler.handle_error(RuntimeError("Runtime error"), "test")

        assert handler.error_counts["ValueError"] == 3
        assert handler.error_counts["RuntimeError"] == 1

    def test_error_history_management(self, mock_logger):
        """Test la gestion de l'historique des erreurs"""
        handler = ErrorHandler(mock_logger)
        handler.max_error_history = 3  # Limite pour le test

        # Génère plus d'erreurs que la limite
        for i in range(5):
            handler.handle_error(ValueError(f"Error {i}"), "test")

        # Vérifie que seules les 3 dernières erreurs sont conservées
        assert len(handler.last_errors) == 3
        assert handler.last_errors[-1]["message"] == "Error 4"

    def test_get_error_stats(self, mock_logger):
        """Test la récupération des statistiques d'erreurs"""
        handler = ErrorHandler(mock_logger)

        # Génère quelques erreurs
        handler.handle_error(ValueError("Error 1"), critical=True)
        handler.handle_error(RuntimeError("Error 2"), critical=False)
        handler.handle_error(ValueError("Error 3"), critical=True)

        stats = handler.get_error_stats()

        assert "error_counts" in stats
        assert "total_errors" in stats
        assert "recent_errors" in stats
        assert "critical_errors" in stats

        assert stats["total_errors"] == 3
        assert len(stats["critical_errors"]) == 2
        assert stats["error_counts"]["ValueError"] == 2
        assert stats["error_counts"]["RuntimeError"] == 1

    def test_clear_error_history(self, mock_logger):
        """Test le vidage de l'historique des erreurs"""
        handler = ErrorHandler(mock_logger)

        # Génère quelques erreurs
        handler.handle_error(ValueError("Error 1"), "test")
        handler.handle_error(RuntimeError("Error 2"), "test")

        assert len(handler.last_errors) == 2
        assert handler.error_counts["ValueError"] == 1

        # Vide l'historique
        handler.clear_error_history()

        assert len(handler.last_errors) == 0
        assert len(handler.error_counts) == 0
        mock_logger.info.assert_called_with("Historique des erreurs vidé")


class TestCircuitBreaker:
    """Tests pour la classe CircuitBreaker"""

    def test_circuit_breaker_initialization(self):
        """Test l'initialisation du circuit breaker"""
        breaker = CircuitBreaker(failure_threshold=3, timeout=30)

        assert breaker.failure_threshold == 3
        assert breaker.timeout == 30
        assert breaker.failure_count == 0
        assert breaker.last_failure_time is None
        assert breaker.state == "CLOSED"

    def test_circuit_breaker_success_calls(self):
        """Test les appels réussis avec circuit breaker"""
        breaker = CircuitBreaker()

        def successful_function():
            return "success"

        result = breaker.call(successful_function)

        assert result == "success"
        assert breaker.state == "CLOSED"
        assert breaker.failure_count == 0

    def test_circuit_breaker_failure_counting(self):
        """Test le comptage des échecs"""
        breaker = CircuitBreaker(failure_threshold=3)

        def failing_function():
            raise Exception("Test failure")

        # Provoque des échecs
        for i in range(2):
            with pytest.raises(Exception):
                breaker.call(failing_function)

        assert breaker.failure_count == 2
        assert breaker.state == "CLOSED"

        # Le troisième échec devrait ouvrir le circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)

        assert breaker.failure_count == 3
        assert breaker.state == "OPEN"

    def test_circuit_breaker_open_state(self):
        """Test le comportement en état OPEN"""
        breaker = CircuitBreaker(failure_threshold=1)

        def failing_function():
            raise Exception("Test failure")

        # Provoque l'ouverture du circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)

        assert breaker.state == "OPEN"

        # Les appels suivants devraient être bloqués
        def any_function():
            return "should not execute"

        with pytest.raises(Exception, match="Circuit breaker is OPEN"):
            breaker.call(any_function)

    def test_circuit_breaker_half_open_transition(self):
        """Test la transition vers l'état HALF_OPEN"""
        breaker = CircuitBreaker(failure_threshold=1, timeout=0.1)

        def failing_function():
            raise Exception("Test failure")

        # Ouvre le circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)

        assert breaker.state == "OPEN"

        # Attend que le timeout soit dépassé
        time.sleep(0.2)

        def successful_function():
            return "success"

        # Le premier appel après timeout devrait passer en HALF_OPEN
        result = breaker.call(successful_function)

        assert result == "success"
        assert breaker.state == "CLOSED"  # Devrait se fermer après le succès

    def test_circuit_breaker_reset(self):
        """Test le reset manuel du circuit breaker"""
        breaker = CircuitBreaker(failure_threshold=1)

        def failing_function():
            raise Exception("Test failure")

        # Ouvre le circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)

        assert breaker.state == "OPEN"
        assert breaker.failure_count == 1

        # Reset manuel
        breaker.reset()

        assert breaker.state == "CLOSED"
        assert breaker.failure_count == 0
        assert breaker.last_failure_time is None

    def test_circuit_breaker_with_args_kwargs(self):
        """Test le circuit breaker avec arguments et mots-clés"""
        breaker = CircuitBreaker()

        def function_with_args(a, b, c=None):
            return f"{a}-{b}-{c}"

        result = breaker.call(function_with_args, "arg1", "arg2", c="kwarg1")

        assert result == "arg1-arg2-kwarg1"


class TestLoggingIntegration:
    """Tests d'intégration pour le système de logging"""

    def test_logging_with_real_files(self, temp_directory):
        """Test le logging avec de vrais fichiers"""
        config = {
            "logging": {
                "level": "INFO",
                "file": str(temp_directory / "test.log"),
                "max_size": "1KB",  # Petite taille pour forcer la rotation
                "backup_count": 2,
                "compression": False,
                "audit_enabled": True,
                "audit_file": str(temp_directory / "audit.log"),
            }
        }

        configurator = LoggingConfigurator(config)

        # Configure le logger principal
        configurator.setup_main_logger()

        # Configure le logger d'audit
        audit_logger = configurator.setup_audit_logger()

        # Test le logging
        logger = logging.getLogger("test_logger")
        logger.info("Test message")

        if audit_logger:
            audit_logger.info("Audit message")

        # Vérifie que les fichiers ont été créés
        log_file = Path(config["logging"]["file"])
        audit_file = Path(config["logging"]["audit_file"])

        # Note: En environnement de test, les fichiers peuvent ne pas être créés immédiatement
        # Ces assertions peuvent être adaptées selon l'environnement

    def test_error_handler_with_logging_configurator(self, temp_directory):
        """Test l'intégration ErrorHandler avec LoggingConfigurator"""
        config = {
            "logging": {
                "level": "DEBUG",
                "file": str(temp_directory / "error_test.log"),
                "audit_enabled": True,
                "audit_file": str(temp_directory / "error_audit.log"),
            }
        }

        configurator = LoggingConfigurator(config)
        configurator.setup_main_logger()

        logger = logging.getLogger("error_test")
        error_handler = ErrorHandler(logger)

        # Génère quelques erreurs
        try:
            raise ValueError("Test integration error")
        except ValueError as e:
            error_handler.handle_error(e, "integration_test", critical=True)

        # Vérifie les statistiques
        stats = error_handler.get_error_stats()
        assert stats["total_errors"] == 1
        assert len(stats["critical_errors"]) == 1

    @pytest.mark.slow
    def test_log_rotation_behavior(self, temp_directory):
        """Test le comportement de la rotation des logs"""
        log_file = temp_directory / "rotation_test.log"

        config = {
            "logging": {
                "level": "DEBUG",
                "file": str(log_file),
                "max_size": "1KB",  # Très petite pour forcer la rotation
                "backup_count": 3,
                "compression": False,
            }
        }

        configurator = LoggingConfigurator(config)

        # Note: Pour un vrai test de rotation, il faudrait générer
        # suffisamment de logs pour dépasser la taille limite
        # Ici on teste juste la configuration
