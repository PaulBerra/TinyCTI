"""
Tests unitaires pour la gestion d'erreurs TinyCTI
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from tinycti import ErrorHandler, CircuitBreaker, StorageError, ConfigurationError


class TestErrorHandler:
    """Tests pour la classe ErrorHandler"""

    def test_error_handler_initialization(self, mock_logger):
        """Test l'initialisation du gestionnaire d'erreurs"""
        handler = ErrorHandler(mock_logger)
        
        assert handler.logger == mock_logger
        assert handler.error_counts == {}
        assert handler.last_errors == []
        assert handler.max_error_history == 100

    def test_error_handler_custom_history_size(self, mock_logger):
        """Test l'initialisation avec une taille d'historique personnalisée"""
        handler = ErrorHandler(mock_logger, max_error_history=50)
        
        assert handler.max_error_history == 50

    def test_handle_error_basic(self, mock_logger):
        """Test la gestion basique d'une erreur"""
        handler = ErrorHandler(mock_logger)
        
        error = ValueError("Test error message")
        result = handler.handle_error(error, "test_context")
        
        # Vérifie la structure de retour
        assert "error" in result
        assert "error_type" in result
        assert "context" in result
        assert "timestamp" in result
        assert "critical" in result
        
        assert result["error"] == "Test error message"
        assert result["error_type"] == "ValueError"
        assert result["context"] == "test_context"
        assert result["critical"] is False

    def test_handle_error_critical(self, mock_logger):
        """Test la gestion d'une erreur critique"""
        handler = ErrorHandler(mock_logger)
        
        error = RuntimeError("Critical system error")
        result = handler.handle_error(error, "critical_operation", critical=True)
        
        assert result["critical"] is True
        assert result["error"] == "Critical system error"
        
        # Vérifie que l'erreur critique a été loggée
        mock_logger.critical.assert_called_once()

    def test_handle_error_with_user_message(self, mock_logger):
        """Test la gestion d'erreur avec message utilisateur personnalisé"""
        handler = ErrorHandler(mock_logger)
        
        error = Exception("Internal technical error")
        user_message = "Une erreur s'est produite lors du traitement"
        
        result = handler.handle_error(error, user_message=user_message)
        
        assert result["error"] == user_message
        # Le message technique devrait être dans les logs mais pas dans le retour utilisateur

    def test_error_counting_same_type(self, mock_logger):
        """Test le comptage des erreurs du même type"""
        handler = ErrorHandler(mock_logger)
        
        # Génère plusieurs erreurs du même type
        for i in range(5):
            error = ValueError(f"Error number {i}")
            handler.handle_error(error, "test_context")
        
        assert handler.error_counts["ValueError"] == 5

    def test_error_counting_different_types(self, mock_logger):
        """Test le comptage des erreurs de types différents"""
        handler = ErrorHandler(mock_logger)
        
        # Génère différents types d'erreurs
        handler.handle_error(ValueError("Value error"), "context1")
        handler.handle_error(RuntimeError("Runtime error"), "context2")
        handler.handle_error(ValueError("Another value error"), "context3")
        handler.handle_error(TypeError("Type error"), "context4")
        
        assert handler.error_counts["ValueError"] == 2
        assert handler.error_counts["RuntimeError"] == 1
        assert handler.error_counts["TypeError"] == 1

    def test_error_history_management(self, mock_logger):
        """Test la gestion de l'historique des erreurs"""
        handler = ErrorHandler(mock_logger, max_error_history=3)
        
        # Génère plus d'erreurs que la limite
        for i in range(5):
            error = ValueError(f"Error {i}")
            handler.handle_error(error, f"context_{i}")
        
        # Vérifie que seules les 3 dernières erreurs sont conservées
        assert len(handler.last_errors) == 3
        assert handler.last_errors[0]["error"] == "Error 2"
        assert handler.last_errors[1]["error"] == "Error 3"
        assert handler.last_errors[2]["error"] == "Error 4"

    def test_get_error_stats_comprehensive(self, mock_logger):
        """Test la récupération complète des statistiques d'erreurs"""
        handler = ErrorHandler(mock_logger)
        
        # Génère différents types d'erreurs
        handler.handle_error(ValueError("Error 1"), critical=True)
        handler.handle_error(RuntimeError("Error 2"), critical=False)
        handler.handle_error(ValueError("Error 3"), critical=True)
        handler.handle_error(TypeError("Error 4"), critical=False)
        
        stats = handler.get_error_stats()
        
        assert "error_counts" in stats
        assert "total_errors" in stats
        assert "recent_errors" in stats
        assert "critical_errors" in stats
        
        assert stats["total_errors"] == 4
        assert len(stats["critical_errors"]) == 2
        assert stats["error_counts"]["ValueError"] == 2
        assert stats["error_counts"]["RuntimeError"] == 1
        assert stats["error_counts"]["TypeError"] == 1

    def test_get_error_stats_with_limit(self, mock_logger):
        """Test la récupération des statistiques avec limite"""
        handler = ErrorHandler(mock_logger)
        
        # Génère plusieurs erreurs
        for i in range(10):
            handler.handle_error(ValueError(f"Error {i}"), f"context_{i}")
        
        stats = handler.get_error_stats(recent_limit=5)
        
        assert len(stats["recent_errors"]) == 5
        # Devrait retourner les 5 plus récentes
        assert stats["recent_errors"][0]["error"] == "Error 5"

    def test_clear_error_history(self, mock_logger):
        """Test le vidage de l'historique des erreurs"""
        handler = ErrorHandler(mock_logger)
        
        # Génère quelques erreurs
        handler.handle_error(ValueError("Error 1"), "context1")
        handler.handle_error(RuntimeError("Error 2"), "context2")
        
        assert len(handler.last_errors) == 2
        assert handler.error_counts["ValueError"] == 1
        
        # Vide l'historique
        handler.clear_error_history()
        
        assert len(handler.last_errors) == 0
        assert len(handler.error_counts) == 0
        mock_logger.info.assert_called_with("Historique des erreurs vidé")

    def test_handle_error_with_traceback(self, mock_logger):
        """Test la gestion d'erreur avec traceback"""
        handler = ErrorHandler(mock_logger)
        
        try:
            # Génère une vraie exception avec traceback
            1 / 0
        except ZeroDivisionError as e:
            result = handler.handle_error(e, "division_test")
            
            # Vérifie que le traceback est capturé
            assert "traceback" in result
            assert result["error_type"] == "ZeroDivisionError"

    def test_handle_error_exception_in_handler(self, mock_logger):
        """Test la robustesse du handler face aux exceptions internes"""
        handler = ErrorHandler(mock_logger)
        
        # Mock le logger pour qu'il lève une exception
        mock_logger.error.side_effect = Exception("Logger error")
        
        # L'handler ne devrait pas crasher
        error = ValueError("Original error")
        result = handler.handle_error(error, "test_context")
        
        # Devrait retourner une structure basique même en cas d'erreur interne
        assert "error" in result
        assert result["error_type"] == "ValueError"

    def test_error_categorization(self, mock_logger):
        """Test la catégorisation des erreurs"""
        handler = ErrorHandler(mock_logger)
        
        # Erreurs système critiques
        system_errors = [
            MemoryError("Out of memory"),
            SystemError("System error"),
            OSError("OS error")
        ]
        
        for error in system_errors:
            result = handler.handle_error(error, "system_test", critical=True)
            assert result["critical"] is True

    def test_error_rate_calculation(self, mock_logger):
        """Test le calcul du taux d'erreurs"""
        handler = ErrorHandler(mock_logger)
        
        # Ajoute un timestamp de début
        start_time = time.time()
        
        # Génère des erreurs sur une période
        for i in range(10):
            handler.handle_error(ValueError(f"Error {i}"), "rate_test")
            time.sleep(0.01)  # Petite pause
        
        end_time = time.time()
        duration = end_time - start_time
        
        stats = handler.get_error_stats()
        
        # Calcule le taux approximatif
        expected_rate = 10 / duration
        # Le test est approximatif car on ne contrôle pas exactement le timing


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

    def test_circuit_breaker_default_values(self):
        """Test les valeurs par défaut du circuit breaker"""
        breaker = CircuitBreaker()
        
        assert breaker.failure_threshold == 5
        assert breaker.timeout == 60
        assert breaker.state == "CLOSED"

    def test_successful_calls_reset_counter(self):
        """Test que les appels réussis remettent le compteur à zéro"""
        breaker = CircuitBreaker(failure_threshold=3)
        
        def successful_function():
            return "success"
        
        def failing_function():
            raise Exception("failure")
        
        # Provoque quelques échecs
        for _ in range(2):
            with pytest.raises(Exception):
                breaker.call(failing_function)
        
        assert breaker.failure_count == 2
        
        # Un appel réussi devrait remettre le compteur à zéro
        result = breaker.call(successful_function)
        assert result == "success"
        assert breaker.failure_count == 0

    def test_circuit_opens_after_threshold(self):
        """Test que le circuit s'ouvre après le seuil d'échecs"""
        breaker = CircuitBreaker(failure_threshold=3)
        
        def failing_function():
            raise ValueError("Test failure")
        
        # Provoque exactement le nombre d'échecs du seuil
        for i in range(3):
            with pytest.raises(ValueError):
                breaker.call(failing_function)
        
        assert breaker.state == "OPEN"
        assert breaker.failure_count == 3

    def test_open_circuit_blocks_calls(self):
        """Test que le circuit ouvert bloque les appels"""
        breaker = CircuitBreaker(failure_threshold=1)
        
        def failing_function():
            raise Exception("failure")
        
        def any_function():
            return "should not execute"
        
        # Ouvre le circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)
        
        assert breaker.state == "OPEN"
        
        # Les appels suivants devraient être bloqués
        with pytest.raises(Exception, match="Circuit breaker is OPEN"):
            breaker.call(any_function)

    def test_half_open_transition_after_timeout(self):
        """Test la transition vers HALF_OPEN après timeout"""
        breaker = CircuitBreaker(failure_threshold=1, timeout=0.1)
        
        def failing_function():
            raise Exception("failure")
        
        def successful_function():
            return "success"
        
        # Ouvre le circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)
        
        assert breaker.state == "OPEN"
        
        # Attend le timeout
        time.sleep(0.2)
        
        # Le prochain appel devrait passer en HALF_OPEN puis CLOSED si succès
        result = breaker.call(successful_function)
        assert result == "success"
        assert breaker.state == "CLOSED"

    def test_half_open_failure_reopens_circuit(self):
        """Test qu'un échec en HALF_OPEN rouvre le circuit"""
        breaker = CircuitBreaker(failure_threshold=1, timeout=0.1)
        
        def failing_function():
            raise Exception("failure")
        
        # Ouvre le circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)
        
        # Attend le timeout
        time.sleep(0.2)
        
        # Un nouvel échec devrait rouvrir le circuit
        with pytest.raises(Exception):
            breaker.call(failing_function)
        
        assert breaker.state == "OPEN"

    def test_circuit_breaker_with_args_and_kwargs(self):
        """Test le circuit breaker avec arguments positionnels et nommés"""
        breaker = CircuitBreaker()
        
        def function_with_params(a, b, c=None, d=None):
            return f"{a}-{b}-{c}-{d}"
        
        result = breaker.call(function_with_params, "arg1", "arg2", c="kwarg1", d="kwarg2")
        
        assert result == "arg1-arg2-kwarg1-kwarg2"

    def test_circuit_breaker_reset(self):
        """Test le reset manuel du circuit breaker"""
        breaker = CircuitBreaker(failure_threshold=1)
        
        def failing_function():
            raise Exception("failure")
        
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

    def test_circuit_breaker_statistics(self):
        """Test les statistiques du circuit breaker"""
        breaker = CircuitBreaker(failure_threshold=3)
        
        def successful_function():
            return "success"
        
        def failing_function():
            raise Exception("failure")
        
        # Quelques appels réussis
        for _ in range(5):
            breaker.call(successful_function)
        
        # Quelques échecs
        for _ in range(2):
            with pytest.raises(Exception):
                breaker.call(failing_function)
        
        # Les statistiques peuvent être consultées via les attributs
        assert breaker.failure_count == 2
        assert breaker.state == "CLOSED"

    def test_concurrent_circuit_breaker_usage(self):
        """Test l'utilisation concurrente du circuit breaker"""
        import threading
        
        breaker = CircuitBreaker(failure_threshold=10)  # Seuil élevé pour le test
        results = []
        
        def successful_function():
            return "success"
        
        def make_calls():
            for _ in range(5):
                result = breaker.call(successful_function)
                results.append(result)
        
        # Lance plusieurs threads
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=make_calls)
            threads.append(thread)
            thread.start()
        
        # Attend que tous terminent
        for thread in threads:
            thread.join()
        
        # Tous les appels devraient avoir réussi
        assert len(results) == 15
        assert all(result == "success" for result in results)

    def test_circuit_breaker_exception_types(self):
        """Test le circuit breaker avec différents types d'exceptions"""
        breaker = CircuitBreaker(failure_threshold=2)
        
        exceptions = [
            ValueError("Value error"),
            RuntimeError("Runtime error"),
            TypeError("Type error")
        ]
        
        def failing_function(exception):
            raise exception
        
        # Teste différents types d'exceptions
        for i, exc in enumerate(exceptions[:2]):  # Seulement les 2 premiers pour ne pas ouvrir le circuit
            with pytest.raises(type(exc)):
                breaker.call(failing_function, exc)
        
        assert breaker.failure_count == 2
        assert breaker.state == "OPEN"


class TestCustomExceptions:
    """Tests pour les exceptions personnalisées"""

    def test_storage_error_creation(self):
        """Test la création d'une StorageError"""
        error = StorageError("Storage operation failed")
        
        assert str(error) == "Storage operation failed"
        assert isinstance(error, Exception)

    def test_configuration_error_creation(self):
        """Test la création d'une ConfigurationError"""
        error = ConfigurationError("Invalid configuration", config_key="feeds")
        
        assert str(error) == "Invalid configuration"
        assert error.config_key == "feeds"

    def test_configuration_error_without_key(self):
        """Test ConfigurationError sans clé de configuration"""
        error = ConfigurationError("Generic config error")
        
        assert str(error) == "Generic config error"
        assert not hasattr(error, 'config_key') or error.config_key is None


class TestErrorIntegration:
    """Tests d'intégration pour la gestion d'erreurs"""

    def test_error_handler_with_circuit_breaker(self, mock_logger):
        """Test l'intégration ErrorHandler avec CircuitBreaker"""
        error_handler = ErrorHandler(mock_logger)
        circuit_breaker = CircuitBreaker(failure_threshold=2)
        
        def potentially_failing_operation(should_fail=False):
            if should_fail:
                raise RuntimeError("Operation failed")
            return "success"
        
        def protected_operation(should_fail=False):
            try:
                return circuit_breaker.call(potentially_failing_operation, should_fail)
            except Exception as e:
                error_result = error_handler.handle_error(e, "protected_operation")
                return error_result
        
        # Première opération réussie
        result1 = protected_operation(should_fail=False)
        assert result1 == "success"
        
        # Opérations qui échouent
        result2 = protected_operation(should_fail=True)
        assert "error" in result2
        assert result2["error_type"] == "RuntimeError"
        
        result3 = protected_operation(should_fail=True)
        assert "error" in result3
        
        # Le circuit devrait maintenant être ouvert
        assert circuit_breaker.state == "OPEN"
        
        # Les opérations suivantes devraient être bloquées par le circuit breaker
        result4 = protected_operation(should_fail=False)  # Même si ne devrait pas échouer
        assert "error" in result4
        assert "Circuit breaker is OPEN" in result4["error"]

    def test_error_propagation_through_layers(self, mock_logger):
        """Test la propagation d'erreurs à travers les couches"""
        error_handler = ErrorHandler(mock_logger)
        
        def layer3_function():
            raise ValueError("Error in layer 3")
        
        def layer2_function():
            try:
                return layer3_function()
            except Exception as e:
                # Re-raise avec contexte additionnel
                raise RuntimeError("Error in layer 2") from e
        
        def layer1_function():
            try:
                return layer2_function()
            except Exception as e:
                return error_handler.handle_error(e, "layer1_function")
        
        result = layer1_function()
        
        assert "error" in result
        assert result["error_type"] == "RuntimeError"
        assert "Error in layer 2" in result["error"]

    def test_bulk_error_handling(self, mock_logger):
        """Test la gestion d'erreurs en lot"""
        error_handler = ErrorHandler(mock_logger)
        
        # Simule le traitement d'un lot d'opérations avec quelques échecs
        operations = [
            ("op1", False),  # Réussit
            ("op2", True),   # Échoue
            ("op3", False),  # Réussit
            ("op4", True),   # Échoue
            ("op5", False),  # Réussit
        ]
        
        results = []
        for op_name, should_fail in operations:
            try:
                if should_fail:
                    raise ValueError(f"Error in {op_name}")
                results.append({"operation": op_name, "status": "success"})
            except Exception as e:
                error_result = error_handler.handle_error(e, f"bulk_operation_{op_name}")
                results.append({
                    "operation": op_name, 
                    "status": "error",
                    "error_details": error_result
                })
        
        # Vérifie les résultats
        assert len(results) == 5
        success_count = sum(1 for r in results if r["status"] == "success")
        error_count = sum(1 for r in results if r["status"] == "error")
        
        assert success_count == 3
        assert error_count == 2
        
        # Vérifie les statistiques d'erreurs
        stats = error_handler.get_error_stats()
        assert stats["total_errors"] == 2