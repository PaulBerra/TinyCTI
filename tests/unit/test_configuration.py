"""
Tests unitaires pour le système de configuration TinyCTI
"""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, mock_open

from tinycti import (
    ConfigurationLoader,
    ConfigurationError,
    LoggingConfigurator
)


class TestConfigurationLoader:
    """Tests pour la classe ConfigurationLoader"""

    def test_init_with_valid_file(self, test_config_file):
        """Test l'initialisation avec un fichier valide"""
        loader = ConfigurationLoader(str(test_config_file))
        assert loader.config_file == Path(test_config_file)
        assert loader.config is None

    def test_init_with_nonexistent_file(self, temp_directory):
        """Test l'initialisation avec un fichier inexistant"""
        nonexistent_file = temp_directory / "nonexistent.yaml"
        loader = ConfigurationLoader(str(nonexistent_file))
        assert loader.config_file == nonexistent_file

    def test_load_valid_config(self, configuration_loader):
        """Test le chargement d'une configuration valide"""
        config = configuration_loader.load_config()
        
        assert config is not None
        assert "feeds" in config
        assert "output_dir" in config
        assert "logging" in config
        assert len(config["feeds"]) > 0

    def test_load_config_file_not_found(self, temp_directory):
        """Test le chargement d'un fichier inexistant"""
        nonexistent_file = temp_directory / "nonexistent.yaml"
        loader = ConfigurationLoader(str(nonexistent_file))
        
        with pytest.raises(ConfigurationError, match="Fichier de configuration non trouvé"):
            loader.load_config()

    def test_load_empty_config_file(self, temp_directory):
        """Test le chargement d'un fichier vide"""
        empty_file = temp_directory / "empty.yaml"
        empty_file.write_text("")
        
        loader = ConfigurationLoader(str(empty_file))
        
        with pytest.raises(ConfigurationError, match="Fichier de configuration vide"):
            loader.load_config()

    def test_load_invalid_yaml(self, temp_directory):
        """Test le chargement d'un YAML invalide"""
        invalid_file = temp_directory / "invalid.yaml"
        invalid_file.write_text("invalid: yaml: content: [")
        
        loader = ConfigurationLoader(str(invalid_file))
        
        with pytest.raises(ConfigurationError):
            loader.load_config()

    def test_validate_feeds_structure(self, configuration_loader):
        """Test la validation de la structure des feeds"""
        config = configuration_loader.load_config()
        
        feeds = config["feeds"]
        assert isinstance(feeds, list)
        
        for feed in feeds:
            assert "name" in feed
            assert "type" in feed
            assert "url" in feed
            assert isinstance(feed.get("enabled", True), bool)

    def test_validate_invalid_feed_type(self, temp_directory):
        """Test la validation avec un type de feed invalide"""
        invalid_config = {
            "feeds": [{
                "name": "test",
                "type": "invalid_type",
                "url": "http://example.com"
            }],
            "output_dir": "test"
        }
        
        config_file = temp_directory / "invalid_feed.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        loader = ConfigurationLoader(str(config_file))
        
        with pytest.raises(ConfigurationError):
            loader.load_config()

    def test_validate_invalid_url(self, temp_directory):
        """Test la validation avec une URL invalide"""
        invalid_config = {
            "feeds": [{
                "name": "test",
                "type": "text",
                "url": "not_a_valid_url"
            }],
            "output_dir": "test"
        }
        
        config_file = temp_directory / "invalid_url.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        loader = ConfigurationLoader(str(config_file))
        
        with pytest.raises(ConfigurationError, match="URL invalide"):
            loader.load_config()

    def test_default_values_applied(self, temp_directory):
        """Test que les valeurs par défaut sont appliquées"""
        minimal_config = {
            "feeds": [{
                "name": "test",
                "type": "text",
                "url": "http://example.com"
            }],
            "output_dir": "test"
        }
        
        config_file = temp_directory / "minimal.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(minimal_config, f)
        
        loader = ConfigurationLoader(str(config_file))
        config = loader.load_config()
        
        feed = config["feeds"][0]
        assert feed["enabled"] is True  # Valeur par défaut
        assert feed["retention"] == "live"  # Valeur par défaut
        assert feed["timeout"] == 30  # Valeur par défaut

    def test_required_fields_missing(self, temp_directory):
        """Test l'erreur quand des champs requis sont manquants"""
        incomplete_config = {
            "feeds": [{
                "name": "test",
                # "type" manquant (requis)
                "url": "http://example.com"
            }]
        }
        
        config_file = temp_directory / "incomplete.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(incomplete_config, f)
        
        loader = ConfigurationLoader(str(config_file))
        
        with pytest.raises(ConfigurationError):
            loader.load_config()


class TestLoggingConfigurator:
    """Tests pour la classe LoggingConfigurator"""

    def test_init_with_defaults(self, test_config_minimal):
        """Test l'initialisation avec la configuration par défaut"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator.log_file == "test.log"
        assert configurator.max_size == 1024 * 1024  # 1MB
        assert configurator.backup_count == 3
        assert configurator.compression is False
        assert configurator.audit_enabled is False

    def test_init_with_override_level(self, test_config_minimal):
        """Test l'initialisation avec niveau de log surchargé"""
        import logging
        
        configurator = LoggingConfigurator(test_config_minimal, logging.DEBUG)
        assert configurator.log_level == logging.DEBUG

    def test_parse_size_kb(self, test_config_minimal):
        """Test le parsing des tailles en KB"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_size("10KB") == 10 * 1024
        assert configurator._parse_size("100kb") == 100 * 1024  # Case insensitive

    def test_parse_size_mb(self, test_config_minimal):
        """Test le parsing des tailles en MB"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_size("5MB") == 5 * 1024 * 1024
        assert configurator._parse_size("10mb") == 10 * 1024 * 1024

    def test_parse_size_gb(self, test_config_minimal):
        """Test le parsing des tailles en GB"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_size("2GB") == 2 * 1024 * 1024 * 1024

    def test_parse_size_bytes(self, test_config_minimal):
        """Test le parsing des tailles en bytes"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_size("1024") == 1024

    def test_parse_duration_hours(self, test_config_minimal):
        """Test le parsing des durées en heures"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_duration("1h") == 3600
        assert configurator._parse_duration("24h") == 24 * 3600

    def test_parse_duration_days(self, test_config_minimal):
        """Test le parsing des durées en jours"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_duration("1d") == 86400
        assert configurator._parse_duration("7d") == 7 * 86400

    def test_parse_duration_minutes(self, test_config_minimal):
        """Test le parsing des durées en minutes"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_duration("30m") == 1800
        assert configurator._parse_duration("60m") == 3600

    def test_parse_duration_seconds(self, test_config_minimal):
        """Test le parsing des durées en secondes"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        assert configurator._parse_duration("120") == 120

    @patch('logging.root')
    def test_setup_main_logger(self, mock_root, test_config_minimal):
        """Test la configuration du logger principal"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        # Mock des handlers existants
        mock_root.handlers = [mock_open(), mock_open()]
        
        configurator.setup_main_logger()
        
        # Vérifie que les handlers existants ont été supprimés
        assert mock_root.removeHandler.call_count == 2
        # Vérifie que le niveau a été configuré
        mock_root.setLevel.assert_called_once()
        # Vérifie que les nouveaux handlers ont été ajoutés
        assert mock_root.addHandler.call_count == 2

    def test_setup_audit_logger_disabled(self, test_config_minimal):
        """Test que le logger d'audit n'est pas créé quand désactivé"""
        configurator = LoggingConfigurator(test_config_minimal)
        
        audit_logger = configurator.setup_audit_logger()
        assert audit_logger is None

    def test_setup_audit_logger_enabled(self, test_config_minimal):
        """Test la création du logger d'audit quand activé"""
        # Active l'audit dans la config
        test_config_minimal["logging"]["audit_enabled"] = True
        test_config_minimal["logging"]["audit_file"] = "test_audit.log"
        
        configurator = LoggingConfigurator(test_config_minimal)
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = mock_open()
            mock_get_logger.return_value = mock_logger
            
            audit_logger = configurator.setup_audit_logger()
            
            assert audit_logger is not None
            mock_get_logger.assert_called_with("tinycti.audit")

    def test_configuration_validation_edge_cases(self, temp_directory):
        """Test les cas limites de validation de configuration"""
        
        # Config avec feed sans URL
        no_url_config = {
            "feeds": [{
                "name": "test",
                "type": "text"
                # URL manquante
            }],
            "output_dir": "test"
        }
        
        config_file = temp_directory / "no_url.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(no_url_config, f)
        
        loader = ConfigurationLoader(str(config_file))
        
        with pytest.raises(ConfigurationError):
            loader.load_config()

    def test_configuration_with_special_characters(self, temp_directory):
        """Test la configuration avec des caractères spéciaux"""
        special_config = {
            "feeds": [{
                "name": "test-feed_123",
                "type": "text",
                "url": "https://example.com/path?param=value&other=test"
            }],
            "output_dir": "test"
        }
        
        config_file = temp_directory / "special.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(special_config, f)
        
        loader = ConfigurationLoader(str(config_file))
        config = loader.load_config()
        
        assert config["feeds"][0]["name"] == "test-feed_123"
        assert "param=value" in config["feeds"][0]["url"]

    @pytest.mark.parametrize("invalid_retention", [
        "invalid_bucket",
        "LIVE",  # Case sensitive
        "hot",   # Nom incorrect
        123      # Type incorrect
    ])
    def test_invalid_retention_values(self, temp_directory, invalid_retention):
        """Test la validation avec des valeurs de rétention invalides"""
        invalid_config = {
            "feeds": [{
                "name": "test",
                "type": "text",
                "url": "http://example.com",
                "retention": invalid_retention
            }],
            "output_dir": "test"
        }
        
        config_file = temp_directory / f"invalid_retention_{invalid_retention}.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        loader = ConfigurationLoader(str(config_file))
        
        with pytest.raises(ConfigurationError):
            loader.load_config()