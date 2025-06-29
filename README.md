# TinyCTI

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-80%25+-green.svg)](#testing)

> **English** | [Français](#français)

## English

### Overview

TinyCTI is a lightweight, modular framework for collecting and managing Cyber Threat Intelligence (CTI) indicators. It automatically fetches IOCs (Indicators of Compromise) from various sources, classifies them, and exports them in multiple formats for integration with security tools.

### ✨ Key Features

**🏗️ Three-Component Architecture:**
- **🌐 External API Client**: Secure IOC collection from third-party APIs with SSL/TLS and advanced auth
- **📁 Internal File API**: Direct .txt file exposure by bucket for system integration  
- **🎛️ Web Management Interface**: Graphical service management and monitoring

**🔄 Advanced Collection:**
- **Multi-source Support**: Text, CSV, JSON, STIX, RSS, and TAXII feeds
- **Enterprise SSL/TLS**: Client certificates, custom CA bundles, production-grade security
- **Advanced Authentication**: Basic, Bearer tokens, API keys, OAuth2 for external APIs
- **Smart Classification**: Automatic IOC type detection with private IP filtering

**📦 Intelligent Storage:**
- **Four-tier Retention**: live, chaud, tiede, froid buckets with automatic transitions
- **Atomic Operations**: Race condition protection and data integrity guarantees
- **Automatic Compression**: Gzip compression for aged buckets (non-live)
- **Pure Raw Format**: Live bucket maintains IOC-only format for direct consumption

**🔒 Production Security:**
- **SSL/TLS Everywhere**: Full certificate management and verification
- **Multi-layer Auth**: Local users, SAML v2, OpenID Connect, and API tokens
- **Rate Limiting**: Configurable limits for all endpoints
- **Audit Logging**: Comprehensive security event tracking

### 🚀 Quick Start

#### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/tinycti.git
cd tinycti

# Install dependencies
pip install -r requirements.txt

# Validate configuration
python3 tinycti.py --validate-config

# Start collecting IOCs (one-shot)
python3 tinycti.py

# Start as daemon with API
python3 tinycti.py --daemon --api
```

#### Using the Binary

```bash
# Make the binary accessible
export PATH="$PWD/bin:$PATH"

# Run TinyCTI
tinycti --help
tinycti --daemon
```

### 📖 Usage Examples

#### Basic Collection
```bash
# One-shot collection with default config
tinycti

# Verbose output
tinycti --verbose

# Debug mode
tinycti --debug
```

#### Daemon Mode
```bash
# Start daemon
tinycti --daemon

# Start daemon with API
tinycti --daemon --api

# Check daemon status
./tools/tinycti-daemon status

# Stop daemon
./tools/tinycti-daemon stop
```

#### API Usage
```bash
# Start API only (no collection)
tinycti --api

# Export IOCs as JSON
curl http://localhost:5000/api/export/json/ipv4

# Export IOCs as CSV
curl http://localhost:5000/api/export/csv/domain

# Get system status
curl http://localhost:5000/api/status
```

#### NGFW Export
```bash
# Manual NGFW export
tinycti --export-ngfw

# Generated files will be in ngfw/ directory:
# - iptables-rules.sh
# - pfsense-aliases.txt
# - malicious-ips.txt
# - malicious-domains.txt
```

### 🛠️ Configuration

The main configuration file is `config.yaml`. Key sections:

#### Bucket Logic & Data Integrity

TinyCTI uses a four-tier retention system with enhanced reliability:

- **live**: Fresh IOCs in raw format (no metadata headers)
- **chaud**: Recent IOCs (24h+ old) 
- **tiede**: Warm IOCs (7d+ old)
- **froid**: Cold IOCs (30d+ old) with automatic compression

**Key Features:**
- ✅ **Atomic file operations** prevent data corruption
- ✅ **Automatic compression** for non-live buckets  
- ✅ **Race condition protection** with file locking
- ✅ **Database-file consistency** with transactional updates
- ✅ **Pure raw format** for live bucket (no comments/headers)
- ✅ **Intelligent deduplication** with bucket priority hierarchy

```yaml
# IOC Sources
feeds:
  - name: "URLhaus_URLs"
    type: "text"
    url: "https://urlhaus.abuse.ch/downloads/text/"
    retention: "live"
    schedule: "30m"

# API Configuration
api:
  enabled: true
  host: "127.0.0.1"
  port: 5000
  auth:
    enabled: true
    password: "your-api-key"

# Authentication
authentication:
  users:
    admin:
      password_hash: "$2b$12$..."
      role: "admin"

# Retention Policy with Compression
retention_policy:
  live_to_chaud: "24h"
  chaud_to_tiede: "7d"
  tiede_to_froid: "30d"
  froid_retention: "365d"
  
# Bucket Configuration
# - live: Raw IOCs only (no metadata, no compression)
# - chaud/tiede/froid: Automatic compression on rotation
```

#### Generate Password Hash
```bash
./tools/generate-password
```

### 🧪 Testing

TinyCTI includes a comprehensive test suite:

```bash
# Run all tests
./scripts/test

# Unit tests only
./scripts/test --unit

# Integration tests only
./scripts/test --integration

# Tests with coverage
./scripts/test --coverage

# Quick tests (skip slow ones)
./scripts/test --quick

# Watch mode (auto-rerun)
./scripts/test --watch
```

#### Using Make
```bash
# Quick tests
make test-quick

# Full test suite
make test-all

# Coverage report
make test-coverage

# Development setup
make setup-dev
```

### 🏗️ Three-Component Architecture

TinyCTI implements a clean separation between three distinct systems:

#### 1. 🌐 External API Client
**Purpose**: Secure collection from third-party APIs
```yaml
feeds:
  - name: "enterprise_feed"
    url: "https://threat-api.company.com/iocs"
    ssl:
      verify: true
      cert_file: "/path/to/client.crt"
      key_file: "/path/to/client.key"
    auth:
      type: "api_key"
      key: "your-api-key"
      header: "X-API-Key"
```

#### 2. 📁 Internal File API  
**Purpose**: Direct .txt file exposure by bucket
```yaml
internal_api:
  enabled: true
  host: "127.0.0.1" 
  port: 8080
  auth_token: "secure-token"
```

**Usage:**
```bash
# Get live IOCs
curl -H "Authorization: Bearer secure-token" \
     http://localhost:8080/bucket/live/ipv4.txt

# Get bucket statistics  
curl http://localhost:8080/bucket/live/stats
```

#### 3. 🎛️ Web Management Interface
**Purpose**: Graphical administration and monitoring
```bash
# Access web interface
http://localhost:5000/

# API management
curl -X POST http://localhost:5000/api/feeds/toggle/feed_name
```

### 📁 Project Structure

```
tinycti/
├── bin/tinycti              # Main executable
├── tools/                   # Utility scripts
│   ├── tinycti-daemon      # Daemon control
│   └── generate-password   # Password hash generator
├── scripts/                 # Development scripts
│   └── test                # Test runner
├── tests/                   # Test suite
│   ├── unit/               # Unit tests
│   └── integration/        # Integration tests
├── docs/                    # Documentation
├── examples/               # Configuration examples
├── tinycti.py              # Main application
├── config.yaml             # Configuration file
└── requirements.txt        # Dependencies
```

### 🔧 Development

#### Prerequisites
- Python 3.8+
- pip
- git

#### Setup Development Environment
```bash
# Clone and setup
git clone https://github.com/your-org/tinycti.git
cd tinycti

# Setup development environment
make setup-dev

# Run tests in watch mode
make test-watch

# Format code
make format

# Run security checks
make security
```

#### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Run the test suite
5. Submit a pull request

### 🔒 Security

TinyCTI implements multiple security layers:

- **Input Validation**: All inputs are validated and sanitized
- **Authentication**: Multiple authentication methods supported
- **Rate Limiting**: API endpoints are rate-limited
- **Audit Logging**: All actions are logged for compliance
- **Secure Defaults**: Security-first configuration defaults

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Français

### Aperçu

TinyCTI est un framework modulaire léger pour la collecte et la gestion d'indicateurs de Cyber Threat Intelligence (CTI). Il récupère automatiquement des IOCs (Indicateurs de Compromission) depuis diverses sources, les classifie et les exporte dans plusieurs formats pour l'intégration avec les outils de sécurité.

### ✨ Fonctionnalités Principales

- **🔄 Collecte Multi-sources**: Support des flux texte, CSV, JSON, STIX, RSS et TAXII
- **🧠 Classification Intelligente**: Détection automatique du type d'IOC (IPs, domaines, URLs, hashs, emails)
- **📦 Gestion de Rétention**: Système à quatre niveaux (live, chaud, tiède, froid) avec transitions automatiques
- **🔒 Authentification Enterprise**: Support utilisateurs locaux, SAML v2 et OpenID Connect
- **🌐 API REST**: API complète avec export JSON/CSV/texte
- **📊 Monitoring Temps Réel**: Dashboard web et logging complet
- **🛡️ Intégration NGFW**: Export direct pour pfSense, iptables et autres firewalls
- **⚡ Haute Performance**: Traitement parallèle et déduplication intelligente
- **🔐 Sécurité d'Abord**: Rate limiting, audit logging et validation d'entrée

### 🚀 Démarrage Rapide

#### Installation

```bash
# Cloner le dépôt
git clone https://github.com/your-org/tinycti.git
cd tinycti

# Installer les dépendances
pip install -r requirements.txt

# Valider la configuration
python3 tinycti.py --validate-config

# Démarrer la collecte d'IOCs (one-shot)
python3 tinycti.py

# Démarrer en mode daemon avec API
python3 tinycti.py --daemon --api
```

### 📖 Exemples d'Utilisation

#### Collecte de Base
```bash
# Collecte one-shot avec config par défaut
tinycti

# Mode verbeux
tinycti --verbose

# Mode debug
tinycti --debug
```

#### Mode Daemon
```bash
# Démarrer le daemon
tinycti --daemon

# Démarrer le daemon avec API
tinycti --daemon --api

# Vérifier le statut du daemon
./tools/tinycti-daemon status

# Arrêter le daemon
./tools/tinycti-daemon stop
```

#### Utilisation de l'API
```bash
# Démarrer l'API seulement (sans collecte)
tinycti --api

# Exporter les IOCs en JSON
curl http://localhost:5000/api/export/json/ipv4

# Exporter les IOCs en CSV
curl http://localhost:5000/api/export/csv/domain

# Obtenir le statut système
curl http://localhost:5000/api/status
```

### 🧪 Tests

TinyCTI inclut une suite de tests complète :

```bash
# Lancer tous les tests
./scripts/test

# Tests unitaires seulement
./scripts/test --unit

# Tests d'intégration seulement
./scripts/test --integration

# Tests avec couverture
./scripts/test --coverage

# Tests rapides (exclut les lents)
./scripts/test --quick

# Mode watch (relance automatique)
./scripts/test --watch
```

#### Utilisation de Make
```bash
# Tests rapides
make test-quick

# Suite de tests complète
make test-all

# Rapport de couverture
make test-coverage

# Configuration développement
make setup-dev
```

### 📁 Logique des Buckets et Intégrité

TinyCTI utilise un système de rétention à quatre niveaux avec fiabilité renforcée :

- **live** : IOCs récents en format brut (sans métadonnées)
- **chaud** : IOCs récents (24h+ d'âge)
- **tiède** : IOCs tièdes (7j+ d'âge)  
- **froid** : IOCs froids (30j+ d'âge) avec compression automatique

**Fonctionnalités Clés :**
- ✅ **Opérations atomiques** préviennent la corruption des données
- ✅ **Compression automatique** pour buckets non-live
- ✅ **Protection race conditions** avec verrouillage de fichiers
- ✅ **Cohérence base-fichiers** avec mises à jour transactionnelles
- ✅ **Format brut pur** pour bucket live (pas de commentaires/headers)
- ✅ **Déduplication intelligente** avec hiérarchie de priorité des buckets

### 🔧 Développement

#### Prérequis
- Python 3.8+
- pip
- git

#### Configuration Environnement de Développement
```bash
# Cloner et configurer
git clone https://github.com/your-org/tinycti.git
cd tinycti

# Configurer l'environnement de développement
make setup-dev

# Lancer les tests en mode watch
make test-watch

# Formater le code
make format

# Lancer les vérifications de sécurité
make security
```

### 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour les détails.

---

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/tinycti/issues)
- **Documentation**: [Wiki](https://github.com/your-org/tinycti/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/tinycti/discussions)

## 🙏 Acknowledgments

- **Abuse.ch** for providing free threat intelligence feeds
- **STIX/TAXII** community for standardization efforts
- **Open Source Security** community for inspiration and feedback