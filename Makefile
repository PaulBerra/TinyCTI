# TinyCTI Makefile - Commandes pour développeurs et déploiement

.PHONY: help install test test-quick test-coverage test-watch clean lint format security 
.PHONY: docker deploy systemd docker-build docker-run docker-stop
.PHONY: start-daemon start-api stop-daemon stop-api status logs oneshot export-ngfw
.PHONY: install-system uninstall-system

# Variables
PYTHON := python3
PIP := pip
PYTEST := pytest
VENV := venv
COVERAGE_THRESHOLD := 80

# Couleurs pour l'affichage
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

# Aide par défaut
help:
	@echo -e "$(BLUE)TinyCTI - Commandes de développement$(NC)"
	@echo ""
	@echo "Commandes disponibles:"
	@echo "  help              Affiche cette aide"
	@echo "  install           Installe les dépendances"
	@echo "  install-dev       Installe les dépendances de développement"
	@echo "  test              Lance tous les tests"
	@echo "  test-quick        Lance les tests rapides"
	@echo "  test-coverage     Lance les tests avec couverture"
	@echo "  test-watch        Mode watch pour tests continus"
	@echo "  test-integration  Lance les tests d'intégration"
	@echo "  test-security     Lance les tests de sécurité"
	@echo "  clean             Nettoie les artifacts"
	@echo "  lint              Vérifications de code (flake8, mypy)"
	@echo "  format            Formate le code (black, isort)"
	@echo "  security          Scans de sécurité (bandit, safety)"
	@echo "  docker-build      Construit l'image Docker"
	@echo "  docker-test       Teste l'image Docker"
	@echo "  setup-dev         Configuration complète pour développement"
	@echo ""
	@echo -e "$(YELLOW)Déploiement:$(NC)"
	@echo "  help-deploy       Aide pour les commandes de déploiement"
	@echo "  install-system    Installation système avec systemd"
	@echo "  start-daemon      Démarre le daemon TinyCTI"
	@echo "  status            Statut des services"
	@echo ""
	@echo "Exemples:"
	@echo "  make install-dev  # Premier setup"
	@echo "  make test-quick   # Tests rapides"
	@echo "  make test-watch   # Tests automatiques"
	@echo "  make help-deploy  # Aide déploiement"
	@echo ""

# Installation des dépendances
install:
	@echo -e "$(YELLOW) Installation des dépendances...$(NC)"
	$(PIP) install -r requirements.txt

install-dev: install
	@echo -e "$(YELLOW) Installation des dépendances de développement...$(NC)"
	$(PIP) install pytest pytest-cov pytest-xdist pytest-mock requests-mock
	$(PIP) install black flake8 mypy isort
	$(PIP) install bandit safety
	$(PIP) install pre-commit
	pre-commit install

# Tests
test:
	@echo -e "$(BLUE) Lancement des tests complets...$(NC)"
	./scripts/test

test-quick:
	@echo -e "$(BLUE) Tests rapides...$(NC)"
	./scripts/test --unit --quick

test-coverage:
	@echo -e "$(BLUE) Tests avec couverture...$(NC)"
	./scripts/test --coverage

test-watch:
	@echo -e "$(BLUE) Mode watch...$(NC)"
	./scripts/test --watch

test-integration:
	@echo -e "$(BLUE) Tests d'intégration...$(NC)"
	./scripts/test --integration

test-unit:
	@echo -e "$(BLUE) Tests unitaires...$(NC)"
	./scripts/test --unit

test-all:
	@echo -e "$(BLUE) Tous les tests...$(NC)"
	./scripts/test --unit --integration --coverage

# Nettoyage
clean:
	@echo -e "$(YELLOW) Nettoyage...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml .pytest_cache/ 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true
	rm -rf test_logs/ temp_test_* 2>/dev/null || true
	rm -f pytest-*.xml test-report.txt 2>/dev/null || true
	@echo -e "$(GREEN) Nettoyage terminé$(NC)"

# Qualité de code
lint:
	@echo -e "$(YELLOW) Vérifications de code...$(NC)"
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
	mypy tinycti.py --ignore-missing-imports || true

format:
	@echo -e "$(YELLOW) Formatage du code...$(NC)"
	black .
	isort .
	@echo -e "$(GREEN) Code formaté$(NC)"

format-check:
	@echo -e "$(YELLOW) Vérification du formatage...$(NC)"
	black --check --diff .
	isort --check-only --diff .

# Sécurité
security:
	@echo -e "$(YELLOW) Scans de sécurité...$(NC)"
	bandit -r . -f txt || true
	safety check || true
	@echo -e "$(GREEN) Scans de sécurité terminés$(NC)"

# Docker (voir section déploiement pour les commandes Docker complètes)

# Configuration développement
setup-dev: install-dev
	@echo -e "$(YELLOW)  Configuration de l'environnement de développement...$(NC)"
	@echo "Création des répertoires de base..."
	mkdir -p logs iocs/{live,chaud,tiede,froid} ngfw
	@echo "Configuration Git hooks..."
	pre-commit install
	@echo -e "$(GREEN) Environnement de développement configuré$(NC)"
	@echo ""
	@echo " Prêt pour le développement!"
	@echo "   Lancez: make test-quick pour vérifier"

# Vérification complète avant commit
pre-commit: clean format-check lint test-quick
	@echo -e "$(GREEN) Vérifications pré-commit terminées$(NC)"

# Build de production
build:
	@echo -e "$(YELLOW) Construction du package...$(NC)"
	$(PYTHON) -m build
	twine check dist/*
	@echo -e "$(GREEN) Package construit$(NC)"

# Installation en mode éditable
install-editable:
	@echo -e "$(YELLOW) Installation en mode éditable...$(NC)"
	$(PIP) install -e .

# Mise à jour des dépendances
update-deps:
	@echo -e "$(YELLOW) Mise à jour des dépendances...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install --upgrade -r requirements.txt

# Génération de la documentation
docs:
	@echo -e "$(YELLOW) Génération de la documentation...$(NC)"
	mkdir -p docs
	$(PYTHON) -c "import tinycti; help(tinycti)" > docs/tinycti-help.txt
	@echo -e "$(GREEN) Documentation générée$(NC)"

# Statistiques du projet
stats:
	@echo -e "$(BLUE) Statistiques du projet$(NC)"
	@echo ""
	@echo "Lignes de code:"
	find . -name "*.py" -not -path "./venv/*" -not -path "./.venv/*" | xargs wc -l | tail -1
	@echo ""
	@echo "Nombre de tests:"
	find tests/ -name "test_*.py" | wc -l
	@echo ""
	@echo "Nombre de fichiers Python:"
	find . -name "*.py" -not -path "./venv/*" -not -path "./.venv/*" | wc -l

# Benchmark
benchmark:
	@echo -e "$(YELLOW) Benchmark de performance...$(NC)"
	$(PYTEST) tests/ -k "benchmark" --benchmark-only --benchmark-sort=mean

# Profiling
profile:
	@echo -e "$(YELLOW) Profiling de performance...$(NC)"
	$(PYTHON) -m cProfile -s cumulative tinycti.py > profile.txt
	@echo "Profil sauvé dans profile.txt"

# Vérification de la sécurité approfondie
security-deep:
	@echo -e "$(YELLOW) Scan de sécurité approfondi...$(NC)"
	bandit -r . -f json -o bandit-report.json
	safety check --json --output safety-report.json
	@echo -e "$(GREEN) Rapports de sécurité générés$(NC)"

# ==============================
# COMMANDES DE DÉPLOIEMENT
# ==============================

# Installation système
install-system:
	@echo -e "$(YELLOW) Installation système de TinyCTI...$(NC)"
	sudo ./deployment/scripts/install.sh --systemd
	@echo -e "$(GREEN) TinyCTI installé avec systemd$(NC)"

install-docker:
	@echo -e "$(YELLOW) Installation avec support Docker...$(NC)"
	sudo ./deployment/scripts/install.sh --docker
	@echo -e "$(GREEN) TinyCTI installé avec Docker$(NC)"

install-standalone:
	@echo -e "$(YELLOW) Installation standalone...$(NC)"
	sudo ./deployment/scripts/install.sh --standalone
	@echo -e "$(GREEN) TinyCTI installé en mode standalone$(NC)"

# Désinstallation
uninstall-system:
	@echo -e "$(YELLOW) Désinstallation de TinyCTI...$(NC)"
	sudo ./deployment/scripts/uninstall.sh
	@echo -e "$(GREEN) TinyCTI désinstallé$(NC)"

uninstall-force:
	@echo -e "$(YELLOW) Désinstallation forcée de TinyCTI...$(NC)"
	sudo ./deployment/scripts/uninstall.sh --force
	@echo -e "$(GREEN) TinyCTI désinstallé (forcé)$(NC)"

# ==============================
# GESTION DES SERVICES
# ==============================

# Démarrage des services
start-daemon:
	@echo -e "$(YELLOW) Démarrage du daemon TinyCTI...$(NC)"
	./deployment/scripts/tinycti-manager.sh start-daemon

start-api:
	@echo -e "$(YELLOW) Démarrage de l'API TinyCTI...$(NC)"
	./deployment/scripts/tinycti-manager.sh start-api

# Arrêt des services
stop-daemon:
	@echo -e "$(YELLOW) Arrêt du daemon TinyCTI...$(NC)"
	./deployment/scripts/tinycti-manager.sh stop-daemon

stop-api:
	@echo -e "$(YELLOW) Arrêt de l'API TinyCTI...$(NC)"
	./deployment/scripts/tinycti-manager.sh stop-api

stop-all:
	@echo -e "$(YELLOW) Arrêt de tous les services TinyCTI...$(NC)"
	./deployment/scripts/tinycti-manager.sh stop-all

# Redémarrage des services
restart-daemon:
	@echo -e "$(YELLOW) Redémarrage du daemon TinyCTI...$(NC)"
	./deployment/scripts/tinycti-manager.sh restart-daemon

restart-api:
	@echo -e "$(YELLOW) Redémarrage de l'API TinyCTI...$(NC)"
	./deployment/scripts/tinycti-manager.sh restart-api

# Statut et logs
status:
	@echo -e "$(BLUE) Statut des services TinyCTI$(NC)"
	./deployment/scripts/tinycti-manager.sh status

logs:
	@echo -e "$(BLUE) Logs du daemon TinyCTI$(NC)"
	./deployment/scripts/tinycti-manager.sh logs daemon

logs-api:
	@echo -e "$(BLUE) Logs de l'API TinyCTI$(NC)"
	./deployment/scripts/tinycti-manager.sh logs api

# ==============================
# OPÉRATIONS TINYCTI
# ==============================

# Collecte manuelle
oneshot:
	@echo -e "$(YELLOW) Collecte one-shot...$(NC)"
	./deployment/scripts/tinycti-manager.sh oneshot

# Export NGFW manuel
export-ngfw:
	@echo -e "$(YELLOW) Export NGFW manuel...$(NC)"
	./deployment/scripts/tinycti-manager.sh export-ngfw

# Utilitaires
generate-password:
	@echo -e "$(YELLOW) Génération de hash de mot de passe...$(NC)"
	./deployment/scripts/generate-password

dev-run:
	@echo -e "$(YELLOW) Démarrage en mode développement...$(NC)"
	./deployment/scripts/dev-run.sh daemon --debug

dev-api:
	@echo -e "$(YELLOW) Démarrage API en mode développement...$(NC)"
	./deployment/scripts/dev-run.sh api --debug --port 8080

dev-clean:
	@echo -e "$(YELLOW) Nettoyage environnement de développement...$(NC)"
	./deployment/scripts/dev-clean.sh

dev-clean-all:
	@echo -e "$(YELLOW) Nettoyage complet environnement de développement...$(NC)"
	./deployment/scripts/dev-clean.sh --all --force

# ==============================
# DOCKER
# ==============================

# Construction Docker
docker-build:
	@echo -e "$(YELLOW) Construction de l'image Docker...$(NC)"
	docker build -f deployment/docker/Dockerfile -t tinycti:latest .
	@echo -e "$(GREEN) Image Docker construite$(NC)"

# Test Docker
docker-test: docker-build
	@echo -e "$(YELLOW) Test de l'image Docker...$(NC)"
	docker run --rm tinycti:latest python -c "import tinycti; print('✓ TinyCTI fonctionne dans Docker')"

# Démarrage Docker Compose
docker-up:
	@echo -e "$(YELLOW) Démarrage avec Docker Compose...$(NC)"
	cd deployment/docker && docker-compose up -d
	@echo -e "$(GREEN) TinyCTI démarré avec Docker Compose$(NC)"

# Arrêt Docker Compose
docker-down:
	@echo -e "$(YELLOW) Arrêt de Docker Compose...$(NC)"
	cd deployment/docker && docker-compose down
	@echo -e "$(GREEN) TinyCTI arrêté$(NC)"

# Logs Docker
docker-logs:
	@echo -e "$(BLUE) Logs Docker TinyCTI$(NC)"
	cd deployment/docker && docker-compose logs -f tinycti

# ==============================
# SYSTEMD
# ==============================

# Services systemd (nécessite installation système)
systemd-start:
	@echo -e "$(YELLOW) Démarrage service systemd...$(NC)"
	sudo systemctl start tinycti
	@echo -e "$(GREEN) Service systemd démarré$(NC)"

systemd-stop:
	@echo -e "$(YELLOW) Arrêt service systemd...$(NC)"
	sudo systemctl stop tinycti
	@echo -e "$(GREEN) Service systemd arrêté$(NC)"

systemd-restart:
	@echo -e "$(YELLOW) Redémarrage service systemd...$(NC)"
	sudo systemctl restart tinycti
	@echo -e "$(GREEN) Service systemd redémarré$(NC)"

systemd-status:
	@echo -e "$(BLUE) Statut service systemd$(NC)"
	sudo systemctl status tinycti

systemd-logs:
	@echo -e "$(BLUE) Logs systemd TinyCTI$(NC)"
	sudo journalctl -u tinycti -f

# ==============================
# AIDE ÉTENDUE
# ==============================

help-deploy:
	@echo -e "$(BLUE)TinyCTI - Commandes de déploiement$(NC)"
	@echo ""
	@echo -e "$(YELLOW)Installation:$(NC)"
	@echo "  install-system     - Installation avec systemd"
	@echo "  install-docker     - Installation avec Docker"
	@echo "  install-standalone - Installation standalone"
	@echo "  uninstall-system   - Désinstallation complète"
	@echo ""
	@echo -e "$(YELLOW)Gestion des services:$(NC)"
	@echo "  start-daemon       - Démarre le daemon TinyCTI"
	@echo "  start-api          - Démarre l'API TinyCTI"
	@echo "  stop-daemon        - Arrête le daemon"
	@echo "  stop-api           - Arrête l'API"
	@echo "  restart-daemon     - Redémarre le daemon"
	@echo "  status             - Affiche le statut"
	@echo "  logs               - Affiche les logs du daemon"
	@echo "  logs-api           - Affiche les logs de l'API"
	@echo ""
	@echo -e "$(YELLOW)Opérations:$(NC)"
	@echo "  oneshot            - Collecte one-shot"
	@echo "  export-ngfw        - Export NGFW manuel"
	@echo "  generate-password  - Génère un hash de mot de passe"
	@echo ""
	@echo -e "$(YELLOW)Développement:$(NC)"
	@echo "  dev-run            - Démarre en mode développement"
	@echo "  dev-api            - Démarre API de dev sur port 8080"
	@echo "  dev-clean          - Nettoie l'environnement de dev"
	@echo "  dev-clean-all      - Nettoyage complet (forcé)"
	@echo ""
	@echo -e "$(YELLOW)Docker:$(NC)"
	@echo "  docker-build       - Construit l'image Docker"
	@echo "  docker-up          - Démarre avec Docker Compose"
	@echo "  docker-down        - Arrête Docker Compose"
	@echo "  docker-logs        - Affiche les logs Docker"
	@echo ""
	@echo -e "$(YELLOW)Systemd:$(NC)"
	@echo "  systemd-start      - Démarre le service systemd"
	@echo "  systemd-stop       - Arrête le service systemd"
	@echo "  systemd-status     - Statut du service systemd"
	@echo "  systemd-logs       - Logs du service systemd"