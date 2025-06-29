# TinyCTI Makefile - Commandes pour développeurs

.PHONY: help install test test-quick test-coverage test-watch clean lint format security docker

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
	@echo "Exemples:"
	@echo "  make install-dev  # Premier setup"
	@echo "  make test-quick   # Tests rapides"
	@echo "  make test-watch   # Tests automatiques"
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
	@echo -e "$(YELLOW)🧹 Nettoyage...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml .pytest_cache/ 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true
	rm -rf test_logs/ temp_test_* 2>/dev/null || true
	rm -f pytest-*.xml test-report.txt 2>/dev/null || true
	@echo -e "$(GREEN)✅ Nettoyage terminé$(NC)"

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
	@echo -e "$(GREEN)✅ Code formaté$(NC)"

format-check:
	@echo -e "$(YELLOW) Vérification du formatage...$(NC)"
	black --check --diff .
	isort --check-only --diff .

# Sécurité
security:
	@echo -e "$(YELLOW) Scans de sécurité...$(NC)"
	bandit -r . -f txt || true
	safety check || true
	@echo -e "$(GREEN)✅ Scans de sécurité terminés$(NC)"

# Docker
docker-build:
	@echo -e "$(YELLOW) Construction de l'image Docker...$(NC)"
	docker build -t tinycti:latest .
	@echo -e "$(GREEN)✅ Image Docker construite$(NC)"

docker-test: docker-build
	@echo -e "$(YELLOW) Test de l'image Docker...$(NC)"
	docker run --rm tinycti:latest python -c "import tinycti; print('✅ TinyCTI fonctionne dans Docker')"

# Configuration développement
setup-dev: install-dev
	@echo -e "$(YELLOW)  Configuration de l'environnement de développement...$(NC)"
	@echo "Création des répertoires de base..."
	mkdir -p logs iocs/{live,chaud,tiede,froid} ngfw
	@echo "Configuration Git hooks..."
	pre-commit install
	@echo -e "$(GREEN)✅ Environnement de développement configuré$(NC)"
	@echo ""
	@echo " Prêt pour le développement!"
	@echo "   Lancez: make test-quick pour vérifier"

# Vérification complète avant commit
pre-commit: clean format-check lint test-quick
	@echo -e "$(GREEN)✅ Vérifications pré-commit terminées$(NC)"

# Build de production
build:
	@echo -e "$(YELLOW) Construction du package...$(NC)"
	$(PYTHON) -m build
	twine check dist/*
	@echo -e "$(GREEN)✅ Package construit$(NC)"

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
	@echo -e "$(GREEN)✅ Documentation générée$(NC)"

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
	@echo -e "$(YELLOW)🔬 Profiling de performance...$(NC)"
	$(PYTHON) -m cProfile -s cumulative tinycti.py > profile.txt
	@echo "Profil sauvé dans profile.txt"

# Vérification de la sécurité approfondie
security-deep:
	@echo -e "$(YELLOW) Scan de sécurité approfondi...$(NC)"
	bandit -r . -f json -o bandit-report.json
	safety check --json --output safety-report.json
	@echo -e "$(GREEN)✅ Rapports de sécurité générés$(NC)"
