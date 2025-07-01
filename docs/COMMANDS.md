# TinyCTI Commands Reference

Complete reference for all TinyCTI commands and deployment options.

##  Quick Start Commands

```bash
# Development
make dev-run              # Start in development mode
make dev-api              # Start API on port 8080
make test-quick           # Run quick tests

# Production Installation
make install-system       # Install with systemd
make start-daemon         # Start the service
make status               # Check status
```

##  All Available Commands

### Development Commands
```bash
make help                 # Show main help
make help-deploy          # Show deployment help
make install-dev          # Install dev dependencies
make setup-dev            # Complete dev environment setup

# Running in Development
make dev-run              # Start daemon in debug mode
make dev-api              # Start API on port 8080 (debug)
./deployment/scripts/dev-run.sh daemon --debug
./deployment/scripts/dev-run.sh api --port 8080
./deployment/scripts/dev-run.sh oneshot --verbose
./deployment/scripts/dev-run.sh validate

# Testing
make test                 # All tests
make test-quick           # Quick tests only
make test-coverage        # Tests with coverage
make test-watch           # Continuous testing
make test-integration     # Integration tests
make test-security        # Security tests

# Code Quality
make lint                 # Code linting
make format               # Code formatting
make format-check         # Check formatting
make security             # Security scans
make security-deep        # Deep security analysis

# Cleanup
make clean                # Clean Python artifacts
make dev-clean            # Interactive dev cleanup
make dev-clean-all        # Force complete cleanup
./deployment/scripts/dev-clean.sh --cache
./deployment/scripts/dev-clean.sh --logs
./deployment/scripts/dev-clean.sh --data
```

### Production Installation
```bash
# Installation Options
sudo ./deployment/scripts/install.sh --systemd
sudo ./deployment/scripts/install.sh --docker
sudo ./deployment/scripts/install.sh --standalone

# Makefile shortcuts
make install-system       # Install with systemd
make install-docker       # Install with Docker support
make install-standalone   # Standalone installation

# Uninstallation
sudo ./deployment/scripts/uninstall.sh
sudo ./deployment/scripts/uninstall.sh --force
sudo ./deployment/scripts/uninstall.sh --keep-data
make uninstall-system     # Standard uninstall
make uninstall-force      # Force uninstall
```

### Service Management
```bash
# Process Management (any installation)
./deployment/scripts/tinycti-manager.sh start-daemon
./deployment/scripts/tinycti-manager.sh start-api
./deployment/scripts/tinycti-manager.sh stop-daemon
./deployment/scripts/tinycti-manager.sh stop-api
./deployment/scripts/tinycti-manager.sh restart-daemon
./deployment/scripts/tinycti-manager.sh status

# Makefile shortcuts
make start-daemon         # Start daemon
make start-api           # Start API only
make stop-daemon         # Stop daemon
make stop-api            # Stop API
make restart-daemon      # Restart daemon
make restart-api         # Restart API
make stop-all            # Stop all services
make status              # Show status
```

### SystemD Service Management
```bash
# SystemD commands (after system installation)
sudo systemctl start tinycti
sudo systemctl stop tinycti
sudo systemctl restart tinycti
sudo systemctl enable tinycti
sudo systemctl disable tinycti
sudo systemctl status tinycti

# Makefile shortcuts
make systemd-start       # Start systemd service
make systemd-stop        # Stop systemd service
make systemd-restart     # Restart systemd service
make systemd-status      # Show systemd status
```

### Docker Commands
```bash
# Docker Build and Test
make docker-build        # Build Docker image
make docker-test         # Test Docker image

# Docker Compose
cd deployment/docker
docker-compose up -d     # Start services
docker-compose down      # Stop services
docker-compose logs -f tinycti  # Follow logs

# Makefile shortcuts
make docker-up           # Start with compose
make docker-down         # Stop compose
make docker-logs         # Show Docker logs

# Manual Docker run
docker run -d --name tinycti \
  -p 5000:5000 \
  -v tinycti_data:/opt/tinycti/iocs \
  tinycti:latest
```

### Operations Commands
```bash
# Manual Operations
./deployment/scripts/tinycti-manager.sh oneshot
./deployment/scripts/tinycti-manager.sh export-ngfw

# Direct Python calls
python tinycti.py --once                    # One-shot collection
python tinycti.py --export-ngfw             # Manual NGFW export
python tinycti.py --validate-config         # Validate configuration
python tinycti.py --status                  # Show scheduler status
python tinycti.py --analyze-csv FEED_NAME   # Analyze CSV structure

# Makefile shortcuts
make oneshot             # One-shot collection
make export-ngfw         # Manual NGFW export
```

### Logging and Monitoring
```bash
# Application Logs
./deployment/scripts/tinycti-manager.sh logs daemon
./deployment/scripts/tinycti-manager.sh logs api
./deployment/scripts/tinycti-manager.sh logs daemon --lines 100

# Makefile shortcuts
make logs                # Show daemon logs
make logs-api            # Show API logs

# SystemD Logs
sudo journalctl -u tinycti -f              # Follow logs
sudo journalctl -u tinycti --since "1 hour ago"
make systemd-logs        # Follow systemd logs

# Docker Logs
docker-compose logs -f tinycti
make docker-logs         # Docker compose logs
```

### Utility Commands
```bash
# Password Generation
./deployment/scripts/generate-password
./deployment/scripts/generate-password mypassword
make generate-password   # Interactive password generator

# Configuration Analysis
python tinycti.py --analyze-csv URLhaus_URLs
python tinycti.py --validate-config

# Performance and Stats
make stats               # Project statistics
make benchmark           # Performance benchmarks
make profile             # Performance profiling
```

### CLI Modes and Options
```bash
# Basic Modes
python tinycti.py                           # Read-Config mode
python tinycti.py --once                    # Force one-shot

# Configuration
python tinycti.py -c config.yaml            # Custom config
python tinycti.py --validate-config         # Validate only

# Logging Levels
python tinycti.py -v                        # Verbose (INFO)
python tinycti.py --debug                   # Debug level

# Special Operations
python tinycti.py --export-ngfw             # Manual NGFW export
python tinycti.py --status                  # Scheduler status
python tinycti.py --analyze-csv FEED_NAME   # CSV analysis
```

##  Common Workflows

### Development Workflow
```bash
# Initial setup
git clone https://github.com/PaulBerra/TinyCTI.git
cd TinyCTI
make install-dev
make setup-dev

# Development cycle
make dev-run             # Start in debug mode
# ... make changes ...
make test-quick          # Quick tests
make lint format         # Code quality
make test-coverage       # Full tests

# Cleanup
make dev-clean           # Clean artifacts
```

### Production Deployment
```bash
# Installation
sudo ./deployment/scripts/install.sh --systemd
sudo systemctl enable tinycti

# Configuration
sudo vim /opt/tinycti/config.yaml
make generate-password   # Generate password hash

# Start and monitor
sudo systemctl start tinycti
make systemd-status
make systemd-logs
```

### Docker Deployment
```bash
# Build and deploy
make docker-build
cd deployment/docker
cp ../../config.yaml .
cp ../../ip_whitelist.yaml .
docker-compose up -d

# Monitor
make docker-logs
docker-compose ps
```

### Maintenance Tasks
```bash
# Regular operations
make oneshot             # Manual collection
make export-ngfw         # Manual export
make status              # Check health

# Updates
git pull
make install-dev         # Update dependencies
make test-quick          # Verify
sudo systemctl restart tinycti  # Restart service

# Troubleshooting
make logs                # Check logs
python tinycti.py --validate-config
make systemd-status
```

##  Reference Links

- **Installation Guide**: `docs/INSTALLATION.md`
- **Architecture**: `docs/ARCHITECTURE.md`
- **Deployment Guide**: `deployment/README.md`
- **Configuration**: `config.yaml`
- **Main Help**: `make help` or `make help-deploy`