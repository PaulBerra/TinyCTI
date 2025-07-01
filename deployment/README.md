# TinyCTI Deployment Guide

This directory contains all the deployment scripts and configurations for TinyCTI.

##  Quick Start

### Development Mode
```bash
# Quick development run
./deployment/scripts/dev-run.sh daemon

# Or using Make
make start-daemon
```

### Production Deployment

#### Option 1: SystemD Service (Recommended)
```bash
# Install with systemd
sudo ./deployment/scripts/install.sh --systemd

# Start service
sudo systemctl start tinycti
sudo systemctl enable tinycti

# Check status
sudo systemctl status tinycti
```

#### Option 2: Docker
```bash
# Install Docker support
sudo ./deployment/scripts/install.sh --docker

# Build and run
cd deployment/docker
docker-compose up -d

# Check logs
docker-compose logs -f tinycti
```

#### Option 3: Standalone
```bash
# Install standalone
sudo ./deployment/scripts/install.sh --standalone

# Run manually
sudo -u tinycti /opt/tinycti/venv/bin/python /opt/tinycti/tinycti.py -d
```

##  Directory Structure

```
deployment/
├── systemd/          # SystemD service files
│   ├── tinycti.service
│   └── tinycti-api.service
├── docker/           # Docker configuration
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── .dockerignore
└── scripts/          # Deployment scripts
    ├── install.sh
    ├── uninstall.sh
    ├── tinycti-manager.sh
    ├── dev-run.sh
    └── generate-password
```

##  Management Scripts

### Installation
- `install.sh` - Main installation script
- `uninstall.sh` - Complete system cleanup

### Process Management
- `tinycti-manager.sh` - Service management
- `dev-run.sh` - Development runner

### Utilities
- `generate-password` - Password hash generator

##  Available Commands

### Using Make (Recommended)
```bash
# Installation
make install-system      # Install with systemd
make install-docker       # Install with Docker
make install-standalone   # Standalone install

# Service Management
make start-daemon         # Start daemon
make start-api           # Start API only
make stop-daemon         # Stop daemon
make status              # Show status
make logs                # Show logs

# Docker
make docker-build        # Build image
make docker-up           # Start with compose
make docker-down         # Stop compose

# Operations
make oneshot             # Run one-shot collection
make export-ngfw         # Manual NGFW export

# Help
make help-deploy         # Full deployment help
```

### Using Scripts Directly
```bash
# Service management
./deployment/scripts/tinycti-manager.sh start-daemon
./deployment/scripts/tinycti-manager.sh status
./deployment/scripts/tinycti-manager.sh logs daemon

# Development
./deployment/scripts/dev-run.sh daemon --debug
./deployment/scripts/dev-run.sh api --port 8080
```

## 🔧 Configuration

### SystemD Service Configuration
The systemd service is configured with:
- User: `tinycti`
- Working Directory: `/opt/tinycti`
- Auto-restart on failure
- Security hardening (NoNewPrivileges, PrivateTmp, etc.)

### Docker Configuration
- Multi-stage build for smaller images
- Non-root user execution
- Volume mounts for persistent data
- Health checks included
- Optional API-only scaling service

##  Service Modes

### 1. Daemon Mode (Full Service)
- Runs scheduled IOC collection
- Includes web API interface
- Automatic NGFW exports
- Recommended for production

```bash
# SystemD
sudo systemctl start tinycti

# Direct
./deployment/scripts/tinycti-manager.sh start-daemon

# Make
make start-daemon
```

### 2. API Only Mode
- Web interface only
- No IOC collection
- Read-only access to existing data
- Good for scaling or monitoring

```bash
# Direct
./deployment/scripts/tinycti-manager.sh start-api

# Make
make start-api
```

### 3. One-Shot Mode
- Single collection run
- Exits after completion
- Good for cron jobs or testing

```bash
# Direct
./deployment/scripts/tinycti-manager.sh oneshot

# Make
make oneshot
```

##  Security Features

### SystemD Security
- Runs as dedicated user
- Filesystem isolation
- Capability restrictions
- Memory protections

### Docker Security
- Non-root container user
- Read-only filesystem where possible
- Minimal base image
- Security scanning ready

##  Monitoring & Logs

### SystemD Logs
```bash
# Real-time logs
sudo journalctl -u tinycti -f

# Recent logs
sudo journalctl -u tinycti --since "1 hour ago"

# Make command
make systemd-logs
```

### Application Logs
```bash
# Daemon logs
./deployment/scripts/tinycti-manager.sh logs daemon

# API logs
./deployment/scripts/tinycti-manager.sh logs api

# Make commands
make logs
make logs-api
```

### Docker Logs
```bash
# Compose logs
cd deployment/docker && docker-compose logs -f

# Make command
make docker-logs
```

##  Cleanup & Uninstall

### Standard Uninstall
```bash
# Interactive uninstall
sudo ./deployment/scripts/uninstall.sh

# Force uninstall (no prompts)
sudo ./deployment/scripts/uninstall.sh --force

# Keep data files
sudo ./deployment/scripts/uninstall.sh --keep-data

# Make command
make uninstall-system
```

### Complete Cleanup
```bash
# Remove everything including Docker
sudo ./deployment/scripts/uninstall.sh --force --docker
```

##  Troubleshooting

### Service Won't Start
1. Check service status: `make status`
2. Check logs: `make logs`
3. Verify configuration: `python tinycti.py --validate-config`
4. Check permissions: `ls -la /opt/tinycti`

### Docker Issues
1. Check container status: `docker ps`
2. Check logs: `make docker-logs`
3. Rebuild image: `make docker-build`
4. Clean and restart: `make docker-down && make docker-up`

### Permission Errors
1. Check user exists: `id tinycti`
2. Fix ownership: `sudo chown -R tinycti:tinycti /opt/tinycti`
3. Reinstall: `make uninstall-system && make install-system`

##  Additional Resources

- Main README: `../README.md`
- Architecture: `../docs/ARCHITECTURE.md`
- Installation Guide: `../docs/INSTALLATION.md`
- Configuration Reference: `../config.yaml`