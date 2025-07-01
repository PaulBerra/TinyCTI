#!/bin/bash
# TinyCTI Installation Script
# Supports: systemd, docker, standalone

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TINYCTI_USER="tinycti"
TINYCTI_GROUP="tinycti"
INSTALL_DIR="/opt/tinycti"
SERVICE_NAME="tinycti"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_system() {
    log_info "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check Python version
    PYTHON_VERSION=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
    REQUIRED_VERSION="3.8"
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        log_error "Python 3.8+ is required, found $PYTHON_VERSION"
        exit 1
    fi
    
    log_success "System requirements met"
}

create_user() {
    log_info "Creating TinyCTI user and group..."
    
    if ! getent group "$TINYCTI_GROUP" > /dev/null 2>&1; then
        groupadd -r "$TINYCTI_GROUP"
        log_success "Created group: $TINYCTI_GROUP"
    else
        log_info "Group $TINYCTI_GROUP already exists"
    fi
    
    if ! getent passwd "$TINYCTI_USER" > /dev/null 2>&1; then
        useradd -r -g "$TINYCTI_GROUP" -d "$INSTALL_DIR" -s /bin/bash "$TINYCTI_USER"
        log_success "Created user: $TINYCTI_USER"
    else
        log_info "User $TINYCTI_USER already exists"
    fi
}

install_dependencies() {
    log_info "Installing system dependencies..."
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y python3-pip python3-venv curl wget ca-certificates
    elif command -v yum &> /dev/null; then
        yum install -y python3-pip python3-venv curl wget ca-certificates
    elif command -v dnf &> /dev/null; then
        dnf install -y python3-pip python3-venv curl wget ca-certificates
    else
        log_warning "Unknown package manager, please install python3-pip, python3-venv, curl, wget manually"
    fi
    
    log_success "System dependencies installed"
}

install_tinycti() {
    log_info "Installing TinyCTI to $INSTALL_DIR..."
    
    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"/{iocs,ngfw,logs}
    mkdir -p "$INSTALL_DIR"/iocs/{active,critical,watch,archive}
    mkdir -p "$INSTALL_DIR"/ngfw/{active,critical,watch,archive}
    
    # Copy files
    if [[ -f "tinycti.py" ]]; then
        # Running from source directory
        cp -r . "$INSTALL_DIR/"
    else
        log_error "TinyCTI source files not found. Please run this script from the TinyCTI directory."
        exit 1
    fi
    
    # Set ownership
    chown -R "$TINYCTI_USER:$TINYCTI_GROUP" "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/tinycti.py"
    
    # Create virtual environment
    log_info "Creating Python virtual environment..."
    sudo -u "$TINYCTI_USER" python3 -m venv "$INSTALL_DIR/venv"
    
    # Install Python dependencies
    log_info "Installing Python dependencies..."
    sudo -u "$TINYCTI_USER" "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
    sudo -u "$TINYCTI_USER" "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
    
    log_success "TinyCTI installed successfully"
}

install_systemd() {
    log_info "Installing systemd service..."
    
    # Copy service file
    cp "$INSTALL_DIR/deployment/systemd/tinycti.service" /etc/systemd/system/
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable tinycti
    
    log_success "Systemd service installed and enabled"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --systemd     Install with systemd service (default)"
    echo "  --docker      Install with Docker support"
    echo "  --standalone  Install standalone (no service)"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                # Install with systemd"
    echo "  $0 --systemd      # Install with systemd"
    echo "  $0 --docker       # Install with Docker support"
    echo "  $0 --standalone   # Install standalone"
}

# Main installation logic
main() {
    local install_type="systemd"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --systemd)
                install_type="systemd"
                shift
                ;;
            --docker)
                install_type="docker"
                shift
                ;;
            --standalone)
                install_type="standalone"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "Starting TinyCTI installation (type: $install_type)..."
    
    check_root
    check_system
    create_user
    install_dependencies
    install_tinycti
    
    case $install_type in
        systemd)
            install_systemd
            log_info "To start TinyCTI: systemctl start tinycti"
            log_info "To check status: systemctl status tinycti"
            log_info "To view logs: journalctl -u tinycti -f"
            ;;
        docker)
            log_info "Docker support installed. Use docker-compose from deployment/docker/ directory"
            log_info "Example: cd $INSTALL_DIR/deployment/docker && docker-compose up -d"
            ;;
        standalone)
            log_info "Standalone installation completed"
            log_info "To run: sudo -u $TINYCTI_USER $INSTALL_DIR/venv/bin/python $INSTALL_DIR/tinycti.py -d"
            ;;
    esac
    
    log_success "TinyCTI installation completed!"
    log_info "Configuration file: $INSTALL_DIR/config.yaml"
    log_info "Web interface: http://localhost:5000 (when API is enabled)"
}

# Run main function
main "$@"