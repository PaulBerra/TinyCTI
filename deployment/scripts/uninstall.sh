#!/bin/bash
# TinyCTI Uninstallation/Cleanup Script

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

confirm_action() {
    local message="$1"
    local default="${2:-n}"
    
    if [[ "$FORCE" == "true" ]]; then
        return 0
    fi
    
    while true; do
        if [[ "$default" == "y" ]]; then
            read -p "$message [Y/n]: " yn
            yn=${yn:-y}
        else
            read -p "$message [y/N]: " yn
            yn=${yn:-n}
        fi
        
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

stop_services() {
    log_info "Stopping TinyCTI services..."
    
    # Stop systemd services
    for service in tinycti tinycti-api; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "Stopping $service service..."
            systemctl stop "$service"
            log_success "$service stopped"
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_info "Disabling $service service..."
            systemctl disable "$service"
            log_success "$service disabled"
        fi
    done
    
    # Stop Docker containers
    if command -v docker &> /dev/null; then
        if docker ps -q --filter "name=tinycti" | grep -q .; then
            log_info "Stopping Docker containers..."
            docker stop $(docker ps -q --filter "name=tinycti") 2>/dev/null || true
            log_success "Docker containers stopped"
        fi
        
        if docker ps -aq --filter "name=tinycti" | grep -q .; then
            if confirm_action "Remove Docker containers?"; then
                docker rm $(docker ps -aq --filter "name=tinycti") 2>/dev/null || true
                log_success "Docker containers removed"
            fi
        fi
    fi
}

remove_services() {
    log_info "Removing service files..."
    
    # Remove systemd service files
    for service in tinycti.service tinycti-api.service; do
        if [[ -f "/etc/systemd/system/$service" ]]; then
            rm -f "/etc/systemd/system/$service"
            log_success "Removed /etc/systemd/system/$service"
        fi
    done
    
    # Reload systemd
    if command -v systemctl &> /dev/null; then
        systemctl daemon-reload
        log_success "Systemd reloaded"
    fi
}

remove_user_group() {
    log_info "Removing TinyCTI user and group..."
    
    if getent passwd "$TINYCTI_USER" > /dev/null 2>&1; then
        # Kill any remaining processes
        pkill -u "$TINYCTI_USER" 2>/dev/null || true
        sleep 2
        
        if confirm_action "Remove user $TINYCTI_USER?"; then
            userdel "$TINYCTI_USER" 2>/dev/null || true
            log_success "User $TINYCTI_USER removed"
        fi
    fi
    
    if getent group "$TINYCTI_GROUP" > /dev/null 2>&1; then
        if confirm_action "Remove group $TINYCTI_GROUP?"; then
            groupdel "$TINYCTI_GROUP" 2>/dev/null || true
            log_success "Group $TINYCTI_GROUP removed"
        fi
    fi
}

remove_files() {
    log_info "Removing TinyCTI files..."
    
    if [[ -d "$INSTALL_DIR" ]]; then
        if confirm_action "Remove installation directory $INSTALL_DIR? (This will delete all data!)"; then
            rm -rf "$INSTALL_DIR"
            log_success "Installation directory removed"
        else
            log_info "Keeping installation directory"
        fi
    fi
    
    # Remove logs from /var/log if they exist
    for logfile in /var/log/tinycti*.log; do
        if [[ -f "$logfile" ]]; then
            if confirm_action "Remove log file $logfile?"; then
                rm -f "$logfile"
                log_success "Log file $logfile removed"
            fi
        fi
    done
}

remove_docker_resources() {
    if ! command -v docker &> /dev/null; then
        return
    fi
    
    log_info "Checking Docker resources..."
    
    # Remove images
    if docker images --format "table {{.Repository}}" | grep -q "tinycti"; then
        if confirm_action "Remove TinyCTI Docker images?"; then
            docker rmi $(docker images --format "{{.Repository}}:{{.Tag}}" | grep tinycti) 2>/dev/null || true
            log_success "Docker images removed"
        fi
    fi
    
    # Remove volumes
    if docker volume ls --format "{{.Name}}" | grep -q "tinycti"; then
        if confirm_action "Remove TinyCTI Docker volumes? (This will delete all data!)"; then
            docker volume rm $(docker volume ls --format "{{.Name}}" | grep tinycti) 2>/dev/null || true
            log_success "Docker volumes removed"
        fi
    fi
    
    # Remove networks
    if docker network ls --format "{{.Name}}" | grep -q "tinycti"; then
        if confirm_action "Remove TinyCTI Docker networks?"; then
            docker network rm $(docker network ls --format "{{.Name}}" | grep tinycti) 2>/dev/null || true
            log_success "Docker networks removed"
        fi
    fi
}

cleanup_system() {
    log_info "Cleaning up system..."
    
    # Remove temporary files
    rm -rf /tmp/tinycti* 2>/dev/null || true
    rm -rf /var/tmp/tinycti* 2>/dev/null || true
    
    # Clean package manager cache (optional)
    if confirm_action "Clean package manager cache?"; then
        if command -v apt-get &> /dev/null; then
            apt-get autoremove -y
            apt-get autoclean
        elif command -v yum &> /dev/null; then
            yum autoremove -y
            yum clean all
        elif command -v dnf &> /dev/null; then
            dnf autoremove -y
            dnf clean all
        fi
        log_success "Package manager cache cleaned"
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --force       Force removal without confirmation prompts"
    echo "  --keep-data   Keep data files (IOCs, logs, etc.)"
    echo "  --docker      Also remove Docker resources"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0            # Interactive uninstall"
    echo "  $0 --force    # Force uninstall without prompts"
    echo "  $0 --docker   # Uninstall including Docker resources"
}

# Main uninstallation logic
main() {
    local keep_data="false"
    local remove_docker="false"
    FORCE="false"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force)
                FORCE="true"
                shift
                ;;
            --keep-data)
                keep_data="true"
                shift
                ;;
            --docker)
                remove_docker="true"
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
    
    log_warning "TinyCTI Uninstallation Script"
    log_warning "This will remove TinyCTI from your system"
    
    if [[ "$FORCE" != "true" ]]; then
        if ! confirm_action "Are you sure you want to continue?"; then
            log_info "Uninstallation cancelled"
            exit 0
        fi
    fi
    
    check_root
    
    stop_services
    remove_services
    
    if [[ "$keep_data" != "true" ]]; then
        remove_files
    else
        log_info "Keeping data files as requested"
    fi
    
    remove_user_group
    
    if [[ "$remove_docker" == "true" ]]; then
        remove_docker_resources
    fi
    
    cleanup_system
    
    log_success "TinyCTI uninstallation completed!"
    
    if [[ "$keep_data" == "true" ]]; then
        log_info "Data files were preserved in $INSTALL_DIR"
    fi
    
    log_info "You may need to reboot to complete the cleanup"
}

# Run main function
main "$@"