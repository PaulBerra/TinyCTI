#!/bin/bash
# TinyCTI Development Cleanup Script
# Cleans up development artifacts, logs, and temporary files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

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

clean_python_cache() {
    log_info "Cleaning Python cache files..."
    
    cd "$PROJECT_ROOT"
    
    # Remove __pycache__ directories
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    
    # Remove .pyc files
    find . -name "*.pyc" -delete 2>/dev/null || true
    
    # Remove .pyo files
    find . -name "*.pyo" -delete 2>/dev/null || true
    
    # Remove .pyd files
    find . -name "*.pyd" -delete 2>/dev/null || true
    
    log_success "Python cache cleaned"
}

clean_test_artifacts() {
    log_info "Cleaning test artifacts..."
    
    cd "$PROJECT_ROOT"
    
    # Remove pytest cache
    rm -rf .pytest_cache/ 2>/dev/null || true
    
    # Remove coverage files
    rm -f .coverage 2>/dev/null || true
    rm -rf htmlcov/ 2>/dev/null || true
    
    # Remove test result files
    rm -f test-results-*.xml 2>/dev/null || true
    
    # Remove tox directories
    rm -rf .tox/ 2>/dev/null || true
    
    log_success "Test artifacts cleaned"
}

clean_logs() {
    log_info "Cleaning log files..."
    
    cd "$PROJECT_ROOT"
    
    # Remove log files
    rm -f *.log 2>/dev/null || true
    rm -f logs/*.log 2>/dev/null || true
    
    # Clean deployment log directories
    rm -rf deployment/scripts/logs/ 2>/dev/null || true
    
    log_success "Log files cleaned"
}

clean_temp_files() {
    log_info "Cleaning temporary files..."
    
    cd "$PROJECT_ROOT"
    
    # Remove temporary files
    find . -name "*.tmp" -delete 2>/dev/null || true
    find . -name "*.temp" -delete 2>/dev/null || true
    find . -name "*~" -delete 2>/dev/null || true
    
    # Remove OS specific files
    find . -name ".DS_Store" -delete 2>/dev/null || true
    find . -name "Thumbs.db" -delete 2>/dev/null || true
    
    # Remove editor backup files
    find . -name "*.swp" -delete 2>/dev/null || true
    find . -name "*.swo" -delete 2>/dev/null || true
    find . -name "*~" -delete 2>/dev/null || true
    
    log_success "Temporary files cleaned"
}

clean_build_artifacts() {
    log_info "Cleaning build artifacts..."
    
    cd "$PROJECT_ROOT"
    
    # Remove build directories
    rm -rf build/ 2>/dev/null || true
    rm -rf dist/ 2>/dev/null || true
    rm -rf *.egg-info/ 2>/dev/null || true
    
    # Remove wheel files
    rm -f *.whl 2>/dev/null || true
    
    log_success "Build artifacts cleaned"
}

clean_docker_artifacts() {
    log_info "Cleaning Docker artifacts..."
    
    # Stop and remove TinyCTI containers
    if command -v docker &> /dev/null; then
        # Stop containers
        docker stop $(docker ps -q --filter "name=tinycti") 2>/dev/null || true
        
        # Remove containers
        docker rm $(docker ps -aq --filter "name=tinycti") 2>/dev/null || true
        
        # Remove dangling images
        docker image prune -f 2>/dev/null || true
        
        log_success "Docker artifacts cleaned"
    else
        log_warning "Docker not found, skipping Docker cleanup"
    fi
}

clean_ioc_data() {
    log_info "Cleaning IOC data files..."
    
    cd "$PROJECT_ROOT"
    
    # Clean IOC files (keep structure)
    for bucket in active critical watch archive; do
        if [[ -d "iocs/$bucket" ]]; then
            for file in iocs/$bucket/*.txt; do
                if [[ -f "$file" ]]; then
                    echo "# TinyCTI IOC file - cleaned $(date)" > "$file"
                fi
            done
        fi
        
        if [[ -d "ngfw/$bucket" ]]; then
            for file in ngfw/$bucket/*.txt; do
                if [[ -f "$file" ]]; then
                    echo "# TinyCTI NGFW file - cleaned $(date)" > "$file"
                fi
            done
        fi
    done
    
    # Clean database
    rm -f iocs/*.db 2>/dev/null || true
    
    log_success "IOC data cleaned"
}

clean_venv() {
    log_info "Cleaning virtual environment..."
    
    cd "$PROJECT_ROOT"
    
    if [[ -d "venv" ]]; then
        rm -rf venv/
        log_success "Virtual environment removed"
    else
        log_info "No virtual environment found"
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all         Clean everything (default)"
    echo "  --cache       Clean Python cache only"
    echo "  --tests       Clean test artifacts only"
    echo "  --logs        Clean log files only"
    echo "  --temp        Clean temporary files only"
    echo "  --build       Clean build artifacts only"
    echo "  --docker      Clean Docker artifacts only"
    echo "  --data        Clean IOC data files"
    echo "  --venv        Remove virtual environment"
    echo "  --force       Force cleanup without prompts"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0              # Clean everything (interactive)"
    echo "  $0 --cache      # Clean Python cache only"
    echo "  $0 --all --force # Clean everything without prompts"
    echo "  $0 --data       # Clean IOC data files"
}

# Main logic
main() {
    local clean_all="true"
    local clean_cache="false"
    local clean_tests="false"
    local clean_logs="false"
    local clean_temp="false"
    local clean_build="false"
    local clean_docker="false"
    local clean_data="false"
    local clean_venv="false"
    FORCE="false"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                clean_all="true"
                shift
                ;;
            --cache)
                clean_all="false"
                clean_cache="true"
                shift
                ;;
            --tests)
                clean_all="false"
                clean_tests="true"
                shift
                ;;
            --logs)
                clean_all="false"
                clean_logs="true"
                shift
                ;;
            --temp)
                clean_all="false"
                clean_temp="true"
                shift
                ;;
            --build)
                clean_all="false"
                clean_build="true"
                shift
                ;;
            --docker)
                clean_all="false"
                clean_docker="true"
                shift
                ;;
            --data)
                clean_all="false"
                clean_data="true"
                shift
                ;;
            --venv)
                clean_all="false"
                clean_venv="true"
                shift
                ;;
            --force)
                FORCE="true"
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
    
    log_warning "TinyCTI Development Cleanup"
    log_warning "This will clean development artifacts"
    
    if [[ "$clean_all" == "true" ]]; then
        if [[ "$FORCE" != "true" ]]; then
            if ! confirm_action "Clean all development artifacts?"; then
                log_info "Cleanup cancelled"
                exit 0
            fi
        fi
        
        clean_python_cache
        clean_test_artifacts
        clean_logs
        clean_temp_files
        clean_build_artifacts
        
        if confirm_action "Also clean Docker artifacts?"; then
            clean_docker_artifacts
        fi
        
        if confirm_action "Also clean IOC data files? (keeps structure)"; then
            clean_ioc_data
        fi
        
        if confirm_action "Also remove virtual environment?"; then
            clean_venv
        fi
    else
        if [[ "$clean_cache" == "true" ]]; then
            clean_python_cache
        fi
        
        if [[ "$clean_tests" == "true" ]]; then
            clean_test_artifacts
        fi
        
        if [[ "$clean_logs" == "true" ]]; then
            clean_logs
        fi
        
        if [[ "$clean_temp" == "true" ]]; then
            clean_temp_files
        fi
        
        if [[ "$clean_build" == "true" ]]; then
            clean_build_artifacts
        fi
        
        if [[ "$clean_docker" == "true" ]]; then
            clean_docker_artifacts
        fi
        
        if [[ "$clean_data" == "true" ]]; then
            if confirm_action "Clean IOC data files? (keeps structure)"; then
                clean_ioc_data
            fi
        fi
        
        if [[ "$clean_venv" == "true" ]]; then
            if confirm_action "Remove virtual environment?"; then
                clean_venv
            fi
        fi
    fi
    
    log_success "Development cleanup completed!"
}

# Run main function
main "$@"