#!/bin/bash
# TinyCTI Development Runner
# Quick script to run TinyCTI in development mode

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
PYTHON_BIN="${PROJECT_ROOT}/venv/bin/python"
TINYCTI_BIN="${PROJECT_ROOT}/tinycti.py"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_venv() {
    if [[ ! -f "$PYTHON_BIN" ]]; then
        log_warning "Virtual environment not found. Creating one..."
        cd "$PROJECT_ROOT"
        python3 -m venv venv
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
        log_success "Virtual environment created and configured"
    fi
}

check_directories() {
    cd "$PROJECT_ROOT"
    
    # Create necessary directories
    mkdir -p iocs/{active,critical,watch,archive}
    mkdir -p ngfw/{active,critical,watch,archive}
    mkdir -p logs
    
    # Create empty IOC files if they don't exist
    for bucket in active critical watch archive; do
        for ioc_type in domain email hash_md5 hash_sha1 hash_sha256 hash_sha512 ipv4 ipv6 url; do
            touch "iocs/${bucket}/${ioc_type}.txt"
            touch "ngfw/${bucket}/malicious-${ioc_type}.txt" 2>/dev/null || true
        done
    done
    
    log_success "Directories and files initialized"
}

show_usage() {
    echo "Usage: $0 [MODE] [OPTIONS]"
    echo ""
    echo "Modes:"
    echo "  daemon      Run in daemon mode (default)"
    echo "  api         Run API server only"
    echo "  oneshot     Run one-shot collection"
    echo "  export      Run NGFW export"
    echo "  validate    Validate configuration"
    echo ""
    echo "Options:"
    echo "  --debug     Enable debug logging"
    echo "  --verbose   Enable verbose logging"
    echo "  --port N    API port (default: 5000)"
    echo "  --host IP   API host (default: 127.0.0.1)"
    echo ""
    echo "Examples:"
    echo "  $0 daemon               # Run daemon with API"
    echo "  $0 api --port 8080      # Run API on port 8080"
    echo "  $0 oneshot --debug      # Run oneshot with debug"
    echo "  $0 validate             # Validate config"
}

# Main logic
main() {
    local mode="daemon"
    local debug=""
    local verbose=""
    local port="5000"
    local host="127.0.0.1"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            daemon|api|oneshot|export|validate)
                mode="$1"
                shift
                ;;
            --debug)
                debug="--debug"
                shift
                ;;
            --verbose)
                verbose="--verbose"
                shift
                ;;
            --port)
                port="$2"
                shift 2
                ;;
            --host)
                host="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "Starting TinyCTI in development mode..."
    log_info "Mode: $mode"
    
    check_venv
    check_directories
    
    cd "$PROJECT_ROOT"
    
    # Build command
    local cmd=("$PYTHON_BIN" "$TINYCTI_BIN")
    
    case $mode in
        daemon)
            cmd+=("-d" "--api" "--api-host" "$host" "--api-port" "$port")
            log_info "Starting daemon with API on http://$host:$port"
            ;;
        api)
            cmd+=("--api" "--api-host" "$host" "--api-port" "$port")
            log_info "Starting API server on http://$host:$port"
            ;;
        oneshot)
            cmd+=("--once")
            log_info "Running one-shot collection"
            ;;
        export)
            cmd+=("--export-ngfw")
            log_info "Running NGFW export"
            ;;
        validate)
            cmd+=("--validate-config")
            log_info "Validating configuration"
            ;;
    esac
    
    # Add logging options
    if [[ -n "$debug" ]]; then
        cmd+=("$debug")
    elif [[ -n "$verbose" ]]; then
        cmd+=("$verbose")
    fi
    
    log_info "Executing: ${cmd[*]}"
    log_success "TinyCTI starting..."
    
    # Execute command
    exec "${cmd[@]}"
}

# Run main function
main "$@"