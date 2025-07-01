#!/bin/bash
# TinyCTI Process Manager
# Manages TinyCTI in various modes: daemon, oneshot, background, etc.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TINYCTI_DIR="${TINYCTI_DIR:-/opt/tinycti}"
TINYCTI_USER="${TINYCTI_USER:-tinycti}"
PYTHON_BIN="${TINYCTI_DIR}/venv/bin/python"
TINYCTI_BIN="${TINYCTI_DIR}/tinycti.py"
PID_DIR="${TINYCTI_DIR}/run"
LOG_DIR="${TINYCTI_DIR}/logs"

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

check_directories() {
    mkdir -p "$PID_DIR" "$LOG_DIR"
    if [[ $(id -u) -eq 0 ]]; then
        chown -R "$TINYCTI_USER:$TINYCTI_USER" "$PID_DIR" "$LOG_DIR" 2>/dev/null || true
    fi
}

get_pid() {
    local service="$1"
    local pid_file="$PID_DIR/${service}.pid"
    
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        else
            rm -f "$pid_file"
        fi
    fi
    return 1
}

start_daemon() {
    log_info "Starting TinyCTI daemon..."
    
    if get_pid "tinycti-daemon" >/dev/null; then
        log_warning "TinyCTI daemon is already running (PID: $(get_pid "tinycti-daemon"))"
        return 1
    fi
    
    check_directories
    
    # Start daemon in background
    if [[ $(id -u) -eq 0 ]]; then
        sudo -u "$TINYCTI_USER" nohup "$PYTHON_BIN" "$TINYCTI_BIN" -d --api \
            >"$LOG_DIR/daemon.log" 2>&1 &
    else
        nohup "$PYTHON_BIN" "$TINYCTI_BIN" -d --api \
            >"$LOG_DIR/daemon.log" 2>&1 &
    fi
    
    local pid=$!
    echo $pid > "$PID_DIR/tinycti-daemon.pid"
    
    # Wait a moment to check if it started successfully
    sleep 2
    if kill -0 $pid 2>/dev/null; then
        log_success "TinyCTI daemon started (PID: $pid)"
        return 0
    else
        log_error "Failed to start TinyCTI daemon"
        rm -f "$PID_DIR/tinycti-daemon.pid"
        return 1
    fi
}

start_api() {
    log_info "Starting TinyCTI API server..."
    
    if get_pid "tinycti-api" >/dev/null; then
        log_warning "TinyCTI API is already running (PID: $(get_pid "tinycti-api"))"
        return 1
    fi
    
    check_directories
    
    # Start API in background
    if [[ $(id -u) -eq 0 ]]; then
        sudo -u "$TINYCTI_USER" nohup "$PYTHON_BIN" "$TINYCTI_BIN" --api \
            >"$LOG_DIR/api.log" 2>&1 &
    else
        nohup "$PYTHON_BIN" "$TINYCTI_BIN" --api \
            >"$LOG_DIR/api.log" 2>&1 &
    fi
    
    local pid=$!
    echo $pid > "$PID_DIR/tinycti-api.pid"
    
    # Wait a moment to check if it started successfully
    sleep 2
    if kill -0 $pid 2>/dev/null; then
        log_success "TinyCTI API started (PID: $pid)"
        return 0
    else
        log_error "Failed to start TinyCTI API"
        rm -f "$PID_DIR/tinycti-api.pid"
        return 1
    fi
}

run_oneshot() {
    log_info "Running TinyCTI oneshot collection..."
    
    if [[ $(id -u) -eq 0 ]]; then
        sudo -u "$TINYCTI_USER" "$PYTHON_BIN" "$TINYCTI_BIN" --once
    else
        "$PYTHON_BIN" "$TINYCTI_BIN" --once
    fi
    
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_success "Oneshot collection completed successfully"
    else
        log_error "Oneshot collection failed (exit code: $exit_code)"
    fi
    return $exit_code
}

stop_service() {
    local service="$1"
    local pid_file="$PID_DIR/${service}.pid"
    
    if ! pid=$(get_pid "$service"); then
        log_warning "$service is not running"
        return 1
    fi
    
    log_info "Stopping $service (PID: $pid)..."
    
    # Try graceful shutdown first
    kill -TERM "$pid" 2>/dev/null || true
    
    # Wait for graceful shutdown
    local count=0
    while kill -0 "$pid" 2>/dev/null && [[ $count -lt 30 ]]; do
        sleep 1
        ((count++))
    done
    
    # Force kill if still running
    if kill -0 "$pid" 2>/dev/null; then
        log_warning "Force killing $service..."
        kill -KILL "$pid" 2>/dev/null || true
    fi
    
    rm -f "$pid_file"
    log_success "$service stopped"
}

status_service() {
    local service="$1"
    
    if pid=$(get_pid "$service"); then
        log_success "$service is running (PID: $pid)"
        
        # Show additional info if available
        if command -v ps &> /dev/null; then
            ps -p "$pid" -o pid,ppid,cmd --no-headers 2>/dev/null || true
        fi
        return 0
    else
        log_info "$service is not running"
        return 1
    fi
}

show_logs() {
    local service="$1"
    local lines="${2:-50}"
    
    local log_file="$LOG_DIR/${service}.log"
    
    if [[ -f "$log_file" ]]; then
        log_info "Showing last $lines lines of $service log:"
        tail -n "$lines" "$log_file"
    else
        log_warning "Log file $log_file not found"
        return 1
    fi
}

export_ngfw() {
    log_info "Running manual NGFW export..."
    
    if [[ $(id -u) -eq 0 ]]; then
        sudo -u "$TINYCTI_USER" "$PYTHON_BIN" "$TINYCTI_BIN" --export-ngfw
    else
        "$PYTHON_BIN" "$TINYCTI_BIN" --export-ngfw
    fi
    
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_success "NGFW export completed successfully"
    else
        log_error "NGFW export failed (exit code: $exit_code)"
    fi
    return $exit_code
}

show_usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start-daemon    Start TinyCTI in daemon mode (with API)"
    echo "  start-api       Start TinyCTI API server only"
    echo "  stop-daemon     Stop TinyCTI daemon"
    echo "  stop-api        Stop TinyCTI API server"
    echo "  stop-all        Stop all TinyCTI services"
    echo "  restart-daemon  Restart TinyCTI daemon"
    echo "  restart-api     Restart TinyCTI API server"
    echo "  status          Show status of all services"
    echo "  logs <service>  Show logs for service (daemon/api)"
    echo "  oneshot         Run one-shot collection"
    echo "  export-ngfw     Run manual NGFW export"
    echo ""
    echo "Options:"
    echo "  --lines N       Number of log lines to show (default: 50)"
    echo ""
    echo "Examples:"
    echo "  $0 start-daemon         # Start daemon with API"
    echo "  $0 start-api            # Start API server only"
    echo "  $0 status               # Check status"
    echo "  $0 logs daemon          # Show daemon logs"
    echo "  $0 logs api --lines 100 # Show 100 lines of API logs"
    echo "  $0 oneshot              # Run one-shot collection"
}

# Main logic
main() {
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi
    
    local command="$1"
    shift
    
    # Parse global options
    local lines=50
    while [[ $# -gt 0 ]]; do
        case $1 in
            --lines)
                lines="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done
    
    case $command in
        start-daemon)
            start_daemon
            ;;
        start-api)
            start_api
            ;;
        stop-daemon)
            stop_service "tinycti-daemon"
            ;;
        stop-api)
            stop_service "tinycti-api"
            ;;
        stop-all)
            stop_service "tinycti-daemon" || true
            stop_service "tinycti-api" || true
            ;;
        restart-daemon)
            stop_service "tinycti-daemon" || true
            sleep 2
            start_daemon
            ;;
        restart-api)
            stop_service "tinycti-api" || true
            sleep 2
            start_api
            ;;
        status)
            echo "=== TinyCTI Service Status ==="
            status_service "tinycti-daemon" || true
            status_service "tinycti-api" || true
            ;;
        logs)
            if [[ $# -eq 0 ]]; then
                log_error "Please specify service: daemon or api"
                exit 1
            fi
            service="$1"
            show_logs "$service" "$lines"
            ;;
        oneshot)
            run_oneshot
            ;;
        export-ngfw)
            export_ngfw
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"