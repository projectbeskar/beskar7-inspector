#!/bin/bash
# Beskar7-Inspector Utility Functions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_debug() {
    if [ "$DEBUG" = "true" ]; then
        echo -e "${BLUE}[DEBUG]${NC} $*"
    fi
}

# Parse kernel command line
parse_cmdline() {
    local param=$1
    cat /proc/cmdline | grep -o "${param}=[^ ]*" | cut -d= -f2
}

# Get Beskar7 configuration from kernel parameters
get_beskar7_config() {
    export BESKAR7_API=$(parse_cmdline "beskar7.api")
    export BESKAR7_NAMESPACE=$(parse_cmdline "beskar7.namespace")
    export BESKAR7_HOST=$(parse_cmdline "beskar7.host")
    export BESKAR7_TIMEOUT=$(parse_cmdline "beskar7.timeout")
    export DEBUG=$(parse_cmdline "beskar7.debug")
    
    # Defaults
    export BESKAR7_API=${BESKAR7_API:-"http://beskar7-inspection:8082"}
    export BESKAR7_NAMESPACE=${BESKAR7_NAMESPACE:-"default"}
    export BESKAR7_HOST=${BESKAR7_HOST:-"unknown"}
    export BESKAR7_TIMEOUT=${BESKAR7_TIMEOUT:-"600"}
    export DEBUG=${DEBUG:-"false"}
    
    log_debug "BESKAR7_API=$BESKAR7_API"
    log_debug "BESKAR7_NAMESPACE=$BESKAR7_NAMESPACE"
    log_debug "BESKAR7_HOST=$BESKAR7_HOST"
    log_debug "BESKAR7_TIMEOUT=$BESKAR7_TIMEOUT"
}

# Retry a command with exponential backoff
retry_command() {
    local max_attempts=${1:-3}
    local delay=${2:-5}
    shift 2
    local cmd="$@"
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log_debug "Attempt $attempt/$max_attempts: $cmd"
        if eval "$cmd"; then
            return 0
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            log_warn "Command failed, retrying in ${delay}s..."
            sleep $delay
            delay=$((delay * 2))
        fi
        attempt=$((attempt + 1))
    done
    
    log_error "Command failed after $max_attempts attempts"
    return 1
}

# Check if required tools are available
check_required_tools() {
    local tools="$@"
    local missing=""
    
    for tool in $tools; do
        if ! command -v $tool &> /dev/null; then
            missing="$missing $tool"
        fi
    done
    
    if [ -n "$missing" ]; then
        log_error "Missing required tools:$missing"
        return 1
    fi
    
    return 0
}

# JSON escape string
json_escape() {
    echo -n "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))'
}

# Get total memory in GB
get_total_memory_gb() {
    local mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    echo $((mem_kb / 1024 / 1024))
}

# Get total CPU cores
get_total_cpu_cores() {
    grep -c ^processor /proc/cpuinfo
}

# Test network connectivity
test_connectivity() {
    local host=$1
    local timeout=${2:-5}
    
    log_debug "Testing connectivity to $host (timeout: ${timeout}s)"
    if timeout $timeout ping -c 1 $host &> /dev/null; then
        return 0
    fi
    return 1
}

# Wait for network
wait_for_network() {
    local timeout=${1:-30}
    local elapsed=0
    
    log_info "Waiting for network connectivity..."
    while [ $elapsed -lt $timeout ]; do
        if ip route | grep -q default; then
            log_info "Network is up"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    
    log_error "Network timeout after ${timeout}s"
    return 1
}

