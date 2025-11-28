#!/bin/bash
# Beskar7-Inspector Network Setup

set -e

. /opt/beskar7-inspector/utils.sh

log_info "===== Setting Up Network ====="

# Wait for network
if ! wait_for_network 60; then
    log_error "Network setup failed"
    exit 1
fi

# Show network configuration
log_info "Network interfaces:"
ip addr show | grep -E "^[0-9]|inet " | sed 's/^/  /'

log_info "Default route:"
ip route show default | sed 's/^/  /'

# Test connectivity to Beskar7 API
API_HOST=$(echo $BESKAR7_API | sed 's|http://||; s|https://||; s|:[0-9]*||; s|/.*||')
log_info "Testing connectivity to $API_HOST..."

if ! test_connectivity $API_HOST 10; then
    log_warn "Cannot reach $API_HOST directly, but continuing anyway"
else
    log_info "Successfully reached $API_HOST"
fi

# Test DNS resolution
log_info "Testing DNS resolution..."
if nslookup $API_HOST &> /dev/null; then
    RESOLVED_IP=$(nslookup $API_HOST | grep "Address:" | tail -1 | awk '{print $2}')
    log_info "  $API_HOST resolves to $RESOLVED_IP"
else
    log_warn "DNS resolution failed for $API_HOST"
fi

log_info "Network setup complete"

