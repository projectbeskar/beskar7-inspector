#!/bin/bash
# Beskar7-Inspector Initialization

set -e

# Load utilities
source /opt/beskar7-inspector/utils.sh

log_info "===== Beskar7-Inspector Starting ====="
log_info "Version: 1.0"

# Parse configuration
get_beskar7_config

log_info "Configuration:"
log_info "  API: $BESKAR7_API"
log_info "  Namespace: $BESKAR7_NAMESPACE"
log_info "  Host: $BESKAR7_HOST"
log_info "  Timeout: ${BESKAR7_TIMEOUT}s"

# Set hostname
hostname beskar7-inspector
log_info "Hostname set to: $(hostname)"

# Create working directory
WORK_DIR=/tmp/beskar7
mkdir -p $WORK_DIR
cd $WORK_DIR
export WORK_DIR

log_info "Working directory: $WORK_DIR"

# Set up logging
exec 1> >(tee -a $WORK_DIR/inspector.log)
exec 2>&1

log_info "Initialization complete"

