#!/bin/bash
# Beskar7-Inspector Kexec Boot

set -e

. /opt/beskar7-inspector/utils.sh

log_info "===== Kexec into Target OS ====="

# Check if kernel exists
if [ ! -f $WORK_DIR/target-kernel ]; then
    log_warn "No target kernel found - inspection only mode"
    log_info "Inspection complete. System will remain in inspector for debugging."
    
    # Drop to shell for debugging
    log_info "=== Debug Shell ==="
    log_info "Inspection report: $WORK_DIR/hardware-report.json"
    log_info "Logs: $WORK_DIR/inspector.log"
    log_info "Type 'exit' to continue or wait for timeout"
    /bin/sh
    exit 0
fi

KERNEL=$WORK_DIR/target-kernel
INITRD=$WORK_DIR/target-initrd

log_info "Preparing kexec..."
log_info "  Kernel: $KERNEL ($(du -h $KERNEL | cut -f1))"
if [ -f "$INITRD" ]; then
    log_info "  Initrd: $INITRD ($(du -h $INITRD | cut -f1))"
fi

# Build kernel command line
# Preserve some parameters, add OS-specific ones
CMDLINE="console=tty0 console=ttyS0,115200"

# Add any beskar7-specific params that should pass through
# You can customize this based on your OS requirements
log_info "Kernel command line: $CMDLINE"

# Load kernel with kexec
log_info "Loading kernel into memory..."

if [ -f "$INITRD" ]; then
    kexec --load "$KERNEL" \
        --initrd="$INITRD" \
        --command-line="$CMDLINE" \
        --reuse-cmdline || {
        log_error "Failed to load kernel with kexec"
        exit 1
    }
else
    kexec --load "$KERNEL" \
        --command-line="$CMDLINE" \
        --reuse-cmdline || {
        log_error "Failed to load kernel with kexec"
        exit 1
    }
fi

log_info "✓ Kernel loaded successfully"

# Sync filesystems
log_info "Syncing filesystems..."
sync

# Final countdown
log_info ""
log_info "===== Kexec Boot in 5 seconds ====="
log_info "Hardware inspection complete"
log_info "Transitioning to target OS..."
sleep 5

# Execute kexec
log_info "Executing kexec now!"
kexec --exec || {
    log_error "Kexec execution failed"
    log_error "Dropping to debug shell"
    /bin/sh
    exit 1
}

# Should never reach here
log_error "Kexec did not execute properly"
/bin/sh

