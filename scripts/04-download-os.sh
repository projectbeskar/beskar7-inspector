#!/bin/bash
# Beskar7-Inspector OS Download

set -e

source /opt/beskar7-inspector/utils.sh

log_info "===== Downloading Target OS ====="

# Check if target OS URL was provided
TARGET_OS_FILE=$WORK_DIR/target-os-url.txt
if [ ! -f "$TARGET_OS_FILE" ]; then
    log_warn "No target OS URL provided - inspection only mode"
    log_info "Skipping OS download and kexec"
    exit 0
fi

TARGET_OS_URL=$(cat $TARGET_OS_FILE)
if [ -z "$TARGET_OS_URL" ]; then
    log_warn "Target OS URL is empty - inspection only mode"
    exit 0
fi

log_info "Target OS URL: $TARGET_OS_URL"

# Create download directory
DOWNLOAD_DIR=$WORK_DIR/os-download
mkdir -p $DOWNLOAD_DIR
cd $DOWNLOAD_DIR

# Determine file type and download
FILENAME=$(basename "$TARGET_OS_URL")
log_info "Downloading $FILENAME..."

download_file() {
    curl -L \
        --progress-bar \
        --max-time 600 \
        --retry 3 \
        --retry-delay 5 \
        -o "$FILENAME" \
        "$TARGET_OS_URL"
}

if ! retry_command 3 10 download_file; then
    log_error "Failed to download target OS"
    exit 1
fi

log_info "Download complete: $(du -h $FILENAME | cut -f1)"

# Extract kernel and initrd based on file type
log_info "Extracting kernel and initrd..."

case "$FILENAME" in
    *.tar.gz|*.tgz)
        log_info "Extracting tar.gz archive..."
        tar -xzf "$FILENAME"
        ;;
    *.tar)
        log_info "Extracting tar archive..."
        tar -xf "$FILENAME"
        ;;
    *.iso)
        log_info "Mounting ISO..."
        mkdir -p /mnt/iso
        mount -o loop "$FILENAME" /mnt/iso
        ;;
    *)
        log_error "Unsupported file format: $FILENAME"
        exit 1
        ;;
esac

# Find kernel and initrd
log_info "Locating kernel and initrd..."

# Common kernel names
KERNEL=$(find . /mnt/iso -name "vmlinuz*" -o -name "kernel" -o -name "bzImage" 2>/dev/null | head -1)
# Common initrd names
INITRD=$(find . /mnt/iso -name "initrd*" -o -name "initramfs*" -o -name "initrd.img" 2>/dev/null | head -1)

if [ -z "$KERNEL" ]; then
    log_error "Kernel not found in downloaded OS"
    ls -laR
    exit 1
fi

if [ -z "$INITRD" ]; then
    log_warn "Initrd not found - some OSes may not need it"
fi

log_info "Kernel: $KERNEL"
log_info "Initrd: $INITRD"

# Copy to known location for kexec
cp "$KERNEL" $WORK_DIR/target-kernel
log_info "✓ Kernel ready"

if [ -n "$INITRD" ]; then
    cp "$INITRD" $WORK_DIR/target-initrd
    log_info "✓ Initrd ready"
else
    touch $WORK_DIR/no-initrd
    log_info "✓ No initrd (OS doesn't require it)"
fi

log_info "Target OS download and extraction complete"

