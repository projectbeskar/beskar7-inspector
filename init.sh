#!/bin/sh
# Beskar7-Inspector Init

# Mount essential filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs none /tmp
mount -t tmpfs none /run

# Setup PATH
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# Setup console
echo "===================================="
echo "Beskar7-Inspector booting..."
echo "===================================="

# Debug: show what we have
echo "Available tools:"
which sh mount ls cat echo grep awk sed cut tr 2>/dev/null || true
echo ""

# Check if scripts exist
echo "Checking for inspection scripts..."
ls -la /opt/beskar7-inspector/ 2>/dev/null || echo "ERROR: /opt/beskar7-inspector not found"
echo ""

# Run inspection workflow
cd /opt/beskar7-inspector || {
    echo "ERROR: Cannot cd to /opt/beskar7-inspector"
    exec /bin/sh
}

# Execute scripts in order
for script in 00-init.sh 01-hardware-inspect.sh 02-network-setup.sh 03-report-to-beskar7.sh 04-download-os.sh 05-kexec-boot.sh; do
    if [ -f "$script" ]; then
        echo "===================================="
        echo "Running $script..."
        echo "===================================="
        /bin/sh "$script"
        rc=$?
        if [ $rc -ne 0 ]; then
            echo "ERROR: $script failed with exit code $rc"
            # Don't exit, continue to next script for debugging
        fi
    else
        echo "WARNING: $script not found"
    fi
done

# If we get here, inspection workflow finished
echo "===================================="
echo "Inspection workflow complete"
echo "===================================="
echo "Dropping to shell for debugging..."
echo "Type 'exit' to power off"
exec /bin/sh

