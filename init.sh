#!/bin/sh
# Beskar7-Inspector Init

# Mount essential filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs none /tmp
mount -t tmpfs none /run

# Setup console
echo "Beskar7-Inspector booting..."

# Run inspection workflow
cd /opt/beskar7-inspector

# Execute scripts in order
for script in 00-init.sh 01-hardware-inspect.sh 02-network-setup.sh 03-report-to-beskar7.sh 04-download-os.sh 05-kexec-boot.sh; do
    if [ -f "$script" ]; then
        echo "Running $script..."
        ./"$script"
        if [ $? -ne 0 ]; then
            echo "ERROR: $script failed"
            # Don't exit, continue to next script for debugging
        fi
    fi
done

# If we get here, something went wrong
echo "Inspection workflow complete or failed"
echo "Dropping to shell for debugging..."
exec /bin/sh

