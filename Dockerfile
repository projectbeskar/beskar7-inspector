# Beskar7-Inspector Alpine Linux Image Builder
FROM alpine:3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    alpine-sdk \
    squashfs-tools \
    xorriso \
    syslinux \
    mkinitfs \
    linux-lts \
    linux-firmware

# Install inspection and boot tools
RUN apk add --no-cache \
    # Hardware detection
    dmidecode \
    lshw \
    pciutils \
    usbutils \
    ethtool \
    smartmontools \
    hdparm \
    util-linux \
    # Networking
    curl \
    wget \
    jq \
    iproute2 \
    # System utilities
    bash \
    coreutils \
    e2fsprogs \
    parted \
    # Boot utilities
    kexec-tools \
    # Debugging (optional, can remove for production)
    strace \
    tcpdump

# Create directory structure
WORKDIR /build
RUN mkdir -p /build/rootfs/{bin,sbin,etc,proc,sys,dev,run,tmp,var,opt}

# Copy inspection scripts
COPY scripts/ /build/rootfs/opt/beskar7-inspector/
COPY config/ /build/rootfs/etc/beskar7-inspector/
COPY templates/ /build/rootfs/opt/beskar7-inspector/templates/

# Make scripts executable
RUN chmod +x /build/rootfs/opt/beskar7-inspector/*.sh

# Create init script
RUN cat > /build/rootfs/init << 'EOF'
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
EOF

RUN chmod +x /build/rootfs/init

# Build initramfs
RUN cd /build/rootfs && \
    find . | cpio -H newc -o | gzip > /build/initrd.img

# Copy kernel
RUN cp /boot/vmlinuz-lts /build/vmlinuz

# Final stage - minimal output
FROM scratch
COPY --from=builder /build/vmlinuz /vmlinuz
COPY --from=builder /build/initrd.img /initrd.img

# Metadata
LABEL org.opencontainers.image.title="Beskar7-Inspector"
LABEL org.opencontainers.image.description="Alpine Linux-based hardware inspection image"
LABEL org.opencontainers.image.version="1.0"
LABEL org.opencontainers.image.vendor="Project Beskar"

