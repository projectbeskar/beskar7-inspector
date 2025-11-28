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
RUN mkdir -p /build/initramfs-root

# Install busybox and create a minimal root filesystem
RUN apk add --no-cache --initramfs-diskless-boot --initdb --root /build/initramfs-root \
    alpine-base \
    busybox \
    || true

# Simpler approach: manually create minimal root with busybox
RUN mkdir -p /build/initramfs-root/bin && \
    mkdir -p /build/initramfs-root/sbin && \
    mkdir -p /build/initramfs-root/etc && \
    mkdir -p /build/initramfs-root/proc && \
    mkdir -p /build/initramfs-root/sys && \
    mkdir -p /build/initramfs-root/dev && \
    mkdir -p /build/initramfs-root/run && \
    mkdir -p /build/initramfs-root/tmp && \
    mkdir -p /build/initramfs-root/var && \
    mkdir -p /build/initramfs-root/lib && \
    mkdir -p /build/initramfs-root/usr && \
    mkdir -p /build/initramfs-root/opt && \
    mkdir -p /build/initramfs-root/etc/beskar7-inspector && \
    mkdir -p /build/initramfs-root/opt/beskar7-inspector

# Copy busybox and create symlinks
RUN cp /bin/busybox /build/initramfs-root/bin/ && \
    cd /build/initramfs-root/bin && \
    for cmd in sh ash bash mount umount ls cat echo mkdir rm cp mv ln grep sed awk cut tr sleep wget curl which find xargs test [ head tail sort uniq wc date hostname tee paste seq yes readlink basename dirname touch; do \
        ln -sf busybox $cmd 2>/dev/null || true; \
    done

# Create sbin symlinks
RUN cd /build/initramfs-root/sbin && \
    for cmd in ifconfig route ip poweroff reboot halt; do \
        ln -sf ../bin/busybox $cmd 2>/dev/null || true; \
    done

# Create usr directories
RUN mkdir -p /build/initramfs-root/usr/bin && \
    mkdir -p /build/initramfs-root/usr/sbin && \
    mkdir -p /build/initramfs-root/usr/lib

# Copy necessary libraries for busybox
RUN mkdir -p /build/initramfs-root/lib && \
    cp -P /lib/ld-musl-*.so* /build/initramfs-root/lib/ 2>/dev/null || true && \
    cp -P /lib/libc.musl-*.so* /build/initramfs-root/lib/ 2>/dev/null || true

# Function to copy binary and its dependencies
RUN copy_with_deps() { \
        binary=$1; \
        dest_dir=$2; \
        if [ -f "$binary" ]; then \
            cp "$binary" "$dest_dir/" 2>/dev/null && \
            ldd "$binary" 2>/dev/null | grep "=> /" | awk '{print $3}' | while read lib; do \
                [ -f "$lib" ] && cp "$lib" /build/initramfs-root/lib/ 2>/dev/null || true; \
            done; \
        fi; \
    } && \
    copy_with_deps /usr/sbin/dmidecode /build/initramfs-root/sbin && \
    copy_with_deps /usr/bin/jq /build/initramfs-root/bin && \
    copy_with_deps /sbin/ethtool /build/initramfs-root/sbin && \
    copy_with_deps /usr/bin/lshw /build/initramfs-root/bin && \
    copy_with_deps /usr/sbin/smartctl /build/initramfs-root/sbin

# Copy util-linux tools (lscpu, lsblk, etc.)
RUN copy_with_deps() { \
        binary=$1; \
        dest_dir=$2; \
        if [ -f "$binary" ]; then \
            cp "$binary" "$dest_dir/" 2>/dev/null && \
            ldd "$binary" 2>/dev/null | grep "=> /" | awk '{print $3}' | while read lib; do \
                [ -f "$lib" ] && cp "$lib" /build/initramfs-root/lib/ 2>/dev/null || true; \
            done; \
        fi; \
    } && \
    copy_with_deps /usr/bin/lscpu /build/initramfs-root/bin && \
    copy_with_deps /bin/lsblk /build/initramfs-root/bin && \
    copy_with_deps /usr/bin/lspci /build/initramfs-root/bin && \
    copy_with_deps /usr/bin/lsusb /build/initramfs-root/bin

# Copy kexec and related tools
RUN copy_with_deps() { \
        binary=$1; \
        dest_dir=$2; \
        if [ -f "$binary" ]; then \
            cp "$binary" "$dest_dir/" 2>/dev/null && \
            ldd "$binary" 2>/dev/null | grep "=> /" | awk '{print $3}' | while read lib; do \
                [ -f "$lib" ] && cp "$lib" /build/initramfs-root/lib/ 2>/dev/null || true; \
            done; \
        fi; \
    } && \
    copy_with_deps /usr/sbin/kexec /build/initramfs-root/sbin

# Create symlinks in /usr for compatibility
RUN cd /build/initramfs-root/usr/bin && \
    for cmd in lscpu lsblk lspci lsusb jq lshw; do \
        [ -f "/build/initramfs-root/bin/$cmd" ] && ln -sf ../../bin/$cmd $cmd 2>/dev/null || true; \
    done && \
    cd /build/initramfs-root/usr/sbin && \
    for cmd in dmidecode smartctl kexec ethtool; do \
        [ -f "/build/initramfs-root/sbin/$cmd" ] && ln -sf ../../sbin/$cmd $cmd 2>/dev/null || true; \
    done

# Copy inspection scripts
COPY scripts/ /build/initramfs-root/opt/beskar7-inspector/
COPY config/ /build/initramfs-root/etc/beskar7-inspector/
COPY templates/ /build/initramfs-root/opt/beskar7-inspector/templates/

# Fix script shebangs (change #!/bin/bash to #!/bin/sh for busybox compatibility)
RUN for script in /build/initramfs-root/opt/beskar7-inspector/*.sh; do \
        sed -i 's|#!/bin/bash|#!/bin/sh|g' "$script" 2>/dev/null || true; \
        sed -i 's|#!/usr/bin/env bash|#!/bin/sh|g' "$script" 2>/dev/null || true; \
    done

# Make scripts executable
RUN chmod +x /build/initramfs-root/opt/beskar7-inspector/*.sh

# Copy init script
COPY init.sh /build/initramfs-root/init
RUN chmod +x /build/initramfs-root/init

# Build initramfs
RUN cd /build/initramfs-root && \
    find . | cpio -H newc -o | gzip > /build/initrd.img

# Copy kernel
RUN cp /boot/vmlinuz-lts /build/vmlinuz

# Final stage - minimal output with shell for extraction
FROM alpine:3.19
COPY --from=builder /build/vmlinuz /vmlinuz
COPY --from=builder /build/initrd.img /initrd.img

# Metadata
LABEL org.opencontainers.image.title="Beskar7-Inspector"
LABEL org.opencontainers.image.description="Alpine Linux-based hardware inspection image"
LABEL org.opencontainers.image.version="1.0"
LABEL org.opencontainers.image.vendor="Project Beskar"

# Provide a command for docker create/run
CMD ["/bin/sh"]
