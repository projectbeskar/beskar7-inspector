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

# Copy init script
COPY init.sh /build/rootfs/init
RUN chmod +x /build/rootfs/init

# Build initramfs
RUN cd /build/rootfs && \
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
