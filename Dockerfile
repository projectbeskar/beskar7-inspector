# syntax=docker/dockerfile:1
#
# Build beskar7-inspector as a self-contained initramfs: one static
# x86_64-musl binary used directly as /init, plus the empty mountpoints it needs
# and a console device node. No shell, no busybox, no external tools — the binary
# probes hardware and performs every provisioning syscall natively. The output is
# the two artifacts an operator serves to iPXE: /vmlinuz and /initrd.img.

# ---- Stage 1: build the static musl binary --------------------------------
FROM rust:alpine AS build
# ring (pulled in by rustls) builds its asm with a C toolchain + make/perl.
RUN apk add --no-cache musl-dev gcc make perl
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl \
 && strip target/x86_64-unknown-linux-musl/release/beskar7-inspector

# ---- Stage 2: assemble the initramfs and take the kernel ------------------
FROM alpine:3.20 AS assemble
RUN apk add --no-cache linux-lts cpio
WORKDIR /irfs
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/beskar7-inspector ./init
# Only the mountpoints the init mounts itself, plus a console node for its
# pre-mount stderr (the kernel wires init's stdio to /dev/console if it exists)
# and /dev/null. devtmpfs (mounted by the init) supplies everything else.
RUN chmod 0755 init \
 && mkdir -p proc sys dev run tmp \
 && mknod -m 0600 dev/console c 5 1 \
 && mknod -m 0666 dev/null c 1 3
RUN find . | cpio --quiet -H newc -o | gzip -9 > /initrd.img \
 && cp /boot/vmlinuz-lts /vmlinuz

# ---- Stage 3: carrier image holding the two artifacts ---------------------
FROM alpine:3.20
COPY --from=assemble /vmlinuz /vmlinuz
COPY --from=assemble /initrd.img /initrd.img
LABEL org.opencontainers.image.title="beskar7-inspector" \
      org.opencontainers.image.description="Rust hardware-inspection initramfs for the Beskar7 CAPI provider" \
      org.opencontainers.image.source="https://github.com/projectbeskar/beskar7-inspector"
# `make build` does `docker create` + `docker cp` to extract /vmlinuz + /initrd.img.
CMD ["/bin/sh"]
