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
# kmod + zstd are build-time only (they resolve module deps and decompress the
# .ko files) — they are NOT copied into the initramfs, which stays binary-only.
FROM alpine:3.20 AS assemble
RUN apk add --no-cache linux-lts cpio kmod zstd
WORKDIR /irfs
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/beskar7-inspector ./init
COPY modules.list /tmp/modules.list
# Only the mountpoints the init mounts itself, plus a console node for its
# pre-mount stderr (the kernel wires init's stdio to /dev/console if it exists)
# and /dev/null. devtmpfs (mounted by the init) supplies the rest.
RUN chmod 0755 init \
 && mkdir -p proc sys dev run tmp \
 && mknod -m 0600 dev/console c 5 1 \
 && mknod -m 0666 dev/null c 1 3
# Curate the kernel modules (D-012): resolve transitive deps + load order at
# build time, ship the .ko files uncompressed under /lib/modules/<kver>/, and
# write an ordered load-list (beskar7.load) the inspector finit_module's at
# startup. Built-in drivers (modprobe reports them as "builtin") are skipped.
RUN set -eu; \
    KVER=$(ls /lib/modules | head -1); \
    DST="/irfs/lib/modules/$KVER"; \
    mkdir -p "$DST"; \
    depmod "$KVER" 2>/dev/null || true; \
    : > "$DST/beskar7.load"; \
    grep -vE '^[[:space:]]*(#|$)' /tmp/modules.list | while read -r mod; do \
        modprobe --show-depends --set-version "$KVER" "$mod" 2>/dev/null || true; \
    done | awk '$1=="insmod"{print $2}' | awk '!seen[$0]++' | while read -r ko; do \
        base=$(basename "$ko"); unc="${base%.gz}"; unc="${unc%.zst}"; \
        case "$ko" in \
            *.gz)  gunzip -c "$ko" > "$DST/$unc" ;; \
            *.zst) zstd -dqc "$ko" > "$DST/$unc" ;; \
            *)     cp "$ko" "$DST/$unc" ;; \
        esac; \
        echo "/lib/modules/$KVER/$unc" >> "$DST/beskar7.load"; \
    done; \
    echo "=== beskar7.load ($(wc -l < "$DST/beskar7.load") modules) ==="; \
    cat "$DST/beskar7.load"
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
