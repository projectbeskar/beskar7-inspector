# beskar7-inspector

The hardware-inspection and provisioning ramdisk for
[Beskar7](https://github.com/projectbeskar/beskar7), a Cluster API infrastructure
provider for bare-metal hosts.

The inspector is a single **static Rust binary** (`x86_64-unknown-linux-musl`)
used directly as the initramfs `/init`. It PXE-boots on a target machine, probes
its hardware natively, reports to the Beskar7 controller, then writes the target
OS image to disk and reboots into it. There is no shell, no busybox, and no
external tools — every probe and provisioning syscall is performed in-process.

## How it works (contract v4.1)

Beskar7 renders a per-host iPXE script that boots this image with the `beskar7.*`
parameters on the kernel cmdline. The inspector then runs two phases:

1. **Enroll & inspect** (always) — parse the cmdline, probe hardware from
   firmware truth (SMBIOS/DMI via `/sys/firmware/dmi/tables`, plus `/sys` and
   `/proc`), select a target disk, and `POST` the report to the controller over
   verified TLS (success is `202 Accepted`). `--dry-run` stops here.
2. **Provision** (when bootstrap data is ready) — `GET` the CAPI bootstrap
   user-data, stream the digest-pinned whole-disk OS image (a Kairos raw image)
   onto the selected disk while verifying its SHA-256, inject a per-host
   cloud-config (carrying the join secret) into the image's `COS_OEM` partition,
   and `reboot(2)` into the provisioned OS.

```
power on → PXE → controller-rendered iPXE → inspector
              Phase 1: probe → POST report (202)
              Phase 2: GET bootstrap → write image (digest-verified)
                       → inject COS_OEM config → reboot → target OS
```

The wire contract — endpoints, cmdline parameters, the report schema, the
digest-pinning trust model, and the disk/`COS_OEM` behavior — is specified in
[`docs/inspector-contract.md`](https://github.com/projectbeskar/beskar7/blob/main/docs/inspector-contract.md)
in the beskar7 repo (the **source of truth**). This repo implements contract
**v4.1** (`CONTRACT_VERSION` in `src/lib.rs`).

## Security posture

- **Verified TLS** to the callback (rustls, CA delivered on the cmdline); no
  insecure-skip-verify on the report/bootstrap path.
- The **target image is integrity-checked by content digest**, not TLS — it may
  be served over plain HTTP and is gated by `beskar7.target-digest`; the inspector
  never boots a non-matching image.
- The **join secret** is written only to a `0600`/root file on the verified
  `COS_OEM` partition, held in zeroizing buffers, and pinned out of swap with
  `mlockall`. The bearer token, boot nonce, full cmdline, and user-data are never
  logged.
- Device identity is re-verified (`st_rdev`) before every destructive write, so a
  repointed `/dev` node cannot redirect the image or the join secret.

## Build, test, lint

```bash
cargo test --all-targets                       # unit + contract tests
cargo fmt --all -- --check                     # formatting (CI-enforced)
cargo clippy --all-targets -- -D warnings      # lint (CI-enforced)
make check                                     # all three of the above
make image                                     # build build/vmlinuz + build/initrd.img
make test-vm                                   # boot the image in QEMU (Phase 1 smoke)
```

`make image` produces the two boot files (`build/vmlinuz`, `build/initrd.img`)
from the multi-stage `Dockerfile`: it builds the static binary, assembles a
minimal initramfs (the binary as `/init` plus the mountpoints it needs), and
takes the kernel from Alpine's `linux-lts`. An operator serves these two files to
the boot infrastructure the controller's iPXE script points at.

> **Status:** the inspector is feature-complete against contract v4.1 (incl. the
> provisioning-complete and provision-failed callbacks) and validated end-to-end on real bare metal; fully unit-
> and contract-tested. End-to-end boot on real firmware (PXE → inspect → provision
> → reboot) is validated as part of Beskar7's integration/e2e work, not in this
> repo's CI (which runs fmt, clippy, and tests).

## Layout

```
src/cmdline.rs      parse /proc/cmdline into the beskar7.* params
src/probe/          native hardware probing (SMBIOS/DMI + /sys + /proc)
src/report.rs       serde structs that serialize to the contract report schema
src/client.rs       rustls callback client: POST report (202), GET bootstrap
src/image.rs        digest-pinned streaming target-image fetch
src/target_disk.rs  target-disk selection
src/oem.rs          locate the COS_OEM partition on the target disk
src/deploy.rs       whole-disk write + COS_OEM mount/inject + reboot
src/run.rs          the PID-1 two-phase pipeline
src/main.rs         thin PID-1 entrypoint over run::run
tests/contract.rs   golden-fixture report round-trip (shared with beskar7)
```
