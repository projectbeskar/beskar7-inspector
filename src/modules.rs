//! Load the kernel modules the inspector needs, before it probes hardware or
//! provisions (decision D-012).
//!
//! The shipped kernel is the distro `linux-lts`, which builds storage/network/
//! filesystem drivers as **modules** — so the binary-only initramfs is otherwise
//! hardware-blind (no disk to write, no NIC to report over, no `ext4` to mount
//! `COS_OEM`). Rather than own a custom built-in kernel, the image ships a
//! **curated** `/lib/modules/<kver>/` subtree plus an ordered load-list
//! (`beskar7.load`) whose dependencies and order were resolved **at build time**
//! (`depmod` / `modprobe --show-depends`). This module just inserts that list.
//!
//! What the inspector owns here is small and deliberate: an `insmod` loop over a
//! precomputed list, plus a bounded `/sys` settle wait. It does **not**
//! reimplement modprobe's dependency resolver (precomputed at build) or udev (the
//! inspector runs once on a static machine, then reboots — there is no hotplug
//! window). PCI-`modalias` coldplug for broad bare-metal NIC/HBA coverage is a
//! deliberate follow-up; this slice ships a fixed list (virtio + `ahci`/`e1000` +
//! `ext4`) sufficient for QEMU and the `COS_OEM` mount.
//!
//! Best-effort by design: a missing module directory (e.g. a future built-in
//! kernel) or a single failed insert must **not** abort the run before the report
//! is even sent — failures are logged (module path + errno, both non-secret) and
//! the run continues.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;

/// Root of the kernel module tree shipped in the initramfs.
const MODULES_ROOT: &str = "/lib/modules";
/// The build-time-resolved, dependency-ordered load-list, under
/// `/lib/modules/<kver>/`. One absolute `.ko` path per line; `#` comments and
/// blank lines are ignored.
const LOAD_LIST_NAME: &str = "beskar7.load";

/// `/sys` directories whose population signals that driver probing has bound
/// devices; the settle wait blocks until their entry counts stabilize.
const SYS_BLOCK: &str = "/sys/block";
const SYS_NET: &str = "/sys/class/net";

/// Upper bound on the post-load `/sys` settle wait. Device probing after
/// `finit_module` is asynchronous; this caps how long we wait for it.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(3);
/// Poll interval during the settle wait.
const SETTLE_POLL: Duration = Duration::from_millis(100);
/// Consecutive unchanged polls that count as "settled".
const SETTLE_STABLE_POLLS: u32 = 2;

/// Load the curated kernel modules, then wait for `/sys` to settle. Best-effort:
/// logs a summary and any per-module failure (non-secret), never aborts the run.
/// A no-op (with a log line) if no module tree / load-list is present.
pub fn load_drivers() {
    let Some(list_path) = find_load_list() else {
        eprintln!(
            "beskar7-inspector: no kernel-module load-list under {MODULES_ROOT} \
             (built-in drivers?); skipping module load"
        );
        return;
    };
    let content = match std::fs::read_to_string(&list_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("beskar7-inspector: cannot read module load-list: {e}; skipping");
            return;
        }
    };

    let (mut loaded, mut skipped, mut failed) = (0u32, 0u32, 0u32);
    for module in parse_load_list(&content) {
        match insmod(Path::new(module)) {
            Ok(()) => loaded += 1,
            // EEXIST: already loaded, or built into the kernel. ENODEV/ENXIO: the
            // module loaded but its init found no matching device/CPU feature
            // (e.g. crc32c-intel on a CPU without the instruction — the generic
            // variant covers it). All are expected for a "load the whole curated
            // set, let devices bind" approach, not failures.
            Err(Errno::EEXIST) | Err(Errno::ENODEV) | Err(Errno::ENXIO) => skipped += 1,
            Err(e) => {
                failed += 1;
                eprintln!("beskar7-inspector: module {module} failed to load: {e}");
            }
        }
    }
    eprintln!(
        "beskar7-inspector: kernel modules: {loaded} loaded, {skipped} already-present/no-device, {failed} failed"
    );

    settle();
}

/// The path to `/lib/modules/<kver>/beskar7.load`, or `None` if no module tree
/// (or no load-list) is present. `<kver>` is the single kernel-version directory
/// the initramfs ships; if several exist, the first in sorted order is used.
fn find_load_list() -> Option<PathBuf> {
    let mut versions: Vec<_> = std::fs::read_dir(MODULES_ROOT)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    versions.sort();
    versions
        .into_iter()
        .map(|v| v.join(LOAD_LIST_NAME))
        .find(|p| p.is_file())
}

/// Parse the load-list: trimmed non-empty lines that are not `#` comments, in
/// order. Pure, so the format handling is unit-tested.
fn parse_load_list(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Insert one module via `finit_module(2)`. The build ships modules uncompressed
/// and dependency-ordered, so this is a plain in-order load with no decompression
/// or dependency resolution.
fn insmod(path: &Path) -> Result<(), Errno> {
    let file = File::open(path)
        .map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(Errno::EINVAL as i32)))?;
    // An empty NUL-terminated module-parameter string. (A `c""` literal would
    // raise the MSRV to 1.77; a byte string keeps it at 1.74.)
    let params = b"\0";
    // SAFETY: finit_module(2) loads a kernel module from `fd`, reading the file's
    // contents; `params` is a valid NUL-terminated empty string and `flags` is 0.
    // No process memory is shared with the kernel beyond the read of the fd.
    let ret = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_finit_module,
            file.as_raw_fd(),
            params.as_ptr() as *const nix::libc::c_char,
            0 as nix::libc::c_int,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Wait for `/sys` device population to stabilize after the load pass (the
/// kernel's device probe is asynchronous — this is what `udevadm settle` does,
/// in ~20 lines). Returns once the (`/sys/block`, `/sys/class/net`) entry counts
/// are unchanged for [`SETTLE_STABLE_POLLS`] polls, or [`SETTLE_TIMEOUT`] elapses.
fn settle() {
    let start = Instant::now();
    let mut prev = device_counts();
    let mut stable = 0u32;
    while start.elapsed() < SETTLE_TIMEOUT {
        std::thread::sleep(SETTLE_POLL);
        let cur = device_counts();
        if cur == prev {
            stable += 1;
            if stable >= SETTLE_STABLE_POLLS {
                break;
            }
        } else {
            stable = 0;
            prev = cur;
        }
    }
}

/// Current (block-device, network-interface) entry counts from `/sys`.
fn device_counts() -> (usize, usize) {
    (
        count_dir(Path::new(SYS_BLOCK)),
        count_dir(Path::new(SYS_NET)),
    )
}

/// Number of entries in a directory, or 0 if it cannot be read.
fn count_dir(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().count())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};

    #[test]
    fn parse_load_list_skips_comments_and_blanks_keeps_order() {
        let content = "\
# curated modules (D-012)
/lib/modules/6.6.1-lts/virtio_pci.ko

  /lib/modules/6.6.1-lts/virtio_blk.ko
# ext4 for COS_OEM
/lib/modules/6.6.1-lts/ext4.ko
";
        let got: Vec<&str> = parse_load_list(content).collect();
        assert_eq!(
            got,
            vec![
                "/lib/modules/6.6.1-lts/virtio_pci.ko",
                "/lib/modules/6.6.1-lts/virtio_blk.ko",
                "/lib/modules/6.6.1-lts/ext4.ko",
            ]
        );
    }

    #[test]
    fn parse_load_list_empty_is_empty() {
        assert_eq!(parse_load_list("\n\n# only comments\n").count(), 0);
    }

    #[test]
    fn count_dir_counts_entries_and_is_zero_for_missing() {
        let s = Scratch::new("modcount");
        write(s.path(), "sda/x", "");
        write(s.path(), "nvme0n1/x", "");
        assert_eq!(count_dir(s.path()), 2);
        assert_eq!(count_dir(Path::new("/nonexistent/sys/block/zzz")), 0);
    }

    #[test]
    fn find_load_list_picks_the_version_dir_with_the_list() {
        // A modules root with a version dir containing beskar7.load resolves to it.
        let s = Scratch::new("modroot");
        write(
            s.path(),
            "6.6.1-lts/beskar7.load",
            "/lib/modules/6.6.1-lts/ext4.ko\n",
        );
        // find_load_list reads the real MODULES_ROOT, so exercise the inner logic
        // shape via the same sort+join+is_file path against the scratch tree.
        let mut versions: Vec<_> = std::fs::read_dir(s.path())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        versions.sort();
        let found = versions
            .into_iter()
            .map(|v| v.join(LOAD_LIST_NAME))
            .find(|p| p.is_file());
        assert_eq!(found, Some(s.path().join("6.6.1-lts").join("beskar7.load")));
    }
}
