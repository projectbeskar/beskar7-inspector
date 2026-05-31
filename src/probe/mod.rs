//! Native hardware probing: turn firmware tables (`smbios`) and `/sys`/`/proc`
//! into the inspection report (`report`).
//!
//! Each submodule owns one slice of the report and the byte-offset / sysfs
//! interpretation for it:
//!
//! | submodule | source | report fields |
//! |-----------|--------|---------------|
//! | [`system`] | SMBIOS Type 1 + Type 0, `/sys/firmware/efi` | `manufacturer`, `model`, `serialNumber`, `firmwareVersion`, `bootModeDetected` |
//! | [`cpu`] | SMBIOS Type 4 | `cpus[]` — one entry per populated central package |
//! | [`memory`] | SMBIOS Type 17 | `memory[]` — one entry per populated DIMM |
//! | [`disk`] | `/sys/block` | `disks[]` — one entry per fixed block device |
//! | [`nic`] | `/sys/class/net` + `getifaddrs` | `nics[]` — one entry per physical NIC |
//!
//! The SMBIOS-backed collectors are split from the raw [`crate::smbios`] parser
//! on purpose: the parser is semantics-free, while the per-type field offsets
//! (which vary by SMBIOS structure type and version) live here, next to where
//! they map onto the report. The `/sys`-backed collectors read the kernel's live
//! view for the inventory firmware does not enumerate (storage, networking). The
//! top-level orchestration that assembles a full
//! [`crate::report::InspectionReport`] from every collector lands once the
//! collectors are all in place.

use std::fs;
use std::path::Path;

pub mod cpu;
pub mod disk;
pub mod memory;
pub mod nic;
pub mod system;

/// Trim the surrounding whitespace SMBIOS strings are commonly padded with;
/// `None` (an absent field or "not specified") becomes "". Shared by the
/// SMBIOS-backed collectors so they clean strings the same way.
pub(crate) fn cleaned(value: Option<&str>) -> String {
    value.map(str::trim).unwrap_or_default().to_string()
}

/// Read a sysfs attribute and trim it; `None` on any read error or when the
/// trimmed value is empty. sysfs attributes carry a trailing newline, and some
/// are present-but-blank, so callers want the trimmed-non-empty value or nothing.
/// Shared by the `/sys`-backed collectors ([`disk`], [`nic`]).
pub(crate) fn read_trimmed(path: &Path) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Filesystem scaffolding shared by the `/sys`-backed collectors' unit tests:
/// a self-cleaning scratch directory and a sysfs-attribute writer, so each test
/// can build a `/sys`-shaped fixture tree without a new dependency.
#[cfg(test)]
pub(crate) mod testutil {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// A unique scratch directory under the system temp dir, removed on drop.
    pub struct Scratch(PathBuf);

    impl Scratch {
        pub fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("b7-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Write `contents` to `<root>/<rel>`, creating parent directories.
    pub fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}
