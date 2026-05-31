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
//! view for the inventory firmware does not enumerate (storage, networking).
//!
//! [`collect`] is the orchestration entry point: it reads the firmware tables
//! once and pairs them with the live `/sys` view to assemble a full
//! [`crate::report::InspectionReport`].

use std::fs;
use std::path::Path;

use crate::report::InspectionReport;
use crate::smbios::{self, Structure};
use system::SystemInfo;

pub mod cpu;
pub mod disk;
pub mod memory;
pub mod nic;
pub mod system;

/// Assemble the full inspection report from the live host: parse the SMBIOS
/// table once (shared by the system, CPU and memory collectors) and pair it with
/// the live `/sys` view (disks, NICs) and the EFI boot-mode marker.
///
/// SMBIOS is best-effort: a host whose DMI tables are unreadable still yields a
/// report carrying its disks, NICs and boot mode (the SMBIOS-derived fields are
/// simply empty), rather than failing inspection outright. The controller
/// validates the report against its hardware requirements regardless.
pub fn collect() -> InspectionReport {
    let structures = smbios::from_sysfs().unwrap_or_default();
    let efi_present = Path::new(system::EFI_SYSFS_PATH).exists();
    assemble(&structures, efi_present, disk::collect(), nic::collect())
}

/// Pure assembly used by [`collect`] and the tests: map the parsed SMBIOS
/// structures, the EFI marker and the already-collected disks/NICs onto the
/// report's fields. Keeping this free of I/O makes the field wiring testable
/// without a live host.
fn assemble(
    structures: &[Structure],
    efi_present: bool,
    disks: Vec<crate::report::Disk>,
    nics: Vec<crate::report::Nic>,
) -> InspectionReport {
    let system = SystemInfo::from_parts(structures, efi_present);
    InspectionReport {
        manufacturer: system.manufacturer,
        model: system.model,
        serial_number: system.serial_number,
        cpus: cpu::collect(structures),
        memory: memory::collect(structures),
        disks,
        nics,
        boot_mode_detected: system.boot_mode,
        firmware_version: system.firmware_version,
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Disk, Nic};
    use crate::smbios::{encode_structure, parse_table};

    /// Type 1 (System Information): manufacturer @0x04, product @0x05, serial
    /// @0x07 (version @0x06 left "not specified").
    fn system_structure() -> Vec<u8> {
        encode_structure(
            1,
            0x0001,
            &[1, 2, 0, 3],
            &["TestCorp", "Model9000", "SERIAL123"],
        )
    }

    /// Type 0 (BIOS Information): BIOS version @0x05.
    fn bios_structure() -> Vec<u8> {
        encode_structure(0, 0x0000, &[1, 2], &["BIOSVendor", "1.2.3"])
    }

    /// Formatted-area index for a structure-relative SMBIOS `offset` (the
    /// formatted area begins at offset 0x04, so this is just `offset - 4`).
    fn fi(offset: usize) -> usize {
        offset - 4
    }

    /// Minimal populated central Type 4 (Processor): socket designation @0x04,
    /// processor type central @0x05, socket-populated status @0x18.
    fn cpu_structure() -> Vec<u8> {
        let mut f = vec![0u8; 36]; // offsets 0x04..=0x27
        f[fi(0x04)] = 1; // socket designation -> string #1
        f[fi(0x05)] = 3; // processor type: central
        f[fi(0x18)] = 0x40 | 0x01; // status: socket populated
        f[fi(0x23)] = 8; // core count
        f[fi(0x25)] = 16; // thread count
        encode_structure(4, 0x0040, &f, &["CPU.Socket.1"])
    }

    /// Minimal populated Type 17 (Memory Device): 16 GiB DDR4 in slot DIMM.A1.
    fn memory_structure() -> Vec<u8> {
        let mut f = vec![0u8; 28]; // offsets 0x04..=0x1F
        let size = 16384u16.to_le_bytes(); // 16 GiB in MB, fits the 15-bit field
        f[fi(0x0C)] = size[0];
        f[fi(0x0D)] = size[1];
        f[fi(0x10)] = 1; // device locator -> string #1
        f[fi(0x12)] = 0x1A; // memory type: DDR4
        encode_structure(17, 0x1100, &f, &["DIMM.A1"])
    }

    fn table(blobs: &[Vec<u8>]) -> Vec<Structure> {
        let mut raw = Vec::new();
        for b in blobs {
            raw.extend_from_slice(b);
        }
        raw.extend(encode_structure(127, 0x7f00, &[], &[]));
        parse_table(&raw).expect("valid table")
    }

    fn sample_disk() -> Disk {
        Disk {
            name: "/dev/nvme0n1".into(),
            model: "Test NVMe".into(),
            size_gb: 960,
            disk_type: "NVMe".into(),
            serial_number: "SER1".into(),
        }
    }

    fn sample_nic() -> Nic {
        Nic {
            name: "eno1".into(),
            mac_address: "aa:bb:cc:dd:ee:01".into(),
            driver: "ixgbe".into(),
            speed: "10Gbps".into(),
            ip_addresses: vec!["192.0.2.10".into()],
        }
    }

    #[test]
    fn assemble_wires_every_collector_into_the_report() {
        let structures = table(&[
            bios_structure(),
            system_structure(),
            cpu_structure(),
            memory_structure(),
        ]);
        let disks = vec![sample_disk()];
        let nics = vec![sample_nic()];

        let report = assemble(&structures, true, disks.clone(), nics.clone());

        // Scalar identity comes from the SMBIOS system/BIOS collectors.
        assert_eq!(report.manufacturer, "TestCorp");
        assert_eq!(report.model, "Model9000");
        assert_eq!(report.serial_number, "SERIAL123");
        assert_eq!(report.firmware_version, "1.2.3");
        assert_eq!(report.boot_mode_detected, "UEFI");

        // CPU and memory come from their SMBIOS collectors.
        assert_eq!(report.cpus.len(), 1);
        assert_eq!(report.cpus[0].id, "CPU.Socket.1");
        assert_eq!(report.memory.len(), 1);
        assert_eq!(report.memory[0].id, "DIMM.A1");
        assert_eq!(report.memory[0].capacity, "16GiB");

        // Disks and NICs are threaded through verbatim from the /sys collectors.
        assert_eq!(report.disks, disks);
        assert_eq!(report.nics, nics);
    }

    #[test]
    fn assemble_reports_legacy_when_no_efi_marker_and_no_smbios() {
        // An empty table and absent EFI marker: identity fields are empty,
        // collections are empty, and boot mode falls back to Legacy — the
        // graceful-degradation contract `collect` relies on.
        let report = assemble(&[], false, Vec::new(), Vec::new());
        assert_eq!(report.manufacturer, "");
        assert_eq!(report.model, "");
        assert_eq!(report.serial_number, "");
        assert_eq!(report.firmware_version, "");
        assert_eq!(report.boot_mode_detected, "Legacy");
        assert!(report.cpus.is_empty());
        assert!(report.memory.is_empty());
        assert!(report.disks.is_empty());
        assert!(report.nics.is_empty());
    }
}
