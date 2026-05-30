//! System-identity collector: the report's scalar fields.
//!
//! Sources (all firmware-truth or kernel-truth, no shelling out):
//!   * **SMBIOS Type 1 (System Information)** — `manufacturer`, `model`
//!     (Product Name), `serialNumber`.
//!   * **SMBIOS Type 0 (BIOS Information)** — `firmwareVersion` (BIOS Version).
//!   * **`/sys/firmware/efi`** — its existence is the canonical UEFI-vs-Legacy
//!     signal the kernel itself uses; present ⇒ `"UEFI"`, absent ⇒ `"Legacy"`
//!     (contract §6).
//!
//! Field offsets are from DSP0134 and are measured from the start of the
//! structure, so they index straight into the formatted area exposed by
//! [`Structure`].

use std::path::Path;

use crate::smbios::Structure;

/// SMBIOS structure type: BIOS Information (DSP0134 §7.1).
const TYPE_BIOS: u8 = 0;
/// SMBIOS structure type: System Information (DSP0134 §7.2).
const TYPE_SYSTEM: u8 = 1;

/// Type 0 offset: BIOS Version (string).
const OFF_BIOS_VERSION: usize = 0x05;
/// Type 1 offset: Manufacturer (string).
const OFF_SYS_MANUFACTURER: usize = 0x04;
/// Type 1 offset: Product Name (string).
const OFF_SYS_PRODUCT: usize = 0x05;
/// Type 1 offset: Serial Number (string).
const OFF_SYS_SERIAL: usize = 0x07;

/// Canonical sysfs marker for UEFI boot: the kernel only creates this directory
/// when booted via UEFI.
pub const EFI_SYSFS_PATH: &str = "/sys/firmware/efi";

const BOOT_MODE_UEFI: &str = "UEFI";
const BOOT_MODE_LEGACY: &str = "Legacy";

/// The report's scalar identity fields, sourced from SMBIOS + the EFI marker.
///
/// Absent SMBIOS strings become empty (the report fields are `omitempty` on the
/// controller side); `boot_mode` is always one of `"UEFI"` / `"Legacy"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfo {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub firmware_version: String,
    pub boot_mode: String,
}

impl SystemInfo {
    /// Collect from the parsed SMBIOS table and live sysfs.
    pub fn collect(structures: &[Structure]) -> Self {
        Self::from_parts(structures, Path::new(EFI_SYSFS_PATH).exists())
    }

    /// Pure mapping used by [`collect`](Self::collect) and the tests.
    /// `efi_present` is whether [`EFI_SYSFS_PATH`] exists.
    pub fn from_parts(structures: &[Structure], efi_present: bool) -> Self {
        let system = find_type(structures, TYPE_SYSTEM);
        let bios = find_type(structures, TYPE_BIOS);

        SystemInfo {
            manufacturer: cleaned(system.and_then(|s| s.string(OFF_SYS_MANUFACTURER))),
            model: cleaned(system.and_then(|s| s.string(OFF_SYS_PRODUCT))),
            serial_number: cleaned(system.and_then(|s| s.string(OFF_SYS_SERIAL))),
            firmware_version: cleaned(bios.and_then(|s| s.string(OFF_BIOS_VERSION))),
            boot_mode: if efi_present {
                BOOT_MODE_UEFI
            } else {
                BOOT_MODE_LEGACY
            }
            .to_string(),
        }
    }
}

/// The first structure of the given type, if any. SMBIOS permits at most one
/// Type 0 and one Type 1, but defend against firmware that emits extras by
/// taking the first.
fn find_type(structures: &[Structure], header_type: u8) -> Option<&Structure> {
    structures.iter().find(|s| s.header_type == header_type)
}

/// Trim surrounding whitespace SMBIOS strings are often padded with; absent ⇒ "".
fn cleaned(value: Option<&str>) -> String {
    value.map(str::trim).unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smbios::{encode_structure, parse_table};

    // Type 1 (System Information) formatted area, offsets 0x04..=0x07:
    //   0x04 Manufacturer (str#), 0x05 Product (str#), 0x06 Version (str#),
    //   0x07 Serial (str#). Indices below select the strings declared after.
    fn system_structure() -> Vec<u8> {
        // formatted starts at offset 0x04: [manufacturer=1, product=2,
        // version=3, serial=4].
        encode_structure(
            TYPE_SYSTEM,
            0x0001,
            &[1, 2, 3, 4],
            &["Dell Inc.", "PowerEdge R650", "01", "ABCD123"],
        )
    }

    // Type 0 (BIOS Information): 0x04 Vendor (str#), 0x05 BIOS Version (str#).
    fn bios_structure() -> Vec<u8> {
        encode_structure(TYPE_BIOS, 0x0000, &[1, 2], &["Dell Inc.", "2.10.2"])
    }

    fn table(blobs: &[Vec<u8>]) -> Vec<Structure> {
        let mut raw = Vec::new();
        for b in blobs {
            raw.extend_from_slice(b);
        }
        raw.extend(encode_structure(127, 0x7f00, &[], &[])); // end of table
        parse_table(&raw).expect("valid table")
    }

    #[test]
    fn maps_type1_and_type0_with_uefi() {
        let structures = table(&[bios_structure(), system_structure()]);
        let info = SystemInfo::from_parts(&structures, true);
        assert_eq!(info.manufacturer, "Dell Inc.");
        assert_eq!(info.model, "PowerEdge R650");
        assert_eq!(info.serial_number, "ABCD123");
        assert_eq!(info.firmware_version, "2.10.2");
        assert_eq!(info.boot_mode, "UEFI");
    }

    #[test]
    fn absent_efi_marker_is_legacy() {
        let structures = table(&[bios_structure(), system_structure()]);
        let info = SystemInfo::from_parts(&structures, false);
        assert_eq!(info.boot_mode, "Legacy");
    }

    #[test]
    fn padded_strings_are_trimmed() {
        let system = encode_structure(
            TYPE_SYSTEM,
            0x0001,
            &[1, 2, 0, 3],
            &["  Supermicro  ", "X11\t", "SN-77  "],
        );
        let structures = table(&[system]);
        let info = SystemInfo::from_parts(&structures, true);
        assert_eq!(info.manufacturer, "Supermicro");
        assert_eq!(info.model, "X11");
        assert_eq!(info.serial_number, "SN-77");
    }

    #[test]
    fn missing_structures_yield_empty_strings_not_panic() {
        // Only an end-of-table marker: no Type 0, no Type 1.
        let structures = table(&[]);
        let info = SystemInfo::from_parts(&structures, true);
        assert_eq!(info.manufacturer, "");
        assert_eq!(info.model, "");
        assert_eq!(info.serial_number, "");
        assert_eq!(info.firmware_version, "");
        assert_eq!(info.boot_mode, "UEFI"); // boot mode is independent of SMBIOS
    }

    #[test]
    fn not_specified_string_index_yields_empty() {
        // Serial field references string #0 ("not specified").
        let system = encode_structure(TYPE_SYSTEM, 0x0001, &[1, 2, 0, 0], &["ACME", "Server9000"]);
        let structures = table(&[system]);
        let info = SystemInfo::from_parts(&structures, true);
        assert_eq!(info.manufacturer, "ACME");
        assert_eq!(info.model, "Server9000");
        assert_eq!(info.serial_number, "");
    }
}
