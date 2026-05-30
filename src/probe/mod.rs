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
//!
//! Collectors are split from the raw [`crate::smbios`] parser on purpose: the
//! parser is semantics-free, while the per-type field offsets (which vary by
//! SMBIOS structure type and version) live here, next to where they map onto the
//! report. The top-level orchestration that assembles a full
//! [`crate::report::InspectionReport`] from every collector lands once the
//! remaining collectors (disk, nic) do.

pub mod cpu;
pub mod memory;
pub mod system;

/// Trim the surrounding whitespace SMBIOS strings are commonly padded with;
/// `None` (an absent field or "not specified") becomes "". Shared by the
/// SMBIOS-backed collectors so they clean strings the same way.
pub(crate) fn cleaned(value: Option<&str>) -> String {
    value.map(str::trim).unwrap_or_default().to_string()
}
