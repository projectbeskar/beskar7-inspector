//! Native hardware probing: turn firmware tables (`smbios`) and `/sys`/`/proc`
//! into the inspection report (`report`).
//!
//! Each submodule owns one slice of the report and the byte-offset / sysfs
//! interpretation for it:
//!
//! | submodule | source | report fields |
//! |-----------|--------|---------------|
//! | [`system`] | SMBIOS Type 1 + Type 0, `/sys/firmware/efi` | `manufacturer`, `model`, `serialNumber`, `firmwareVersion`, `bootModeDetected` |
//!
//! Collectors are split from the raw [`crate::smbios`] parser on purpose: the
//! parser is semantics-free, while the per-type field offsets (which vary by
//! SMBIOS structure type and version) live here, next to where they map onto the
//! report. The top-level orchestration that assembles a full
//! [`crate::report::InspectionReport`] from every collector lands once the
//! remaining collectors (cpu, memory, disk, nic) do.

pub mod system;
