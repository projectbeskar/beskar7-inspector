//! Inspection report wire types — the producer side of the Beskar7
//! controller↔inspector contract (`docs/inspector-contract.md`, §6, contract v1).
//!
//! These structs serialize to exactly the JSON the controller decodes into
//! `InspectionReportRequest` (`controllers/inspection_handler.go`). The shared
//! golden fixture (`test/contract/golden_inspection_report.json`, byte-identical
//! in both repos) is the anti-drift guard: a schema change here that diverges
//! from the contract fails the round-trip test in `tests/contract.rs` and the Go
//! test in beskar7 (`controllers/inspection_contract_test.go`), forcing a
//! coordinated contract bump.
//!
//! Conventions that make the drift guard bite:
//!   * Field order mirrors the contract for human-diff friendliness (serde emits
//!     in declaration order).
//!   * No `skip_serializing_if`: every field is always serialized, so a struct
//!     field the fixture does not carry surfaces as a JSON key the golden value
//!     lacks (reverse-drift catch).
//!   * `deny_unknown_fields`: a fixture field the structs do not model fails to
//!     decode with a clear error (forward-drift catch). The inspector is the
//!     report *producer* and never decodes reports in production, so strict
//!     decoding costs nothing operationally.

use serde::{Deserialize, Serialize};

/// Top-level inspection report — the POST body for
/// `/api/v1/inspection/{namespace}/{hostName}` (§4.2).
///
/// `namespace`/`hostName` are URL path parameters, not body fields (§4.2), and
/// are deliberately absent here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectionReport {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub cpus: Vec<Cpu>,
    pub memory: Vec<MemoryModule>,
    pub disks: Vec<Disk>,
    pub nics: Vec<Nic>,
    /// `"UEFI"` or `"Legacy"` (§6).
    pub boot_mode_detected: String,
    pub firmware_version: String,
}

/// One entry **per physical CPU package** (SMBIOS Type 4).
///
/// §6.1: the controller sums `cpus[].cores` for `MinCPUCores`. Emit one entry
/// per package with that package's real core count — never one entry per logical
/// processor, and never the per-socket core count repeated. (The legacy bash
/// inspector got this wrong.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cpu {
    pub id: String,
    pub vendor: String,
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub frequency: String,
}

/// One entry per populated DIMM (SMBIOS Type 17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryModule {
    pub id: String,
    /// DRAM type, e.g. `"DDR4"`.
    #[serde(rename = "type")]
    pub mem_type: String,
    /// §6.1: MUST carry a unit suffix the controller accepts —
    /// `GB`/`GiB`/`MB`/`MiB`/`TB`/`TiB`. A bare integer is rejected by the
    /// controller's `parseMemoryCapacityGB`.
    pub capacity: String,
    pub speed: String,
}

/// One entry per disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Disk {
    pub name: String,
    pub model: String,
    /// §6.1: summed for `MinDiskGB`; integer GB.
    #[serde(rename = "sizeGB")]
    pub size_gb: u64,
    /// `"HDD"`, `"SSD"`, or `"NVMe"` (§6).
    #[serde(rename = "type")]
    pub disk_type: String,
    pub serial_number: String,
}

/// One entry per NIC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Nic {
    pub name: String,
    pub mac_address: String,
    pub driver: String,
    pub speed: String,
    /// §6.1: a real JSON array of individual address strings — never a single
    /// comma-joined string.
    pub ip_addresses: Vec<String>,
}
