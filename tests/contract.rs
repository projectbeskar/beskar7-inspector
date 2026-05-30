//! Contract test: the report serde types are a lossless mirror of the shared
//! golden fixture and emit the values the controller's validation expects.
//!
//! `test/contract/golden_inspection_report.json` is byte-identical to the copy in
//! the beskar7 repo (`test/contract/golden_inspection_report.json`), decoded there
//! by `controllers/inspection_contract_test.go`. A schema change on either side
//! breaks one of the two suites, forcing a coordinated contract bump.
//! See `docs/inspector-contract.md` §10.

use beskar7_inspector::report::InspectionReport;

const GOLDEN: &str = include_str!("../test/contract/golden_inspection_report.json");

// Canonical aggregates the controller derives from the golden fixture. Kept in
// lockstep with the constants in beskar7's controllers/inspection_contract_test.go.
const GOLDEN_NUM_CPU_SOCKETS: usize = 2;
const GOLDEN_TOTAL_CPU_CORES: u32 = 64;
const GOLDEN_NUM_DIMMS: usize = 4;
const GOLDEN_NUM_DISKS: usize = 2;
const GOLDEN_TOTAL_DISK_GB: u64 = 1920;
const GOLDEN_NUM_NICS: usize = 2;
const GOLDEN_FIRST_NIC_NUM_IPS: usize = 2;

const ACCEPTED_MEMORY_SUFFIXES: [&str; 6] = ["GiB", "MiB", "TiB", "GB", "MB", "TB"];

/// Forward-drift catch: `deny_unknown_fields` makes a fixture field the structs
/// do not model fail to decode with a clear "unknown field" error.
#[test]
fn golden_fixture_decodes_strictly() {
    let report: InspectionReport = serde_json::from_str(GOLDEN)
        .expect("golden fixture must decode under the report schema (deny_unknown_fields)");
    assert_eq!(report.manufacturer, "Dell Inc.");
    assert_eq!(report.boot_mode_detected, "UEFI");
    assert_eq!(report.firmware_version, "2.10.2");
}

/// Lossless round-trip: re-serializing the decoded report reproduces the golden
/// value exactly. Bidirectional `Value` equality catches drift in both
/// directions — a fixture field the struct drops (forward) and a struct field
/// the fixture lacks (reverse, because every field is always serialized).
#[test]
fn report_round_trips_losslessly() {
    let report: InspectionReport = serde_json::from_str(GOLDEN).expect("decode golden");
    let from_struct: serde_json::Value =
        serde_json::to_value(&report).expect("re-serialize report");
    let from_golden: serde_json::Value =
        serde_json::from_str(GOLDEN).expect("golden as untyped value");
    assert_eq!(
        from_struct, from_golden,
        "report struct is not a lossless mirror of the golden fixture — schema drift"
    );
}

/// Hardware aggregates the controller computes, locked here so the inspector
/// cannot silently start emitting data the controller would reject.
#[test]
fn hardware_aggregates_match_contract() {
    let report: InspectionReport = serde_json::from_str(GOLDEN).expect("decode golden");

    assert_eq!(
        report.cpus.len(),
        GOLDEN_NUM_CPU_SOCKETS,
        "one CPU entry per physical package (§6.1)"
    );
    let total_cores: u32 = report.cpus.iter().map(|c| c.cores).sum();
    assert_eq!(
        total_cores, GOLDEN_TOTAL_CPU_CORES,
        "the controller sums cpus[].cores for MinCPUCores"
    );

    assert_eq!(
        report.memory.len(),
        GOLDEN_NUM_DIMMS,
        "one entry per populated DIMM (§6.1)"
    );
    for dimm in &report.memory {
        assert!(
            ACCEPTED_MEMORY_SUFFIXES
                .iter()
                .any(|s| dimm.capacity.len() > s.len() && dimm.capacity.ends_with(s)),
            "memory capacity {:?} must carry a controller-accepted unit suffix and a \
             magnitude (§6.1); a bare integer is rejected by parseMemoryCapacityGB",
            dimm.capacity
        );
    }

    assert_eq!(report.disks.len(), GOLDEN_NUM_DISKS);
    let total_disk_gb: u64 = report.disks.iter().map(|d| d.size_gb).sum();
    assert_eq!(
        total_disk_gb, GOLDEN_TOTAL_DISK_GB,
        "the controller sums disks[].sizeGB for MinDiskGB"
    );

    assert_eq!(report.nics.len(), GOLDEN_NUM_NICS);
    assert_eq!(
        report.nics[0].ip_addresses.len(),
        GOLDEN_FIRST_NIC_NUM_IPS,
        "ipAddresses is a real array, not a comma-joined string (§6.1)"
    );
}
