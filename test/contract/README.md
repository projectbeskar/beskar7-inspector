# Contract fixtures

`golden_inspection_report.json` is the canonical inspection report from the
Beskar7 controller↔inspector contract (`docs/inspector-contract.md` in the
[beskar7](https://github.com/projectbeskar/beskar7) repo, **contract `v1`**,
§6).

## Dual-repo anti-drift

This file is **byte-identical** to its counterpart in the beskar7 repo at
`test/contract/golden_inspection_report.json`. The two copies are the shared
guard against the producer (this inspector) and the consumer (the controller)
drifting apart:

| Repo | Test | Asserts |
|---|---|---|
| beskar7-inspector | `tests/contract.rs` | the report serde types decode this fixture strictly (`deny_unknown_fields`), round-trip it losslessly, and emit the controller-expected aggregates |
| beskar7 | `controllers/inspection_contract_test.go` | the same bytes decode into `InspectionReportRequest`, round-trip, run `buildInspectionReport`, and pass the hardware-requirement validation (`parseMemoryCapacityGB`) |

A schema change must update **both** copies in lockstep and bump the contract
version in `docs/inspector-contract.md`. Changing one side alone fails one of
the two suites.

## Canonical aggregates

The fixture describes a dual-socket Dell PowerEdge R650:

| Quantity | Value | Why it matters |
|---|---|---|
| CPU packages | 2 | one entry per physical package (§6.1) |
| Total cores | 64 | the controller sums `cpus[].cores` for `MinCPUCores` |
| DIMMs | 4 × `32GiB` | one entry per populated DIMM; capacity carries a unit suffix |
| Total disk | 1920 GB (2 × 960) | the controller sums `disks[].sizeGB` for `MinDiskGB` |
| NICs | 2 | first NIC carries 2 IPs (incl. IPv6) — `ipAddresses` is a real array |

> **Memory suffix gotcha.** `capacity` must end in `GB`/`GiB`/`MB`/`MiB`/`TB`/`TiB`
> (§6.1); a bare integer is rejected by the controller. The controller reads
> `32GiB` as IEC (× 1024) and truncates to decimal GB — `32GiB` → 34 GB — so the
> matching beskar7 test expects 34, not 32. The inspector test only locks the
> suffix and structural counts; the GB conversion is the controller's.

Every modelled field is populated (non-zero) so the round-trip is lossless under
the contract's `omitempty` semantics.
