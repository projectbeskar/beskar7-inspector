# Contract fixtures (vendored — contract `v4.2`)

These files are **byte-copies** of the canonical wire-contract fixtures in the
[beskar7](https://github.com/projectbeskar/beskar7) repo
(`test/contract/*`, spec: `docs/inspector-contract.md`). **beskar7 is the single
source of truth**; this inspector never edits them by hand — it vendors them and
pins the immutable beskar7 git tag they were taken from.

| File | What it is |
|---|---|
| `VERSION` | the one-line contract version marker (`v4.2`); the Rust `CONTRACT_VERSION` must equal its trimmed value |
| `CONTRACT_REF` | the pinned beskar7 tag (`contract/v4.2`) the copies were taken from — the ref the CI drift job fetches |
| `golden_inspection_report.json` | the inspection-report POST body the inspector produces (§6) |
| `golden_boot_cmdline.txt` | the byte-exact iPXE `/boot` render, incl. `beskar7.provider-id` (v4.2 deploy-path, §5/§9.1) |
| `golden_provider_id_artifact.json` | descriptor of the `/oem/beskar7/provider-id` `COS_OEM` artifact the inspector writes (v4.2, §9.1 5.4) |

## Dual-repo anti-drift (Option D)

The vendored copies are the shared guard against the producer (this inspector)
and the consumer (the controller) drifting apart. Two mechanisms enforce it:

- **CI `contract-sync` job** (`.github/workflows/ci.yml`) — fetches beskar7's
  canonical files at `CONTRACT_REF` and `diff`s each against the vendored copy;
  any single-byte delta fails. It also re-asserts `CONTRACT_VERSION == VERSION`.
  This is the only step that reaches across repos.
- **Behavioral tests** — run purely against these vendored copies (no network):

  | Repo | Test | Asserts |
  |---|---|---|
  | beskar7-inspector | `tests/contract.rs`, `src/{cmdline,deploy}.rs` | the report round-trips losslessly and emits the expected aggregates; `beskar7.provider-id` parses from the golden cmdline; the `provider-id` artifact is written 0600/root, no trailing newline, matching the golden artifact; `CONTRACT_VERSION == VERSION.trim()` |
  | beskar7 | `controllers/*_contract_test.go` | the same bytes decode into the Go types, round-trip, and the renders match `buildBootIPXEScript`/`providerID()` |

Adopting a new contract version means bumping `CONTRACT_REF` + `VERSION` and
re-vendoring every file here in one change; a schema change alone (without the
matching beskar7 tag) is caught by the failing `contract-sync` diff.

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
