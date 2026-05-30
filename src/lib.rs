//! beskar7-inspector library crate.
//!
//! Houses the contract-facing types and — in subsequent PRs — the cmdline,
//! probe, client, and kexec modules. The binary (`src/main.rs`) is a thin PID 1
//! orchestrator over this library so every module is unit- and contract-testable
//! without booting a ramdisk.

pub mod cmdline;
pub mod report;
pub mod secret;

/// The controller↔inspector contract version this build implements
/// (`docs/inspector-contract.md` in the beskar7 repo).
///
/// Changing the wire format, auth, endpoints, or cmdline parameters is a
/// contract version change that must be coordinated across both repos and the
/// shared golden fixture (see that document's "Versioning and anti-drift").
pub const CONTRACT_VERSION: &str = "v1";
