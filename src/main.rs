//! beskar7-inspector entrypoint — the initramfs `/init` (PID 1).
//!
//! A thin wrapper over [`beskar7_inspector::run`]: it parses the `--dry-run`
//! flag and runs the two-phase enroll/provision pipeline (contract §9). On the
//! production path a successful run does not return (the host reboots into the
//! provisioned OS); on failure, since a returning PID 1 panics the kernel, this
//! logs the (non-secret) error and parks the process so the controller's
//! inspection/provisioning timeout re-drives the host (fresh nonce/token, §9.2).

use std::time::Duration;

use beskar7_inspector::{run, CONTRACT_VERSION};

fn main() {
    let dry_run = std::env::args().skip(1).any(|a| a == "--dry-run");
    eprintln!(
        "beskar7-inspector (contract {CONTRACT_VERSION}){}",
        if dry_run { " --dry-run" } else { "" }
    );

    match run::run(dry_run) {
        // Reachable only in --dry-run (the production path reboots, diverging).
        Ok(()) => {}
        Err(e) => {
            // RunError carries no secrets (§9) — safe to log in full.
            eprintln!("beskar7-inspector: run failed: {e}");
            if dry_run {
                std::process::exit(1);
            }
            // PID 1 must not exit (the kernel panics if init dies). Park so the
            // controller observes a provisioning timeout and re-drives the host.
            park();
        }
    }
}

/// Sleep forever, keeping PID 1 alive after an unrecoverable error.
fn park() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
