//! beskar7-inspector entrypoint.
//!
//! The shipped binary runs as the initramfs `/init` (PID 1): it mounts the
//! pseudo-filesystems, parses the kernel cmdline (`beskar7.*`), probes hardware,
//! POSTs the inspection report, fetches CAPI bootstrap data, and `kexec`s into
//! the target OS. Those stages land in later PRs (cmdline/probe/client/kexec);
//! this scaffold establishes the crate and the contract-anchored report types.

use beskar7_inspector::CONTRACT_VERSION;

fn main() {
    eprintln!(
        "beskar7-inspector (contract {CONTRACT_VERSION}): scaffold build — \
         cmdline parsing, hardware probing, callback client, and kexec are not \
         yet implemented"
    );
}
