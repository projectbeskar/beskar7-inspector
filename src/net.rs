//! Phase-1 network bring-up (decision D-013).
//!
//! The inspector must reach the callback (`beskar7.api`) to POST its report and
//! GET bootstrap data, but it boots with the provisioning NIC down and
//! unaddressed: the kernel's `ip=dhcp` autoconfig cannot help because the NIC
//! driver is a module loaded by the inspector *after* boot (D-012). So the
//! inspector configures networking itself, natively — no `dhclient`/`udhcpc`, no
//! shell, consistent with the single-binary-userspace principle.
//!
//! [`bring_up_provisioning_network`] is the one entry point `run()` calls,
//! immediately after [`crate::modules::load_drivers`] and before the callback
//! client. It:
//!   1. selects the provisioning NIC — by the `BOOTIF=<mac>` cmdline param (the
//!      pxelinux/iPXE convention: the NIC that just PXE-booted), or the single
//!      physical NIC when only one is present;
//!   2. brings the link up (RTNETLINK `RTM_NEWLINK`);
//!   3. runs a one-shot DHCP exchange (DISCOVER/OFFER/REQUEST/ACK), hand-rolled —
//!      the inspector runs once then reboots, so there is no lease renewal;
//!   4. assigns the leased address + default route (RTNETLINK `RTM_NEWADDR` /
//!      `RTM_NEWROUTE`).
//!
//! ## Scope (Smoke-1 minimum)
//! Single-NIC DHCP. DNS is out of scope — `beskar7.api` is expected to be an
//! IP-literal (contract §8). The multi-NIC "DHCP every link and race", a
//! `beskar7.ip=` static fallback, VLAN, and DHCP-option-6 → `/etc/resolv.conf`
//! are deliberate D-013 follow-ups; the single entry point is shaped so they land
//! additively without touching the `run()` call site.
//!
//! ## Secret hygiene (§9)
//! No secret passes through here — DHCP is unauthenticated by design and the
//! provisioning L2 is semi-trusted (the join secret is protected by the
//! verified-TLS `/bootstrap` GET, not the network). [`NetError`] carries only
//! interface names, IPs, and errnos, all non-secret.

mod dhcp;
mod netlink;

use std::net::Ipv4Addr;
use std::path::Path;

use nix::errno::Errno;

use crate::cmdline::BootParams;
use crate::probe::read_trimmed;

/// `/sys/class/net` — one entry per network interface.
const SYSFS_NET: &str = "/sys/class/net";

/// The resolved network configuration applied to the provisioning interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetConfig {
    /// The provisioning interface kernel name (e.g. `eth0`, `ens3`).
    pub iface: String,
    /// The leased IPv4 address.
    pub ip: Ipv4Addr,
    /// The subnet prefix length (e.g. 24 for a `/24`).
    pub prefix_len: u8,
    /// The default gateway (DHCP option 3), if the lease supplied one.
    pub gateway: Option<Ipv4Addr>,
    /// DNS servers (DHCP option 6). Unused in the Smoke-1 IP-literal path;
    /// carried for the future `/etc/resolv.conf` writer (D-013 follow-up).
    pub dns: Vec<Ipv4Addr>,
}

/// Errors from network bring-up. All variants carry only non-secret material
/// (interface names, IPs, errnos), so logging a `NetError` is safe (§9).
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// No usable (non-loopback) network interface was found.
    #[error("no network interface found")]
    NoInterface,
    /// More than one NIC is present and no `BOOTIF` pinned which to use.
    #[error("multiple NICs and no BOOTIF to select one: {0}")]
    AmbiguousInterface(String),
    /// `BOOTIF` was given but no interface's MAC matched it.
    #[error("BOOTIF MAC {0} matched no interface")]
    BootifNoMatch(String),
    /// A required `/sys/class/net/<iface>/...` attribute could not be read.
    #[error("reading {0}")]
    SysRead(String),
    /// A socket operation (open/bind/setsockopt/send/recv) failed.
    #[error("DHCP socket: {0}")]
    Socket(#[source] Errno),
    /// No DHCP OFFER/ACK arrived within the retry budget.
    #[error("DHCP timed out (no lease offered)")]
    DhcpTimeout,
    /// A DHCP reply was malformed (bad cookie, truncated, no message-type).
    #[error("malformed DHCP reply")]
    DhcpMalformed,
    /// A netlink configuration message (link/addr/route) failed.
    #[error("netlink {op}: {source}")]
    Netlink {
        /// Which configuration step failed.
        op: &'static str,
        /// The netlink/errno failure.
        #[source]
        source: Errno,
    },
}

/// Bring up the provisioning network and return the applied configuration
/// (D-013). Live entry point; the policy pieces it calls are pure and tested.
pub fn bring_up_provisioning_network(params: &BootParams) -> Result<NetConfig, NetError> {
    let iface = select_nic(Path::new(SYSFS_NET), params.bootif.as_deref())?;
    let ifindex = read_ifindex(&iface)?;
    let mac = read_mac(&iface)?;

    netlink::link_up(ifindex).map_err(|source| NetError::Netlink {
        op: "link up",
        source,
    })?;
    wait_for_link(&iface);

    let lease = dhcp::acquire(&iface, mac)?;

    netlink::add_address(ifindex, lease.ip, lease.prefix_len).map_err(|source| {
        NetError::Netlink {
            op: "add address",
            source,
        }
    })?;
    if let Some(gw) = lease.gateway {
        netlink::add_default_route(ifindex, gw).map_err(|source| NetError::Netlink {
            op: "add default route",
            source,
        })?;
    }

    Ok(NetConfig {
        iface,
        ip: lease.ip,
        prefix_len: lease.prefix_len,
        gateway: lease.gateway,
        dns: lease.dns,
    })
}

/// Select the provisioning interface from `net_dir` (a `/sys/class/net`-shaped
/// directory). With `bootif`, returns the interface whose MAC matches; otherwise
/// the single non-loopback interface (erroring if there are several). Pure over
/// the directory, so the selection policy is unit-tested.
fn select_nic(net_dir: &Path, bootif: Option<&str>) -> Result<String, NetError> {
    let mut candidates: Vec<String> = match std::fs::read_dir(net_dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| name != "lo")
            .collect(),
        Err(_) => return Err(NetError::NoInterface),
    };
    candidates.sort();
    if candidates.is_empty() {
        return Err(NetError::NoInterface);
    }

    if let Some(bootif) = bootif {
        let want = normalize_bootif(bootif);
        for iface in &candidates {
            if let Some(mac) = read_trimmed(&net_dir.join(iface).join("address")) {
                if mac.eq_ignore_ascii_case(&want) {
                    return Ok(iface.clone());
                }
            }
        }
        return Err(NetError::BootifNoMatch(want));
    }

    match candidates.as_slice() {
        [only] => Ok(only.clone()),
        many => Err(NetError::AmbiguousInterface(many.join(", "))),
    }
}

/// Normalize a `BOOTIF` value to a lowercase colon-separated MAC. pxelinux/iPXE
/// render it as `01-aa-bb-cc-dd-ee-ff` (a `01` hardware-type prefix + the MAC
/// with dashes); strip the prefix and convert to the `/sys/.../address` form.
fn normalize_bootif(bootif: &str) -> String {
    let hex = bootif.strip_prefix("01-").unwrap_or(bootif);
    hex.replace('-', ":").to_ascii_lowercase()
}

/// Read `/sys/class/net/<iface>/ifindex`.
fn read_ifindex(iface: &str) -> Result<u32, NetError> {
    let path = format!("{SYSFS_NET}/{iface}/ifindex");
    read_trimmed(Path::new(&path))
        .and_then(|s| s.parse().ok())
        .ok_or(NetError::SysRead(path))
}

/// Read and parse `/sys/class/net/<iface>/address` into 6 MAC bytes.
fn read_mac(iface: &str) -> Result<[u8; 6], NetError> {
    let path = format!("{SYSFS_NET}/{iface}/address");
    let raw = read_trimmed(Path::new(&path)).ok_or_else(|| NetError::SysRead(path.clone()))?;
    parse_mac(&raw).ok_or(NetError::SysRead(path))
}

/// Parse an `aa:bb:cc:dd:ee:ff` MAC into 6 bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in out.iter_mut() {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// Briefly wait for the link carrier after bringing the interface up, so DHCP
/// does not race a not-yet-up link. Best-effort and bounded; a link that never
/// reports a carrier still proceeds (DHCP will simply time out and surface that).
fn wait_for_link(iface: &str) {
    use std::time::{Duration, Instant};
    let carrier = format!("{SYSFS_NET}/{iface}/carrier");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if read_trimmed(Path::new(&carrier)).as_deref() == Some("1") {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Count the leading one-bits of a subnet mask (DHCP option 1) into a prefix
/// length. A non-contiguous mask falls back to a `/24` rather than erroring —
/// the address is still usable for the brief inspection window.
fn mask_to_prefix_len(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    let ones = bits.count_ones();
    // Contiguous masks have all ones at the top; if not, default to /24.
    if bits.leading_ones() == ones {
        ones as u8
    } else {
        24
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};

    fn write_iface(root: &Path, name: &str, mac: &str) {
        write(root, &format!("{name}/address"), &format!("{mac}\n"));
        write(root, &format!("{name}/ifindex"), "2\n");
    }

    #[test]
    fn select_nic_single_non_loopback() {
        let s = Scratch::new("net-single");
        write(s.path(), "lo/address", "00:00:00:00:00:00\n");
        write_iface(s.path(), "eth0", "52:54:00:12:34:56");
        assert_eq!(select_nic(s.path(), None).unwrap(), "eth0");
    }

    #[test]
    fn select_nic_ambiguous_without_bootif_errors() {
        let s = Scratch::new("net-ambig");
        write_iface(s.path(), "eth0", "52:54:00:00:00:01");
        write_iface(s.path(), "eth1", "52:54:00:00:00:02");
        assert!(matches!(
            select_nic(s.path(), None),
            Err(NetError::AmbiguousInterface(_))
        ));
    }

    #[test]
    fn select_nic_bootif_matches_mac() {
        let s = Scratch::new("net-bootif");
        write_iface(s.path(), "eth0", "52:54:00:00:00:01");
        write_iface(s.path(), "eth1", "52:54:00:aa:bb:cc");
        // pxelinux form: 01- prefix, dashes, any case.
        let got = select_nic(s.path(), Some("01-52-54-00-AA-BB-CC")).unwrap();
        assert_eq!(got, "eth1");
    }

    #[test]
    fn select_nic_bootif_no_match_errors() {
        let s = Scratch::new("net-bootif-miss");
        write_iface(s.path(), "eth0", "52:54:00:00:00:01");
        assert!(matches!(
            select_nic(s.path(), Some("01-de-ad-be-ef-00-00")),
            Err(NetError::BootifNoMatch(_))
        ));
    }

    #[test]
    fn select_nic_no_interface() {
        let s = Scratch::new("net-none");
        write(s.path(), "lo/address", "00:00:00:00:00:00\n");
        assert!(matches!(
            select_nic(s.path(), None),
            Err(NetError::NoInterface)
        ));
    }

    #[test]
    fn normalize_bootif_strips_prefix_and_lowercases() {
        assert_eq!(
            normalize_bootif("01-52-54-00-AA-BB-CC"),
            "52:54:00:aa:bb:cc"
        );
        // Already-bare MAC with dashes is tolerated.
        assert_eq!(normalize_bootif("52-54-00-11-22-33"), "52:54:00:11:22:33");
    }

    #[test]
    fn parse_mac_roundtrips_and_rejects_bad() {
        assert_eq!(
            parse_mac("52:54:00:12:34:56"),
            Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
        );
        assert_eq!(parse_mac("52:54:00:12:34"), None); // too short
        assert_eq!(parse_mac("52:54:00:12:34:56:78"), None); // too long
        assert_eq!(parse_mac("zz:54:00:12:34:56"), None); // non-hex
    }

    #[test]
    fn mask_to_prefix_len_common_masks() {
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 192)), 26);
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(0, 0, 0, 0)), 0);
        // Non-contiguous (pathological) falls back to /24.
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(255, 0, 255, 0)), 24);
    }
}
