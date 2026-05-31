//! NIC collector: the report's `nics[]`, one entry **per physical network
//! interface**.
//!
//! Sources:
//!   * **`/sys/class/net/<iface>`** — name, `address` (MAC), `device/driver`
//!     (driver), `speed` (link speed, MT/s). Firmware SMBIOS does not enumerate
//!     usable networking, so this is the kernel's live view.
//!   * **`getifaddrs(3)`** — the per-interface IP addresses, which sysfs does not
//!     expose as a simple attribute. `ipAddresses[]` MUST be a real JSON array
//!     (contract §6.1), so addresses are collected individually here.
//!
//! Only **physical** interfaces are reported: virtual ones (loopback, bridges,
//! `veth`, bonds, tun/tap, `docker0`) have no backing `device` link under
//! `/sys/class/net` and are filtered out, matching the disk collector's
//! `device`-link test. This keeps `nics[]` to the host's real NICs, the set the
//! controller's optional MAC pinning (§"MAC learning") expects.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use super::read_trimmed;
use crate::report::Nic;

/// Kernel network-interface directory: one subdirectory per interface.
const SYSFS_NET: &str = "/sys/class/net";

const MBPS_PER_GBPS: i64 = 1000;

/// Interface name → its IP addresses. Lifted behind a map so the sysfs decode is
/// unit-testable without a live network stack (the only un-mocked seam is
/// [`interface_addresses`], the thin `getifaddrs` wrapper).
type AddressMap = HashMap<String, Vec<IpAddr>>;

/// Collect one [`Nic`] per physical interface from the live `/sys/class/net`
/// plus `getifaddrs`.
pub fn collect() -> Vec<Nic> {
    collect_from(Path::new(SYSFS_NET), &interface_addresses())
}

/// Enumerate `net_dir` (a `/sys/class/net`-shaped directory) in stable name
/// order, pairing each physical interface with its addresses from `addrs`.
/// Unreadable directories yield no NICs rather than an error.
fn collect_from(net_dir: &Path, addrs: &AddressMap) -> Vec<Nic> {
    let Ok(entries) = fs::read_dir(net_dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries.flatten().map(|e| e.file_name()).collect();
    names.sort();
    names
        .iter()
        .filter_map(|name| decode(net_dir, name, addrs))
        .collect()
}

/// Decode one `/sys/class/net/<name>` interface, or `None` when it is virtual
/// (no backing `device` link).
fn decode(net_dir: &Path, name: &OsStr, addrs: &AddressMap) -> Option<Nic> {
    let name = name.to_str()?;
    let iface = net_dir.join(name);

    // Physical NICs have a `device` link to their PCI/USB device; loopback,
    // bridges, veth, bonds and tun/tap do not.
    if !iface.join("device").exists() {
        return None;
    }

    Some(Nic {
        name: name.to_string(),
        mac_address: read_trimmed(&iface.join("address")).unwrap_or_default(),
        driver: driver(&iface),
        speed: speed(read_trimmed(&iface.join("speed")).as_deref()),
        ip_addresses: addrs
            .get(name)
            .map(|ips| ips.iter().map(IpAddr::to_string).collect())
            .unwrap_or_default(),
    })
}

/// Driver name from the `device/driver` symlink's target basename (e.g.
/// `ixgbe`); "" when the link is absent (some virtual or unbound interfaces).
fn driver(iface: &Path) -> String {
    fs::read_link(iface.join("device/driver"))
        .ok()
        .and_then(|target| target.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

/// Render link speed (the sysfs `speed` attribute, in Mbit/s) as e.g. `"10Gbps"`
/// or `"100Mbps"`. A down/unknown link (the attribute reads `-1`), `0`, or an
/// unreadable/garbage value yields "" — the `v > 0` guard covers all three, and
/// the field is `omitempty` on the controller side.
fn speed(raw: Option<&str>) -> String {
    let mbps = match raw.and_then(|s| s.parse::<i64>().ok()) {
        Some(v) if v > 0 => v,
        _ => return String::new(),
    };
    if mbps % MBPS_PER_GBPS == 0 {
        format!("{}Gbps", mbps / MBPS_PER_GBPS)
    } else if mbps > MBPS_PER_GBPS {
        // Fractional multi-gig links (e.g. 2.5GbE reports 2500).
        format!("{}Gbps", mbps as f64 / MBPS_PER_GBPS as f64)
    } else {
        format!("{mbps}Mbps")
    }
}

/// The live per-interface IP addresses via `getifaddrs(3)`. AF_INET / AF_INET6
/// entries are kept; the AF_PACKET (link-layer) entry `getifaddrs` returns per
/// interface is skipped — the MAC is read from sysfs, not inferred here. Each
/// interface's addresses are sorted (IPv4 before IPv6, then numerically) so the
/// report is deterministic across retries. A failed call yields an empty map
/// rather than aborting inspection.
fn interface_addresses() -> AddressMap {
    let mut map: AddressMap = HashMap::new();
    let Ok(ifaddrs) = nix::ifaddrs::getifaddrs() else {
        return map;
    };
    for ifaddr in ifaddrs {
        if let Some(ip) = ifaddr.address.as_ref().and_then(sockaddr_to_ip) {
            map.entry(ifaddr.interface_name).or_default().push(ip);
        }
    }
    for ips in map.values_mut() {
        ips.sort();
        ips.dedup();
    }
    map
}

/// Convert a `getifaddrs` socket address to an [`IpAddr`], or `None` for
/// non-IP families (notably AF_PACKET, the link-layer address).
fn sockaddr_to_ip(storage: &nix::sys::socket::SockaddrStorage) -> Option<IpAddr> {
    if let Some(v4) = storage.as_sockaddr_in() {
        return Some(IpAddr::V4(v4.ip()));
    }
    storage.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::symlink;

    /// A physical NIC fixture: `device/driver` symlink (its basename is the
    /// driver), `address` (MAC), and `speed`.
    fn write_nic(root: &Path, name: &str, mac: &str, drv: &str, speed_mbps: &str) {
        write(root, &format!("{name}/address"), &format!("{mac}\n"));
        write(root, &format!("{name}/speed"), &format!("{speed_mbps}\n"));
        let driver_link = root.join(format!("{name}/device/driver"));
        fs::create_dir_all(driver_link.parent().unwrap()).unwrap();
        // The target need not exist for read_link to return its basename.
        symlink(format!("/sys/bus/pci/drivers/{drv}"), driver_link).unwrap();
    }

    fn addr_map(pairs: &[(&str, &[&str])]) -> AddressMap {
        pairs
            .iter()
            .map(|(name, ips)| {
                let parsed = ips.iter().map(|s| s.parse::<IpAddr>().unwrap()).collect();
                (name.to_string(), parsed)
            })
            .collect()
    }

    #[test]
    fn reproduces_the_golden_nics() {
        let s = Scratch::new("nic-golden");
        write_nic(s.path(), "eno1", "aa:bb:cc:dd:ee:01", "ixgbe", "10000");
        write_nic(s.path(), "eno2", "aa:bb:cc:dd:ee:02", "ixgbe", "10000");
        let addrs = addr_map(&[
            ("eno1", &["192.0.2.10", "fe80::a8bb:ccff:fedd:ee01"]),
            ("eno2", &["192.0.2.11"]),
        ]);
        let nics = collect_from(s.path(), &addrs);
        assert_eq!(
            nics,
            vec![
                Nic {
                    name: "eno1".into(),
                    mac_address: "aa:bb:cc:dd:ee:01".into(),
                    driver: "ixgbe".into(),
                    speed: "10Gbps".into(),
                    ip_addresses: vec!["192.0.2.10".into(), "fe80::a8bb:ccff:fedd:ee01".into(),],
                },
                Nic {
                    name: "eno2".into(),
                    mac_address: "aa:bb:cc:dd:ee:02".into(),
                    driver: "ixgbe".into(),
                    speed: "10Gbps".into(),
                    ip_addresses: vec!["192.0.2.11".into()],
                },
            ]
        );
    }

    #[test]
    fn virtual_interfaces_are_filtered() {
        let s = Scratch::new("nic-filter");
        write_nic(s.path(), "eno1", "aa:bb:cc:dd:ee:01", "ixgbe", "1000");
        // loopback: an `address` but no `device` link.
        write(s.path(), "lo/address", "00:00:00:00:00:00\n");
        // bridge: `address` but no `device` link.
        write(s.path(), "docker0/address", "02:42:ac:11:00:01\n");
        // veth pair end: no `device` link.
        write(s.path(), "veth123/address", "9a:bb:cc:dd:ee:ff\n");

        let nics = collect_from(s.path(), &AddressMap::new());
        assert_eq!(nics.len(), 1);
        assert_eq!(nics[0].name, "eno1");
        assert!(nics[0].ip_addresses.is_empty()); // not in the address map
    }

    #[test]
    fn missing_driver_or_speed_yields_empty_strings() {
        let s = Scratch::new("nic-sparse");
        // `device/` dir exists (so it passes the physical filter) but no
        // `driver` symlink and no `speed` attribute.
        write(s.path(), "eth0/address", "aa:bb:cc:dd:ee:10\n");
        fs::create_dir_all(s.path().join("eth0/device")).unwrap();

        let nics = collect_from(s.path(), &AddressMap::new());
        assert_eq!(nics.len(), 1);
        assert_eq!(nics[0].driver, "");
        assert_eq!(nics[0].speed, "");
        assert_eq!(nics[0].mac_address, "aa:bb:cc:dd:ee:10");
    }

    #[test]
    fn speed_rendering() {
        assert_eq!(speed(Some("10000")), "10Gbps");
        assert_eq!(speed(Some("1000")), "1Gbps");
        assert_eq!(speed(Some("25000")), "25Gbps");
        assert_eq!(speed(Some("2500")), "2.5Gbps"); // 2.5GbE
        assert_eq!(speed(Some("100")), "100Mbps");
        assert_eq!(speed(Some("10")), "10Mbps");
        assert_eq!(speed(Some("-1")), ""); // link down / unknown
        assert_eq!(speed(Some("0")), "");
        assert_eq!(speed(Some("garbage")), "");
        assert_eq!(speed(None), "");
    }

    #[test]
    fn sockaddr_conversion_keeps_ip_families() {
        use nix::sys::socket::SockaddrStorage;
        use std::net::{SocketAddrV4, SocketAddrV6};

        let v4 = SockaddrStorage::from(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 0));
        assert_eq!(
            sockaddr_to_ip(&v4),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );

        let v6_addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xa8bb, 0xccff, 0xfedd, 0xee01);
        let v6 = SockaddrStorage::from(SocketAddrV6::new(v6_addr, 0, 0, 0));
        assert_eq!(sockaddr_to_ip(&v6), Some(IpAddr::V6(v6_addr)));
    }

    #[test]
    fn missing_net_dir_yields_no_nics() {
        let nics = collect_from(Path::new("/nonexistent/sys/class/net"), &AddressMap::new());
        assert!(nics.is_empty());
    }
}
