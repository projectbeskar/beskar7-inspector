//! Configure the provisioning link via RTNETLINK (D-013): bring the interface
//! up, assign the leased IPv4 address, add the default route. Hand-rolled over a
//! raw `AF_NETLINK`/`NETLINK_ROUTE` socket — the `rtnetlink` crate pulls tokio
//! (banned in this sync PID 1), and `ioctl` route install (`SIOCADDRT`) is
//! deprecated. The message *builders* are pure and unit-tested; only the socket
//! send/ack is live.

use std::net::Ipv4Addr;

use nix::errno::Errno;
use nix::libc;

// Netlink message types (kernel ABI).
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
// nlmsg flags.
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_REPLACE: u16 = 0x100;
const NLMSG_ERROR: u16 = 0x2;
// Header / body sizes referenced by the builders and tests.
const NLMSGHDR_LEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const RTATTR_HDR_LEN: usize = 4;
// link flags.
const IFF_UP: u32 = 0x1;
// address-family / attr / route constants.
const AF_UNSPEC: u8 = 0;
const AF_INET_U8: u8 = 2;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
/// A fixed sequence number — the inspector sends one netlink request at a time
/// and reads its ack synchronously, so a constant seq is fine.
const SEQ: u32 = 1;

/// Bring interface `ifindex` administratively up (`RTM_NEWLINK`, `IFF_UP`).
pub fn link_up(ifindex: u32) -> Result<(), Errno> {
    send_and_ack(&build_link_set_flags(ifindex, IFF_UP))
}

/// Bring interface `ifindex` administratively down (`RTM_NEWLINK`, clear `IFF_UP`).
/// Used to tear the losing links back down after the multi-NIC DHCP race (D-013),
/// so exactly one interface is left up and addressed.
pub fn link_down(ifindex: u32) -> Result<(), Errno> {
    send_and_ack(&build_link_set_flags(ifindex, 0))
}

/// Assign `ip/prefix_len` to interface `ifindex` (`RTM_NEWADDR`).
pub fn add_address(ifindex: u32, ip: Ipv4Addr, prefix_len: u8) -> Result<(), Errno> {
    send_and_ack(&build_add_address(ifindex, ip, prefix_len))
}

/// Add a default route via `gw` out of interface `ifindex` (`RTM_NEWROUTE`).
pub fn add_default_route(ifindex: u32, gw: Ipv4Addr) -> Result<(), Errno> {
    send_and_ack(&build_add_route(ifindex, gw))
}

/// Align `n` up to the netlink 4-byte boundary.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Append a netlink message header (length patched in by the caller once the
/// body is built).
fn push_nlmsghdr(buf: &mut Vec<u8>, msg_type: u16, flags: u16) {
    buf.extend_from_slice(&0u32.to_ne_bytes()); // len, patched later
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&SEQ.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // pid 0 = kernel assigns
}

/// Append an `rtattr` (type + payload, padded to 4 bytes).
fn push_rtattr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = RTATTR_HDR_LEN + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf.resize(align4(buf.len()), 0);
}

/// Patch the leading `nlmsghdr.nlmsg_len` to the buffer's final length.
fn finalize(buf: &mut [u8]) {
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
}

/// Build an `RTM_NEWLINK` that sets `ifi_flags` to `flags` within the `IFF_UP`
/// change mask: `IFF_UP` brings the link up, `0` brings it down. The mask is
/// always just `IFF_UP`, so no other link flag is touched.
fn build_link_set_flags(ifindex: u32, flags: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(NLMSGHDR_LEN + IFINFOMSG_LEN);
    push_nlmsghdr(&mut b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    // ifinfomsg: family, pad, type(u16), index(i32), flags(u32), change(u32)
    b.push(AF_UNSPEC);
    b.push(0); // pad
    b.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    b.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    b.extend_from_slice(&flags.to_ne_bytes()); // ifi_flags
    b.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_change mask: only IFF_UP
    finalize(&mut b);
    b
}

fn build_add_address(ifindex: u32, ip: Ipv4Addr, prefix_len: u8) -> Vec<u8> {
    let mut b = Vec::new();
    push_nlmsghdr(
        &mut b,
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
    );
    // ifaddrmsg: family, prefixlen, flags, scope, index(u32)
    b.push(AF_INET_U8);
    b.push(prefix_len);
    b.push(0); // flags
    b.push(RT_SCOPE_UNIVERSE);
    b.extend_from_slice(&ifindex.to_ne_bytes());
    push_rtattr(&mut b, IFA_LOCAL, &ip.octets());
    push_rtattr(&mut b, IFA_ADDRESS, &ip.octets());
    finalize(&mut b);
    b
}

fn build_add_route(ifindex: u32, gw: Ipv4Addr) -> Vec<u8> {
    let mut b = Vec::new();
    push_nlmsghdr(
        &mut b,
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    );
    // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags(u32)
    b.push(AF_INET_U8);
    b.push(0); // dst_len 0 = default route
    b.push(0); // src_len
    b.push(0); // tos
    b.push(RT_TABLE_MAIN);
    b.push(RTPROT_STATIC);
    b.push(RT_SCOPE_UNIVERSE);
    b.push(RTN_UNICAST);
    b.extend_from_slice(&0u32.to_ne_bytes()); // flags
    push_rtattr(&mut b, RTA_GATEWAY, &gw.octets());
    push_rtattr(&mut b, RTA_OIF, &ifindex.to_ne_bytes());
    finalize(&mut b);
    b
}

/// Open a `NETLINK_ROUTE` socket, send `msg`, and read the ack. A zero
/// `nlmsgerr.error` is success; a negative value is `-errno`.
fn send_and_ack(msg: &[u8]) -> Result<(), Errno> {
    let sock = NlSocket::open()?;
    sock.send(msg)?;
    sock.recv_ack()
}

/// Close-on-drop wrapper over the netlink socket fd.
struct NlSocket(libc::c_int);

impl Drop for NlSocket {
    fn drop(&mut self) {
        // SAFETY: self.0 is an open fd we own.
        unsafe { libc::close(self.0) };
    }
}

impl NlSocket {
    fn open() -> Result<Self, Errno> {
        // SAFETY: socket(2) with constant args; -1 on error.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(Errno::last());
        }
        let sock = NlSocket(fd);
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: binding a correctly-sized sockaddr_nl (nl_pid 0 = kernel assigns).
        let rc = unsafe {
            libc::bind(
                sock.0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Errno::last());
        }
        // A receive timeout so a missing ack (e.g. a message the kernel silently
        // drops) cannot wedge PID 1 forever — the kernel normally acks at once.
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: SO_RCVTIMEO with a timeval of known size.
        let rc = unsafe {
            libc::setsockopt(
                sock.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Errno::last());
        }
        Ok(sock)
    }

    fn send(&self, msg: &[u8]) -> Result<(), Errno> {
        // SAFETY: send the fully-built netlink message; -1 on error.
        let n = unsafe { libc::send(self.0, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if n < 0 {
            Err(Errno::last())
        } else {
            Ok(())
        }
    }

    /// Read the kernel's `NLMSG_ERROR` ack and translate it: `error == 0` is
    /// success; `error < 0` is `-errno`.
    fn recv_ack(&self) -> Result<(), Errno> {
        let mut buf = [0u8; 4096];
        // SAFETY: recv into a valid buffer; -1 on error.
        let n = unsafe { libc::recv(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(Errno::last());
        }
        parse_ack(&buf[..n as usize])
    }
}

/// Interpret a netlink ack buffer: a leading `NLMSG_ERROR` whose `error` field
/// (the i32 right after the 16-byte header) is 0 means success; otherwise it is
/// `-errno`. Pure; unit-tested.
fn parse_ack(buf: &[u8]) -> Result<(), Errno> {
    if buf.len() < NLMSGHDR_LEN + 4 {
        return Err(Errno::EBADMSG);
    }
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    if msg_type != NLMSG_ERROR {
        // Not an error message at all — nothing to complain about.
        return Ok(());
    }
    let err = i32::from_ne_bytes(buf[NLMSGHDR_LEN..NLMSGHDR_LEN + 4].try_into().unwrap());
    if err == 0 {
        Ok(())
    } else {
        Err(Errno::from_raw(-err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nlmsg_len(buf: &[u8]) -> u32 {
        u32::from_ne_bytes(buf[0..4].try_into().unwrap())
    }
    fn nlmsg_type(buf: &[u8]) -> u16 {
        u16::from_ne_bytes([buf[4], buf[5]])
    }

    #[test]
    fn link_up_message_is_well_formed() {
        let b = build_link_set_flags(3, IFF_UP);
        assert_eq!(nlmsg_len(&b) as usize, b.len());
        assert_eq!(nlmsg_len(&b) as usize, NLMSGHDR_LEN + IFINFOMSG_LEN);
        assert_eq!(nlmsg_type(&b), RTM_NEWLINK);
        // ifi_index (i32) at offset NLMSGHDR_LEN + 4.
        let idx = i32::from_ne_bytes(b[NLMSGHDR_LEN + 4..NLMSGHDR_LEN + 8].try_into().unwrap());
        assert_eq!(idx, 3);
        // ifi_flags carries IFF_UP; the change mask is exactly IFF_UP.
        let flags = u32::from_ne_bytes(b[NLMSGHDR_LEN + 8..NLMSGHDR_LEN + 12].try_into().unwrap());
        assert_eq!(flags & IFF_UP, IFF_UP);
        let change =
            u32::from_ne_bytes(b[NLMSGHDR_LEN + 12..NLMSGHDR_LEN + 16].try_into().unwrap());
        assert_eq!(change, IFF_UP);
    }

    #[test]
    fn link_down_clears_iff_up_within_the_same_mask() {
        let b = build_link_set_flags(7, 0);
        assert_eq!(nlmsg_type(&b), RTM_NEWLINK);
        let idx = i32::from_ne_bytes(b[NLMSGHDR_LEN + 4..NLMSGHDR_LEN + 8].try_into().unwrap());
        assert_eq!(idx, 7);
        // ifi_flags has IFF_UP cleared, but the change mask still scopes the write
        // to IFF_UP so no unrelated link flag is disturbed.
        let flags = u32::from_ne_bytes(b[NLMSGHDR_LEN + 8..NLMSGHDR_LEN + 12].try_into().unwrap());
        assert_eq!(flags & IFF_UP, 0);
        let change =
            u32::from_ne_bytes(b[NLMSGHDR_LEN + 12..NLMSGHDR_LEN + 16].try_into().unwrap());
        assert_eq!(change, IFF_UP);
    }

    #[test]
    fn add_address_message_carries_ip_and_prefix() {
        let ip = Ipv4Addr::new(192, 168, 122, 50);
        let b = build_add_address(3, ip, 24);
        assert_eq!(nlmsg_len(&b) as usize, b.len());
        assert_eq!(nlmsg_type(&b), RTM_NEWADDR);
        // ifaddrmsg: family, prefixlen at [hdr], [hdr+1].
        assert_eq!(b[NLMSGHDR_LEN], AF_INET_U8);
        assert_eq!(b[NLMSGHDR_LEN + 1], 24);
        // The IP octets appear as an IFA_LOCAL attribute payload.
        assert!(b.windows(4).any(|w| w == ip.octets()));
        // Length is 4-byte aligned.
        assert_eq!(b.len() % 4, 0);
    }

    #[test]
    fn add_route_message_is_default_via_gateway() {
        let gw = Ipv4Addr::new(192, 168, 122, 1);
        let b = build_add_route(3, gw);
        assert_eq!(nlmsg_len(&b) as usize, b.len());
        assert_eq!(nlmsg_type(&b), RTM_NEWROUTE);
        // rtmsg dst_len == 0 (default route) at offset hdr+1.
        assert_eq!(b[NLMSGHDR_LEN + 1], 0);
        assert_eq!(b[NLMSGHDR_LEN], AF_INET_U8);
        // Gateway octets present (RTA_GATEWAY payload).
        assert!(b.windows(4).any(|w| w == gw.octets()));
        assert_eq!(b.len() % 4, 0);
    }

    #[test]
    fn parse_ack_success_and_failure() {
        // NLMSG_ERROR with error == 0 → success.
        let mut ok = vec![0u8; NLMSGHDR_LEN + 4];
        ok[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        assert!(parse_ack(&ok).is_ok());
        // error == -EPERM → Err(EPERM).
        let mut bad = vec![0u8; NLMSGHDR_LEN + 4];
        bad[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        bad[NLMSGHDR_LEN..NLMSGHDR_LEN + 4]
            .copy_from_slice(&(-(Errno::EPERM as i32)).to_ne_bytes());
        assert_eq!(parse_ack(&bad), Err(Errno::EPERM));
        // Too short → EBADMSG.
        assert_eq!(parse_ack(&[0u8; 4]), Err(Errno::EBADMSG));
    }
}
