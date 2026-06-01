//! Hand-rolled one-shot DHCP (D-013): DISCOVER → OFFER → REQUEST → ACK to lease
//! an IPv4 address. No renewal — the inspector configures the link once and then
//! reboots. The packet build/parse is pure and unit-tested; only [`acquire`]
//! touches a socket.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::libc;

use super::{mask_to_prefix_len, NetError};

/// BOOTP `op`: a client request.
const OP_REQUEST: u8 = 1;
/// BOOTP `op`: a server reply (OFFER/ACK arrive with this).
const OP_REPLY: u8 = 2;
const HTYPE_ETHER: u8 = 1;
const HLEN_ETHER: u8 = 6;
/// Ask the server to broadcast its reply — we have no address yet to receive a
/// unicast on, so this is required for the plain-`AF_INET` socket path.
const FLAG_BROADCAST: u16 = 0x8000;
/// The DHCP magic cookie that precedes the options (`99.130.83.99`).
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// Offset of the magic cookie / start of the BOOTP fixed area's end.
const COOKIE_OFFSET: usize = 236;
/// Offset of `chaddr` (the client hardware address) in the BOOTP header.
const CHADDR_OFFSET: usize = 28;
/// Offset of `yiaddr` (the address the server assigns) in the BOOTP header.
const YIADDR_OFFSET: usize = 16;
/// Offset of `xid` (the transaction id) in the BOOTP header.
const XID_OFFSET: usize = 4;

// DHCP option codes.
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_LEASE_TIME: u8 = 51;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_LIST: u8 = 55;
const OPT_PAD: u8 = 0;
const OPT_END: u8 = 255;

// DHCP message types (option 53 values).
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;
/// Per-receive timeout; the exchange retries this many rounds.
const RECV_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ROUNDS: u32 = 4;

/// A successful DHCP lease, reduced to what the inspector applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

/// Acquire a lease on `iface` for `mac` (D-013). Runs the four-way exchange over
/// a broadcast `AF_INET` UDP socket bound to the interface, retrying up to
/// [`MAX_ROUNDS`] times.
pub fn acquire(iface: &str, mac: [u8; 6]) -> Result<Lease, NetError> {
    let sock = Socket::open_dhcp(iface)?;
    let xid = random_xid();

    for _ in 0..MAX_ROUNDS {
        sock.send_broadcast(&build_packet(DHCP_DISCOVER, xid, mac, None, None))?;
        let Some(offer) = sock.recv_reply(xid, DHCP_OFFER)? else {
            continue; // timed out waiting for an OFFER; retry the round
        };

        let request = build_packet(DHCP_REQUEST, xid, mac, Some(offer.yiaddr), offer.server_id);
        sock.send_broadcast(&request)?;
        let Some(ack) = sock.recv_reply(xid, DHCP_ACK)? else {
            continue; // OFFER but no ACK; retry the round
        };

        return Ok(Lease {
            ip: ack.yiaddr,
            prefix_len: ack.mask.map(mask_to_prefix_len).unwrap_or(24),
            gateway: ack.router,
            dns: ack.dns,
        });
    }
    Err(NetError::DhcpTimeout)
}

/// Build a DHCP client packet (DISCOVER or REQUEST). Pure; unit-tested.
fn build_packet(
    msg_type: u8,
    xid: u32,
    mac: [u8; 6],
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut p = vec![0u8; COOKIE_OFFSET + 4];
    p[0] = OP_REQUEST;
    p[1] = HTYPE_ETHER;
    p[2] = HLEN_ETHER;
    p[XID_OFFSET..XID_OFFSET + 4].copy_from_slice(&xid.to_be_bytes());
    p[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes());
    p[CHADDR_OFFSET..CHADDR_OFFSET + 6].copy_from_slice(&mac);
    p[COOKIE_OFFSET..COOKIE_OFFSET + 4].copy_from_slice(&MAGIC);

    p.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
    if let Some(ip) = requested_ip {
        p.push(OPT_REQUESTED_IP);
        p.push(4);
        p.extend_from_slice(&ip.octets());
    }
    if let Some(sid) = server_id {
        p.push(OPT_SERVER_ID);
        p.push(4);
        p.extend_from_slice(&sid.octets());
    }
    p.extend_from_slice(&[
        OPT_PARAM_LIST,
        4,
        OPT_SUBNET_MASK,
        OPT_ROUTER,
        OPT_DNS,
        OPT_LEASE_TIME,
    ]);
    p.push(OPT_END);
    p
}

/// The fields we extract from a server reply.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    msg_type: u8,
    yiaddr: Ipv4Addr,
    server_id: Option<Ipv4Addr>,
    mask: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
}

/// Parse a server reply, returning it only if it is a BOOTP reply, matches `xid`,
/// and carries the magic cookie and a message-type option. Pure; unit-tested
/// against crafted OFFER/ACK buffers.
fn parse_reply(buf: &[u8], xid: u32) -> Option<Reply> {
    if buf.len() < COOKIE_OFFSET + 4
        || buf[0] != OP_REPLY
        || u32::from_be_bytes(buf[XID_OFFSET..XID_OFFSET + 4].try_into().ok()?) != xid
        || buf[COOKIE_OFFSET..COOKIE_OFFSET + 4] != MAGIC
    {
        return None;
    }
    let yiaddr = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[YIADDR_OFFSET..YIADDR_OFFSET + 4]).ok()?);

    let mut r = Reply {
        msg_type: 0,
        yiaddr,
        server_id: None,
        mask: None,
        router: None,
        dns: Vec::new(),
    };
    let mut i = COOKIE_OFFSET + 4;
    while i < buf.len() {
        let code = buf[i];
        i += 1;
        match code {
            OPT_PAD => continue,
            OPT_END => break,
            _ => {}
        }
        if i >= buf.len() {
            break;
        }
        let len = buf[i] as usize;
        i += 1;
        if i + len > buf.len() {
            break;
        }
        let val = &buf[i..i + len];
        match code {
            OPT_MSG_TYPE if len >= 1 => r.msg_type = val[0],
            OPT_SERVER_ID if len >= 4 => r.server_id = Some(ip4(val)),
            OPT_SUBNET_MASK if len >= 4 => r.mask = Some(ip4(val)),
            OPT_ROUTER if len >= 4 => r.router = Some(ip4(val)),
            OPT_DNS => {
                for chunk in val.chunks_exact(4) {
                    r.dns.push(ip4(chunk));
                }
            }
            _ => {}
        }
        i += len;
    }
    (r.msg_type != 0).then_some(r)
}

/// First four bytes of `b` as an IPv4 address.
fn ip4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

/// Four random bytes for the DHCP transaction id, read from `/dev/urandom`
/// (present once the init mounts devtmpfs). Reads **exactly** four bytes —
/// `/dev/urandom` is an infinite stream, so a read-to-end would never terminate.
/// Falls back to a fixed value if unreadable; the xid only needs to be unguessed
/// within one exchange.
fn random_xid() -> u32 {
    use std::io::Read;
    let mut buf = [0u8; 4];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|()| u32::from_ne_bytes(buf))
        .unwrap_or(0xB7B7_0001)
}

/// A close-on-drop wrapper over the DHCP socket fd.
struct Socket(libc::c_int);

impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: self.0 is an open fd we own; closing once on drop is correct.
        unsafe { libc::close(self.0) };
    }
}

impl Socket {
    /// Open a broadcast UDP socket bound to `iface` on the DHCP client port.
    fn open_dhcp(iface: &str) -> Result<Self, NetError> {
        // SAFETY: standard socket(2) with constant args; returns -1 on error.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(NetError::Socket(Errno::last()));
        }
        let sock = Socket(fd);
        sock.set_int(libc::SO_REUSEADDR, 1)?;
        sock.set_int(libc::SO_BROADCAST, 1)?;
        sock.bind_to_device(iface)?;
        sock.set_rcv_timeout(RECV_TIMEOUT)?;
        sock.bind_client_port()?;
        Ok(sock)
    }

    fn set_int(&self, opt: libc::c_int, val: libc::c_int) -> Result<(), NetError> {
        // SAFETY: setsockopt with a c_int option value of known size.
        let rc = unsafe {
            libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                opt,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        rc_to_result(rc)
    }

    fn bind_to_device(&self, iface: &str) -> Result<(), NetError> {
        // SAFETY: SO_BINDTODEVICE takes the interface name bytes (no NUL needed).
        let rc = unsafe {
            libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface.as_ptr() as *const libc::c_void,
                iface.len() as libc::socklen_t,
            )
        };
        rc_to_result(rc)
    }

    fn set_rcv_timeout(&self, d: Duration) -> Result<(), NetError> {
        let tv = libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: 0,
        };
        // SAFETY: SO_RCVTIMEO takes a timeval of known size.
        let rc = unsafe {
            libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        rc_to_result(rc)
    }

    fn bind_client_port(&self) -> Result<(), NetError> {
        let addr = sockaddr_in(Ipv4Addr::UNSPECIFIED, CLIENT_PORT);
        // SAFETY: binding a correctly-sized sockaddr_in to the socket.
        let rc = unsafe {
            libc::bind(
                self.0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        rc_to_result(rc)
    }

    /// Send `pkt` to the limited broadcast address on the DHCP server port.
    fn send_broadcast(&self, pkt: &[u8]) -> Result<(), NetError> {
        let dest = sockaddr_in(Ipv4Addr::BROADCAST, SERVER_PORT);
        // SAFETY: sendto with a valid buffer and a correctly-sized destination.
        let rc = unsafe {
            libc::sendto(
                self.0,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            Err(NetError::Socket(Errno::last()))
        } else {
            Ok(())
        }
    }

    /// Receive replies until one parses as `want_type` for `xid`, the receive
    /// times out (returns `Ok(None)`), or a hard socket error occurs. Bounded by
    /// the socket receive timeout so it cannot block forever.
    fn recv_reply(&self, xid: u32, want_type: u8) -> Result<Option<Reply>, NetError> {
        let deadline = Instant::now() + RECV_TIMEOUT;
        // Larger than a 1500-byte MTU so a reply with a long option set (option
        // overload, a long DNS list) is not silently truncated by the datagram
        // recv — a truncated reply would lose the cookie/message-type and look
        // like a spurious timeout. The parser is bounded regardless of length.
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: recv into a valid buffer; returns -1 on error/timeout.
            let n =
                unsafe { libc::recv(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                return match Errno::last() {
                    // Receive timeout (SO_RCVTIMEO; EAGAIN == EWOULDBLOCK on Linux)
                    // or an interrupted call — no (more) replies this round.
                    Errno::EAGAIN | Errno::EINTR => Ok(None),
                    e => Err(NetError::Socket(e)),
                };
            }
            if let Some(reply) = parse_reply(&buf[..n as usize], xid) {
                if reply.msg_type == want_type {
                    return Ok(Some(reply));
                }
            }
            // A reply that wasn't ours / wrong type: keep reading until the
            // overall deadline, then treat as a timeout for this round.
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }
}

/// A `sockaddr_in` for `(ip, port)` in network byte order.
fn sockaddr_in(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from(ip).to_be(),
    };
    addr
}

fn rc_to_result(rc: libc::c_int) -> Result<(), NetError> {
    if rc < 0 {
        Err(NetError::Socket(Errno::last()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_discover_has_header_cookie_and_msg_type() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let p = build_packet(DHCP_DISCOVER, 0xDEAD_BEEF, mac, None, None);
        assert_eq!(p[0], OP_REQUEST);
        assert_eq!(p[1], HTYPE_ETHER);
        assert_eq!(
            &p[XID_OFFSET..XID_OFFSET + 4],
            &0xDEAD_BEEFu32.to_be_bytes()
        );
        assert_eq!(&p[CHADDR_OFFSET..CHADDR_OFFSET + 6], &mac);
        assert_eq!(&p[COOKIE_OFFSET..COOKIE_OFFSET + 4], &MAGIC);
        // option 53 = 1 (DISCOVER) immediately after the cookie.
        assert_eq!(
            &p[COOKIE_OFFSET + 4..COOKIE_OFFSET + 7],
            &[OPT_MSG_TYPE, 1, DHCP_DISCOVER]
        );
        assert_eq!(*p.last().unwrap(), OPT_END);
    }

    #[test]
    fn build_request_includes_requested_ip_and_server_id() {
        let mac = [0u8; 6];
        let p = build_packet(
            DHCP_REQUEST,
            1,
            mac,
            Some(Ipv4Addr::new(192, 168, 122, 50)),
            Some(Ipv4Addr::new(192, 168, 122, 1)),
        );
        // The requested-IP (50) and server-id (54) options must be present.
        assert!(p
            .windows(6)
            .any(|w| w == [OPT_REQUESTED_IP, 4, 192, 168, 122, 50]));
        assert!(p
            .windows(6)
            .any(|w| w == [OPT_SERVER_ID, 4, 192, 168, 122, 1]));
    }

    /// Build a minimal server reply (OFFER/ACK) for round-trip parse tests.
    fn make_reply(msg_type: u8, xid: u32, yiaddr: Ipv4Addr, opts: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut p = vec![0u8; COOKIE_OFFSET + 4];
        p[0] = OP_REPLY;
        p[XID_OFFSET..XID_OFFSET + 4].copy_from_slice(&xid.to_be_bytes());
        p[YIADDR_OFFSET..YIADDR_OFFSET + 4].copy_from_slice(&yiaddr.octets());
        p[COOKIE_OFFSET..COOKIE_OFFSET + 4].copy_from_slice(&MAGIC);
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
        for (code, val) in opts {
            p.push(*code);
            p.push(val.len() as u8);
            p.extend_from_slice(val);
        }
        p.push(OPT_END);
        p
    }

    #[test]
    fn parse_offer_extracts_address_and_options() {
        let xid = 0x1234_5678;
        let yi = Ipv4Addr::new(192, 168, 122, 77);
        let buf = make_reply(
            DHCP_OFFER,
            xid,
            yi,
            &[
                (OPT_SERVER_ID, vec![192, 168, 122, 1]),
                (OPT_SUBNET_MASK, vec![255, 255, 255, 0]),
                (OPT_ROUTER, vec![192, 168, 122, 1]),
                (OPT_DNS, vec![8, 8, 8, 8, 1, 1, 1, 1]),
            ],
        );
        let r = parse_reply(&buf, xid).expect("parses");
        assert_eq!(r.msg_type, DHCP_OFFER);
        assert_eq!(r.yiaddr, yi);
        assert_eq!(r.server_id, Some(Ipv4Addr::new(192, 168, 122, 1)));
        assert_eq!(r.mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(r.router, Some(Ipv4Addr::new(192, 168, 122, 1)));
        assert_eq!(
            r.dns,
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)]
        );
    }

    #[test]
    fn parse_reply_rejects_wrong_xid_and_bad_cookie() {
        let buf = make_reply(DHCP_ACK, 1, Ipv4Addr::new(10, 0, 0, 2), &[]);
        assert!(parse_reply(&buf, 999).is_none(), "xid mismatch");
        let mut bad = buf.clone();
        bad[COOKIE_OFFSET] ^= 0xFF;
        assert!(parse_reply(&bad, 1).is_none(), "bad cookie");
        let short = vec![0u8; 100];
        assert!(parse_reply(&short, 1).is_none(), "truncated");
    }
}
