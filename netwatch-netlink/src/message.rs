//! Typed rtnetlink messages and requests.
//!
//! Only the message families and attributes netwatch consumes are parsed;
//! everything else is preserved as [`Message::Other`] or skipped.

use std::net::IpAddr;

use crate::wire::{self, AttrIter};

// Attribute types not exposed by the libc crate.
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_TABLE: u16 = 15;

/// Address family selector for route dumps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteFamily {
    /// Dump routes of every family.
    Unspec,
    /// Dump IPv4 routes.
    Ipv4,
    /// Dump IPv6 routes.
    Ipv6,
}

impl RouteFamily {
    fn family(self) -> u8 {
        match self {
            RouteFamily::Unspec => libc::AF_UNSPEC as u8,
            RouteFamily::Ipv4 => libc::AF_INET as u8,
            RouteFamily::Ipv6 => libc::AF_INET6 as u8,
        }
    }
}

/// A parsed `RTM_NEWLINK` or `RTM_DELLINK` message.
#[derive(Debug, Clone)]
pub struct LinkMessage {
    /// Interface index from `ifinfomsg`.
    pub index: u32,
    /// Interface flags (`IFF_*`) from `ifinfomsg`.
    pub flags: u32,
    /// Interface name from `IFLA_IFNAME`.
    pub name: Option<String>,
    /// Hardware address bytes from `IFLA_ADDRESS`.
    pub address: Option<Vec<u8>>,
}

impl LinkMessage {
    /// Parses the message from an `ifinfomsg` payload.
    ///
    /// Wire layout: family `u8`, pad `u8`, type `u16`, index `i32`, flags
    /// `u32`, change mask `u32`, then attributes.
    fn parse(data: &[u8]) -> Option<Self> {
        let index = wire::read_i32(data, 4)? as u32;
        let flags = wire::read_u32(data, 8)?;
        let mut name = None;
        let mut address = None;
        for (kind, payload) in AttrIter::new(data.get(16..)?) {
            match kind {
                IFLA_IFNAME => name = parse_string(payload),
                IFLA_ADDRESS => address = Some(payload.to_vec()),
                _ => {}
            }
        }
        Some(Self {
            index,
            flags,
            name,
            address,
        })
    }
}

/// A parsed `RTM_NEWADDR` or `RTM_DELADDR` message.
#[derive(Debug, Clone)]
pub struct AddressMessage {
    /// Address family (`AF_INET` or `AF_INET6`) from `ifaddrmsg`.
    pub family: u8,
    /// Prefix length of the address.
    pub prefix_len: u8,
    /// Address scope (`RT_SCOPE_*`) from `ifaddrmsg`.
    pub scope: u8,
    /// Interface index the address belongs to.
    pub index: u32,
    /// The address from `IFA_ADDRESS`.
    ///
    /// For IPv4 this is the peer address on point-to-point links and equal
    /// to [`AddressMessage::local`] everywhere else; for IPv6 it is the
    /// interface address.
    pub address: Option<IpAddr>,
    /// The local interface address from `IFA_LOCAL`, when present.
    pub local: Option<IpAddr>,
    /// Address flags (`IFA_F_*`) from the `IFA_FLAGS` attribute.
    ///
    /// `None` when the kernel did not send the attribute; use
    /// [`AddressMessage::flags`] for the value with the header fallback
    /// applied.
    pub flags_attr: Option<u32>,
    /// Address flags from the `ifaddrmsg` header byte.
    ///
    /// Truncated to eight bits; superseded by `flags_attr` when present.
    pub header_flags: u8,
}

impl AddressMessage {
    /// Parses the message from an `ifaddrmsg` payload.
    ///
    /// Wire layout: family `u8`, prefixlen `u8`, flags `u8`, scope `u8`,
    /// index `u32`, then attributes.
    fn parse(data: &[u8]) -> Option<Self> {
        let family = *data.first()?;
        let prefix_len = *data.get(1)?;
        let header_flags = *data.get(2)?;
        let scope = *data.get(3)?;
        let index = wire::read_u32(data, 4)?;
        let mut address = None;
        let mut local = None;
        let mut flags_attr = None;
        for (kind, payload) in AttrIter::new(data.get(8..)?) {
            match kind {
                IFA_ADDRESS => address = parse_ip(family, payload),
                IFA_LOCAL => local = parse_ip(family, payload),
                IFA_FLAGS => flags_attr = wire::read_u32(payload, 0),
                _ => {}
            }
        }
        Some(Self {
            family,
            prefix_len,
            scope,
            index,
            address,
            local,
            flags_attr,
            header_flags,
        })
    }

    /// The address flags (`IFA_F_*`), preferring the 32-bit `IFA_FLAGS`
    /// attribute over the truncated header byte.
    pub fn flags(&self) -> u32 {
        self.flags_attr.unwrap_or(self.header_flags as u32)
    }

    /// The interface address, preferring `IFA_LOCAL` over `IFA_ADDRESS`.
    ///
    /// This matches what `ip addr` shows: for IPv4 the kernel puts the
    /// interface address in `IFA_LOCAL` and the (peer) address in
    /// `IFA_ADDRESS`; for IPv6 only `IFA_ADDRESS` is sent.
    pub fn interface_address(&self) -> Option<IpAddr> {
        self.local.or(self.address)
    }
}

/// A parsed `RTM_NEWROUTE` or `RTM_DELROUTE` message.
#[derive(Debug, Clone)]
pub struct RouteMessage {
    /// Address family (`AF_INET` or `AF_INET6`) from `rtmsg`.
    pub family: u8,
    /// Prefix length of the destination; zero for default routes.
    pub dst_len: u8,
    /// Routing table id from the `RTA_TABLE` attribute.
    ///
    /// `None` when the kernel did not send the attribute. The legacy
    /// eight-bit `rtmsg` table byte is intentionally not exposed: netwatch
    /// has always used only the attribute.
    pub table: Option<u32>,
    /// Route destination from `RTA_DST`; absent for default routes.
    pub destination: Option<IpAddr>,
    /// Gateway address from `RTA_GATEWAY`.
    pub gateway: Option<IpAddr>,
    /// Output interface index from `RTA_OIF`.
    pub oif: Option<u32>,
}

impl RouteMessage {
    /// Parses the message from an `rtmsg` payload.
    ///
    /// Wire layout: family, dst_len, src_len, tos, table, protocol, scope,
    /// type (all `u8`), flags `u32`, then attributes.
    fn parse(data: &[u8]) -> Option<Self> {
        let family = *data.first()?;
        let dst_len = *data.get(1)?;
        let mut table = None;
        let mut destination = None;
        let mut gateway = None;
        let mut oif = None;
        for (kind, payload) in AttrIter::new(data.get(12..)?) {
            match kind {
                RTA_TABLE => table = wire::read_u32(payload, 0),
                RTA_DST => destination = parse_ip(family, payload),
                RTA_GATEWAY => gateway = parse_ip(family, payload),
                RTA_OIF => oif = wire::read_u32(payload, 0),
                _ => {}
            }
        }
        Some(Self {
            family,
            dst_len,
            table,
            destination,
            gateway,
            oif,
        })
    }
}

/// A parsed rtnetlink message.
///
/// Rule messages carry no payload here because netwatch only reacts to
/// their presence.
#[derive(Debug, Clone)]
pub enum Message {
    /// A link was added or changed.
    NewLink(LinkMessage),
    /// A link was removed.
    DelLink(LinkMessage),
    /// An address was added or changed.
    NewAddress(AddressMessage),
    /// An address was removed.
    DelAddress(AddressMessage),
    /// A route was added or changed.
    NewRoute(RouteMessage),
    /// A route was removed.
    DelRoute(RouteMessage),
    /// A routing policy rule was added.
    NewRule,
    /// A routing policy rule was removed.
    DelRule,
    /// Any other rtnetlink message type.
    Other {
        /// The `nlmsghdr` message type.
        kind: u16,
    },
}

impl Message {
    /// Parses a message payload for the given `nlmsghdr` type.
    ///
    /// Returns `None` when the payload is too short for its fixed header.
    pub(crate) fn parse(kind: u16, payload: &[u8]) -> Option<Self> {
        let message = match kind {
            libc::RTM_NEWLINK => Message::NewLink(LinkMessage::parse(payload)?),
            libc::RTM_DELLINK => Message::DelLink(LinkMessage::parse(payload)?),
            libc::RTM_NEWADDR => Message::NewAddress(AddressMessage::parse(payload)?),
            libc::RTM_DELADDR => Message::DelAddress(AddressMessage::parse(payload)?),
            libc::RTM_NEWROUTE => Message::NewRoute(RouteMessage::parse(payload)?),
            libc::RTM_DELROUTE => Message::DelRoute(RouteMessage::parse(payload)?),
            libc::RTM_NEWRULE => Message::NewRule,
            libc::RTM_DELRULE => Message::DelRule,
            kind => Message::Other { kind },
        };
        Some(message)
    }
}

/// One frame of a received datagram, before dump or event bookkeeping.
#[derive(Debug)]
pub(crate) enum Frame {
    /// An rtnetlink message.
    Message { seq: u32, message: Message },
    /// `NLMSG_DONE`, the end of a multipart response.
    Done { seq: u32 },
    /// `NLMSG_ERROR`; `code` is zero for acknowledgments.
    Error { seq: u32, code: i32 },
    /// A frame to ignore (noop, overrun or malformed).
    Skip,
}

/// Splits a received datagram into its netlink frames.
///
/// Iteration stops at the first frame whose length field is inconsistent
/// with the remaining data.
pub(crate) fn parse_frames(datagram: &[u8]) -> impl Iterator<Item = Frame> + '_ {
    let mut data = datagram;
    std::iter::from_fn(move || {
        let header = wire::Header::parse(data)?;
        let len = header.len as usize;
        if len < wire::HEADER_LEN || len > data.len() {
            return None;
        }
        let payload = &data[wire::HEADER_LEN..len];
        data = data.get(wire::align(len)..).unwrap_or_default();
        let frame = match header.kind as i32 {
            libc::NLMSG_DONE => Frame::Done { seq: header.seq },
            libc::NLMSG_ERROR => match wire::read_i32(payload, 0) {
                Some(code) => Frame::Error {
                    seq: header.seq,
                    code,
                },
                None => Frame::Skip,
            },
            libc::NLMSG_NOOP | libc::NLMSG_OVERRUN => Frame::Skip,
            _ => match Message::parse(header.kind, payload) {
                Some(message) => Frame::Message {
                    seq: header.seq,
                    message,
                },
                None => Frame::Skip,
            },
        };
        Some(frame)
    })
}

/// Builds an `RTM_GETLINK` dump request.
pub(crate) fn dump_links_request(seq: u32) -> Vec<u8> {
    dump_request(libc::RTM_GETLINK, seq, &[0u8; 16])
}

/// Builds an `RTM_GETADDR` dump request covering both address families.
pub(crate) fn dump_addresses_request(seq: u32) -> Vec<u8> {
    dump_request(libc::RTM_GETADDR, seq, &[0u8; 8])
}

/// Builds an `RTM_GETROUTE` dump request.
///
/// The filter fields (main table, static protocol, unicast type) match what
/// netwatch has always sent; the kernel ignores them for non-strict dumps
/// and filters by family only.
pub(crate) fn dump_routes_request(seq: u32, family: RouteFamily) -> Vec<u8> {
    let mut rtmsg = [0u8; 12];
    rtmsg[0] = family.family();
    rtmsg[4] = libc::RT_TABLE_MAIN;
    rtmsg[5] = libc::RTPROT_STATIC;
    rtmsg[6] = libc::RT_SCOPE_UNIVERSE;
    rtmsg[7] = libc::RTN_UNICAST;
    dump_request(libc::RTM_GETROUTE, seq, &rtmsg)
}

/// Builds an `RTM_GETLINK` request for a single interface index.
pub(crate) fn get_link_request(seq: u32, index: u32) -> Vec<u8> {
    let mut ifinfomsg = [0u8; 16];
    ifinfomsg[4..8].copy_from_slice(&(index as i32).to_ne_bytes());
    let mut buf = Vec::with_capacity(wire::HEADER_LEN + ifinfomsg.len());
    wire::push_header(
        &mut buf,
        libc::RTM_GETLINK,
        libc::NLM_F_REQUEST as u16,
        seq,
        ifinfomsg.len(),
    );
    buf.extend_from_slice(&ifinfomsg);
    buf
}

fn dump_request(kind: u16, seq: u32, fixed_header: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(wire::HEADER_LEN + fixed_header.len());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    wire::push_header(&mut buf, kind, flags, seq, fixed_header.len());
    buf.extend_from_slice(fixed_header);
    buf
}

/// Parses a NUL-terminated attribute payload into a string.
fn parse_string(payload: &[u8]) -> Option<String> {
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    String::from_utf8(payload[..end].to_vec()).ok()
}

/// Parses an address attribute payload according to the message family.
fn parse_ip(family: u8, payload: &[u8]) -> Option<IpAddr> {
    if family as i32 == libc::AF_INET {
        let bytes: [u8; 4] = payload.get(..4)?.try_into().ok()?;
        Some(IpAddr::from(bytes))
    } else if family as i32 == libc::AF_INET6 {
        let bytes: [u8; 16] = payload.get(..16)?.try_into().ok()?;
        Some(IpAddr::from(bytes))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::wire;

    /// Builds a response frame the way the kernel would.
    fn build_frame(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        wire::push_header(&mut buf, kind, libc::NLM_F_MULTI as u16, seq, payload.len());
        buf.extend_from_slice(payload);
        buf.resize(wire::align(buf.len()), 0);
        buf
    }

    fn push_attr(buf: &mut Vec<u8>, kind: u16, payload: &[u8]) {
        let len = (4 + payload.len()) as u16;
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(payload);
        buf.resize(wire::align(buf.len()), 0);
    }

    #[test]
    fn test_parse_link_message() {
        let mut payload = vec![0u8; 16];
        payload[4..8].copy_from_slice(&2i32.to_ne_bytes());
        payload[8..12].copy_from_slice(&0x1003u32.to_ne_bytes());
        push_attr(&mut payload, IFLA_IFNAME, b"eth0\0");
        push_attr(&mut payload, IFLA_ADDRESS, &[1, 2, 3, 4, 5, 6]);

        let datagram = build_frame(libc::RTM_NEWLINK, 1, &payload);
        let frames: Vec<_> = parse_frames(&datagram).collect();
        assert_eq!(frames.len(), 1);
        let Frame::Message {
            seq: 1,
            message: Message::NewLink(link),
        } = &frames[0]
        else {
            panic!("expected NewLink, got {:?}", frames[0]);
        };
        assert_eq!(link.index, 2);
        assert_eq!(link.flags, 0x1003);
        assert_eq!(link.name.as_deref(), Some("eth0"));
        assert_eq!(link.address.as_deref(), Some(&[1, 2, 3, 4, 5, 6][..]));
    }

    #[test]
    fn test_parse_address_message_v4() {
        let mut payload = vec![0u8; 8];
        payload[0] = libc::AF_INET as u8;
        payload[1] = 24; // prefix len
        payload[2] = 0x80; // header flags: IFA_F_PERMANENT
        payload[4..8].copy_from_slice(&3u32.to_ne_bytes());
        push_attr(&mut payload, IFA_ADDRESS, &[192, 168, 0, 255]);
        push_attr(&mut payload, IFA_LOCAL, &[192, 168, 0, 1]);

        let datagram = build_frame(libc::RTM_NEWADDR, 2, &payload);
        let Some(Frame::Message {
            message: Message::NewAddress(addr),
            ..
        }) = parse_frames(&datagram).next()
        else {
            panic!("expected NewAddress");
        };
        assert_eq!(addr.prefix_len, 24);
        assert_eq!(addr.index, 3);
        assert_eq!(
            addr.address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)))
        );
        assert_eq!(addr.local, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert_eq!(
            addr.interface_address(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
        );
        // No IFA_FLAGS attribute: the header byte is used.
        assert_eq!(addr.flags(), 0x80);
    }

    #[test]
    fn test_parse_address_message_v6_flags_attr() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mut payload = vec![0u8; 8];
        payload[0] = libc::AF_INET6 as u8;
        payload[1] = 64;
        payload[2] = 0x80;
        payload[4..8].copy_from_slice(&5u32.to_ne_bytes());
        push_attr(&mut payload, IFA_ADDRESS, &ip.octets());
        push_attr(&mut payload, IFA_FLAGS, &0x81u32.to_ne_bytes());

        let datagram = build_frame(libc::RTM_NEWADDR, 2, &payload);
        let Some(Frame::Message {
            message: Message::NewAddress(addr),
            ..
        }) = parse_frames(&datagram).next()
        else {
            panic!("expected NewAddress");
        };
        assert_eq!(addr.address, Some(IpAddr::V6(ip)));
        assert_eq!(addr.interface_address(), Some(IpAddr::V6(ip)));
        // IFA_FLAGS wins over the header byte.
        assert_eq!(addr.flags(), 0x81);
    }

    #[test]
    fn test_parse_route_message() {
        let mut payload = vec![0u8; 12];
        payload[0] = libc::AF_INET as u8;
        payload[1] = 0; // default route
        push_attr(&mut payload, RTA_TABLE, &254u32.to_ne_bytes());
        push_attr(&mut payload, RTA_GATEWAY, &[10, 0, 0, 1]);
        push_attr(&mut payload, RTA_OIF, &2u32.to_ne_bytes());

        let datagram = build_frame(libc::RTM_NEWROUTE, 3, &payload);
        let Some(Frame::Message {
            message: Message::NewRoute(route),
            ..
        }) = parse_frames(&datagram).next()
        else {
            panic!("expected NewRoute");
        };
        assert_eq!(route.dst_len, 0);
        assert_eq!(route.table, Some(254));
        assert_eq!(route.gateway, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(route.oif, Some(2));
        assert_eq!(route.destination, None);
    }

    #[test]
    fn test_parse_multipart_with_done() {
        let mut payload = vec![0u8; 12];
        payload[0] = libc::AF_INET as u8;
        let mut datagram = build_frame(libc::RTM_NEWROUTE, 4, &payload);
        datagram.extend_from_slice(&build_frame(
            libc::NLMSG_DONE as u16,
            4,
            &0i32.to_ne_bytes(),
        ));

        let frames: Vec<_> = parse_frames(&datagram).collect();
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[0], Frame::Message { seq: 4, .. }));
        assert!(matches!(frames[1], Frame::Done { seq: 4 }));
    }

    #[test]
    fn test_parse_error_frame() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(-13i32).to_ne_bytes());
        payload.extend_from_slice(&[0u8; 16]); // echoed request header
        let datagram = build_frame(libc::NLMSG_ERROR as u16, 5, &payload);
        let frames: Vec<_> = parse_frames(&datagram).collect();
        assert!(matches!(frames[0], Frame::Error { seq: 5, code: -13 }));
    }

    #[test]
    fn test_parse_rule_messages() {
        let datagram = build_frame(libc::RTM_NEWRULE, 6, &[0u8; 12]);
        let Some(Frame::Message { message, .. }) = parse_frames(&datagram).next() else {
            panic!("expected message");
        };
        assert!(matches!(message, Message::NewRule));
    }

    #[test]
    fn test_requests_have_valid_headers() {
        for (buf, kind, payload_len) in [
            (dump_links_request(1), libc::RTM_GETLINK, 16),
            (dump_addresses_request(2), libc::RTM_GETADDR, 8),
            (
                dump_routes_request(3, RouteFamily::Ipv4),
                libc::RTM_GETROUTE,
                12,
            ),
            (get_link_request(4, 7), libc::RTM_GETLINK, 16),
        ] {
            let header = wire::Header::parse(&buf).unwrap();
            assert_eq!(header.kind, kind);
            assert_eq!(header.len as usize, buf.len());
            assert_eq!(buf.len(), wire::HEADER_LEN + payload_len);
            let flags = wire::read_u16(&buf, 6).unwrap();
            assert_ne!(flags & libc::NLM_F_REQUEST as u16, 0);
        }
    }

    #[test]
    fn test_route_family_bytes() {
        let buf = dump_routes_request(1, RouteFamily::Ipv6);
        assert_eq!(buf[wire::HEADER_LEN], libc::AF_INET6 as u8);
        let buf = dump_routes_request(1, RouteFamily::Unspec);
        assert_eq!(buf[wire::HEADER_LEN], 0);
    }
}
