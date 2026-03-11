//! IP address related utilities — fallback for platforms without `netdev`.

use std::net::Ipv6Addr;

/// List of machine's IP addresses (stub).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalAddresses {
    /// Loopback addresses.
    pub loopback: Vec<std::net::IpAddr>,
    /// Regular addresses.
    pub regular: Vec<std::net::IpAddr>,
}

pub(crate) fn is_private_v6(ip: &Ipv6Addr) -> bool {
    ip.octets()[0] & 0xfe == 0xfc
}

/// Returns true if the address is a unicast address with link-local scope, as defined in RFC 4291.
pub const fn is_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
