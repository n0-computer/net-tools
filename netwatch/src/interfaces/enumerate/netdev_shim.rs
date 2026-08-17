//! Temporary enumeration backend that converts from the `netdev` crate.
//!
//! Platforms move to inlined backends one by one; this shim disappears
//! when the last one (windows) lands. Nothing it produces exposes a
//! `netdev` type, which is enforced by `cargo check-external-types`.

#[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
use std::net::IpAddr;

use super::super::{Interface, IpNet, Ipv6AddrFlags};

/// Converts netdev's IPv6 address flags into our mirrored [`Ipv6AddrFlags`].
///
/// This is a free function rather than a `From` impl on purpose: a public
/// `From<netdev::...>` would re-expose the `netdev` type in our public API,
/// which is exactly what the [`Ipv6AddrFlags`] mirror exists to avoid.
fn to_ipv6_addr_flags(flags: netdev::interface::ipv6_addr_flags::Ipv6AddrFlags) -> Ipv6AddrFlags {
    Ipv6AddrFlags {
        deprecated: flags.deprecated,
        temporary: flags.temporary,
        tentative: flags.tentative,
        duplicated: flags.duplicated,
        permanent: flags.permanent,
    }
}

/// Converts a [`netdev::Interface`] into our platform-agnostic [`Interface`].
///
/// Addresses are sorted (IPv4 first, then IPv6, each by address) so that
/// comparisons between successive snapshots are stable.
fn to_interface(iface: netdev::Interface) -> Interface {
    // netdev keeps these three IPv6 arrays parallel, one entry per address.
    // The zip below relies on that; assert it so a netdev change that breaks
    // the invariant surfaces in tests rather than silently dropping addresses.
    debug_assert_eq!(iface.ipv6.len(), iface.ipv6_scope_ids.len());
    debug_assert_eq!(iface.ipv6.len(), iface.ipv6_addr_flags.len());

    let mut v4: Vec<IpNet> = iface.ipv4.iter().copied().map(IpNet::V4).collect();
    let mut v6: Vec<IpNet> = iface
        .ipv6
        .iter()
        .copied()
        .zip(iface.ipv6_scope_ids.iter().copied())
        .zip(iface.ipv6_addr_flags.iter().copied())
        .map(|((net, scope_id), flags)| IpNet::V6 {
            net,
            scope_id,
            flags: to_ipv6_addr_flags(flags),
        })
        .collect();

    // Sort each family by address so successive snapshots compare equal, then
    // concatenate as IPv4-first.
    v4.sort_by_key(IpNet::addr);
    v6.sort_by_key(IpNet::addr);
    let mut addrs = v4;
    addrs.append(&mut v6);

    Interface {
        name: iface.name,
        index: iface.index,
        flags: iface.flags,
        mac_addr: iface.mac_addr.as_ref().map(|a| a.octets()),
        addrs,
    }
}

/// Enumerates the machine's network interfaces.
pub(super) fn interfaces() -> Vec<Interface> {
    netdev::interface::get_interfaces()
        .into_iter()
        .map(to_interface)
        .collect()
}

/// The gateway address of the default route, as reported by `netdev`.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
pub(super) fn default_gateway() -> Option<IpAddr> {
    let gateway = netdev::get_default_gateway().ok()?;
    gateway
        .ipv4
        .iter()
        .copied()
        .map(IpAddr::V4)
        .chain(gateway.ipv6.iter().copied().map(IpAddr::V6))
        .next()
}
