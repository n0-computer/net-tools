//! Interface enumeration and state assembly.
//!
//! [`get_state`], [`home_router`] and [`LocalAddresses`] are assembled here
//! from two platform primitives: `interfaces()`, the list of network
//! interfaces in our own [`Interface`] type, and `default_gateway()`, the
//! gateway address of the default route. BSD platforms do not use
//! `default_gateway()`; they parse the routing table in
//! [`crate::interfaces::bsd`] instead.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

#[cfg(any(target_os = "linux", target_os = "android", bsd))]
use ipnet::{Ipv4Net, Ipv6Net};

use super::{Interface, State};
#[cfg(any(target_os = "linux", target_os = "android", bsd))]
use super::{IpNet, Ipv6AddrFlags};
use crate::ip::{LocalAddresses, is_link_local, is_private, is_private_v6};

#[cfg(any(target_os = "linux", target_os = "android", bsd))]
mod ifaddrs;
#[cfg(target_os = "windows")]
mod netdev_shim;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod netlink;
#[cfg(target_os = "linux")]
mod procfs;

/// The interface flag bit indicating a loopback interface.
///
/// Matches the POSIX `IFF_LOOPBACK` value. The windows backend synthesizes
/// BSD-style flags but maps loopback to the winsock value `0x4`, so this
/// bit is never set there; loopback addresses are still classified by
/// [`IpAddr::is_loopback`].
const IFF_LOOPBACK: u32 = 0x8;

/// Enumerates the machine's network interfaces.
///
/// Prefers netlink dumps and falls back to getifaddrs when they fail,
/// which notably happens on Android 11+ where SELinux denies netlink link
/// dumps to apps.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn interfaces() -> Vec<Interface> {
    match netlink::interfaces() {
        Ok(ifaces) => ifaces,
        Err(err) => {
            tracing::debug!("netlink enumeration failed ({err:?}), falling back to getifaddrs");
            ifaddrs::interfaces()
        }
    }
}

/// Enumerates the machine's network interfaces.
#[cfg(bsd)]
pub(super) fn interfaces() -> Vec<Interface> {
    ifaddrs::interfaces()
}

/// Enumerates the machine's network interfaces.
#[cfg(target_os = "windows")]
pub(super) fn interfaces() -> Vec<Interface> {
    netdev_shim::interfaces()
}

/// The gateway address of the default route.
///
/// Follows netdev's algorithm: find the interface owning the local IP the
/// OS routes outbound traffic through, then return that interface's
/// default-route gateway from a netlink route dump, with a procfs fallback
/// on linux when the dump fails.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn default_gateway() -> Option<IpAddr> {
    let local_ip = local_ip()?;
    let ifaces = interfaces();
    let iface = ifaces
        .iter()
        .find(|iface| iface.addrs.iter().any(|net| net.addr() == local_ip))?;
    match netlink::default_gateways_by_interface() {
        Ok(mut gateways) => {
            let (v4, v6) = gateways.remove(&iface.index)?;
            v4.first()
                .copied()
                .map(IpAddr::V4)
                .or_else(|| v6.first().copied().map(IpAddr::V6))
        }
        #[cfg(target_os = "linux")]
        Err(err) => {
            tracing::debug!("netlink route dump failed ({err:?}), trying procfs");
            let (v4, v6) = procfs::gateways_by_interface_name().remove(iface.name())?;
            v4.map(IpAddr::V4)
                .or_else(|| v6.first().copied().map(IpAddr::V6))
        }
        // Android has no readable /proc/net/route; without netlink there
        // is no gateway source.
        #[cfg(target_os = "android")]
        Err(_) => None,
    }
}

/// The gateway address of the default route.
#[cfg(target_os = "windows")]
fn default_gateway() -> Option<IpAddr> {
    netdev_shim::default_gateway()
}

/// Accumulates one [`Interface`] during enumeration.
///
/// The push methods deduplicate addresses on (address, prefix) pairs the
/// way netdev did, and `finish` produces the stable address order the
/// state comparison relies on.
#[cfg(any(target_os = "linux", target_os = "android", bsd))]
#[derive(Debug)]
struct IfaceBuilder {
    name: String,
    index: u32,
    flags: u32,
    mac: Option<[u8; 6]>,
    v4: Vec<Ipv4Net>,
    v6: Vec<(Ipv6Net, u32, Ipv6AddrFlags)>,
}

#[cfg(any(target_os = "linux", target_os = "android", bsd))]
impl IfaceBuilder {
    fn new(name: String, index: u32, flags: u32) -> Self {
        Self {
            name,
            index,
            flags,
            mac: None,
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    fn push_v4(&mut self, net: Ipv4Net) {
        let duplicate = self
            .v4
            .iter()
            .any(|have| have.addr() == net.addr() && have.prefix_len() == net.prefix_len());
        if !duplicate {
            self.v4.push(net);
        }
    }

    fn push_v6(&mut self, net: Ipv6Net, scope_id: u32, flags: Ipv6AddrFlags) {
        let duplicate = self
            .v6
            .iter()
            .any(|(have, _, _)| have.addr() == net.addr() && have.prefix_len() == net.prefix_len());
        if !duplicate {
            self.v6.push((net, scope_id, flags));
        }
    }

    /// Builds the [`Interface`], sorting each address family by address
    /// (IPv4 first) so successive snapshots compare equal.
    fn finish(self) -> Interface {
        let mut v4: Vec<IpNet> = self.v4.into_iter().map(IpNet::V4).collect();
        let mut v6: Vec<IpNet> = self
            .v6
            .into_iter()
            .map(|(net, scope_id, flags)| IpNet::V6 {
                net,
                scope_id,
                flags,
            })
            .collect();
        v4.sort_by_key(IpNet::addr);
        v6.sort_by_key(IpNet::addr);
        let mut addrs = v4;
        addrs.append(&mut v6);

        Interface {
            name: self.name,
            index: self.index,
            flags: self.flags,
            mac_addr: self.mac,
            addrs,
        }
    }
}

/// Returns the scope ID for an IPv6 interface address.
///
/// Prefers the scope reported by the OS and falls back to the interface
/// index for link-local addresses, which is netdev behavior the rest of
/// the code relies on.
#[cfg(any(target_os = "linux", target_os = "android", bsd))]
fn resolve_v6_scope_id(addr: &Ipv6Addr, raw_scope_id: u32, if_index: u32) -> u32 {
    if raw_scope_id != 0 {
        raw_scope_id
    } else if crate::ip::is_unicast_link_local(*addr) {
        if_index
    } else {
        0
    }
}

/// Enumerates the machine's network interfaces and assembles the [`State`].
pub(super) async fn get_state() -> State {
    let ifaces = interfaces();
    let local_addresses = local_addresses(&ifaces);

    let mut interfaces = std::collections::HashMap::new();
    let mut have_v6 = false;
    let mut have_v4 = false;

    for iface in ifaces {
        if iface.is_up() {
            for pfx in iface.addrs() {
                let addr = pfx.addr();
                if addr.is_loopback() {
                    continue;
                }
                have_v6 |= is_usable_v6(&addr);
                have_v4 |= is_usable_v4(&addr);
            }
        }
        interfaces.insert(iface.name().to_string(), iface);
    }

    let default_route_interface = super::default_route_interface().await;

    State {
        interfaces,
        local_addresses,
        have_v4,
        have_v6,
        is_expensive: false,
        default_route_interface,
        last_unsuspend: None,
    }
}

/// The shared home-router lookup for linux, android and windows.
///
/// BSD platforms do not use this; they parse the routing table directly in
/// [`crate::interfaces::bsd`].
#[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
pub(super) fn home_router() -> Option<super::HomeRouter> {
    let gateway = default_gateway()?;
    Some(super::HomeRouter {
        gateway,
        my_ip: local_ip(),
    })
}

/// The local IP address selected for outbound traffic.
///
/// Opens a UDP socket and lets the operating system choose the source
/// address it would use to reach a non-routable destination; no packets
/// are sent.
pub(super) fn local_ip() -> Option<IpAddr> {
    // Binding the IPv4 socket can succeed while a later step fails in
    // IPv6-only environments, so fall back to IPv6 whenever any IPv4 step
    // fails.
    local_ip_family(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 254, 254, 254)), 1),
    )
    .or_else(|| {
        local_ip_family(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                )),
                1,
            ),
        )
    })
}

fn local_ip_family(bind: SocketAddr, probe: SocketAddr) -> Option<IpAddr> {
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(probe).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Reports whether `ip` is a usable IPv4 address which should have Internet connectivity.
///
/// Globally routable and private IPv4 addresses are always usable, and link-local
/// 169.254.x.x addresses are in some environments.
fn is_usable_v4(ip: &IpAddr) -> bool {
    if !ip.is_ipv4() || ip.is_loopback() {
        return false;
    }

    true
}

/// Reports whether `ip` is a usable IPv6 address which should have Internet connectivity.
///
/// Globally routable IPv6 addresses are always usable, and Unique Local Addresses
/// (fc00::/7) are in some environments used with address translation.
///
/// We consider all 2000::/3 addresses to be routable, which is the interpretation of
/// <https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml>
/// as well.  However this probably includes some addresses which should not be routed,
/// e.g. documentation addresses.  See also
/// <https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#method.is_global> for an
/// alternative implementation which is both stricter and laxer in some regards.
fn is_usable_v6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ip) => {
            // V6 Global1 2000::/3
            let mask: u16 = 0b1110_0000_0000_0000;
            let base: u16 = 0x2000;
            let segment1 = ip.segments()[0];
            if (base & mask) == (segment1 & mask) {
                return true;
            }

            is_private_v6(ip)
        }
        IpAddr::V4(_) => false,
    }
}

const fn is_loopback(interface: &Interface) -> bool {
    interface.flags & IFF_LOOPBACK != 0
}

/// Builds the machine's [`LocalAddresses`] from an interface list.
///
/// If there are no regular addresses it falls back to IPv4 link-local or IPv6
/// unique-local addresses, because we know of environments where these are used
/// with NAT to provide connectivity.
fn local_addresses(ifaces: &[Interface]) -> LocalAddresses {
    let mut loopback = Vec::new();
    let mut regular4 = Vec::new();
    let mut regular6 = Vec::new();
    let mut linklocal4 = Vec::new();
    let mut ula6 = Vec::new();

    for iface in ifaces {
        if !iface.is_up() {
            // Skip down interfaces
            continue;
        }
        let ifc_is_loopback = is_loopback(iface);

        for ip in iface.addrs().map(|pfx| pfx.addr()) {
            let ip = ip.to_canonical();

            if ip.is_loopback() || ifc_is_loopback {
                loopback.push(ip);
            } else if is_link_local(ip) {
                if ip.is_ipv4() {
                    linklocal4.push(ip);
                }

                // We know of no cases where the IPv6 fe80:: addresses
                // are used to provide WAN connectivity. It is also very
                // common for users to have no IPv6 WAN connectivity,
                // but their OS supports IPv6 so they have an fe80::
                // address. We don't want to report all of those
                // IPv6 LL to Control.
            } else if ip.is_ipv6() && is_private(&ip) {
                // Google Cloud Run uses NAT with IPv6 Unique
                // Local Addresses to provide IPv6 connectivity.
                ula6.push(ip);
            } else if ip.is_ipv4() {
                regular4.push(ip);
            } else {
                regular6.push(ip);
            }
        }
    }

    if regular4.is_empty() && regular6.is_empty() {
        // if we have no usable IP addresses then be willing to accept
        // addresses we otherwise wouldn't, like:
        //   + 169.254.x.x (AWS Lambda uses NAT with these)
        //   + IPv6 ULA (Google Cloud Run uses these with address translation)
        regular4 = linklocal4;
        regular6 = ula6;
    }
    let mut regular = regular4;
    regular.extend(regular6);

    regular.sort();
    loopback.sort();

    LocalAddresses { loopback, regular }
}

impl LocalAddresses {
    /// Returns the machine's IP addresses.
    ///
    /// If there are no regular addresses it will return any IPv4 link-local or
    /// IPv6 unique-local addresses, because we know of environments where these
    /// are used with NAT to provide connectivity.
    pub fn new() -> Self {
        local_addresses(&interfaces())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn test_local_addresses() {
        let addrs = LocalAddresses::new();
        dbg!(&addrs);
        assert!(!addrs.loopback.is_empty());
        assert!(!addrs.regular.is_empty());
    }

    #[test]
    fn test_is_usable_v6() {
        let loopback = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x1);
        assert!(!is_usable_v6(&loopback.into()));

        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xcbc9, 0x6aff, 0x5b07, 0x4a9e);
        assert!(!is_usable_v6(&link_local.into()));

        let relay_use1 = Ipv6Addr::new(0x2a01, 0x4ff, 0xf0, 0xc4a1, 0, 0, 0, 0x1);
        assert!(is_usable_v6(&relay_use1.into()));

        let random_2603 = Ipv6Addr::new(0x2603, 0x3ff, 0xf1, 0xc3aa, 0x1, 0x2, 0x3, 0x1);
        assert!(is_usable_v6(&random_2603.into()));
    }

    #[test]
    fn test_local_ip() {
        // Either family may be unavailable in a test environment; only
        // check that a returned address is not unspecified.
        if let Some(ip) = local_ip() {
            assert!(!ip.is_unspecified());
        }
    }
}
