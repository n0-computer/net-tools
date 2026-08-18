//! Netlink-based enumeration backend for linux and android.
//!
//! Interfaces come from an `RTM_GETLINK` plus an `RTM_GETADDR` dump, the
//! default gateways from an `RTM_GETROUTE` dump. Mirrors what netdev did
//! on these platforms, including the android leniency: there the address
//! dump is allowed to fail (yielding interfaces without addresses) while
//! a failed link dump makes the caller fall back to getifaddrs.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::{Ipv4Net, Ipv6Net};
use netwatch_netlink::{Connection, RouteFamily};

use super::{IfaceBuilder, Interface, Ipv6AddrFlags, resolve_v6_scope_id};

/// Enumerates interfaces via netlink dumps.
pub(super) fn interfaces() -> Result<Vec<Interface>, netwatch_netlink::Error> {
    let mut conn = Connection::new()?;
    let links = conn.dump_links()?;

    // Android 11+ SELinux denies link dumps but allows address dumps; the
    // reverse does not happen. netdev nevertheless tolerated a failed
    // address dump on android only, so keep that shape.
    #[cfg(target_os = "android")]
    let addresses = conn.dump_addresses().unwrap_or_default();
    #[cfg(not(target_os = "android"))]
    let addresses = conn.dump_addresses()?;

    let mut builders: HashMap<u32, IfaceBuilder> = HashMap::new();
    for link in links {
        let name = link.name.clone().unwrap_or_else(|| link.index.to_string());
        let mut builder = IfaceBuilder::new(name, link.index, link.flags);
        builder.mac = link
            .address
            .as_deref()
            .and_then(|mac| <[u8; 6]>::try_from(mac).ok());
        builders.insert(link.index, builder);
    }

    for address in addresses {
        // Addresses for unknown link indices are dropped.
        let Some(builder) = builders.get_mut(&address.index) else {
            continue;
        };
        let Some(ip) = address.interface_address() else {
            continue;
        };
        match ip {
            IpAddr::V4(ip) => {
                if let Ok(net) = Ipv4Net::new(ip, address.prefix_len) {
                    builder.push_v4(net);
                }
            }
            IpAddr::V6(ip) => {
                if let Ok(net) = Ipv6Net::new(ip, address.prefix_len) {
                    let scope_id = resolve_v6_scope_id(&ip, 0, address.index);
                    let flags = from_netlink_flags(address.flags());
                    builder.push_v6(net, scope_id, flags);
                }
            }
        }
    }

    Ok(builders.into_values().map(IfaceBuilder::finish).collect())
}

/// Collects the default-route gateways, keyed by output interface index.
///
/// Only routes with a zero destination prefix and a gateway attribute
/// count; on-link default routes carry no gateway and are skipped.
#[allow(clippy::type_complexity)]
pub(super) fn default_gateways_by_interface()
-> Result<HashMap<u32, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)>, netwatch_netlink::Error> {
    let mut conn = Connection::new()?;
    let routes = conn.dump_routes(RouteFamily::Unspec)?;

    let mut gateways: HashMap<u32, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)> = HashMap::new();
    for route in routes {
        if route.dst_len != 0 {
            continue;
        }
        let (Some(gateway), Some(oif)) = (route.gateway, route.oif) else {
            continue;
        };
        let (v4, v6) = gateways.entry(oif).or_default();
        match gateway {
            IpAddr::V4(ip) if !v4.contains(&ip) => v4.push(ip),
            IpAddr::V6(ip) if !v6.contains(&ip) => v6.push(ip),
            _ => {}
        }
    }
    Ok(gateways)
}

/// Maps netlink `IFA_F_*` bits into [`Ipv6AddrFlags`].
fn from_netlink_flags(raw: u32) -> Ipv6AddrFlags {
    Ipv6AddrFlags {
        deprecated: raw & libc::IFA_F_DEPRECATED != 0,
        temporary: raw & libc::IFA_F_TEMPORARY != 0,
        tentative: raw & libc::IFA_F_TENTATIVE != 0,
        duplicated: raw & libc::IFA_F_DADFAILED != 0,
        permanent: raw & libc::IFA_F_PERMANENT != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interfaces_contains_loopback() {
        let ifaces = interfaces().unwrap();
        let lo = ifaces
            .iter()
            .find(|iface| iface.name == "lo")
            .expect("no loopback interface");
        assert!(lo.index >= 1);
        assert!(lo.is_up());
        assert!(
            lo.addrs
                .iter()
                .any(|net| net.addr() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn test_flag_mapping() {
        let flags = from_netlink_flags(
            libc::IFA_F_DEPRECATED | libc::IFA_F_TEMPORARY | libc::IFA_F_PERMANENT,
        );
        assert!(flags.deprecated);
        assert!(flags.temporary);
        assert!(flags.permanent);
        assert!(!flags.tentative);
        assert!(!flags.duplicated);

        assert_eq!(from_netlink_flags(0), Ipv6AddrFlags::default());
    }

    #[test]
    fn test_default_gateways() {
        // May be empty in an isolated namespace; only check it works.
        let gateways = default_gateways_by_interface().unwrap();
        for (oif, (v4, v6)) in gateways {
            assert_ne!(oif, 0);
            assert!(!v4.is_empty() || !v6.is_empty());
        }
    }
}
