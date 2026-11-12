//! Network interfaces on illumos.
//!
//! illumos has no `sysctl()` routing-table dump like the BSDs, so the `bsd`
//! backend can't be used, and `netdev` can't find the default gateway either.
//!
//! - [`default_route`] asks the OS which local address it would use to reach
//!   the internet and picks the interface that owns it.
//! - [`home_router`] needs the gateway's own address, which that approach
//!   can't give, so it always returns `None` for now.

use std::net::IpAddr;

pub(super) use super::netdev_impl::get_state;
use super::{DefaultRouteDetails, HomeRouter};

/// Finds the interface that owns the default route by matching the OS's
/// chosen outbound-routing address (see the module docs) against each
/// enumerated interface's addresses.
pub async fn default_route() -> Option<DefaultRouteDetails> {
    let local_ip = super::netdev_impl::local_ip()?;
    let interfaces = netdev::get_interfaces();
    interfaces
        .into_iter()
        .find(|iface| {
            iface
                .ipv4
                .iter()
                .any(|net| local_ip == IpAddr::V4(net.addr()))
                || iface
                    .ipv6
                    .iter()
                    .any(|net| local_ip == IpAddr::V6(net.addr()))
        })
        .map(|iface| DefaultRouteDetails {
            interface_name: iface.name,
        })
}

/// Not yet implemented on illumos: see the module docs for why. Always
/// returns `None` -- callers should treat this as "unknown", not "no
/// gateway configured".
pub(super) fn home_router() -> Option<HomeRouter> {
    None
}
