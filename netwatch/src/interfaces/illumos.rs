//! illumos-specific network interfaces implementation.
//!
//! `netdev` cannot currently determine illumos' default gateway (see
//! `crate::os::illumos` in the `netdev` crate), and this crate's own
//! `bsd.rs` backend -- which finds the default route and home router by
//! dumping the kernel routing table via `sysctl(CTL_NET, AF_ROUTE, ...,
//! NET_RT_DUMP, ...)` and parsing the resulting `rt_msghdr` stream -- does
//! not port to illumos: illumos has no `sysctl()` at all. A `PF_ROUTE`
//! routing-socket reader (`RTM_GET`) could in principle provide the same
//! data, but its wire format was not reverse-engineered here without real
//! illumos hardware to verify the result against, so getting it wrong would
//! silently report an incorrect gateway. Instead:
//!
//! - [`default_route`] avoids routing-table access entirely: it asks the OS
//!   which local address it would use to reach the public internet (the
//!   same technique `netdev::net::ip::get_local_ipaddr`, exposed here via
//!   [`super::netdev_impl::local_ip`], already relies on), then matches
//!   that address against the enumerated interfaces. This reflects the
//!   OS's live routing decision rather than a possibly-stale routing-table
//!   entry, so it isn't just a fallback -- it's arguably a better signal
//!   for this specific purpose.
//! - [`home_router`] additionally needs the gateway's *own* IP address, not
//!   just the outbound interface, which the technique above cannot provide.
//!   It returns `None` until real routing-table access lands.

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
