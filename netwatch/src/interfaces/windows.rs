use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use n0_error::stack_error;
use tracing::warn;
use windows::Win32::{
    Foundation::{ERROR_NETWORK_UNREACHABLE, ERROR_NOT_SUPPORTED, WIN32_ERROR},
    NetworkManagement::{
        IpHelper::{GetBestInterfaceEx, GetIfEntry2, MIB_IF_ROW2},
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR, SOCKADDR_IN,
        SOCKADDR_IN6, SOCKADDR_INET,
    },
};

use super::DefaultRouteDetails;
pub(super) use super::netdev_impl::{get_state, home_router};

/// One address from each IPv4 documentation network (RFC 5737).
///
/// Networks do not route these specifically, so their best route is the one
/// carrying Internet traffic. Using three separate networks lets a vote
/// outweigh a specific route that diverts one of them.
const PROBES_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(192, 0, 2, 1),
    Ipv4Addr::new(198, 51, 100, 1),
    Ipv4Addr::new(203, 0, 113, 1),
];

/// An IPv6 documentation address (RFC 3849), used without an IPv4 route.
const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

#[stack_error(derive, add_meta, std_sources, from_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("win32")]
    Win32 { source: windows_result::Error },
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut addr = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(ip) => {
            addr.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                ..Default::default()
            };
        }
        IpAddr::V6(ip) => {
            addr.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: ip.octets() },
                },
                ..Default::default()
            };
        }
    }
    addr
}

/// Returns the index of the interface Windows would use to reach `destination`.
fn best_interface(destination: IpAddr) -> Result<Option<u32>, Error> {
    let destination = sockaddr(destination);
    let mut index = 0;
    let result = WIN32_ERROR(unsafe {
        GetBestInterfaceEx(&destination as *const _ as *const SOCKADDR, &mut index)
    });
    // No route, or no stack for this address family.
    if result == ERROR_NETWORK_UNREACHABLE || result == ERROR_NOT_SUPPORTED {
        return Ok(None);
    }
    result.ok()?;
    Ok(Some(index))
}

/// Orders interface indices by how many probes chose them, most first.
///
/// Ties keep the order of the probes, so the result is stable for an
/// unchanged routing table.
fn by_votes(indices: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut votes: Vec<(u32, usize)> = Vec::new();
    for index in indices {
        match votes.iter_mut().find(|(i, _)| *i == index) {
            Some((_, count)) => *count += 1,
            None => votes.push((index, 1)),
        }
    }
    // A stable sort keeps first-seen order among equal counts.
    votes.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
    votes.into_iter().map(|(index, _)| index).collect()
}

/// Returns the up interface that most probes route through.
fn vote(probes: impl IntoIterator<Item = IpAddr>) -> Result<Option<MIB_IF_ROW2>, Error> {
    let mut indices = Vec::new();
    for probe in probes {
        indices.extend(best_interface(probe)?);
    }
    for index in by_votes(indices) {
        let mut iface = MIB_IF_ROW2 {
            InterfaceIndex: index,
            ..Default::default()
        };
        unsafe { GetIfEntry2(&mut iface) }.ok()?;
        // Windows keeps the default routes of disconnected interfaces and
        // still returns them when no interface is up.
        if iface.OperStatus == IfOperStatusUp {
            return Ok(Some(iface));
        }
    }
    Ok(None)
}

/// Finds the interface carrying Internet traffic.
///
/// A multihomed host has no single default route: Windows picks among
/// equal-metric default routes per destination, and more specific routes win
/// over all of them. This asks the stack which interface it would use for
/// documentation addresses, which follows the lowest-metric default route as
/// well as split default routes such as `0.0.0.0/1` plus `128.0.0.0/1`.
fn get_default_route() -> Result<Option<DefaultRouteDetails>, Error> {
    let mut iface = vote(PROBES_V4.map(IpAddr::V4))?;
    if iface.is_none() {
        iface = vote([IpAddr::V6(PROBE_V6)])?;
    }
    Ok(iface.map(|iface| DefaultRouteDetails {
        // netdev, and therefore `State::interfaces`, names Windows interfaces
        // by their braced adapter GUID.
        interface_name: format!("{{{:?}}}", iface.InterfaceGuid),
    }))
}

pub async fn default_route() -> Option<DefaultRouteDetails> {
    // Keep synchronous IP Helper calls off the async worker thread.
    match tokio::task::spawn_blocking(get_default_route).await {
        Ok(Ok(route)) => route,
        Ok(Err(err)) => {
            warn!("failed to retrieve default route: {:#?}", err);
            None
        }
        Err(err) => {
            warn!("default route task panicked: {:#?}", err);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_route_names_an_enumerated_interface() {
        let state = get_state().await;
        // A disconnected host may have no default route.
        if let Some(name) = &state.default_route_interface {
            assert!(
                state.interfaces.contains_key(name),
                "default route interface {:?} is missing from {:?}",
                name,
                state.interfaces.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn one_diverted_probe_does_not_change_the_answer() {
        // A specific route sends the first probe to interface 19.
        assert_eq!(by_votes([19, 6, 6]), [6, 19]);
    }

    #[test]
    fn split_votes_resolve_to_the_earlier_probe() {
        // Equal-metric default routes spread probes across interfaces; the
        // answer must not flap while the routing table is unchanged.
        assert_eq!(by_votes([6, 19, 29]), [6, 19, 29]);
        assert_eq!(by_votes([19, 6]), [19, 6]);
    }
}
