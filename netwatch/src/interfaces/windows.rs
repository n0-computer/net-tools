use std::net::{Ipv4Addr, Ipv6Addr};

use n0_error::stack_error;
use tracing::warn;
use windows::Win32::{
    Foundation::{ERROR_NETWORK_UNREACHABLE, ERROR_NOT_SUPPORTED},
    NetworkManagement::{
        IpHelper::{GetBestRoute2, GetIfEntry2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2},
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_INET,
    },
};

use super::DefaultRouteDetails;
pub(super) use super::netdev_impl::{get_state, home_router};

/// Documentation addresses (RFC 5737, RFC 3849), which networks do not route
/// specifically, so their best route is the one carrying Internet traffic.
const PROBE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

#[stack_error(derive, add_meta, std_sources, from_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("win32")]
    Win32 { source: windows_result::Error },
}

fn probe_destinations() -> [SOCKADDR_INET; 2] {
    let mut v4 = SOCKADDR_INET::default();
    v4.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(PROBE_V4.octets()),
            },
        },
        ..Default::default()
    };
    let mut v6 = SOCKADDR_INET::default();
    v6.Ipv6 = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: PROBE_V6.octets(),
            },
        },
        ..Default::default()
    };
    [v4, v6]
}

/// Finds the interface Windows would use to reach the Internet.
///
/// Asking the stack for its best route, instead of reading the route table,
/// honors longest-prefix matching, the sum of route and interface metrics, and
/// interfaces that ignore default routes. The probes follow the default route
/// or split default routes such as `0.0.0.0/1` plus `128.0.0.0/1`, but not
/// routes for private ranges. IPv6 is only consulted without an IPv4 route.
fn get_default_route() -> Result<Option<DefaultRouteDetails>, Error> {
    for destination in probe_destinations() {
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        let result =
            unsafe { GetBestRoute2(None, 0, None, &destination, 0, &mut route, &mut source) };
        // No route, or no stack for this address family.
        if result == ERROR_NETWORK_UNREACHABLE || result == ERROR_NOT_SUPPORTED {
            continue;
        }
        result.ok()?;

        let mut iface = MIB_IF_ROW2 {
            InterfaceLuid: route.InterfaceLuid,
            ..Default::default()
        };
        unsafe { GetIfEntry2(&mut iface) }.ok()?;
        // Windows keeps the default routes of disconnected interfaces and
        // still returns them when no interface is up.
        if iface.OperStatus != IfOperStatusUp {
            continue;
        }
        return Ok(Some(DefaultRouteDetails {
            // netdev, and therefore `State::interfaces`, names Windows
            // interfaces by their braced adapter GUID.
            interface_name: format!("{{{:?}}}", iface.InterfaceGuid),
        }));
    }
    Ok(None)
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
}
