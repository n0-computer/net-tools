//! Fallback interfaces implementation for platforms without `netdev`.
//! Provides stub types — no network interface enumeration available.

use std::{collections::HashMap, fmt, net::IpAddr};

pub(crate) use ipnet::{Ipv4Net, Ipv6Net};
use n0_future::time::Instant;

use crate::ip::LocalAddresses;

/// Represents a network interface (stub).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface;

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown")
    }
}

impl Interface {
    /// A list of all ip addresses of this interface.
    pub fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        std::iter::empty()
    }
}

/// State flags for a single IPv6 address.
///
/// Hand-kept mirror of netdev's `Ipv6AddrFlags`, so the `interfaces` API is
/// identical on platforms built without `netdev` (e.g. esp-idf). All fields
/// default to `false` when the platform does not provide the information.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ipv6AddrFlags {
    /// Preferred lifetime expired; should not be used for new connections.
    pub deprecated: bool,
    /// Privacy address ([RFC 4941](https://datatracker.ietf.org/doc/html/rfc4941)).
    pub temporary: bool,
    /// Undergoing duplicate address detection.
    pub tentative: bool,
    /// Duplicate address detection failed.
    pub duplicated: bool,
    /// Manually configured, not from SLAAC.
    pub permanent: bool,
}

/// Structure of an IP network, either IPv4 or IPv6.
///
/// The shape mirrors the `netdev`-based `IpNet` so downstream code is
/// platform-agnostic.
#[derive(Clone, Debug)]
pub enum IpNet {
    /// Structure of IPv4 Network.
    V4(Ipv4Net),
    /// Structure of IPv6 Network.
    V6 {
        /// The actual network address.
        net: Ipv6Net,
        /// IPv6 scope ID
        scope_id: u32,
        /// IPv6 address flags.
        flags: Ipv6AddrFlags,
    },
}

impl PartialEq for IpNet {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IpNet::V4(a), IpNet::V4(b)) => {
                a.addr() == b.addr()
                    && a.prefix_len() == b.prefix_len()
                    && a.netmask() == b.netmask()
            }
            (
                IpNet::V6 {
                    net: net_a,
                    scope_id: scope_id_a,
                    flags: flags_a,
                },
                IpNet::V6 {
                    net: net_b,
                    scope_id: scope_id_b,
                    flags: flags_b,
                },
            ) => {
                net_a.addr() == net_b.addr()
                    && net_a.prefix_len() == net_b.prefix_len()
                    && net_a.netmask() == net_b.netmask()
                    && scope_id_a == scope_id_b
                    && flags_a == flags_b
            }
            _ => false,
        }
    }
}
impl Eq for IpNet {}

impl IpNet {
    /// The IP address of this structure.
    pub fn addr(&self) -> IpAddr {
        match self {
            IpNet::V4(a) => IpAddr::V4(a.addr()),
            IpNet::V6 { net, .. } => IpAddr::V6(net.addr()),
        }
    }
}

/// The router/gateway of the local network (stub — always returns `None`).
#[derive(Debug, Clone)]
pub struct HomeRouter {
    /// Ip of the router.
    pub gateway: IpAddr,
    /// Our local Ip if known.
    pub my_ip: Option<IpAddr>,
}

impl HomeRouter {
    /// Returns `None` — no gateway discovery available on this platform.
    pub fn new() -> Option<Self> {
        None
    }
}

/// Intended to store the state of the machine's network interfaces.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Maps from an interface name to interface.
    pub interfaces: HashMap<String, Interface>,
    /// List of machine's local IP addresses.
    pub local_addresses: LocalAddresses,
    /// Whether this machine has IPv6 connectivity.
    pub have_v6: bool,
    /// Whether the machine has IPv4 connectivity.
    pub have_v4: bool,
    /// Whether the current network interface is considered "expensive".
    pub(crate) is_expensive: bool,
    /// The interface name for the machine's default route.
    pub default_route_interface: Option<String>,
    /// Monotonic timestamp, when an unsuspend was detected.
    pub last_unsuspend: Option<Instant>,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fallback(no interfaces)")
    }
}

impl State {
    /// Returns a default empty state (no interface enumeration on this platform).
    pub async fn new() -> Self {
        State {
            interfaces: HashMap::new(),
            local_addresses: LocalAddresses::default(),
            have_v6: false,
            have_v4: true,
            is_expensive: false,
            default_route_interface: None,
            last_unsuspend: None,
        }
    }

    /// Is this a major change compared to the `old` one?
    pub fn is_major_change(&self, old: &State) -> bool {
        self != old
    }
}
