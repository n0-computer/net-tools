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
    /// Is this interface up?
    pub fn is_up(&self) -> bool {
        false
    }

    /// The name of the interface.
    pub fn name(&self) -> &str {
        "unknown"
    }

    /// A list of all ip addresses of this interface.
    pub fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        std::iter::empty()
    }
}

/// Structure of an IP network, either IPv4 or IPv6.
#[derive(Clone, Debug)]
pub enum IpNet {
    /// Structure of IPv4 Network.
    V4(Ipv4Net),
    /// Structure of IPv6 Network.
    V6(Ipv6Net),
}

impl PartialEq for IpNet {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IpNet::V4(a), IpNet::V4(b)) => {
                a.addr() == b.addr()
                    && a.prefix_len() == b.prefix_len()
                    && a.netmask() == b.netmask()
            }
            (IpNet::V6(a), IpNet::V6(b)) => {
                a.addr() == b.addr()
                    && a.prefix_len() == b.prefix_len()
                    && a.netmask() == b.netmask()
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
            IpNet::V6(a) => IpAddr::V6(a.addr()),
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
    pub is_expensive: bool,
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

    /// Creates a fake interface state for usage in tests.
    pub fn fake() -> Self {
        Self {
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
