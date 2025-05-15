//! Contains helpers for looking up system network interfaces.

use std::{collections::HashMap, fmt, net::IpAddr};

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
pub(super) mod bsd;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

pub(crate) use netdev::ipnet::{Ipv4Net, Ipv6Net};

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
use self::bsd::default_route;
#[cfg(any(target_os = "linux", target_os = "android"))]
use self::linux::default_route;
#[cfg(target_os = "windows")]
use self::windows::default_route;
#[cfg(not(wasm_browser))]
use crate::ip::is_link_local;
use crate::ip::{is_private_v6, is_up};
#[cfg(not(wasm_browser))]
use crate::netmon::is_interesting_interface;

/// Represents a network interface.
#[derive(Debug, Clone)]
pub struct Interface {
    iface: netdev::interface::Interface,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}. {} {:?} ipv4={:?} ipv6={:?}",
            self.iface.index, self.iface.name, self.iface.if_type, self.iface.ipv4, self.iface.ipv6
        )
    }
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.iface.index == other.iface.index
            && self.iface.name == other.iface.name
            && self.iface.flags == other.iface.flags
            && self.iface.mac_addr.as_ref().map(|a| a.octets())
                == other.iface.mac_addr.as_ref().map(|a| a.octets())
    }
}

impl Eq for Interface {}

impl Interface {
    /// Is this interface up?
    pub fn is_up(&self) -> bool {
        is_up(&self.iface)
    }

    /// The name of the interface.
    pub fn name(&self) -> &str {
        &self.iface.name
    }

    /// A list of all ip addresses of this interface.
    pub fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.iface
            .ipv4
            .iter()
            .cloned()
            .map(IpNet::V4)
            .chain(self.iface.ipv6.iter().cloned().map(IpNet::V6))
    }

    /// Creates a fake interface for usage in tests.
    ///
    /// This allows tests to be independent of the host interfaces.
    pub(crate) fn fake() -> Self {
        use std::net::Ipv4Addr;

        use netdev::{interface::InterfaceType, mac::MacAddr, NetworkDevice};

        Self {
            iface: netdev::Interface {
                index: 2,
                name: String::from("wifi0"),
                friendly_name: None,
                description: None,
                if_type: InterfaceType::Ethernet,
                mac_addr: Some(MacAddr::new(2, 3, 4, 5, 6, 7)),
                ipv4: vec![Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 189), 24).unwrap()],
                ipv6: vec![],
                flags: 69699,
                transmit_speed: None,
                receive_speed: None,
                gateway: Some(NetworkDevice {
                    mac_addr: MacAddr::new(2, 3, 4, 5, 6, 8),
                    ipv4: vec![Ipv4Addr::from([192, 168, 0, 1])],
                    ipv6: vec![],
                }),
                dns_servers: vec![],
                default: false,
            },
        }
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

/// Intended to store the state of the machine's network interfaces, routing table, and
/// other network configuration. For now it's pretty basic.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Maps from an interface name interface.
    pub interfaces: HashMap<String, Interface>,

    /// Whether this machine has an IPv6 Global or Unique Local Address
    /// which might provide connectivity.
    pub have_v6: bool,

    /// Whether the machine has some non-localhost, non-link-local IPv4 address.
    pub have_v4: bool,

    /// Whether the current network interface is considered "expensive", which currently means LTE/etc
    /// instead of Wifi. This field is not populated by `get_state`.
    pub is_expensive: bool,

    /// The interface name for the machine's default route.
    ///
    /// It is not yet populated on all OSes.
    ///
    /// When set, its value is the map key into `interface` and `interface_ips`.
    pub default_route_interface: Option<String>,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ifaces: Vec<_> = self.interfaces.values().collect();
        ifaces.sort_by_key(|iface| iface.iface.index);
        for iface in ifaces {
            write!(f, "{iface}")?;
            if let Some(ref default_if) = self.default_route_interface {
                if iface.name() == default_if {
                    write!(f, " (default)")?;
                }
            }
            if f.alternate() {
                writeln!(f)?;
            } else {
                write!(f, "; ")?;
            }
        }
        Ok(())
    }
}

impl State {
    /// Returns the state of all the current machine's network interfaces.
    ///
    /// It does not set the returned `State.is_expensive`. The caller can populate that.
    pub async fn new() -> Self {
        let mut interfaces = HashMap::new();
        let mut have_v6 = false;
        let mut have_v4 = false;

        let ifaces = netdev::interface::get_interfaces();
        for iface in ifaces {
            let ni = Interface { iface };
            let if_up = ni.is_up();
            let name = ni.iface.name.clone();
            let pfxs: Vec<_> = ni.addrs().collect();

            if if_up {
                for pfx in &pfxs {
                    if pfx.addr().is_loopback() {
                        continue;
                    }
                    have_v6 |= is_usable_v6(&pfx.addr());
                    have_v4 |= is_usable_v4(&pfx.addr());
                }
            }

            interfaces.insert(name, ni);
        }

        let default_route_interface = default_route_interface().await;

        State {
            interfaces,
            have_v4,
            have_v6,
            is_expensive: false,
            default_route_interface,
        }
    }

    /// Creates a fake interface state for usage in tests.
    ///
    /// This allows tests to be independent of the host interfaces.
    pub fn fake() -> Self {
        let fake = Interface::fake();
        let ifname = fake.iface.name.clone();
        Self {
            interfaces: [(ifname.clone(), fake)].into_iter().collect(),
            have_v6: true,
            have_v4: true,
            is_expensive: false,
            default_route_interface: Some(ifname),
        }
    }

    /// Is this a major change compared to the `old` one?.
    #[cfg(wasm_browser)]
    pub fn is_major_change(&self, old: &State) -> bool {
        // All changes are major.
        // In the browser, there only are changes from online to offline
        self != old
    }

    /// Is this a major change compared to the `old` one?.
    #[cfg(not(wasm_browser))]
    pub fn is_major_change(&self, old: &State) -> bool {
        if self.have_v6 != old.have_v6
            || self.have_v4 != old.have_v4
            || self.is_expensive != old.is_expensive
            || self.default_route_interface != old.default_route_interface
        {
            return true;
        }

        for (iname, i) in &old.interfaces {
            if !is_interesting_interface(i.name()) {
                continue;
            }
            let Some(i2) = self.interfaces.get(iname) else {
                return true;
            };
            if i != i2 || !prefixes_major_equal(i.addrs(), i2.addrs()) {
                return true;
            }
        }

        false
    }
}

/// Reports whether ip is a usable IPv4 address which should have Internet connectivity.
///
/// Globally routable and private IPv4 addresses are always Usable, and link local
/// 169.254.x.x addresses are in some environments.
fn is_usable_v4(ip: &IpAddr) -> bool {
    if !ip.is_ipv4() || ip.is_loopback() {
        return false;
    }

    true
}

/// Reports whether ip is a usable IPv6 address which should have Internet connectivity.
///
/// Globally routable IPv6 addresses are always Usable, and Unique Local Addresses
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

/// The details about a default route.
#[derive(Debug, Clone)]
pub struct DefaultRouteDetails {
    /// The interface name.
    /// It's like "eth0" (Linux), "Ethernet 2" (Windows), "en0" (macOS).
    pub interface_name: String,
}

impl DefaultRouteDetails {
    /// Reads the default route from the current system and returns the details.
    pub async fn new() -> Option<Self> {
        default_route().await
    }
}

/// Like `DefaultRoutDetails::new` but only returns the interface name.
pub async fn default_route_interface() -> Option<String> {
    DefaultRouteDetails::new().await.map(|v| v.interface_name)
}

/// Likely IPs of the residentla router, and the ip address of the current
/// machine using it.
#[derive(Debug, Clone)]
pub struct HomeRouter {
    /// Ip of the router.
    pub gateway: IpAddr,
    /// Our local Ip if known.
    pub my_ip: Option<IpAddr>,
}

impl HomeRouter {
    /// Returns the likely IP of the residential router, which will always
    /// be a private address, if found.
    /// In addition, it returns the IP address of the current machine on
    /// the LAN using that gateway.
    /// This is used as the destination for UPnP, NAT-PMP, PCP, etc queries.
    pub fn new() -> Option<Self> {
        let gateway = Self::get_default_gateway()?;
        let my_ip = netdev::interface::get_local_ipaddr();

        Some(HomeRouter { gateway, my_ip })
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos",
        target_os = "ios"
    ))]
    fn get_default_gateway() -> Option<IpAddr> {
        // netdev doesn't work yet
        // See: https://github.com/shellrow/default-net/issues/34
        bsd::likely_home_router()
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
    fn get_default_gateway() -> Option<IpAddr> {
        let gateway = netdev::get_default_gateway().ok()?;
        gateway
            .ipv4
            .iter()
            .cloned()
            .map(IpAddr::V4)
            .chain(gateway.ipv6.iter().cloned().map(IpAddr::V6))
            .next()
    }
}

/// Checks whether `a` and `b` are equal after ignoring uninteresting
/// things, like link-local, loopback and multicast addresses.
#[cfg(not(wasm_browser))]
fn prefixes_major_equal(a: impl Iterator<Item = IpNet>, b: impl Iterator<Item = IpNet>) -> bool {
    fn is_interesting(p: &IpNet) -> bool {
        let a = p.addr();
        if is_link_local(a) || a.is_loopback() || a.is_multicast() {
            return false;
        }
        true
    }

    let a = a.filter(is_interesting);
    let b = b.filter(is_interesting);

    for (a, b) in a.zip(b) {
        if a != b {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[tokio::test]
    async fn test_default_route() {
        let default_route = DefaultRouteDetails::new()
            .await
            .expect("missing default route");
        println!("default_route: {:#?}", default_route);
    }

    #[tokio::test]
    async fn test_likely_home_router() {
        let home_router = HomeRouter::new().expect("missing home router");
        println!("home router: {:#?}", home_router);
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
}
