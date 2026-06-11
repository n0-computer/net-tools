//! Minimal POSIX interfaces implementation using `getifaddrs`.
//!
//! Used on platforms (like ESP-IDF) where `netdev` is not available but
//! standard POSIX networking APIs are supported.

use std::{
    collections::HashMap,
    ffi::CStr,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub(crate) use ipnet::{Ipv4Net, Ipv6Net};
use n0_future::time::Instant;

use crate::ip::LocalAddresses;

// POSIX interface flags — standard values across all POSIX systems.
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;

/// FFI declarations for `getifaddrs`/`freeifaddrs`.
///
/// We declare these manually because the `libc` crate may not expose them
/// for all targets (e.g. espidf). ESP-IDF's lwIP provides these since IDF v5.0.
mod ffi {
    #[repr(C)]
    pub(super) struct ifaddrs {
        pub ifa_next: *mut ifaddrs,
        pub ifa_name: *mut libc::c_char,
        pub ifa_flags: libc::c_uint,
        pub ifa_addr: *mut libc::sockaddr,
        pub ifa_netmask: *mut libc::sockaddr,
        pub ifa_ifu: *mut libc::sockaddr,
        pub ifa_data: *mut libc::c_void,
    }

    unsafe extern "C" {
        pub(super) fn getifaddrs(ifap: *mut *mut ifaddrs) -> libc::c_int;
        pub(super) fn freeifaddrs(ifa: *mut ifaddrs);
    }
}

/// Extract an IP address from a raw `sockaddr` pointer.
///
/// # Safety
/// The pointer must be null or point to a valid `sockaddr_in` or `sockaddr_in6`.
unsafe fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // Safety: caller guarantees sa is valid
    unsafe {
        match (*sa).sa_family as i32 {
            libc::AF_INET => {
                let sa_in = sa as *const libc::sockaddr_in;
                let ip = Ipv4Addr::from(u32::from_be((*sa_in).sin_addr.s_addr));
                Some(IpAddr::V4(ip))
            }
            libc::AF_INET6 => {
                let sa_in6 = sa as *const libc::sockaddr_in6;
                let ip = Ipv6Addr::from((*sa_in6).sin6_addr.s6_addr);
                Some(IpAddr::V6(ip))
            }
            _ => None,
        }
    }
}

/// Convert a netmask IP to a prefix length by counting leading ones.
fn prefix_len(mask: IpAddr) -> u8 {
    match mask {
        IpAddr::V4(m) => u32::from_be_bytes(m.octets()).leading_ones() as u8,
        IpAddr::V6(m) => u128::from_be_bytes(m.octets()).leading_ones() as u8,
    }
}

/// A single address entry from `getifaddrs`.
struct IfAddrEntry {
    name: String,
    flags: u32,
    addr: Option<IpAddr>,
    netmask: Option<IpAddr>,
}

/// Call `getifaddrs` and collect all entries.
fn enumerate_ifaddrs() -> Vec<IfAddrEntry> {
    let mut result = Vec::new();
    let mut ifap: *mut ffi::ifaddrs = std::ptr::null_mut();

    // Safety: getifaddrs is a standard POSIX function.
    unsafe {
        if ffi::getifaddrs(&mut ifap) != 0 {
            return result;
        }

        let mut cursor = ifap;
        while !cursor.is_null() {
            let ifa = &*cursor;
            if !ifa.ifa_name.is_null() {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let flags = ifa.ifa_flags;
                let addr = sockaddr_to_ip(ifa.ifa_addr);
                let netmask = sockaddr_to_ip(ifa.ifa_netmask);
                result.push(IfAddrEntry {
                    name,
                    flags,
                    addr,
                    netmask,
                });
            }
            cursor = ifa.ifa_next;
        }

        ffi::freeifaddrs(ifap);
    }

    result
}

/// Represents a network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    name: String,
    flags: u32,
    ipv4: Vec<Ipv4Net>,
    ipv6: Vec<Ipv6Net>,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ipv4={:?} ipv6={:?}", self.name, self.ipv4, self.ipv6)
    }
}

impl Interface {
    /// Is this interface up?
    pub fn is_up(&self) -> bool {
        self.flags & IFF_UP != 0
    }

    /// The name of the interface.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Is this a loopback interface?
    pub(crate) fn is_loopback(&self) -> bool {
        self.flags & IFF_LOOPBACK != 0
    }

    /// A list of all ip addresses of this interface.
    pub fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.ipv4
            .iter()
            .cloned()
            .map(IpNet::V4)
            .chain(self.ipv6.iter().cloned().map(IpNet::V6))
    }
}

/// State flags for a single IPv6 address.
///
/// Hand-kept mirror of netdev's [`Ipv6AddrFlags`], so the `interfaces` API is
/// identical on platforms built without `netdev` (e.g. esp-idf). Keep this in
/// sync with netdev; the documentation below is copied verbatim from it.
///
/// All fields default to `false` when the platform does not provide the
/// corresponding information.
///
/// Flags are collected from platform-specific sources:
///
/// - **Linux/Android**: netlink `IFA_FLAGS` attribute (`IFA_F_*` from [`<linux/if_addr.h>`])
/// - **macOS/iOS**: `SIOCGIFAFLAG_IN6` ioctl (`IN6_IFF_*` from [`<netinet6/in6_var.h>`][xnu])
/// - **FreeBSD/OpenBSD/NetBSD**: `SIOCGIFAFLAG_IN6` ioctl (`IN6_IFF_*` from [`<netinet6/in6_var.h>`][freebsd])
/// - **Windows**: [`NL_DAD_STATE`] and [`NL_SUFFIX_ORIGIN`] from `IP_ADAPTER_UNICAST_ADDRESS`
///
/// [`Ipv6AddrFlags`]: https://docs.rs/netdev/0.44.0/netdev/interface/ipv6_addr_flags/struct.Ipv6AddrFlags.html
/// [`<linux/if_addr.h>`]: https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h
/// [xnu]: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6_var.h
/// [freebsd]: https://github.com/freebsd/freebsd-src/blob/main/sys/netinet6/in6_var.h
/// [`NL_DAD_STATE`]: https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_dad_state
/// [`NL_SUFFIX_ORIGIN`]: https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_suffix_origin
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ipv6AddrFlags {
    /// Preferred lifetime expired; should not be used for new connections.
    ///
    /// Sourced from `IFA_F_DEPRECATED` (Linux), `IN6_IFF_DEPRECATED` (BSD),
    /// or `IpDadStateDeprecated` (Windows).
    pub deprecated: bool,
    /// Privacy address ([RFC 4941](https://datatracker.ietf.org/doc/html/rfc4941)).
    ///
    /// Sourced from `IFA_F_TEMPORARY` (Linux), `IN6_IFF_TEMPORARY` (BSD),
    /// or `IpSuffixOriginRandom` (Windows).
    pub temporary: bool,
    /// Undergoing duplicate address detection.
    ///
    /// Sourced from `IFA_F_TENTATIVE` (Linux), `IN6_IFF_TENTATIVE` (BSD),
    /// or `IpDadStateTentative` (Windows).
    pub tentative: bool,
    /// Duplicate address detection failed.
    ///
    /// Sourced from `IFA_F_DADFAILED` (Linux), `IN6_IFF_DUPLICATED` (BSD),
    /// or `IpDadStateDuplicate` (Windows).
    pub duplicated: bool,
    /// Manually configured, not from SLAAC.
    ///
    /// Sourced from `IFA_F_PERMANENT` (Linux). Not available on BSD or Windows.
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

/// The router/gateway of the local network.
///
/// Gateway discovery is not available on this platform.
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

/// Collect `getifaddrs` entries into a map of `Interface` structs grouped by name.
fn collect_interfaces() -> HashMap<String, Interface> {
    let entries = enumerate_ifaddrs();
    let mut map: HashMap<String, Interface> = HashMap::new();

    for entry in entries {
        let iface = map.entry(entry.name.clone()).or_insert_with(|| Interface {
            name: entry.name,
            flags: entry.flags,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        });

        // Merge flags (take the union).
        iface.flags |= entry.flags;

        if let Some(addr) = entry.addr {
            let pfx = entry.netmask.map(prefix_len);
            match addr {
                IpAddr::V4(v4) => {
                    if let Ok(net) = Ipv4Net::new(v4, pfx.unwrap_or(32)) {
                        iface.ipv4.push(net);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(net) = Ipv6Net::new(v6, pfx.unwrap_or(128)) {
                        iface.ipv6.push(net);
                    }
                }
            }
        }
    }

    // Sort addresses for stable comparison.
    for iface in map.values_mut() {
        iface.ipv4.sort();
        iface.ipv6.sort();
    }

    map
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
        for iface in self.interfaces.values() {
            write!(f, "{iface}")?;
            if let Some(ref default_if) = self.default_route_interface
                && iface.name() == default_if
            {
                write!(f, " (default)")?;
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

/// Reports whether ip is a usable IPv4 address.
fn is_usable_v4(ip: &IpAddr) -> bool {
    ip.is_ipv4() && !ip.is_loopback()
}

/// Reports whether ip is a usable IPv6 address (global or ULA).
fn is_usable_v6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ip) => {
            let segment1 = ip.segments()[0];
            // Global unicast: 2000::/3
            if (segment1 & 0xe000) == 0x2000 {
                return true;
            }
            // Unique local: fc00::/7
            ip.octets()[0] & 0xfe == 0xfc
        }
        IpAddr::V4(_) => false,
    }
}

impl State {
    /// Returns the state of all the current machine's network interfaces.
    pub async fn new() -> Self {
        let interfaces = collect_interfaces();
        let local_addresses = LocalAddresses::from_interfaces(interfaces.values());

        let mut have_v4 = false;
        let mut have_v6 = false;

        for iface in interfaces.values() {
            if !iface.is_up() {
                continue;
            }
            for pfx in iface.addrs() {
                let addr = pfx.addr();
                if addr.is_loopback() {
                    continue;
                }
                have_v4 |= is_usable_v4(&addr);
                have_v6 |= is_usable_v6(&addr);
            }
        }

        State {
            interfaces,
            local_addresses,
            have_v4,
            have_v6,
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
