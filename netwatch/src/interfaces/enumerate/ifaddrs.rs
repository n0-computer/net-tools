//! getifaddrs-based interface enumeration.
//!
//! The primary backend on BSD and Apple platforms, and the fallback on
//! linux and android when netlink is unavailable (Android 11+ denies
//! netlink link dumps to apps via SELinux).
//!
//! Every getifaddrs entry carries one address; entries are merged per
//! interface name, with flags taken from the first entry of a name the
//! way netdev did it. The unsafe surface is confined to the [`IfAddrs`]
//! list wrapper, the [`Entry`] accessors, and the flag ioctl; the walk
//! itself is safe code.
//!
//! We wrap the FFI ourselves instead of using nix, the one crate whose
//! getifaddrs wrapper exposes enough (flags, MAC, scope IDs): nix only
//! zero-pads the truncated netmask sockaddrs BSD kernels produce on
//! Apple targets (on the other BSDs the netmask would parse as /0),
//! links `getifaddrs` directly (bionic exports it only since API 24, so
//! binaries would stop loading on older Android), and does not cover
//! the flag ioctl anyway.

use std::{
    ffi::CStr,
    net::{Ipv4Addr, Ipv6Addr},
};

use ipnet::{Ipv4Net, Ipv6Net};

use super::{IfaceBuilder, Interface, Ipv6AddrFlags, resolve_v6_scope_id};

/// The address family link-layer (MAC) addresses arrive with.
#[cfg(any(target_os = "linux", target_os = "android"))]
const MAC_FAMILY: libc::c_int = libc::AF_PACKET;
#[cfg(bsd)]
const MAC_FAMILY: libc::c_int = libc::AF_LINK;

/// Enumerates the machine's network interfaces via `getifaddrs(3)`.
///
/// Returns an empty list when the call fails; there is no error channel,
/// matching the behavior callers have relied on so far.
pub(super) fn interfaces() -> Vec<Interface> {
    let Some(list) = IfAddrs::load() else {
        return Vec::new();
    };

    let mut builders: Vec<IfaceBuilder> = Vec::new();
    for entry in list.iter() {
        let Some(name) = entry.name() else {
            continue;
        };
        let position = match builders.iter().position(|builder| builder.name == name) {
            Some(position) => position,
            None => {
                builders.push(IfaceBuilder::new(name, entry.index(), entry.flags()));
                builders.len() - 1
            }
        };
        let builder = &mut builders[position];

        let Some((family, sa)) = entry.addr() else {
            continue;
        };
        if family == MAC_FAMILY {
            if let Some(mac) = parse_mac(sa) {
                builder.mac = Some(mac);
            }
        } else if family == libc::AF_INET {
            let Some(ip) = parse_v4_addr(sa) else {
                continue;
            };
            // A non-contiguous netmask fails here and drops the address.
            let Ok(net) = Ipv4Net::with_netmask(ip, parse_v4_mask(entry.netmask())) else {
                continue;
            };
            builder.push_v4(net);
        } else if family == libc::AF_INET6 {
            let Some((ip, raw_scope_id)) = parse_v6_addr(sa) else {
                continue;
            };
            let Ok(net) = Ipv6Net::with_netmask(ip, parse_v6_mask(entry.netmask())) else {
                continue;
            };
            let scope_id = resolve_v6_scope_id(&ip, raw_scope_id, builder.index);
            let flags = ipv6_addr_flags(&builder.name, &ip);
            builder.push_v6(net, scope_id, flags);
        }
    }

    builders.into_iter().map(IfaceBuilder::finish).collect()
}

/// The list returned by `getifaddrs(3)`, freed on drop.
struct IfAddrs {
    list: *mut libc::ifaddrs,
    free: unsafe extern "C" fn(*mut libc::ifaddrs),
}

impl IfAddrs {
    /// Queries the list.
    ///
    /// Returns `None` when the call fails or, on android, when the
    /// symbols are unavailable.
    fn load() -> Option<Self> {
        #[cfg(target_os = "android")]
        let (getifaddrs, freeifaddrs) = compat::symbols()?;
        #[cfg(not(target_os = "android"))]
        let (getifaddrs, freeifaddrs) = (
            libc::getifaddrs as unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int,
            libc::freeifaddrs as unsafe extern "C" fn(*mut libc::ifaddrs),
        );

        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `list` is a valid out-pointer for getifaddrs.
        if unsafe { getifaddrs(&mut list) } != 0 {
            return None;
        }
        Some(Self {
            list,
            free: freeifaddrs,
        })
    }

    /// Iterates the entries of the list.
    fn iter(&self) -> impl Iterator<Item = Entry<'_>> {
        let mut next = self.list.cast_const();
        std::iter::from_fn(move || {
            // SAFETY: `next` is null or points at a live node of the
            // list, which stays allocated for the borrow's lifetime.
            let ifa = unsafe { next.as_ref() }?;
            next = ifa.ifa_next;
            Some(Entry { ifa })
        })
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.list.is_null() {
            // SAFETY: `list` came from getifaddrs and is freed exactly
            // once.
            unsafe { (self.free)(self.list) };
        }
    }
}

/// One getifaddrs entry: an interface name paired with one address.
///
/// The accessors encapsulate the pointer handling; the invariants they
/// rely on (NUL-terminated name, length-backed sockaddrs) are guaranteed
/// by getifaddrs for the lifetime of the [`IfAddrs`] list.
#[derive(Clone, Copy)]
struct Entry<'a> {
    ifa: &'a libc::ifaddrs,
}

impl<'a> Entry<'a> {
    /// The interface name.
    fn name(&self) -> Option<String> {
        if self.ifa.ifa_name.is_null() {
            return None;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(self.ifa.ifa_name) };
        Some(name.to_string_lossy().into_owned())
    }

    /// The OS interface index; zero when the lookup fails.
    fn index(&self) -> u32 {
        if self.ifa.ifa_name.is_null() {
            return 0;
        }
        // SAFETY: ifa_name is a valid NUL-terminated string, see name().
        unsafe { libc::if_nametoindex(self.ifa.ifa_name) }
    }

    /// The interface flags (`IFF_*`).
    fn flags(&self) -> u32 {
        self.ifa.ifa_flags
    }

    /// The entry's address family and sockaddr bytes.
    fn addr(&self) -> Option<(libc::c_int, &'a [u8])> {
        // SAFETY: ifa_addr is null or a sockaddr whose reported length is
        // backed by its allocation, as getifaddrs guarantees.
        unsafe { sockaddr_slice(self.ifa.ifa_addr) }
    }

    /// The netmask family and sockaddr bytes.
    fn netmask(&self) -> Option<(libc::c_int, &'a [u8])> {
        // SAFETY: as for addr().
        unsafe { sockaddr_slice(self.ifa.ifa_netmask) }
    }
}

/// Reads the address family and the valid bytes of a sockaddr.
///
/// On BSD-derived systems the length comes from `sa_len` (clamped to the
/// size of `sockaddr_storage`, with family-based defaults when zero); on
/// linux and android it is implied by the family.
///
/// # Safety
///
/// `sa` must be null or point to a sockaddr whose reported length is
/// backed by its allocation, as getifaddrs guarantees.
unsafe fn sockaddr_slice<'a>(sa: *const libc::sockaddr) -> Option<(libc::c_int, &'a [u8])> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: `sa` points at a sockaddr whose reported length is backed
    // by its allocation, per the caller contract.
    unsafe {
        let family = (*sa).sa_family as libc::c_int;

        #[cfg(bsd)]
        let len = {
            let sa_len = (*sa).sa_len as usize;
            if sa_len == 0 {
                match family {
                    libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
                    libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
                    libc::AF_LINK => std::mem::size_of::<libc::sockaddr_dl>(),
                    _ => return None,
                }
            } else {
                sa_len.min(std::mem::size_of::<libc::sockaddr_storage>())
            }
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let len = match family {
            libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
            libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
            libc::AF_PACKET => std::mem::size_of::<libc::sockaddr_ll>(),
            _ => return None,
        };

        Some((family, std::slice::from_raw_parts(sa.cast::<u8>(), len)))
    }
}

/// Parses the address of a full-length `sockaddr_in`.
fn parse_v4_addr(sa: &[u8]) -> Option<Ipv4Addr> {
    // sin_addr sits at offset 4 on every supported platform.
    if sa.len() < std::mem::size_of::<libc::sockaddr_in>() {
        return None;
    }
    Some(Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]))
}

/// Parses the address and scope of a full-length `sockaddr_in6`.
fn parse_v6_addr(sa: &[u8]) -> Option<(Ipv6Addr, u32)> {
    // sin6_addr sits at offset 8 and sin6_scope_id at 24 on every
    // supported platform.
    if sa.len() < std::mem::size_of::<libc::sockaddr_in6>() {
        return None;
    }
    let octets: [u8; 16] = sa[8..24].try_into().expect("length checked");
    let scope_id = u32::from_ne_bytes(sa[24..28].try_into().expect("length checked"));
    Some((Ipv6Addr::from(octets), scope_id))
}

/// Extracts an IPv4 netmask, tolerating the truncated sockaddrs BSD
/// kernels produce (trailing zero bytes are trimmed from `sa_len`).
fn parse_v4_mask(netmask: Option<(libc::c_int, &[u8])>) -> Ipv4Addr {
    let Some((family, sa)) = netmask else {
        return Ipv4Addr::UNSPECIFIED;
    };
    if family != libc::AF_INET {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mut octets = [0u8; 4];
    let available = sa.len().saturating_sub(4).min(4);
    octets[..available].copy_from_slice(&sa[4..4 + available]);
    Ipv4Addr::from(octets)
}

/// Extracts an IPv6 netmask; see [`parse_v4_mask`] for the truncation
/// handling.
fn parse_v6_mask(netmask: Option<(libc::c_int, &[u8])>) -> Ipv6Addr {
    let Some((family, sa)) = netmask else {
        return Ipv6Addr::UNSPECIFIED;
    };
    if family != libc::AF_INET6 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mut octets = [0u8; 16];
    let available = sa.len().saturating_sub(8).min(16);
    octets[..available].copy_from_slice(&sa[8..8 + available]);
    Ipv6Addr::from(octets)
}

/// Extracts the MAC address from a `sockaddr_ll`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_mac(sa: &[u8]) -> Option<[u8; 6]> {
    // sll_halen sits at offset 11, sll_addr at 12.
    let halen = *sa.get(11)? as usize;
    if halen < 6 {
        return None;
    }
    sa.get(12..18)?.try_into().ok()
}

/// Extracts the MAC address from a `sockaddr_dl`.
///
/// Wire layout: len, family, index (2), type, name length, address
/// length, selector length, then name and address bytes.
#[cfg(bsd)]
fn parse_mac(sa: &[u8]) -> Option<[u8; 6]> {
    if sa.len() < 8 {
        return None;
    }
    let name_len = sa[5] as usize;
    let addr_len = sa[6] as usize;
    if addr_len < 6 {
        return None;
    }
    let start = 8 + name_len;
    sa.get(start..start + 6)?.try_into().ok()
}

/// Queries the per-address IPv6 flags via the `SIOCGIFAFLAG_IN6` ioctl.
///
/// Any failure yields all-false flags; `permanent` is never reported on
/// these platforms.
#[cfg(bsd)]
fn ipv6_addr_flags(name: &str, addr: &Ipv6Addr) -> Ipv6AddrFlags {
    use std::os::fd::AsRawFd;

    // From in6_var.h (xnu and FreeBSD agree); the libc crate exposes
    // neither the ioctl number nor the flag bits. The request encodes a
    // 288-byte `struct in6_ifreq`. The same number is used on OpenBSD and
    // NetBSD even though their struct differs; there the ioctl fails and
    // the flags stay false, which is the behavior netdev shipped.
    const SIOCGIFAFLAG_IN6: libc::c_ulong = 0xC120_6949;
    const IN6_IFF_TENTATIVE: i32 = 0x02;
    const IN6_IFF_DUPLICATED: i32 = 0x04;
    const IN6_IFF_DEPRECATED: i32 = 0x10;
    const IN6_IFF_TEMPORARY: i32 = 0x80;

    /// Layout-compatible with the kernel's `struct in6_ifreq`: the
    /// interface name followed by a union accessed only as the request
    /// address (in) and the flag word (out). `data` is sized so the
    /// struct matches the 288 bytes the ioctl copies.
    #[repr(C, align(8))]
    struct In6Ifreq {
        name: [u8; libc::IFNAMSIZ],
        data: [u8; 288 - libc::IFNAMSIZ],
    }

    let flags = Ipv6AddrFlags::default();

    let Ok(socket) = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None) else {
        return flags;
    };

    let mut req = In6Ifreq {
        name: [0; libc::IFNAMSIZ],
        data: [0; 288 - libc::IFNAMSIZ],
    };
    let name = name.as_bytes();
    let name_len = name.len().min(libc::IFNAMSIZ - 1);
    req.name[..name_len].copy_from_slice(&name[..name_len]);

    // The union starts with a sockaddr_in6 holding the queried address:
    // the length and family bytes, then the address at offset 8.
    req.data[0] = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    req.data[1] = libc::AF_INET6 as u8;
    req.data[8..24].copy_from_slice(&addr.octets());

    // SAFETY: `req` matches the 288-byte struct size encoded in the
    // ioctl request; the kernel reads and writes only within it.
    let res = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCGIFAFLAG_IN6, &mut req) };
    if res != 0 {
        return flags;
    }
    // On success the union holds the flag word instead of the address.
    let raw = i32::from_ne_bytes(req.data[..4].try_into().expect("length checked"));

    Ipv6AddrFlags {
        deprecated: raw & IN6_IFF_DEPRECATED != 0,
        temporary: raw & IN6_IFF_TEMPORARY != 0,
        tentative: raw & IN6_IFF_TENTATIVE != 0,
        duplicated: raw & IN6_IFF_DUPLICATED != 0,
        permanent: false,
    }
}

/// On linux and android the per-address IPv6 flags come from netlink;
/// this getifaddrs fallback reports none, like netdev's fallback did.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn ipv6_addr_flags(_name: &str, _addr: &Ipv6Addr) -> Ipv6AddrFlags {
    Ipv6AddrFlags::default()
}

/// `getifaddrs` resolved at runtime.
///
/// Bionic provides getifaddrs only since API 24; resolving the symbols at
/// runtime keeps binaries loadable on older Android versions, at the
/// price of enumerating nothing there. This matches netdev, which
/// dlopened libc for the same reason.
#[cfg(target_os = "android")]
mod compat {
    use std::sync::OnceLock;

    pub(super) type GetIfAddrsFn = unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int;
    pub(super) type FreeIfAddrsFn = unsafe extern "C" fn(*mut libc::ifaddrs);

    pub(super) fn symbols() -> Option<(GetIfAddrsFn, FreeIfAddrsFn)> {
        static SYMBOLS: OnceLock<Option<(usize, usize)>> = OnceLock::new();
        let (getifaddrs, freeifaddrs) = (*SYMBOLS.get_or_init(|| {
            // SAFETY: dlsym with valid NUL-terminated symbol names.
            let (getifaddrs, freeifaddrs) = unsafe {
                (
                    libc::dlsym(libc::RTLD_DEFAULT, c"getifaddrs".as_ptr()),
                    libc::dlsym(libc::RTLD_DEFAULT, c"freeifaddrs".as_ptr()),
                )
            };
            if getifaddrs.is_null() || freeifaddrs.is_null() {
                None
            } else {
                Some((getifaddrs as usize, freeifaddrs as usize))
            }
        }))?;
        // SAFETY: the addresses come from dlsym for symbols with exactly
        // these C signatures.
        unsafe {
            Some((
                std::mem::transmute::<usize, GetIfAddrsFn>(getifaddrs),
                std::mem::transmute::<usize, FreeIfAddrsFn>(freeifaddrs),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn test_interfaces_contains_loopback() {
        let ifaces = interfaces();
        let lo = ifaces
            .iter()
            .find(|iface| iface.addrs.iter().any(|net| net.addr().is_loopback()))
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
    fn test_parse_v4_mask() {
        // A full-length AF_INET sockaddr with mask 255.255.255.0.
        let mut sa = [0u8; 16];
        sa[4..8].copy_from_slice(&[255, 255, 255, 0]);
        assert_eq!(
            parse_v4_mask(Some((libc::AF_INET, &sa))),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        // A truncated sockaddr (BSD style): only one mask byte present.
        assert_eq!(
            parse_v4_mask(Some((libc::AF_INET, &sa[..5]))),
            Ipv4Addr::new(255, 0, 0, 0)
        );
        // Missing or wrong-family netmask means prefix zero.
        assert_eq!(parse_v4_mask(None), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            parse_v4_mask(Some((libc::AF_INET6, &sa))),
            Ipv4Addr::UNSPECIFIED
        );
    }

    #[test]
    fn test_parse_v6_addr_and_mask() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mut sa = [0u8; 28];
        sa[8..24].copy_from_slice(&ip.octets());
        sa[24..28].copy_from_slice(&3u32.to_ne_bytes());
        assert_eq!(parse_v6_addr(&sa), Some((ip, 3)));
        assert_eq!(parse_v6_addr(&sa[..20]), None);

        let mut mask = [0u8; 28];
        mask[8..16].copy_from_slice(&[0xff; 8]);
        assert_eq!(
            parse_v6_mask(Some((libc::AF_INET6, &mask))),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)
        );
    }
}
