//! Windows interface enumeration via `GetAdaptersAddresses`.
//!
//! Mirrors what netdev did on windows: every adapter is reported
//! (loopback and tunnels included), interface flags are synthesized from
//! the operational status and interface type using winsock `IFF_*`
//! values, and the default gateway requires an ARP-resolvable IPv4
//! gateway on the adapter owning the local IP.
//!
//! The unsafe surface is confined to the [`Adapters`] buffer wrapper and
//! its accessors; the enumeration logic itself is safe code.

use std::{
    ffi::CStr,
    net::{IpAddr, Ipv4Addr},
};

use ipnet::{Ipv4Net, Ipv6Net};
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            GAA_FLAG_INCLUDE_GATEWAYS, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
            IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_UNICAST_ADDRESS_LH, SendARP,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated, IpDadStateDuplicate,
        IpDadStateTentative, IpSuffixOriginRandom, SOCKADDR_INET, SOCKET_ADDRESS,
    },
};

use super::{IfaceBuilder, Interface, Ipv6AddrFlags};

// Winsock interface flag values; these differ from the POSIX ones
// (loopback is 0x4 here, 0x8 there). netdev synthesized flags from these
// values, so keeping them preserves the meaning of `Interface::flags` on
// windows.
const IFF_UP: u32 = 1;
const IFF_BROADCAST: u32 = 2;
const IFF_LOOPBACK: u32 = 4;
const IFF_POINTTOPOINT: u32 = 8;
const IFF_MULTICAST: u32 = 16;

/// Enumerates the machine's network interfaces.
///
/// Returns an empty list when the adapter query fails; there is no error
/// channel, matching the behavior callers have relied on so far.
pub(super) fn interfaces() -> Vec<Interface> {
    let Some(adapters) = Adapters::load() else {
        return Vec::new();
    };

    let mut interfaces = Vec::new();
    for adapter in adapters.iter() {
        let mut builder = IfaceBuilder::new(
            adapter_name(adapter),
            adapter_index(adapter),
            adapter_flags(adapter),
        );
        if adapter.PhysicalAddressLength == 6 {
            builder.mac = adapter.PhysicalAddress[..6].try_into().ok();
        }

        for unicast in unicast_addrs(adapter) {
            let Some((ip, scope_id)) = socket_address_to_ip(adapter, &unicast.Address) else {
                continue;
            };
            match ip {
                IpAddr::V4(ip) => {
                    // An out-of-range prefix drops the address, as it
                    // always has.
                    if let Ok(net) = Ipv4Net::new(ip, unicast.OnLinkPrefixLength) {
                        builder.push_v4(net);
                    }
                }
                IpAddr::V6(ip) => {
                    if let Ok(net) = Ipv6Net::new(ip, unicast.OnLinkPrefixLength) {
                        // No link-local ifindex fallback here: windows
                        // reports real scope IDs.
                        builder.push_v6(net, scope_id, unicast_v6_flags(unicast));
                    }
                }
            }
        }

        interfaces.push(builder.finish());
    }
    interfaces
}

/// The gateway address of the default route.
///
/// netdev's rules, preserved: the adapter must own the local IP the OS
/// routes outbound traffic through, be up, and have an IPv4 gateway whose
/// MAC resolves via ARP; the first IPv4 gateway wins. An adapter with
/// only an IPv6 gateway yields nothing, like it did with netdev.
pub(super) fn default_gateway() -> Option<IpAddr> {
    let local_ip = super::local_ip()?;
    let adapters = Adapters::load()?;

    for adapter in adapters.iter() {
        if adapter_flags(adapter) & IFF_UP == 0 {
            continue;
        }

        let mut v4_addrs = Vec::new();
        let mut owns_local_ip = false;
        for unicast in unicast_addrs(adapter) {
            let Some((ip, _)) = socket_address_to_ip(adapter, &unicast.Address) else {
                continue;
            };
            owns_local_ip |= ip == local_ip;
            if let IpAddr::V4(ip) = ip {
                v4_addrs.push(ip);
            }
        }
        if !owns_local_ip {
            continue;
        }

        for gateway in gateway_addrs(adapter) {
            let Some((IpAddr::V4(gateway), _)) = socket_address_to_ip(adapter, &gateway.Address)
            else {
                continue;
            };
            let Some(src) = v4_addrs.first() else {
                continue;
            };
            if arp_resolves(*src, gateway) {
                return Some(IpAddr::V4(gateway));
            }
        }
    }
    None
}

/// The adapter list returned by `GetAdaptersAddresses`.
///
/// Owns the backing buffer; all adapter references and the pointers
/// inside them stay valid for as long as this value lives, which is what
/// the accessor functions below rely on.
struct Adapters {
    buf: Vec<u8>,
}

impl Adapters {
    /// Queries the adapter list, growing the buffer up to three times as
    /// `GetAdaptersAddresses` requests.
    fn load() -> Option<Self> {
        // 15k is the size MSDN recommends to avoid the second call.
        let mut buf: Vec<u8> = Vec::with_capacity(15000);
        let mut retries = 3;
        loop {
            let mut size = buf.capacity() as u32;
            // SAFETY: the buffer is valid for writes of `size` bytes, and
            // on success the call wrote `size` bytes (bounded by the
            // capacity).
            let res = unsafe {
                let res = GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    GAA_FLAG_INCLUDE_GATEWAYS,
                    None,
                    Some(buf.as_mut_ptr().cast()),
                    &mut size,
                );
                if res == NO_ERROR.0 {
                    buf.set_len(size as usize);
                }
                res
            };
            if res == NO_ERROR.0 {
                return Some(Self { buf });
            } else if res == ERROR_BUFFER_OVERFLOW.0 && retries > 0 {
                buf.reserve(size as usize);
                retries -= 1;
            } else {
                return None;
            }
        }
    }

    /// Iterates the adapters in the list.
    fn iter(&self) -> impl Iterator<Item = &IP_ADAPTER_ADDRESSES_LH> {
        iter_list(
            self.buf.as_ptr().cast(),
            |adapter: &IP_ADAPTER_ADDRESSES_LH| adapter.Next.cast_const(),
        )
    }
}

/// Iterates the unicast addresses of an adapter.
fn unicast_addrs(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
) -> impl Iterator<Item = &IP_ADAPTER_UNICAST_ADDRESS_LH> {
    iter_list(
        adapter.FirstUnicastAddress.cast_const().cast(),
        |unicast: &IP_ADAPTER_UNICAST_ADDRESS_LH| unicast.Next.cast_const(),
    )
}

/// Iterates the gateway addresses of an adapter.
fn gateway_addrs(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
) -> impl Iterator<Item = &IP_ADAPTER_GATEWAY_ADDRESS_LH> {
    iter_list(adapter.FirstGatewayAddress.cast_const(), |gateway| {
        gateway.Next.cast_const()
    })
}

/// The adapter name (its GUID string).
fn adapter_name(adapter: &IP_ADAPTER_ADDRESSES_LH) -> String {
    // SAFETY: AdapterName is a NUL-terminated ANSI string owned by the
    // adapter buffer.
    let name = unsafe { CStr::from_ptr(adapter.AdapterName.0.cast()) };
    name.to_string_lossy().into_owned()
}

/// The adapter's interface index; may be zero when IPv4 is disabled.
fn adapter_index(adapter: &IP_ADAPTER_ADDRESSES_LH) -> u32 {
    // SAFETY: reading the IfIndex variant of the union is always valid;
    // both variants are plain integers.
    unsafe { adapter.Anonymous1.Anonymous.IfIndex }
}

/// Iterates a `Next`-linked list of structs inside the adapter buffer.
///
/// The returned references borrow from the start pointer's referent, so
/// they cannot outlive the [`Adapters`] buffer they point into.
fn iter_list<'a, T: 'a>(
    mut ptr: *const T,
    next: fn(&T) -> *const T,
) -> impl Iterator<Item = &'a T> {
    std::iter::from_fn(move || {
        // SAFETY: the pointer is null or points into the live adapter
        // buffer the caller borrows from.
        let current = unsafe { ptr.as_ref() }?;
        ptr = next(current);
        Some(current)
    })
}

/// Synthesizes BSD-style flags from the adapter state and type.
fn adapter_flags(adapter: &IP_ADAPTER_ADDRESSES_LH) -> u32 {
    let mut flags = 0;
    if adapter.OperStatus == IfOperStatusUp {
        flags |= IFF_UP;
    }
    // Raw IANA ifType values, as netdev matched them.
    flags |= match adapter.IfType {
        // ethernet, token ring, 802.11 wireless, IEEE 1394
        6 | 9 | 71 | 144 => IFF_BROADCAST | IFF_MULTICAST,
        // PPP, tunnel
        23 | 131 => IFF_POINTTOPOINT | IFF_MULTICAST,
        // software loopback
        24 => IFF_LOOPBACK | IFF_MULTICAST,
        // ATM
        37 => IFF_BROADCAST | IFF_POINTTOPOINT | IFF_MULTICAST,
        _ => 0,
    };
    flags
}

/// Maps the address' duplicate-address-detection state and suffix origin
/// into [`Ipv6AddrFlags`].
fn unicast_v6_flags(unicast: &IP_ADAPTER_UNICAST_ADDRESS_LH) -> Ipv6AddrFlags {
    Ipv6AddrFlags {
        deprecated: unicast.DadState == IpDadStateDeprecated,
        temporary: unicast.SuffixOrigin == IpSuffixOriginRandom,
        tentative: unicast.DadState == IpDadStateTentative,
        duplicated: unicast.DadState == IpDadStateDuplicate,
        // Not reported on windows.
        permanent: false,
    }
}

/// Parses a `SOCKET_ADDRESS`, returning the address and, for IPv6, the
/// scope ID.
///
/// The unused adapter argument pins down that the sockaddr pointer
/// borrows from the adapter buffer, which guarantees it is null or
/// points to a sockaddr at least as large as its family's
/// `SOCKADDR_IN`/`SOCKADDR_IN6`.
fn socket_address_to_ip(
    _owner: &IP_ADAPTER_ADDRESSES_LH,
    address: &SOCKET_ADDRESS,
) -> Option<(IpAddr, u32)> {
    // SAFETY: the sockaddr lives in the adapter buffer (see above);
    // si_family overlaps the family field of both union variants and
    // selects which one is initialized.
    unsafe {
        let sockaddr = address.lpSockaddr.cast::<SOCKADDR_INET>().as_ref()?;
        let family = sockaddr.si_family;
        if family == AF_INET {
            let octets = sockaddr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
            Some((IpAddr::V4(Ipv4Addr::from(octets)), 0))
        } else if family == AF_INET6 {
            let ip = IpAddr::from(sockaddr.Ipv6.sin6_addr.u.Byte);
            // Both variants of the scope union are a u32.
            let scope_id = sockaddr.Ipv6.Anonymous.sin6_scope_id;
            Some((ip, scope_id))
        } else {
            None
        }
    }
}

/// Reports whether the gateway's MAC address resolves via ARP.
///
/// netdev used the resolved MAC only as a liveness gate for the gateway,
/// and so do we.
fn arp_resolves(src: Ipv4Addr, dst: Ipv4Addr) -> bool {
    let mut mac = [0u8; 6];
    let mut mac_len = mac.len() as u32;
    // SAFETY: `mac` is valid for writes of `mac_len` bytes.
    let res = unsafe {
        SendARP(
            u32::from_ne_bytes(dst.octets()),
            u32::from_ne_bytes(src.octets()),
            mac.as_mut_ptr().cast(),
            &mut mac_len,
        )
    };
    res == NO_ERROR.0 && mac_len == 6 && mac != [0u8; 6]
}
