//! Windows interface enumeration via `GetAdaptersAddresses`.
//!
//! Mirrors what netdev did on windows: every adapter is reported
//! (loopback and tunnels included), interface flags are synthesized from
//! the operational status and interface type using winsock `IFF_*`
//! values, and the default gateway requires an ARP-resolvable IPv4
//! gateway on the adapter owning the local IP.

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
            IP_ADAPTER_UNICAST_ADDRESS_LH, SendARP,
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
    let Some(buf) = adapters_buffer() else {
        return Vec::new();
    };

    let mut interfaces = Vec::new();
    for adapter in iter_list(buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(), |a| {
        a.Next.cast_const()
    }) {
        // SAFETY: AdapterName is a NUL-terminated ANSI string (the
        // adapter GUID) owned by the buffer.
        let name = unsafe { CStr::from_ptr(adapter.AdapterName.0.cast()) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: reading the IfIndex variant of the union is always
        // valid; both variants are plain integers.
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };

        let mut builder = IfaceBuilder::new(name, index, adapter_flags(adapter));
        if adapter.PhysicalAddressLength == 6 {
            builder.mac = adapter.PhysicalAddress[..6].try_into().ok();
        }

        for unicast in iter_list(
            adapter
                .FirstUnicastAddress
                .cast_const()
                .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
            |u| u.Next.cast_const(),
        ) {
            // SAFETY: the SOCKET_ADDRESS points into the adapter buffer.
            let Some((ip, scope_id)) = (unsafe { socket_address_to_ip(&unicast.Address) }) else {
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
    let buf = adapters_buffer()?;

    for adapter in iter_list(buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(), |a| {
        a.Next.cast_const()
    }) {
        if adapter_flags(adapter) & IFF_UP == 0 {
            continue;
        }

        let mut v4_addrs = Vec::new();
        let mut owns_local_ip = false;
        for unicast in iter_list(
            adapter
                .FirstUnicastAddress
                .cast_const()
                .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
            |u| u.Next.cast_const(),
        ) {
            // SAFETY: the SOCKET_ADDRESS points into the adapter buffer.
            let Some((ip, _)) = (unsafe { socket_address_to_ip(&unicast.Address) }) else {
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

        for gateway in iter_list(adapter.FirstGatewayAddress.cast_const(), |g| {
            g.Next.cast_const()
        }) {
            // SAFETY: as above.
            let Some((IpAddr::V4(gateway), _)) =
                (unsafe { socket_address_to_ip(&gateway.Address) })
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

/// Queries the adapter list, growing the buffer up to three times as
/// `GetAdaptersAddresses` requests.
fn adapters_buffer() -> Option<Vec<u8>> {
    // 15k is the size MSDN recommends to avoid the second call.
    let mut buf: Vec<u8> = Vec::with_capacity(15000);
    let mut retries = 3;
    loop {
        let mut size = buf.capacity() as u32;
        // SAFETY: the buffer is valid for writes of `size` bytes.
        let res = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_GATEWAYS,
                None,
                Some(buf.as_mut_ptr().cast()),
                &mut size,
            )
        };
        if res == NO_ERROR.0 {
            // SAFETY: the call wrote `size` bytes (bounded by capacity).
            unsafe { buf.set_len(size as usize) };
            return Some(buf);
        } else if res == ERROR_BUFFER_OVERFLOW.0 && retries > 0 {
            buf.reserve(size as usize);
            retries -= 1;
        } else {
            return None;
        }
    }
}

/// Iterates a `Next`-linked list of structs inside the adapter buffer.
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
/// # Safety
///
/// `address.lpSockaddr` must be null or point to a sockaddr at least as
/// large as its family's `SOCKADDR_IN`/`SOCKADDR_IN6`, as the adapter
/// buffer guarantees.
unsafe fn socket_address_to_ip(address: &SOCKET_ADDRESS) -> Option<(IpAddr, u32)> {
    // SAFETY: per the caller contract.
    let sockaddr = unsafe { address.lpSockaddr.cast::<SOCKADDR_INET>().as_ref() }?;
    // SAFETY: si_family overlaps the family field of both variants.
    let family = unsafe { sockaddr.si_family };
    if family == AF_INET {
        // SAFETY: family says this is a SOCKADDR_IN.
        let octets = unsafe { sockaddr.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes();
        Some((IpAddr::V4(Ipv4Addr::from(octets)), 0))
    } else if family == AF_INET6 {
        // SAFETY: family says this is a SOCKADDR_IN6.
        let ip = IpAddr::from(unsafe { sockaddr.Ipv6.sin6_addr.u.Byte });
        // SAFETY: both union variants are a u32.
        let scope_id = unsafe { sockaddr.Ipv6.Anonymous.sin6_scope_id };
        Some((ip, scope_id))
    } else {
        None
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
