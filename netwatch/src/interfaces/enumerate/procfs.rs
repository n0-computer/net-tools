//! `/proc/net` based gateway fallback, used when netlink route dumps fail.
//!
//! Mirrors netdev's procfs parser, including its quirks: the IPv4 pass
//! records the gateway of any gatewayed route (not just default routes),
//! later rows overwriting earlier ones per interface, while the IPv6 pass
//! only accepts real default routes.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Collects gateway addresses per interface name.
pub(super) fn gateways_by_interface_name() -> HashMap<String, (Option<Ipv4Addr>, Vec<Ipv6Addr>)> {
    let mut gateways: HashMap<String, (Option<Ipv4Addr>, Vec<Ipv6Addr>)> = HashMap::new();

    if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
        // Header line, then: Iface Destination Gateway Flags RefCnt Use
        // Metric Mask MTU Window IRTT. Destination, gateway and mask are
        // little-endian hex words.
        for line in routes.lines().skip(1) {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            let (Some(iface), Some(gateway)) = (fields.first(), fields.get(2)) else {
                continue;
            };
            if *gateway == "00000000" {
                continue;
            }
            let Some(gateway) = parse_hex_ipv4_le(gateway) else {
                continue;
            };
            gateways.entry(iface.to_string()).or_default().0 = Some(gateway);
        }
    }

    if let Ok(routes) = std::fs::read_to_string("/proc/net/ipv6_route") {
        // Fields: dest, dest prefix, source, source prefix, next hop,
        // metric, refcnt, use, flags, device.
        const ZERO_V6: &str = "00000000000000000000000000000000";
        for line in routes.lines() {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            if fields[0] != ZERO_V6 || fields[1] != "00" || fields[4] == ZERO_V6 {
                continue;
            }
            let Some(gateway) = parse_hex_ipv6(fields[4]) else {
                continue;
            };
            let iface = fields[9];
            gateways
                .entry(iface.to_string())
                .or_default()
                .1
                .push(gateway);
        }
    }

    gateways
}

/// Parses an 8-digit little-endian hex word as used in `/proc/net/route`.
fn parse_hex_ipv4_le(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    let [a, b, c, d] = value.to_le_bytes();
    Some(Ipv4Addr::new(a, b, c, d))
}

/// Parses a 32-digit hex address as used in `/proc/net/ipv6_route`.
fn parse_hex_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, octet) in octets.iter_mut().enumerate() {
        *octet = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_ipv4_le() {
        // 192.168.0.1 in little-endian word order.
        assert_eq!(
            parse_hex_ipv4_le("0100A8C0"),
            Some(Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(parse_hex_ipv4_le("00000000"), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(parse_hex_ipv4_le("123"), None);
    }

    #[test]
    fn test_parse_hex_ipv6() {
        assert_eq!(
            parse_hex_ipv6("fe800000000000000000000000000001"),
            Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(parse_hex_ipv6("fe80"), None);
    }

    #[test]
    fn test_gateways_smoke() {
        // Just verify /proc parsing does not panic on the live system.
        let gateways = gateways_by_interface_name();
        for (name, (v4, v6)) in gateways {
            assert!(!name.is_empty());
            assert!(v4.is_some() || !v6.is_empty());
        }
    }
}
