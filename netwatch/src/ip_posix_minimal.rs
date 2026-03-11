//! IP address related utilities — minimal POSIX implementation.

use std::net::IpAddr;

use crate::interfaces::Interface;

/// List of machine's IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalAddresses {
    /// Loopback addresses.
    pub loopback: Vec<IpAddr>,
    /// Regular addresses.
    pub regular: Vec<IpAddr>,
}

impl LocalAddresses {
    /// Build local addresses from already-enumerated interfaces.
    pub(crate) fn from_interfaces<'a>(ifaces: impl Iterator<Item = &'a Interface>) -> Self {
        let mut loopback = Vec::new();
        let mut regular = Vec::new();

        for iface in ifaces {
            if !iface.is_up() {
                continue;
            }
            for pfx in iface.addrs() {
                let ip = pfx.addr();
                if ip.is_loopback() || iface.is_loopback() {
                    loopback.push(ip);
                } else {
                    regular.push(ip);
                }
            }
        }

        loopback.sort();
        regular.sort();

        LocalAddresses { loopback, regular }
    }
}
