//! IP address related utilities — fallback for platforms without `netdev`.

/// List of machine's IP addresses (stub).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalAddresses {
    /// Loopback addresses.
    pub loopback: Vec<std::net::IpAddr>,
    /// Regular addresses.
    pub regular: Vec<std::net::IpAddr>,
}
