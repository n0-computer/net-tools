//! Linux-specific network interfaces implementations.

use n0_error::{e, stack_error};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

use super::DefaultRouteDetails;
pub(super) use super::netdev_impl::{get_state, home_router};

#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("IO")]
    Io { source: std::io::Error },
    #[cfg(not(target_os = "android"))]
    #[error("no netlink response")]
    NoResponse {},
    #[cfg(not(target_os = "android"))]
    #[error("interface not found")]
    InterfaceNotFound {},
    #[error("iface field is missing")]
    MissingIfaceField {},
    #[error("destination field is missing")]
    MissingDestinationField {},
    #[error("mask field is missing")]
    MissingMaskField {},
    #[cfg(not(target_os = "android"))]
    #[error("netlink")]
    Netlink { source: netwatch_netlink::Error },
}

pub async fn default_route() -> Option<DefaultRouteDetails> {
    // /proc/net/route only contains IPv4 routes. If it finds one, return it.
    // If it returns Ok(None) (no IPv4 default route) or Err (file unreadable),
    // fall through to netlink which checks both IPv4 and IPv6.
    if let Ok(Some(route)) = default_route_proc().await {
        return Some(route);
    }

    #[cfg(target_os = "android")]
    let res = android::default_route().await;

    #[cfg(not(target_os = "android"))]
    let res = sane::default_route().await;

    res.ok().flatten()
}

const PROC_NET_ROUTE_PATH: &str = "/proc/net/route";

async fn default_route_proc() -> Result<Option<DefaultRouteDetails>, Error> {
    const ZERO_ADDR: &str = "00000000";
    let file = File::open(PROC_NET_ROUTE_PATH).await?;

    // Explicitly set capacity, this is min(4096, DEFAULT_BUF_SIZE):
    // https://github.com/google/gvisor/issues/5732
    // On a regular Linux kernel you can read the first 128 bytes of /proc/net/route,
    // then come back later to read the next 128 bytes and so on.
    //
    // In Google Cloud Run, where /proc/net/route comes from gVisor, you have to
    // read it all at once. If you read only the first few bytes then the second
    // read returns 0 bytes no matter how much originally appeared to be in the file.
    //
    // At the time of this writing (Mar 2021) Google Cloud Run has eth0 and eth1
    // with a 384 byte /proc/net/route. We allocate a large buffer to ensure we'll
    // read it all in one call.
    let reader = BufReader::with_capacity(8 * 1024, file);
    let mut lines_iter = reader.lines();
    while let Some(line) = lines_iter.next_line().await? {
        if !line.contains(ZERO_ADDR) {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let iface = fields.next().ok_or_else(|| e!(Error::MissingIfaceField))?;
        let destination = fields
            .next()
            .ok_or_else(|| e!(Error::MissingDestinationField))?;
        let mask = fields.nth(5).ok_or_else(|| e!(Error::MissingMaskField))?;
        // if iface.starts_with("tailscale") || iface.starts_with("wg") {
        //     continue;
        // }
        if destination == ZERO_ADDR && mask == ZERO_ADDR {
            return Ok(Some(DefaultRouteDetails {
                interface_name: iface.to_string(),
            }));
        }
    }
    Ok(None)
}

#[cfg(target_os = "android")]
mod android {
    use tokio::process::Command;

    use super::*;

    /// Try find the default route by parsing the "ip route" command output.
    ///
    /// We use this on Android where /proc/net/route can be missing entries or have locked-down
    /// permissions.  See also comments in <https://github.com/tailscale/tailscale/pull/666>.
    pub async fn default_route() -> Result<Option<DefaultRouteDetails>, Error> {
        const IP_PATHS: &[&str] = &["/system/bin/ip", "/system/xbin/ip", "ip"];
        for path in IP_PATHS {
            let output = match Command::new(path)
                .args(["route", "show", "table", "0"])
                .kill_on_drop(true)
                .output()
                .await
            {
                Ok(output) => output,
                Err(err) => {
                    tracing::debug!(%path, ?err, "ip command not available, trying next");
                    continue;
                }
            };
            let stdout = std::string::String::from_utf8_lossy(&output.stdout);
            let details = parse_android_ip_route(&stdout).map(|iface| DefaultRouteDetails {
                interface_name: iface.to_string(),
            });
            return Ok(details);
        }
        Err(e!(Error::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "ip command not found at any known path"
            )
        }))
    }
}

#[cfg(not(target_os = "android"))]
mod sane {
    use n0_error::e;
    use netwatch_netlink::{AsyncConnection, RouteFamily};

    use super::*;

    pub async fn default_route() -> Result<Option<DefaultRouteDetails>, Error> {
        let mut conn = AsyncConnection::new().map_err(|err| e!(Error::Netlink, err))?;

        let default = default_route_netlink_family(&mut conn, RouteFamily::Ipv4).await?;
        let default = match default {
            Some(default) => Some(default),
            None => default_route_netlink_family(&mut conn, RouteFamily::Ipv6).await?,
        };
        Ok(default.map(|(name, _index)| DefaultRouteDetails {
            interface_name: name,
        }))
    }

    /// Returns the `(name, index)` of the interface for the default route.
    async fn default_route_netlink_family(
        conn: &mut AsyncConnection,
        family: RouteFamily,
    ) -> Result<Option<(String, u32)>, Error> {
        let routes = conn.dump_routes(family).await?;
        for route in routes {
            if route.gateway.is_none() {
                // A default route has a gateway.
                continue;
            }
            if route.dst_len > 0 {
                // A default route has no destination prefix length because it needs to route all
                // destinations.
                continue;
            }
            let Some(index) = route.oif else {
                continue;
            };
            if index == 0 {
                continue;
            }
            let name = iface_by_index(conn, index).await?;
            return Ok(Some((name, index)));
        }
        Ok(None)
    }

    async fn iface_by_index(conn: &mut AsyncConnection, index: u32) -> Result<String, Error> {
        let link = conn
            .get_link_by_index(index)
            .await?
            .ok_or_else(|| e!(Error::NoResponse))?;
        link.name.ok_or_else(|| e!(Error::InterfaceNotFound))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn test_default_route_netlink() {
            let route = default_route().await.unwrap();
            // assert!(route.is_some());
            if let Some(route) = route {
                assert!(!route.interface_name.is_empty());
            }
        }
    }
}

/// Parses the output of the android `/system/bin/ip` command for the default route.
///
/// Searches for line like `default via 10.0.2.2. dev radio0 table 1016 proto static mtu
/// 1500`
#[cfg(any(target_os = "android", test))]
fn parse_android_ip_route(stdout: &str) -> Option<&str> {
    for line in stdout.lines() {
        if !line.starts_with("default via") {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        if let Some(_dev) = fields.find(|s: &&str| *s == "dev") {
            return fields.next();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_route_proc() {
        let route = default_route_proc().await.unwrap();
        // assert!(route.is_some());
        if let Some(route) = route {
            assert!(!route.interface_name.is_empty());
        }
    }

    #[test]
    fn test_parse_android_ip_route() {
        let stdout = "default via 10.0.2.2. dev radio0 table 1016 proto static mtu 1500";
        let iface = parse_android_ip_route(stdout).unwrap();
        assert_eq!(iface, "radio0");
    }
}
