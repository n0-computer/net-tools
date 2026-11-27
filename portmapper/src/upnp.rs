use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};

use igd_next::{AddAnyPortError, GetExternalIpError, RemovePortError, SearchError, aio as aigd};
use n0_error::{e, stack_error};
use tracing::debug;

use super::Metrics;

pub type Gateway = aigd::Gateway<aigd::tokio::Tokio>;

use crate::{Config, Protocol, defaults::UPNP_SEARCH_TIMEOUT as SEARCH_TIMEOUT};

/// Seconds we ask the router to maintain the port mapping by default. Use 2 hours for now.
///
/// Tailscale uses the recommended port mapping lifetime for PMP, which is 2 hours. So we assume a
/// half lifetime of 1h. See <https://datatracker.ietf.org/doc/html/rfc6886#section-3.3>
const PORT_MAPPING_LEASE_DURATION_SECONDS: u32 = 2 * 60 * 60;

/// Shortest time between creating a mapping and renewing it.
const MIN_RENEW_AFTER: Duration = Duration::from_secs(1);

/// Name with which we register the mapping in the router.
const PORT_MAPPING_DESCRIPTION: &str = "iroh-portmap";

#[derive(derive_more::Debug, Clone)]
pub struct Mapping {
    /// Protocol for this mapping.
    protocol: igd_next::PortMappingProtocol,
    /// The internet Gateway device (router) used to create this mapping.
    #[debug("{}", gateway)]
    gateway: Gateway,
    /// The external address obtained by this mapping.
    external_ip: Ipv4Addr,
    /// External port obtained by this mapping.
    external_port: NonZeroU16,
    /// Time after which this mapping should be renewed.
    renew_after: Duration,
    /// Time after which this mapping expires.
    lease: Duration,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources, from_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("Zero external port")]
    ZeroExternalPort {},
    #[error("igd device's external ip is ipv6")]
    NotIpv4 {},
    #[error("Remove Port")]
    RemovePort { source: RemovePortError },
    #[error("Search")]
    Search { source: SearchError },
    #[error("Get external IP")]
    GetExternalIp { source: GetExternalIpError },
    #[error("Add any port")]
    AddAnyPort { source: AddAnyPortError },
    #[error("IO")]
    Io { source: std::io::Error },
}

impl Mapping {
    pub(crate) async fn new(
        config: Config,
        local_addr: Ipv4Addr,
        port: NonZeroU16,
        gateway: Option<Gateway>,
        preferred_port: Option<NonZeroU16>,
    ) -> Result<Self, Error> {
        let local_addr = SocketAddrV4::new(local_addr, port.into());

        // search for a gateway if there is not one already
        let gateway = if let Some(known_gateway) = gateway {
            known_gateway
        } else {
            let mut opts = igd_next::SearchOptions::default();
            opts.timeout = Some(SEARCH_TIMEOUT);
            aigd::tokio::search_gateway(opts).await?
        };

        let std::net::IpAddr::V4(external_ip) = gateway.get_external_ip().await? else {
            return Err(e!(Error::NotIpv4));
        };

        let protocol = match config.protocol {
            Protocol::Udp => igd_next::PortMappingProtocol::UDP,
            Protocol::Tcp => igd_next::PortMappingProtocol::TCP,
        };

        let description = config
            .mapping_description
            .as_deref()
            .unwrap_or(PORT_MAPPING_DESCRIPTION);
        // A lease of 0 means "forever" for UPnP, so request at least one second.
        let mut lease_secs = config
            .lease_duration
            .map_or(PORT_MAPPING_LEASE_DURATION_SECONDS, |d| {
                u32::try_from(d.as_secs()).unwrap_or(u32::MAX).max(1)
            });
        let add = |lease_secs| {
            add_port(
                &gateway,
                protocol,
                local_addr,
                preferred_port,
                lease_secs,
                description,
            )
        };
        let external_port = match add(lease_secs).await {
            // the gateway may not accept a custom lease, so retry with the default
            Err(Error::AddAnyPort { source, .. })
                if lease_secs != PORT_MAPPING_LEASE_DURATION_SECONDS && is_lease_error(&source) =>
            {
                debug!(
                    "upnp mapping with a lease of {lease_secs}s failed, using the default: {source}"
                );
                lease_secs = PORT_MAPPING_LEASE_DURATION_SECONDS;
                add(lease_secs).await?
            }
            res => res?,
        };

        let lease = Duration::from_secs(lease_secs.into());
        let renew_after = match config.renew_margin {
            Some(margin) => lease.saturating_sub(margin).max(MIN_RENEW_AFTER),
            None => lease / 2,
        };
        Ok(Mapping {
            protocol,
            gateway,
            external_ip,
            external_port,
            renew_after,
            lease,
        })
    }

    pub fn half_lifetime(&self) -> Duration {
        self.renew_after
    }

    pub fn expiry_after_renew(&self) -> Duration {
        self.lease - self.renew_after
    }

    /// Releases the mapping.
    pub(crate) async fn release(self) -> Result<(), Error> {
        let Mapping {
            gateway,
            external_port,
            protocol,
            ..
        } = self;
        gateway.remove_port(protocol, external_port.into()).await?;
        Ok(())
    }

    /// Returns the external gateway ip and port that can be used to contact this node.
    pub fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        (self.external_ip, self.external_port)
    }
}

/// Whether the gateway may have refused the requested lease.
///
/// Besides the typed "only permanent leases" error, some gateways answer with an arbitrary SOAP
/// fault (e.g. 402 or 501), which igd-next reports as an untyped `ErrorCode`. Errors that are not
/// about the lease (unauthorized, no free ports, IO, ...) are not worth another attempt.
fn is_lease_error(err: &AddAnyPortError) -> bool {
    matches!(
        err,
        AddAnyPortError::OnlyPermanentLeasesSupported
            | AddAnyPortError::RequestError(igd_next::RequestError::ErrorCode(..))
    )
}

/// Maps `local_addr`, preferring `preferred_port` as external port and falling back to any port.
async fn add_port(
    gateway: &Gateway,
    protocol: igd_next::PortMappingProtocol,
    local_addr: SocketAddrV4,
    preferred_port: Option<NonZeroU16>,
    lease_secs: u32,
    description: &str,
) -> Result<NonZeroU16, Error> {
    // if we are trying to get a specific external port, try this first. If this fails, default
    // to try to get any port
    if let Some(external_port) = preferred_port
        && gateway
            .add_port(
                protocol,
                external_port.into(),
                local_addr.into(),
                lease_secs,
                description,
            )
            .await
            .is_ok()
    {
        return Ok(external_port);
    }

    gateway
        .add_any_port(protocol, local_addr.into(), lease_secs, description)
        .await?
        .try_into()
        .map_err(|_| e!(Error::ZeroExternalPort))
}

/// Searches for UPnP gateways.
pub async fn probe_available(metrics: &Arc<Metrics>) -> Option<Gateway> {
    metrics.upnp_probes.inc();

    let mut opts = igd_next::SearchOptions::default();
    opts.timeout = Some(SEARCH_TIMEOUT);
    let res = aigd::tokio::search_gateway(opts).await;

    match res {
        Ok(gateway) => Some(gateway),
        Err(e) => {
            metrics.upnp_probes_failed.inc();
            debug!("upnp probe failed: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[tokio::test]
    async fn mapping_rejects_oversized_soap_response() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n")
                .await;
            let _ = stream.write_all(&vec![b' '; 4 * 1024 * 1024]).await;
            std::future::pending::<()>().await;
        });
        let gateway = Gateway {
            addr,
            root_url: "/rootDesc.xml".to_string(),
            control_url: "/ctl".to_string(),
            control_schema_url: "/scpd.xml".to_string(),
            control_schema: HashMap::new(),
            service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
            provider: aigd::tokio::Tokio,
        };
        let mapping = tokio::time::timeout(
            Duration::from_secs(5),
            Mapping::new(
                Config::default(),
                Ipv4Addr::LOCALHOST,
                NonZeroU16::new(9586).unwrap(),
                Some(gateway),
                None,
            ),
        )
        .await;
        server.abort();
        assert!(matches!(mapping, Ok(Err(_))), "{mapping:?}");
    }

    /// Serves a gateway that records `AddPortMapping` requests and rejects any lease other than
    /// `accepted_lease`, if set.
    async fn fake_gateway(
        accepted_lease: Option<u32>,
        fault_code: u16,
    ) -> (Gateway, Arc<std::sync::Mutex<Vec<String>>>) {
        let fault = format!(
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><detail><UPnPError><errorCode>{fault_code}</errorCode><errorDescription>Fault</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = if request.contains("GetExternalIPAddress") {
                    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.1</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
                } else {
                    let lease_ok = accepted_lease.is_none_or(|lease| {
                        request.contains(&format!("<NewLeaseDuration>{lease}</NewLeaseDuration>"))
                    });
                    recorded.lock().unwrap().push(request);
                    if lease_ok {
                        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>"
                    } else {
                        &fault
                    }
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        let gateway = Gateway {
            addr,
            root_url: "/rootDesc.xml".to_string(),
            control_url: "/ctl".to_string(),
            control_schema_url: "/scpd.xml".to_string(),
            control_schema: HashMap::from([(
                "AddPortMapping".to_string(),
                [
                    "NewRemoteHost",
                    "NewExternalPort",
                    "NewProtocol",
                    "NewInternalPort",
                    "NewInternalClient",
                    "NewEnabled",
                    "NewPortMappingDescription",
                    "NewLeaseDuration",
                ]
                .map(String::from)
                .to_vec(),
            )]),
            service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
            provider: aigd::tokio::Tokio,
        };
        (gateway, requests)
    }

    async fn map(config: Config, gateway: Gateway) -> Mapping {
        Mapping::new(
            config,
            Ipv4Addr::LOCALHOST,
            NonZeroU16::new(9586).unwrap(),
            Some(gateway),
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn mapping_defaults() {
        let (gateway, requests) = fake_gateway(None, 402).await;
        let mapping = map(Config::default(), gateway).await;
        let requests = requests.lock().unwrap();
        assert!(requests[0].contains("<NewLeaseDuration>7200</NewLeaseDuration>"));
        assert!(requests[0].contains("<NewPortMappingDescription>iroh-portmap<"));
        assert_eq!(mapping.half_lifetime(), Duration::from_secs(3600));
        assert_eq!(mapping.expiry_after_renew(), Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn mapping_custom_lease_and_description() {
        let (gateway, requests) = fake_gateway(None, 402).await;
        let config = Config {
            lease_duration: Some(Duration::from_secs(600)),
            renew_margin: Some(Duration::from_secs(60)),
            mapping_description: Some("custom".into()),
            ..Config::default()
        };
        let mapping = map(config, gateway).await;
        let requests = requests.lock().unwrap();
        assert!(requests[0].contains("<NewLeaseDuration>600</NewLeaseDuration>"));
        assert!(requests[0].contains("<NewPortMappingDescription>custom<"));
        assert_eq!(mapping.half_lifetime(), Duration::from_secs(540));
        assert_eq!(mapping.expiry_after_renew(), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn mapping_falls_back_to_default_lease() {
        let (gateway, requests) =
            fake_gateway(Some(PORT_MAPPING_LEASE_DURATION_SECONDS), 402).await;
        let config = Config {
            lease_duration: Some(Duration::from_secs(600)),
            ..Config::default()
        };
        let mapping = map(config, gateway).await;
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("<NewLeaseDuration>600</NewLeaseDuration>"));
        assert!(requests[1].contains("<NewLeaseDuration>7200</NewLeaseDuration>"));
        assert_eq!(mapping.half_lifetime(), Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn mapping_does_not_retry_non_lease_errors() {
        // 606: not authorized, unrelated to the lease
        let (gateway, requests) = fake_gateway(Some(0), 606).await;
        let config = Config {
            lease_duration: Some(Duration::from_secs(600)),
            ..Config::default()
        };
        let res = Mapping::new(
            config,
            Ipv4Addr::LOCALHOST,
            NonZeroU16::new(9586).unwrap(),
            Some(gateway),
            None,
        )
        .await;
        assert!(res.is_err(), "{res:?}");
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn mapping_renew_margin_covering_lease_renews_after_floor() {
        let (gateway, _) = fake_gateway(None, 402).await;
        let config = Config {
            lease_duration: Some(Duration::from_secs(600)),
            renew_margin: Some(Duration::from_secs(600)),
            ..Config::default()
        };
        let mapping = map(config, gateway).await;
        assert_eq!(mapping.half_lifetime(), MIN_RENEW_AFTER);
    }
}
