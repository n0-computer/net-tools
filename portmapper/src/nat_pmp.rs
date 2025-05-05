//! Definitions and utilities to interact with a NAT-PMP server.

use std::{net::Ipv4Addr, num::NonZeroU16, time::Duration};

use nested_enum_utils::common_fields;
use netwatch::UdpSocket;
use snafu::{Backtrace, Snafu};
use tracing::{debug, trace};

use self::protocol::{MapProtocol, Request, Response};
use crate::defaults::NAT_PMP_RECV_TIMEOUT as RECV_TIMEOUT;

mod protocol;

/// Recommended lifetime is 2 hours. See [RFC 6886 Requesting a
/// Mapping](https://datatracker.ietf.org/doc/html/rfc6886#section-3.3).
const MAPPING_REQUESTED_LIFETIME_SECONDS: u32 = 60 * 60 * 2;

/// A mapping successfully registered with a NAT-PMP server.
#[derive(Debug)]
pub struct Mapping {
    /// Local ip used to create this mapping.
    local_ip: Ipv4Addr,
    /// Local port used to create this mapping.
    local_port: NonZeroU16,
    /// Gateway address used to registered this mapping.
    gateway: Ipv4Addr,
    /// External port of the mapping.
    external_port: NonZeroU16,
    /// External address of the mapping.
    external_addr: Ipv4Addr,
    /// Allowed time for this mapping as informed by the server.
    lifetime_seconds: u32,
}

#[common_fields({
    backtrace: Option<Backtrace>
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("server returned unexpected response for mapping request"))]
    UnexpectedServerResponse {},
    #[snafu(display("received 0 port from server as external port"))]
    ZeroExternalPort {},
    #[snafu(transparent)]
    Io { source: std::io::Error },
    #[snafu(transparent)]
    Protocol { source: protocol::Error },
}

impl super::mapping::PortMapped for Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        (self.external_addr, self.external_port)
    }

    fn half_lifetime(&self) -> Duration {
        Duration::from_secs((self.lifetime_seconds / 2).into())
    }
}

impl Mapping {
    /// Attempt to register a new mapping with the NAT-PMP server on the provided gateway.
    pub async fn new(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        external_port: Option<NonZeroU16>,
    ) -> Result<Self, Error> {
        // create the socket and send the request
        let socket = UdpSocket::bind_full((local_ip, 0))?;
        socket.connect((gateway, protocol::SERVER_PORT).into())?;

        let req = Request::Mapping {
            proto: MapProtocol::Udp,
            local_port: local_port.into(),
            external_port: external_port.map(Into::into).unwrap_or_default(),
            lifetime_seconds: MAPPING_REQUESTED_LIFETIME_SECONDS,
        };

        socket.send(&req.encode()).await?;

        // wait for the response and decode it
        let mut buffer = vec![0; Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout".to_string())
            })??;
        let response = Response::decode(&buffer[..read])?;

        let (external_port, lifetime_seconds) = match response {
            Response::PortMap {
                proto: MapProtocol::Udp,
                epoch_time: _,
                private_port,
                external_port,
                lifetime_seconds,
            } if private_port == Into::<u16>::into(local_port) => (external_port, lifetime_seconds),
            _ => return Err(UnexpectedServerResponseSnafu.build()),
        };

        let external_port = external_port
            .try_into()
            .map_err(|_| ZeroExternalPortSnafu.build())?;

        // now send the second request to get the external address
        let req = Request::ExternalAddress;
        socket.send(&req.encode()).await?;

        // wait for the response and decode it
        let mut buffer = vec![0; Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout".to_string())
            })??;
        let response = Response::decode(&buffer[..read])?;

        let external_addr = match response {
            Response::PublicAddress {
                epoch_time: _,
                public_ip,
            } => public_ip,
            _ => return Err(UnexpectedServerResponseSnafu.build()),
        };

        Ok(Mapping {
            external_port,
            external_addr,
            lifetime_seconds,
            local_ip,
            local_port,
            gateway,
        })
    }

    /// Releases the mapping.
    pub(crate) async fn release(self) -> Result<(), Error> {
        // A client requests explicit deletion of a mapping by sending a message to the NAT gateway
        // requesting the mapping, with the Requested Lifetime in Seconds set to zero. The
        // Suggested External Port MUST be set to zero by the client on sending

        let Mapping {
            local_ip,
            local_port,
            gateway,
            ..
        } = self;

        // create the socket and send the request
        let socket = UdpSocket::bind_full((local_ip, 0))?;
        socket.connect((gateway, protocol::SERVER_PORT).into())?;

        let req = Request::Mapping {
            proto: MapProtocol::Udp,
            local_port: local_port.into(),
            external_port: 0,
            lifetime_seconds: 0,
        };

        socket.send(&req.encode()).await?;

        // mapping deletion is a notification, no point in waiting for the response
        Ok(())
    }
}

/// Probes the local gateway for NAT-PMP support.
pub async fn probe_available(local_ip: Ipv4Addr, gateway: Ipv4Addr) -> bool {
    match probe_available_fallible(local_ip, gateway).await {
        Ok(response) => {
            trace!("probe response: {response:?}");
            match response {
                Response::PublicAddress { .. } => true,
                _ => {
                    debug!("server returned an unexpected response type for probe");
                    // missbehaving server is not useful
                    false
                }
            }
        }
        Err(e) => {
            debug!("probe failed: {e}");
            false
        }
    }
}

async fn probe_available_fallible(
    local_ip: Ipv4Addr,
    gateway: Ipv4Addr,
) -> Result<Response, Error> {
    // create the socket and send the request
    let socket = UdpSocket::bind_full((local_ip, 0))?;
    socket.connect((gateway, protocol::SERVER_PORT).into())?;
    let req = Request::ExternalAddress;
    socket.send(&req.encode()).await?;

    // wait for the response and decode it
    let mut buffer = vec![0; Response::MAX_SIZE];
    let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout".to_string())
        })??;
    let response = Response::decode(&buffer[..read])?;

    Ok(response)
}
