//! Definitions and utilities to interact with a PCP server.

use std::{net::Ipv4Addr, num::NonZeroU16, time::Duration};

use nested_enum_utils::common_fields;
use netwatch::UdpSocket;
use rand::RngCore;
use snafu::{Backtrace, ResultExt, Snafu};
use tracing::{debug, trace};

use crate::defaults::PCP_RECV_TIMEOUT as RECV_TIMEOUT;

mod protocol;

/// Use the recommended port mapping lifetime for PMP, which is 2 hours. See
/// <https://datatracker.ietf.org/doc/html/rfc6886#section-3.3>
const MAPPING_REQUESTED_LIFETIME_SECONDS: u32 = 60 * 60;

/// A mapping successfully registered with a PCP server.
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
    external_address: Ipv4Addr,
    /// Allowed time for this mapping as informed by the server.
    lifetime_seconds: u32,
    /// The nonce of the mapping, used for modifications with the PCP server, for example releasing
    /// the mapping.
    nonce: [u8; 12],
}

#[common_fields({
    backtrace: Option<Backtrace>,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("received nonce does not match sent request"))]
    NonceMissmatch {},
    #[snafu(display("received mapping is not for UDP"))]
    ProtocolMissmatch {},
    #[snafu(display(
        "received mapping is for a local port that does not match the requested one"
    ))]
    PortMissmatch {},
    #[snafu(display("received 0 external port for mapping"))]
    ZeroExternalPort {},
    #[snafu(display("received external address is not ipv4"))]
    NotIpv4 {},
    #[snafu(display("received an announce response for a map request"))]
    InvalidAnnounce {},
    #[snafu(display("IO error during PCP"))]
    Io { source: std::io::Error },
    #[snafu(display("Protocol error during PCP"))]
    Protocol { source: protocol::Error },
}

impl super::mapping::PortMapped for Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        (self.external_address, self.external_port)
    }

    fn half_lifetime(&self) -> Duration {
        Duration::from_secs((self.lifetime_seconds / 2).into())
    }
}

impl Mapping {
    /// Attempt to registered a new mapping with the PCP server on the provided gateway.
    pub async fn new(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        preferred_external_address: Option<(Ipv4Addr, NonZeroU16)>,
    ) -> Result<Self, Error> {
        // create the socket and send the request
        let socket = UdpSocket::bind_full((local_ip, 0)).context(IoSnafu)?;
        socket
            .connect((gateway, protocol::SERVER_PORT).into())
            .context(IoSnafu)?;

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let (requested_address, requested_port) = match preferred_external_address {
            Some((ip, port)) => (Some(ip), Some(port.into())),
            None => (None, None),
        };

        let req = protocol::Request::mapping(
            nonce,
            local_port.into(),
            local_ip,
            requested_port,
            requested_address,
            MAPPING_REQUESTED_LIFETIME_SECONDS,
        );

        socket.send(&req.encode()).await.context(IoSnafu)?;

        // wait for the response and decode it
        let mut buffer = vec![0; protocol::Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout".to_string())
            })
            .context(IoSnafu)?
            .context(IoSnafu)?;
        let response = protocol::Response::decode(&buffer[..read]).context(ProtocolSnafu)?;

        // verify that the response is correct and matches the request
        let protocol::Response {
            lifetime_seconds,
            epoch_time: _,
            data,
        } = response;

        match data {
            protocol::OpcodeData::MapData(map_data) => {
                let protocol::MapData {
                    nonce: received_nonce,
                    protocol,
                    local_port: received_local_port,
                    external_port,
                    external_address,
                } = map_data;

                if nonce != received_nonce {
                    return Err(NonceMissmatchSnafu.build());
                }

                if protocol != protocol::MapProtocol::Udp {
                    return Err(ProtocolMissmatchSnafu.build());
                }

                let sent_port: u16 = local_port.into();
                if received_local_port != sent_port {
                    return Err(PortMissmatchSnafu.build());
                }
                let external_port = external_port
                    .try_into()
                    .map_err(|_| ZeroExternalPortSnafu.build())?;

                let external_address = external_address
                    .to_ipv4_mapped()
                    .ok_or(NotIpv4Snafu.build())?;

                Ok(Mapping {
                    external_port,
                    external_address,
                    lifetime_seconds,
                    nonce,
                    local_ip,
                    local_port,
                    gateway,
                })
            }
            protocol::OpcodeData::Announce => Err(InvalidAnnounceSnafu.build()),
        }
    }

    pub async fn release(self) -> Result<(), Error> {
        let Mapping {
            nonce,
            local_ip,
            local_port,
            gateway,
            ..
        } = self;

        // create the socket and send the request
        let socket = UdpSocket::bind_full((local_ip, 0)).context(IoSnafu)?;
        socket
            .connect((gateway, protocol::SERVER_PORT).into())
            .context(IoSnafu)?;

        let local_port = local_port.into();
        let req = protocol::Request::mapping(nonce, local_port, local_ip, None, None, 0);

        socket.send(&req.encode()).await.context(IoSnafu)?;

        // mapping deletion is a notification, no point in waiting for the response
        Ok(())
    }
}

/// Probes the local gateway for PCP support.
pub async fn probe_available(local_ip: Ipv4Addr, gateway: Ipv4Addr) -> bool {
    match probe_available_fallible(local_ip, gateway).await {
        Ok(response) => {
            trace!("probe response: {response:?}");
            let protocol::Response {
                lifetime_seconds: _,
                epoch_time: _,
                data,
            } = response;
            match data {
                protocol::OpcodeData::Announce => true,
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
) -> Result<protocol::Response, Error> {
    // create the socket and send the request
    let socket = UdpSocket::bind_full((local_ip, 0)).context(IoSnafu)?;
    socket
        .connect((gateway, protocol::SERVER_PORT).into())
        .context(IoSnafu)?;
    let req = protocol::Request::announce(local_ip.to_ipv6_mapped());
    socket.send(&req.encode()).await.context(IoSnafu)?;

    // wait for the response and decode it
    let mut buffer = vec![0; protocol::Response::MAX_SIZE];
    let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout".to_string()))
        .context(IoSnafu)?
        .context(IoSnafu)?;
    let response = protocol::Response::decode(&buffer[..read]).context(ProtocolSnafu)?;

    Ok(response)
}
