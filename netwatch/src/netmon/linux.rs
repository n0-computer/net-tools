use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use libc::{
    RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_IFADDR,
    RTNLGRP_IPV6_ROUTE, RTNLGRP_IPV6_RULE,
};
use n0_error::stack_error;
use n0_future::{
    task::AbortOnDropHandle,
    time::{self, Duration},
};
use netwatch_netlink::{EventSocket, Message, group_flag};
use tokio::sync::mpsc;
use tracing::{trace, warn};

use super::actor::NetworkMessage;
use crate::ip::is_link_local;

#[derive(Debug)]
pub(super) struct RouteMonitor {
    _handle: AbortOnDropHandle<()>,
}

#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("IO")]
    Io { source: std::io::Error },
}

/// Subscribes to the rtnetlink groups netwatch reacts to: address, route
/// and rule changes for both address families.
fn subscribe() -> Result<EventSocket, netwatch_netlink::Error> {
    let groups = group_flag(RTNLGRP_IPV4_IFADDR)
        | group_flag(RTNLGRP_IPV6_IFADDR)
        | group_flag(RTNLGRP_IPV4_ROUTE)
        | group_flag(RTNLGRP_IPV6_ROUTE)
        | group_flag(RTNLGRP_IPV4_RULE)
        | group_flag(RTNLGRP_IPV6_RULE);
    EventSocket::subscribe(groups)
}

/// Returns `true` if the connection was lost (should reconnect),
/// `false` if the sender is gone (should shut down).
async fn process_messages(sender: &mpsc::Sender<NetworkMessage>, events: &mut EventSocket) -> bool {
    let mut addr_cache: HashMap<u32, HashSet<IpAddr>> = HashMap::new();

    loop {
        let message = match events.next().await {
            Ok(message) => message,
            Err(netwatch_netlink::Error::ErrorMessage { code, .. }) => {
                warn!("error reading netlink payload: code {code}");
                continue;
            }
            Err(err) => {
                trace!("netlink event socket lost ({err:?}), reconnecting");
                return true;
            }
        };
        match message {
            Message::NewAddress(msg) => {
                trace!("NEWADDR: {:?}", msg);
                let addrs = addr_cache.entry(msg.index).or_default();
                if let Some(addr) = msg.address {
                    if addrs.contains(&addr) {
                        continue;
                    } else {
                        addrs.insert(addr);
                        if sender.send(NetworkMessage::Change).await.is_err() {
                            return false;
                        }
                    }
                }
            }
            Message::DelAddress(msg) => {
                trace!("DELADDR: {:?}", msg);
                let addrs = addr_cache.entry(msg.index).or_default();
                if let Some(addr) = msg.address {
                    addrs.remove(&addr);
                }
                if sender.send(NetworkMessage::Change).await.is_err() {
                    return false;
                }
            }
            Message::NewRoute(msg) | Message::DelRoute(msg) => {
                trace!("ROUTE:: {:?}", msg);

                let table = msg.table.unwrap_or_default();
                if let Some(dst) = msg.destination
                    && (table == 255 || table == 254)
                    && (dst.is_multicast() || is_link_local(dst))
                {
                    // Ignore multicast and link-local route changes in the
                    // local and main tables; they are not interesting.
                    continue;
                }
                if sender.send(NetworkMessage::Change).await.is_err() {
                    return false;
                }
            }
            Message::NewRule => {
                trace!("NEWRULE");
                if sender.send(NetworkMessage::Change).await.is_err() {
                    return false;
                }
            }
            Message::DelRule => {
                trace!("DELRULE");
                if sender.send(NetworkMessage::Change).await.is_err() {
                    return false;
                }
            }
            Message::NewLink(msg) => {
                trace!("NEWLINK: {:?}", msg);
            }
            Message::DelLink(msg) => {
                trace!("DELLINK: {:?}", msg);
            }
            msg => {
                trace!("unhandled: {:?}", msg);
            }
        }
    }
}

impl RouteMonitor {
    pub(super) fn new(sender: mpsc::Sender<NetworkMessage>) -> Result<Self, Error> {
        let handle = tokio::task::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            const MAX_BACKOFF: Duration = Duration::from_secs(30);

            loop {
                match subscribe() {
                    Ok(mut events) => {
                        backoff = Duration::from_secs(1);
                        let should_reconnect = process_messages(&sender, &mut events).await;
                        // events dropped here, closing the socket
                        if !should_reconnect {
                            break;
                        }
                        warn!("netlink connection lost, reconnecting");
                    }
                    Err(err) => {
                        warn!("failed to setup netlink: {:?}", err);
                    }
                }
                time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        });

        Ok(RouteMonitor {
            _handle: AbortOnDropHandle::new(handle),
        })
    }
}
