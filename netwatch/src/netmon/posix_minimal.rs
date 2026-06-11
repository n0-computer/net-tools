//! Polling-based route monitor for platforms without OS-specific change notifications.
//!
//! Since ESP-IDF doesn't have netlink or routing sockets, we poll for changes
//! on a fixed interval and let the actor debounce and diff.

use n0_error::stack_error;
use n0_future::time::Duration;
use tokio::sync::mpsc;

use super::actor::NetworkMessage;

/// Poll interval for checking network changes.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

#[stack_error(derive, add_meta)]
pub struct Error;

#[derive(Debug)]
pub(super) struct RouteMonitor {
    _handle: tokio::task::JoinHandle<()>,
}

impl RouteMonitor {
    pub(super) fn new(sender: mpsc::Sender<NetworkMessage>) -> Result<Self, Error> {
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(POLL_INTERVAL);
            // Skip the immediate first tick.
            interval.tick().await;
            loop {
                interval.tick().await;
                if sender.send(NetworkMessage::Change).await.is_err() {
                    break;
                }
            }
        });
        Ok(RouteMonitor { _handle: handle })
    }
}
