//! A route monitor that does nothing.
//!
//! It never reports changes. Users of it only see a new network state when
//! the periodic poll runs or when `Monitor::network_change` is called. Used on
//! platforms without route-change notifications.

use n0_error::stack_error;
use tokio::sync::mpsc;

use super::actor::NetworkMessage;

#[stack_error(derive, add_meta)]
pub struct Error;

#[derive(Debug)]
pub(super) struct RouteMonitor {
    _sender: mpsc::Sender<NetworkMessage>,
}

impl RouteMonitor {
    pub(super) fn new(sender: mpsc::Sender<NetworkMessage>) -> Result<Self, Error> {
        Ok(RouteMonitor { _sender: sender })
    }
}
