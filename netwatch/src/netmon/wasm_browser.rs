use tokio::sync::mpsc;

use super::actor::NetworkMessage;

#[derive(Debug, thiserror::Error)]
#[error("error")]
pub struct Error;

#[derive(Debug)]
pub(super) struct RouteMonitor {
    _sender: mpsc::Sender<NetworkMessage>,
}

impl RouteMonitor {
    pub(super) fn new(_sender: mpsc::Sender<NetworkMessage>) -> Result<Self, Error> {
        Ok(RouteMonitor { _sender })
    }
}
