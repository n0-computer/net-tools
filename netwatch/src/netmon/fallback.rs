//! Fallback netmon implementation for platforms without OS-specific route monitoring.
//! Does nothing — no route monitoring available.

use n0_error::stack_error;
use tokio::sync::mpsc;

use super::actor::NetworkMessage;

#[stack_error(derive, add_meta)]
pub struct Error;

#[derive(Debug)]
pub(super) struct RouteMonitor;

impl RouteMonitor {
    pub(super) fn new(_sender: mpsc::Sender<NetworkMessage>) -> Result<Self, Error> {
        Ok(RouteMonitor)
    }
}

pub(crate) fn is_interesting_interface(_name: &str) -> bool {
    true
}
