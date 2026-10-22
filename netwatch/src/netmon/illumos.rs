//! Fallback netmon implementation for illumos: no OS-level route-change
//! notification yet.
//!
//! Real route-change notification would mean keeping a `PF_ROUTE` routing
//! socket open and parsing the messages it delivers -- the same wire format
//! `crate::interfaces::illumos` avoids for `default_route`/`home_router`,
//! for the same reason (not verifiable against real illumos hardware here).
//! This mirrors `posix_minimal.rs`'s no-op `RouteMonitor` rather than risk
//! a monitor that silently misses or misparses change events.
//!
//! Practical effect: `Actor` still calls `State::new()` on its periodic
//! wall-time check (primarily meant to detect wake-from-sleep, not routine
//! polling) and whenever the embedder calls
//! [`crate::netmon::Monitor::network_change`] explicitly, so a `Monitor` on
//! illumos is not entirely inert -- it just never *proactively* notices an
//! interface or route change the way it does on platforms with a real
//! `RouteMonitor`. Applications that need timely change detection on
//! illumos should call `network_change()` on their own schedule (e.g. after
//! any operation that might have changed the network) until real `PF_ROUTE`
//! monitoring lands here.

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
