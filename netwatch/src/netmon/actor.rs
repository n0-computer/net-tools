use std::sync::Arc;

use n0_future::{
    FutureExt as _,
    boxed::BoxFuture,
    time::{self, Duration, Instant},
};
use n0_watcher::Watchable;
pub(super) use os::Error;
use os::RouteMonitor;
#[cfg(not(wasm_browser))]
pub(crate) use os::is_interesting_interface;
use tokio::sync::mpsc;
use tracing::{debug, trace};

#[cfg(target_os = "android")]
use super::android as os;
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
use super::bsd as os;
#[cfg(target_os = "linux")]
use super::linux as os;
#[cfg(wasm_browser)]
use super::wasm_browser as os;
#[cfg(target_os = "windows")]
use super::windows as os;
use crate::interfaces::State;

/// The message sent by the OS specific monitors.
#[derive(Debug, Copy, Clone)]
pub(super) enum NetworkMessage {
    /// A change was detected.
    #[allow(dead_code)]
    Change,
}

/// How often the actor wakes up to check for wall-time jumps and to
/// re-enumerate interfaces (see [`Actor::run`]).
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Set background polling time to 1h to effectively disable it on mobile,
/// to avoid increased battery usage. Sleep detection won't work this way there.
#[cfg(any(target_os = "ios", target_os = "android"))]
const POLL_INTERVAL: Duration = Duration::from_secs(60 * 60);
const MON_CHAN_CAPACITY: usize = 16;
const ACTOR_CHAN_CAPACITY: usize = 16;

/// Enumerates the host's network interfaces. Boxed so tests can substitute it.
type StateFn = Arc<dyn Fn() -> BoxFuture<State> + Send + Sync + 'static>;

pub(super) fn default_state_fn() -> StateFn {
    Arc::new(|| State::new().boxed())
}

pub(super) struct Actor {
    /// Latest known interface state.
    interface_state: Watchable<State>,
    /// Latest observed wall time.
    wall_time: Instant,
    mon_receiver: mpsc::Receiver<NetworkMessage>,
    actor_receiver: mpsc::Receiver<ActorMessage>,
    actor_sender: mpsc::Sender<ActorMessage>,
}

pub(super) enum ActorMessage {
    NetworkChange,
}

impl Actor {
    pub(super) async fn new() -> Result<(Self, RouteMonitor), os::Error> {
        let interface_state = State::new().await;
        let wall_time = Instant::now();

        let (mon_sender, mon_receiver) = mpsc::channel(MON_CHAN_CAPACITY);
        let route_monitor = RouteMonitor::new(mon_sender)?;
        let (actor_sender, actor_receiver) = mpsc::channel(ACTOR_CHAN_CAPACITY);

        let actor = Actor {
            interface_state: Watchable::new(interface_state),
            wall_time,
            mon_receiver,
            actor_receiver,
            actor_sender,
        };
        Ok((actor, route_monitor))
    }

    pub(super) fn state(&self) -> &Watchable<State> {
        &self.interface_state
    }

    pub(super) fn subscribe(&self) -> mpsc::Sender<ActorMessage> {
        self.actor_sender.clone()
    }

    pub(super) async fn run(mut self, route_monitor: Option<RouteMonitor>, get_state: StateFn) {
        // Held only to keep the OS monitor task alive; `None` in tests.
        let _route_monitor = route_monitor;

        const DEBOUNCE: Duration = Duration::from_millis(250);

        let mut pending_change = false;
        let mut pending_time_jump = false;
        let debounce = time::sleep(DEBOUNCE);
        tokio::pin!(debounce);
        let mut poll_interval = time::interval(POLL_INTERVAL);
        // Skip the immediate first tick; we just enumerated in `new`.
        poll_interval.tick().await;

        loop {
            tokio::select! {
                _ = &mut debounce, if pending_change || pending_time_jump => {
                    self.handle_potential_change(&get_state, pending_time_jump).await;
                    pending_change = false;
                    pending_time_jump = false;
                }
                _ = poll_interval.tick() => {
                    trace!("tick: poll_interval");
                    if self.check_wall_time_advance() {
                        pending_time_jump = true;
                    }
                    // Reconcile on every tick, not just on wall-time jumps. OS
                    // route monitors are best-effort and can drop events
                    // silently (or stop delivering entirely), which would
                    // otherwise freeze the interface state until restart.
                    // `handle_potential_change` diffs, so this is a no-op when
                    // nothing changed.
                    pending_change = true;
                    debounce.as_mut().reset(Instant::now() + DEBOUNCE);
                }
                event = self.mon_receiver.recv() => {
                    match event {
                        Some(NetworkMessage::Change) => {
                            trace!("network activity detected");
                            pending_change = true;
                            debounce.as_mut().reset(Instant::now() + DEBOUNCE);
                        }
                        None => {
                            debug!("shutting down, network monitor receiver gone");
                            break;
                        }
                    }
                }
                msg = self.actor_receiver.recv() => {
                    match msg {
                        Some(ActorMessage::NetworkChange) => {
                            trace!("external network activity detected");
                            pending_change = true;
                            debounce.as_mut().reset(Instant::now() + DEBOUNCE);
                        }
                        None => {
                            debug!("shutting down, actor receiver gone");
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn handle_potential_change(&mut self, get_state: &StateFn, time_jumped: bool) {
        trace!("potential change");

        let mut new_state = (get_state)().await;
        let old_state = &self.interface_state.get();

        if time_jumped {
            new_state.last_unsuspend.replace(Instant::now());
        } else if old_state == &new_state {
            // No major changes, continue on
            debug!("no changes detected");
            return;
        }

        self.interface_state.set(new_state).ok();
    }

    /// Reports whether wall time jumped more than 150%
    /// of [`POLL_INTERVAL`], indicating we probably just came out of sleep.
    fn check_wall_time_advance(&mut self) -> bool {
        let now = Instant::now();
        let jumped = if let Some(elapsed) = now.checked_duration_since(self.wall_time) {
            elapsed > POLL_INTERVAL * 3 / 2
        } else {
            false
        };

        self.wall_time = now;
        jumped
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use n0_watcher::Watcher as _;

    use super::*;

    /// Builds two distinct interface states so a transition is observable.
    fn state_pair() -> (State, State) {
        let with_iface = State::fake();
        let mut without_iface = with_iface.clone();
        without_iface.interfaces.clear();
        assert_ne!(with_iface, without_iface);
        (with_iface, without_iface)
    }

    /// State must converge via the periodic reconcile alone, with no
    /// route-monitor events. Paused time auto-advances through the poll
    /// interval, so this does not wait in real time.
    #[tokio::test(start_paused = true)]
    async fn recovers_state_without_route_events() {
        // Enumeration returns "before" once, then "after" on every later call:
        // an interface change the route monitor never signalled.
        let (before, after) = state_pair();
        let calls = Arc::new(Mutex::new(0usize));
        let states = Arc::new((before.clone(), after.clone()));
        let get_state: StateFn = {
            let calls = calls.clone();
            let states = states.clone();
            Arc::new(move || {
                let n = {
                    let mut g = calls.lock().unwrap();
                    let n = *g;
                    *g += 1;
                    n
                };
                let states = states.clone();
                async move {
                    if n == 0 {
                        states.0.clone()
                    } else {
                        states.1.clone()
                    }
                }
                .boxed()
            })
        };

        // Keep `_mon_sender` alive so the actor does not see all senders gone
        // and shut down.
        let initial = (get_state)().await;
        assert_eq!(initial, before);
        let (_mon_sender, mon_receiver) = mpsc::channel(MON_CHAN_CAPACITY);
        let (actor_sender, actor_receiver) = mpsc::channel(ACTOR_CHAN_CAPACITY);
        let interface_state = Watchable::new(initial);
        let mut watch = interface_state.watch();

        let actor = Actor {
            interface_state,
            wall_time: Instant::now(),
            mon_receiver,
            actor_receiver,
            actor_sender,
        };
        let handle = tokio::spawn(actor.run(None, get_state));

        // Must exceed POLL_INTERVAL, or auto-advanced time trips it before the
        // first reconcile. Without the fix, state never converges and this fires.
        let updated = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let state = watch.updated().await.expect("watcher closed");
                if state == after {
                    return state;
                }
            }
        })
        .await
        .expect("interface state was not reconciled without route events");
        assert_eq!(updated, after);

        drop(_mon_sender);
        handle.abort();
    }
}
