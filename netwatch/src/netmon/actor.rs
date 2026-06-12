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

/// Produces the current [`State`] of the host's network interfaces.
///
/// Boxed so the enumeration can be substituted in tests; in production it is
/// always [`State::new`].
type StateFn = Arc<dyn Fn() -> BoxFuture<State> + Send + Sync + 'static>;

fn default_state_fn() -> StateFn {
    Arc::new(|| State::new().boxed())
}

pub(super) struct Actor {
    /// Latest known interface state.
    interface_state: Watchable<State>,
    /// Latest observed wall time.
    wall_time: Instant,
    /// OS specific monitor.
    ///
    /// `None` only in tests, where the OS route monitor is intentionally
    /// absent so that recovery via the periodic reconcile can be exercised in
    /// isolation. Held purely to keep the monitor task alive.
    #[allow(dead_code)]
    route_monitor: Option<RouteMonitor>,
    mon_receiver: mpsc::Receiver<NetworkMessage>,
    actor_receiver: mpsc::Receiver<ActorMessage>,
    actor_sender: mpsc::Sender<ActorMessage>,
    /// How the actor enumerates interfaces. Always [`State::new`] in
    /// production; overridable in tests.
    get_state: StateFn,
    /// Interval at which the actor re-enumerates interfaces and checks wall
    /// time. Defaults to [`POLL_INTERVAL`].
    poll_interval: Duration,
}

pub(super) enum ActorMessage {
    NetworkChange,
}

impl Actor {
    pub(super) async fn new() -> Result<Self, os::Error> {
        let get_state = default_state_fn();
        let interface_state = (get_state)().await;
        let wall_time = Instant::now();

        let (mon_sender, mon_receiver) = mpsc::channel(MON_CHAN_CAPACITY);
        let route_monitor = RouteMonitor::new(mon_sender)?;
        let (actor_sender, actor_receiver) = mpsc::channel(ACTOR_CHAN_CAPACITY);

        Ok(Actor {
            interface_state: Watchable::new(interface_state),
            wall_time,
            route_monitor: Some(route_monitor),
            mon_receiver,
            actor_receiver,
            actor_sender,
            get_state,
            poll_interval: POLL_INTERVAL,
        })
    }

    pub(super) fn state(&self) -> &Watchable<State> {
        &self.interface_state
    }

    pub(super) fn subscribe(&self) -> mpsc::Sender<ActorMessage> {
        self.actor_sender.clone()
    }

    pub(super) async fn run(mut self) {
        const DEBOUNCE: Duration = Duration::from_millis(250);

        let mut pending_change = false;
        let mut pending_time_jump = false;
        let debounce = time::sleep(DEBOUNCE);
        tokio::pin!(debounce);
        let mut poll_interval = time::interval(self.poll_interval);
        // The first tick fires immediately; skip it so startup does not do a
        // redundant reconcile right after the initial enumeration.
        poll_interval.tick().await;

        loop {
            tokio::select! {
                _ = &mut debounce, if pending_change || pending_time_jump => {
                    self.handle_potential_change(pending_time_jump).await;
                    pending_change = false;
                    pending_time_jump = false;
                }
                _ = poll_interval.tick() => {
                    trace!("tick: poll_interval");
                    if self.check_wall_time_advance() {
                        pending_time_jump = true;
                    }
                    // Re-enumerate interfaces on every tick, not just on
                    // wall-time jumps. The OS route monitors are best-effort
                    // and an event can be missed without any error: a routing
                    // socket drops messages when its receive buffer overflows,
                    // and on macOS (XNU `raw_input`) that drop is silent (no
                    // `so_error`, no `SO_RERROR`), so a change can be missed on
                    // an otherwise-working socket. We have also observed the
                    // macOS AF_ROUTE read simply stop delivering events (no
                    // further reads, no error), after which the actor has
                    // nothing to react to. A missed or absent event must not
                    // freeze the interface state forever, so reconcile
                    // periodically. `handle_potential_change` diffs against the
                    // current state, so this is a no-op (beyond the enumeration
                    // itself) whenever nothing actually changed.
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

    async fn handle_potential_change(&mut self, time_jumped: bool) {
        trace!("potential change");

        let mut new_state = (self.get_state)().await;
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
    /// of [`Self::poll_interval`], indicating we probably just came out of sleep.
    fn check_wall_time_advance(&mut self) -> bool {
        let now = Instant::now();
        let jumped = if let Some(elapsed) = now.checked_duration_since(self.wall_time) {
            elapsed > self.poll_interval * 3 / 2
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

    /// The actor must recover the correct interface state purely from its
    /// periodic reconcile, with no route-monitor events at all.
    ///
    /// This reproduces the production failure where the OS route monitor stops
    /// delivering events (on macOS the raw AF_ROUTE socket can lose its read
    /// readiness after a burst of messages): the interface state would
    /// otherwise stay frozen forever. Before the periodic reconcile was added
    /// this test hangs until the timeout, because nothing ever re-enumerates.
    #[tokio::test]
    async fn recovers_state_without_route_events() {
        // The enumeration reports the "before" state once (the initial state),
        // then the "after" state on every subsequent call, modelling an
        // interface change that the route monitor never signalled.
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

        // No route monitor: the only path that can update state is the
        // periodic reconcile. Keep `mon_sender` alive so the receiver does not
        // report all senders gone (which would shut the actor down).
        let initial = (get_state)().await;
        assert_eq!(initial, before);
        let (mon_sender, mon_receiver) = mpsc::channel(MON_CHAN_CAPACITY);
        let (actor_sender, actor_receiver) = mpsc::channel(ACTOR_CHAN_CAPACITY);
        let interface_state = Watchable::new(initial);
        let mut watch = interface_state.watch();

        let actor = Actor {
            interface_state,
            wall_time: Instant::now(),
            route_monitor: None,
            mon_receiver,
            actor_receiver,
            actor_sender,
            get_state,
            // Short interval so the test does not wait the production 15s,
            // but above the 250ms debounce so each tick settles into a reconcile.
            poll_interval: Duration::from_millis(400),
        };
        let handle = tokio::spawn(actor.run());

        let updated = tokio::time::timeout(Duration::from_secs(5), async {
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

        drop(mon_sender);
        handle.abort();
    }
}
