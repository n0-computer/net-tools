use js_sys::{
    wasm_bindgen::{prelude::Closure, JsCast, JsValue},
    JsString, Reflect,
};
use n0_future::{
    task::{self, AbortOnDropHandle},
    TryFutureExt,
};
use tokio::sync::mpsc;
use tracing::{info_span, Instrument};
use web_sys::{EventListener, EventTarget};

use super::actor::NetworkMessage;

#[derive(Debug, thiserror::Error)]
#[error("error")]
pub struct Error;

#[derive(Debug)]
pub(super) struct RouteMonitor {
    listeners: Listeners,
}

impl RouteMonitor {
    pub(super) fn new(sender: mpsc::Sender<NetworkMessage>) -> Result<Self, Error> {
        let closure: Function =
            Closure::new(move || {
                // task::spawn is effectively translated into a queueMicrotask in JS
                task::spawn(sender.send(NetworkMessage::Change).inspect_err(|err| {
                    tracing::debug!(?err, "failed sending NetworkMessage::Change")
                }));
            })
            .into_js_value()
            .unchecked_into();
        // The closure keeps itself alive via reference counting internally
        let listeners = add_event_listeners(&closure);
        Ok(RouteMonitor { listeners })
    }
}

fn get_navigator() -> Option<JsValue> {
    Reflect::get(
        js_sys::global().as_ref(),
        JsString::from("navigator").as_ref(),
    )
    .inspect_err(|err| tracing::debug!(?err, "failed fetching globalThis.navigator"))
    .ok()
}

fn add_event_listeners(f: &Function) -> Option<Listeners> {
    let navigator = get_navigator()?;

    let online_listener = EventListener::new();
    online_listener.set_handle_event(f);
    let offline_listener = EventListener::new();
    offline_listener.set_handle_event(f);

    let navigator: EventTarget = navigator.unchecked_into();
    navigator
        .add_event_listener_with_event_listener("online", &online_listener)
        .inspect_err(|err| tracing::debug!(?err, "failed adding event listener"))
        .ok()?;

    navigator
        .add_event_listener_with_event_listener("offline", &offline_listener)
        .inspect_err(|err| tracing::debug!(?err, "failed adding event listener"))
        .ok()?;

    Some(Listeners {
        online_listener,
        offline_listener,
    })
}

#[derive(Debug)]
struct Listeners {
    online_listener: EventListener,
    offline_listener: EventListener,
}

impl Drop for Listeners {
    fn drop(&mut self) {
        if let Some(navigator) = get_navigator() {
            let et: EventTarget = navigator.unchecked_into();
            et.remove_event_listener_with_event_listener("online", &self.online_listener)
                .ok();
            et.remove_event_listener_with_event_listener("offline", &self.offline_listener)
                .ok();
        }
    }
}
