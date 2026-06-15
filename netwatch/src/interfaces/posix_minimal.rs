//! Fallback interface enumeration for POSIX platforms without `netdev`
//! (e.g. esp-idf). No interface enumeration, default route, or home router is
//! available, so these report empty or absent.

use std::collections::HashMap;

use super::{DefaultRouteDetails, HomeRouter, State};
use crate::ip::LocalAddresses;

pub(super) async fn get_state() -> State {
    State {
        interfaces: HashMap::new(),
        local_addresses: LocalAddresses::default(),
        have_v6: false,
        have_v4: true,
        is_expensive: false,
        default_route_interface: None,
        last_unsuspend: None,
    }
}

pub(super) async fn default_route() -> Option<DefaultRouteDetails> {
    None
}

pub(super) fn home_router() -> Option<HomeRouter> {
    None
}
