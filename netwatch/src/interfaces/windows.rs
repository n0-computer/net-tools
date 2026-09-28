use n0_error::stack_error;
use tracing::warn;

use super::DefaultRouteDetails;
pub(super) use super::netdev_impl::{get_state, home_router};

#[stack_error(derive, add_meta, std_sources, from_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("IO")]
    Io { source: std::io::Error },
}

fn get_default_route() -> Result<DefaultRouteDetails, Error> {
    // Use the same interface names as get_state, without requiring WMI/COM
    // access in sandboxed processes.
    let route = netdev::get_default_interface().map_err(std::io::Error::other)?;

    Ok(DefaultRouteDetails {
        interface_name: route.name,
    })
}

pub async fn default_route() -> Option<DefaultRouteDetails> {
    // Keep synchronous interface enumeration off the async worker thread.
    match tokio::task::spawn_blocking(get_default_route).await {
        Ok(Ok(route)) => Some(route),
        Ok(Err(err)) => {
            warn!("failed to retrieve default route: {:#?}", err);
            None
        }
        Err(err) => {
            warn!("default route task panicked: {:#?}", err);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_route_names_an_enumerated_interface() {
        let state = get_state().await;
        // A disconnected host may have no default route.
        if let Some(name) = &state.default_route_interface {
            assert!(
                state.interfaces.contains_key(name),
                "default route interface {:?} is missing from {:?}",
                name,
                state.interfaces.keys().collect::<Vec<_>>()
            );
        }
    }
}
