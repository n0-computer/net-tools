use std::collections::HashMap;

use serde::Deserialize;
use tracing::warn;
use wmi::{query::FilterValue, COMLibrary, WMIConnection};

use super::DefaultRouteDetails;

/// API Docs: <https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmiiprouteprov/win32-ip4routetable>
#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types, non_snake_case)]
struct Win32_IP4RouteTable {
    Name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO {0}")]
    Io(#[from] std::io::Error),
    #[error("not route found")]
    NoRoute,
    #[error("WMI {0}")]
    Wmi(#[from] wmi::WMIError),
}

fn get_default_route() -> Result<DefaultRouteDetails, Error> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con)?;

    let query: HashMap<_, _> = [("Destination".into(), FilterValue::Str("0.0.0.0"))].into();
    let route: Win32_IP4RouteTable = wmi_con
        .filtered_query(&query)?
        .drain(..)
        .next()
        .ok_or(Error::NoRoute)?;

    Ok(DefaultRouteDetails {
        interface_name: route.Name,
    })
}

pub async fn default_route() -> Option<DefaultRouteDetails> {
    match get_default_route() {
        Ok(route) => Some(route),
        Err(err) => {
            warn!("failed to retrieve default route: {:#?}", err);
            None
        }
    }
}
