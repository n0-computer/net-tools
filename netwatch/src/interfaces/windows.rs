use std::collections::HashMap;

use serde::Deserialize;
use n0_error::{e, stack_error, StdResultExt};
use tracing::warn;
use wmi::{COMLibrary, FilterValue, WMIConnection};

use super::DefaultRouteDetails;

/// API Docs: <https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmiiprouteprov/win32-ip4routetable>
#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types, non_snake_case)]
struct Win32_IP4RouteTable {
    Name: String,
}

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum Error {
    #[allow(dead_code)] // not sure why we have this here?
    #[error(transparent)]
    Io { #[error(std_err)] source: std::io::Error },
    #[error("not route found")]
    NoRoute {},
    #[error("WMI")]
    Wmi { source: wmi::WMIError },
}

fn get_default_route() -> Result<DefaultRouteDetails, Error> {
    let com_con = COMLibrary::new().map_err(|err| e!(Error::Wmi, err))?;
    let wmi_con = WMIConnection::new(com_con).map_err(|err| e!(Error::Wmi, err))?;

    let query: HashMap<_, _> = [("Destination".into(), FilterValue::Str("0.0.0.0"))].into();
    let route: Win32_IP4RouteTable = wmi_con
        .filtered_query(&query)
        .map_err(|err| e!(Error::Wmi, err))?
        .drain(..)
        .next()
        .ok_or_else(|| e!(Error::NoRoute))?;

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
