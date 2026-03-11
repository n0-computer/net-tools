//! Networking related utilities

#[cfg_attr(wasm_browser, path = "interfaces/wasm_browser.rs")]
#[cfg_attr(posix_minimal, path = "interfaces/posix_minimal.rs")]
pub mod interfaces;
#[cfg_attr(posix_minimal, path = "ip_posix_minimal.rs")]
pub mod ip;
mod ip_family;
pub mod netmon;
#[cfg(not(wasm_browser))]
mod udp;

pub use self::ip_family::IpFamily;
#[cfg(not(wasm_browser))]
pub use self::udp::{UdpSender, UdpSocket};
