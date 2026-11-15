//! Networking related utilities

pub mod interfaces;
pub mod ip;
mod ip_family;
pub mod netmon;
#[cfg(not(wasm_browser))]
mod udp;
#[cfg(all(wasm_browser, wasm_native_udp))]
#[path = "udp_wasm.rs"]
mod udp;

pub use self::ip_family::IpFamily;
#[cfg(not(wasm_browser))]
pub use self::udp::{BindOptions, SocketRef, UdpSender, UdpSocket};
#[cfg(all(wasm_browser, wasm_native_udp))]
pub use self::udp::{BindOptions, UdpSender, UdpSocket};
/// The UDP shim backing [`UdpSocket`], re-exported so apps call its `init()`.
#[cfg(all(wasm_browser, wasm_native_udp))]
pub use wasm_native_udp;
