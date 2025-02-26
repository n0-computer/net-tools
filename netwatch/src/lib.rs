//! Networking related utilities

#[cfg_attr(
    all(target_family = "wasm", target_os = "unknown"),
    path = "interfaces/wasm_browser.rs"
)]
pub mod interfaces;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub mod ip;
mod ip_family;
pub mod netmon;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod udp;

pub use self::ip_family::IpFamily;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use self::udp::UdpSocket;
