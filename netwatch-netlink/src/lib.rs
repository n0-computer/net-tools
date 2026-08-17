//! Minimal rtnetlink client for netwatch.
//!
//! Covers exactly the subset of the netlink route protocol that netwatch
//! uses on Linux and Android:
//!
//! - dumping links, addresses and routes ([`Connection`] for blocking
//!   callers, [`AsyncConnection`] inside tokio),
//! - looking up a single link by interface index,
//! - listening to rtnetlink multicast groups for change events
//!   ([`EventSocket`]).
//!
//! Messages are parsed into the small typed structs in this crate
//! ([`LinkMessage`], [`AddressMessage`], [`RouteMessage`]); attributes we do
//! not use are skipped. On every platform other than Linux and Android the
//! crate compiles to nothing.
#![cfg(any(target_os = "linux", target_os = "android"))]

use n0_error::stack_error;

mod conn;
mod message;
mod wire;

pub use self::{
    conn::{AsyncConnection, Connection, EventSocket},
    message::{AddressMessage, LinkMessage, Message, RouteFamily, RouteMessage},
};

/// Errors surfaced by the netlink socket wrappers.
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum Error {
    /// A socket operation failed.
    #[error("IO")]
    Io { source: std::io::Error },
    /// The kernel replied with an `NLMSG_ERROR` message.
    ///
    /// `code` is a negative errno value.
    #[error("netlink error message: code {code}")]
    ErrorMessage { code: i32 },
    /// The kernel dropped events because the socket buffer overran.
    ///
    /// Subscribers should resynchronize by re-reading the state they care
    /// about.
    #[error("netlink socket buffer overrun")]
    Overrun {},
    /// The kernel signaled the end of a multipart message on an event
    /// socket.
    ///
    /// Subscribers should treat this like a lost connection and
    /// resubscribe.
    #[error("end of multipart message")]
    Done {},
    /// A datagram did not fit the receive buffer and was truncated.
    #[error("truncated netlink datagram")]
    Truncated {},
}

/// Returns the `sockaddr_nl` group mask bit for an rtnetlink multicast
/// group.
///
/// Only the first 31 groups can be subscribed through the bind mask; all
/// `RTNLGRP_*` groups netwatch uses fall in that range.
///
/// # Panics
///
/// Panics when `group` is larger than 31.
pub const fn group_flag(group: u32) -> u32 {
    assert!(group <= 31, "group not reachable via the bind mask");
    if group == 0 { 0 } else { 1 << (group - 1) }
}
