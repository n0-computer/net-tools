//! Netlink route sockets: blocking and async dump connections, and the
//! multicast event socket.

use std::{
    collections::VecDeque,
    io,
    mem::MaybeUninit,
    os::fd::{AsRawFd, RawFd},
    time::{Duration, Instant},
};

use n0_error::e;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tracing::warn;

use crate::{
    Error,
    message::{
        self, AddressMessage, Frame, LinkMessage, Message, RouteFamily, RouteMessage,
        dump_addresses_request, dump_links_request, dump_routes_request, get_link_request,
    },
};

/// Receive buffer size for a single datagram.
///
/// The kernel caps rtnetlink dump datagrams well below this (32k), so a
/// larger buffer only wastes memory.
const RECV_BUF_SIZE: usize = 64 * 1024;

/// Deadline for a whole dump.
///
/// When the deadline passes, the messages collected so far are returned:
/// enumeration should degrade rather than fail when the kernel drops a
/// datagram.
const DUMP_TIMEOUT: Duration = Duration::from_secs(2);

/// Builds the netlink socket address for the given multicast group mask.
///
/// A zero mask addresses the kernel for request/response use.
fn netlink_addr(groups: u32) -> SockAddr {
    // SAFETY: an all-zero sockaddr_nl is valid; only the family and the
    // group mask need real values (pid zero lets the kernel assign one).
    // The storage is larger than sockaddr_nl and the length says so.
    unsafe {
        let mut storage = socket2::SockAddrStorage::zeroed();
        let addr = std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_nl>();
        (*addr).nl_family = libc::AF_NETLINK as libc::sa_family_t;
        (*addr).nl_groups = groups;
        SockAddr::new(
            storage,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    }
}

/// A `NETLINK_ROUTE` socket.
#[derive(Debug)]
struct NetlinkSocket {
    socket: Socket,
}

impl NetlinkSocket {
    /// Opens the socket, subscribed to the multicast groups in `groups`
    /// (zero for request/response use).
    ///
    /// Blocking receives use a per-call timeout; async users flip the
    /// socket to non-blocking and drive it through an [`AsyncFd`].
    fn new(groups: u32, nonblocking: bool) -> io::Result<Self> {
        let socket = Socket::new(
            Domain::from(libc::AF_NETLINK),
            Type::DGRAM,
            Some(Protocol::from(libc::NETLINK_ROUTE)),
        )?;
        socket.set_nonblocking(nonblocking)?;

        // On Android 11+ SELinux denies bind on netlink route sockets for
        // apps; the kernel auto-binds on the first send instead. Group
        // subscription requires the bind and is not used on Android
        // (netmon is a no-op there).
        let bind = groups != 0 || cfg!(not(target_os = "android"));
        if bind {
            socket.bind(&netlink_addr(groups))?;
        }
        Ok(Self { socket })
    }

    /// Sends a request datagram to the kernel.
    fn send_request(&self, buf: &[u8]) -> io::Result<()> {
        let sent = self.socket.send_to(buf, &netlink_addr(0))?;
        // Datagram sockets send whole messages; a short send cannot happen.
        debug_assert_eq!(sent, buf.len());
        Ok(())
    }

    /// Receives one datagram.
    ///
    /// Returns the datagram's true length, which exceeds `buf.len()` when
    /// the datagram was truncated (`MSG_TRUNC`).
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: MaybeUninit<u8> has the same layout as u8, and the
        // receive only writes initialized bytes into the buffer.
        let buf = unsafe { &mut *(std::ptr::from_mut::<[u8]>(buf) as *mut [MaybeUninit<u8>]) };
        self.socket.recv_with_flags(buf, libc::MSG_TRUNC)
    }

    /// Blocking receive of one datagram, bounded by `deadline`.
    ///
    /// Returns `None` when the deadline passes first.
    fn recv_deadline(&self, buf: &mut [u8], deadline: Instant) -> io::Result<Option<usize>> {
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            // A zero timeout would mean "block forever".
            self.socket
                .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))?;
            match self.recv(buf) {
                Ok(len) => return Ok(Some(len)),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Maps a receive error, turning `ENOBUFS` into [`Error::Overrun`].
fn map_recv_err(err: io::Error) -> Error {
    if err.raw_os_error() == Some(libc::ENOBUFS) {
        e!(Error::Overrun)
    } else {
        e!(Error::Io, err)
    }
}

/// Collects the frames of one dump, keyed by sequence number.
#[derive(Debug, Default)]
struct DumpCollector {
    messages: Vec<Message>,
    done: bool,
}

impl DumpCollector {
    fn push_datagram(&mut self, seq: u32, datagram: &[u8]) -> Result<(), Error> {
        for frame in message::parse_frames(datagram) {
            match frame {
                Frame::Message { seq: s, message } if s == seq => self.messages.push(message),
                Frame::Done { seq: s } if s == seq => {
                    self.done = true;
                    return Ok(());
                }
                Frame::Error { seq: s, code } if s == seq && code != 0 => {
                    return Err(e!(Error::ErrorMessage { code }));
                }
                // Acks (code zero), foreign sequence numbers and skipped
                // frames are ignored.
                _ => {}
            }
        }
        Ok(())
    }
}

fn filter_links(messages: Vec<Message>) -> Vec<LinkMessage> {
    messages
        .into_iter()
        .filter_map(|message| match message {
            Message::NewLink(link) => Some(link),
            _ => None,
        })
        .collect()
}

fn filter_addresses(messages: Vec<Message>) -> Vec<AddressMessage> {
    messages
        .into_iter()
        .filter_map(|message| match message {
            Message::NewAddress(address) => Some(address),
            _ => None,
        })
        .collect()
}

fn filter_routes(messages: Vec<Message>) -> Vec<RouteMessage> {
    messages
        .into_iter()
        .filter_map(|message| match message {
            Message::NewRoute(route) => Some(route),
            _ => None,
        })
        .collect()
}

/// A blocking request/response connection.
///
/// Dumps wait at most two seconds and return the messages received so far
/// when the deadline passes.
#[derive(Debug)]
pub struct Connection {
    socket: NetlinkSocket,
    seq: u32,
    buf: Vec<u8>,
}

impl Connection {
    /// Opens a new connection.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            socket: NetlinkSocket::new(0, false)?,
            seq: 0,
            buf: vec![0; RECV_BUF_SIZE],
        })
    }

    /// Dumps all links.
    pub fn dump_links(&mut self) -> Result<Vec<LinkMessage>, Error> {
        self.dump(dump_links_request).map(filter_links)
    }

    /// Dumps all addresses of both families.
    pub fn dump_addresses(&mut self) -> Result<Vec<AddressMessage>, Error> {
        self.dump(dump_addresses_request).map(filter_addresses)
    }

    /// Dumps the routes of the given family.
    pub fn dump_routes(&mut self, family: RouteFamily) -> Result<Vec<RouteMessage>, Error> {
        self.dump(|seq| dump_routes_request(seq, family))
            .map(filter_routes)
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn dump(&mut self, build: impl FnOnce(u32) -> Vec<u8>) -> Result<Vec<Message>, Error> {
        let seq = self.next_seq();
        self.socket.send_request(&build(seq))?;
        let deadline = Instant::now() + DUMP_TIMEOUT;
        let mut collector = DumpCollector::default();
        while !collector.done {
            match self.socket.recv_deadline(&mut self.buf, deadline) {
                Ok(None) => {
                    warn!("netlink dump timed out, returning partial result");
                    break;
                }
                Ok(Some(len)) if len > self.buf.len() => return Err(e!(Error::Truncated)),
                Ok(Some(len)) => collector.push_datagram(seq, &self.buf[..len])?,
                Err(err) => return Err(map_recv_err(err)),
            }
        }
        Ok(collector.messages)
    }
}

/// An async request/response connection.
///
/// The async twin of [`Connection`], with the same dump semantics.
#[derive(Debug)]
pub struct AsyncConnection {
    socket: AsyncFd<NetlinkSocket>,
    seq: u32,
    buf: Vec<u8>,
}

impl AsyncConnection {
    /// Opens a new connection.
    ///
    /// Must be called from within a tokio runtime.
    pub fn new() -> Result<Self, Error> {
        let socket = NetlinkSocket::new(0, true)?;
        Ok(Self {
            socket: AsyncFd::new(socket).map_err(|err| e!(Error::Io, err))?,
            seq: 0,
            buf: vec![0; RECV_BUF_SIZE],
        })
    }

    /// Dumps all links.
    pub async fn dump_links(&mut self) -> Result<Vec<LinkMessage>, Error> {
        self.dump(dump_links_request).await.map(filter_links)
    }

    /// Dumps all addresses of both families.
    pub async fn dump_addresses(&mut self) -> Result<Vec<AddressMessage>, Error> {
        self.dump(dump_addresses_request)
            .await
            .map(filter_addresses)
    }

    /// Dumps the routes of the given family.
    pub async fn dump_routes(&mut self, family: RouteFamily) -> Result<Vec<RouteMessage>, Error> {
        self.dump(|seq| dump_routes_request(seq, family))
            .await
            .map(filter_routes)
    }

    /// Requests a single link by interface index.
    ///
    /// Returns `None` when the kernel does not answer within the dump
    /// deadline.
    pub async fn get_link_by_index(&mut self, index: u32) -> Result<Option<LinkMessage>, Error> {
        let seq = self.next_seq();
        self.socket
            .get_ref()
            .send_request(&get_link_request(seq, index))?;
        let deadline = tokio::time::Instant::now() + DUMP_TIMEOUT;
        loop {
            let Some(len) = self.recv_datagram(deadline).await? else {
                return Ok(None);
            };
            for frame in message::parse_frames(&self.buf[..len]) {
                match frame {
                    Frame::Message {
                        seq: s,
                        message: Message::NewLink(link),
                    } if s == seq => return Ok(Some(link)),
                    Frame::Error { seq: s, code } if s == seq && code != 0 => {
                        return Err(e!(Error::ErrorMessage { code }));
                    }
                    Frame::Done { seq: s } if s == seq => return Ok(None),
                    _ => {}
                }
            }
        }
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    async fn dump(&mut self, build: impl FnOnce(u32) -> Vec<u8>) -> Result<Vec<Message>, Error> {
        let seq = self.next_seq();
        self.socket.get_ref().send_request(&build(seq))?;
        let deadline = tokio::time::Instant::now() + DUMP_TIMEOUT;
        let mut collector = DumpCollector::default();
        while !collector.done {
            let Some(len) = self.recv_datagram(deadline).await? else {
                warn!("netlink dump timed out, returning partial result");
                break;
            };
            collector.push_datagram(seq, &self.buf[..len])?;
        }
        Ok(collector.messages)
    }

    /// Receives one datagram into the connection buffer.
    ///
    /// Returns its length, or `None` when `deadline` passes first.
    async fn recv_datagram(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<Option<usize>, Error> {
        let Self { socket, buf, .. } = self;
        loop {
            let Ok(guard) = tokio::time::timeout_at(deadline, socket.readable()).await else {
                return Ok(None);
            };
            let mut guard = guard.map_err(|err| e!(Error::Io, err))?;
            match guard.try_io(|socket| socket.get_ref().recv(buf)) {
                Ok(Ok(len)) if len > buf.len() => return Err(e!(Error::Truncated)),
                Ok(Ok(len)) => return Ok(Some(len)),
                Ok(Err(err)) => return Err(map_recv_err(err)),
                // Spurious readiness: wait again.
                Err(_would_block) => {}
            }
        }
    }
}

/// A pending event parsed from a received datagram.
#[derive(Debug)]
enum PendingEvent {
    Message(Message),
    Done,
    Error { code: i32 },
}

/// A socket subscribed to rtnetlink multicast groups.
///
/// Build the `groups` mask from `RTNLGRP_*` values with
/// [`group_flag`](crate::group_flag).
#[derive(Debug)]
pub struct EventSocket {
    socket: AsyncFd<NetlinkSocket>,
    buf: Vec<u8>,
    pending: VecDeque<PendingEvent>,
}

impl EventSocket {
    /// Subscribes to the multicast groups in the `groups` bind mask.
    ///
    /// Must be called from within a tokio runtime.
    pub fn subscribe(groups: u32) -> Result<Self, Error> {
        let socket = NetlinkSocket::new(groups, true)?;
        Ok(Self {
            socket: AsyncFd::new(socket).map_err(|err| e!(Error::Io, err))?,
            buf: vec![0; RECV_BUF_SIZE],
            pending: VecDeque::new(),
        })
    }

    /// Waits for the next event message.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrorMessage`]: the kernel sent an error frame; the
    ///   socket remains usable and `next` can be called again.
    /// - [`Error::Overrun`], [`Error::Done`], [`Error::Truncated`],
    ///   [`Error::Io`]: events may have been lost; the caller should drop
    ///   the socket, resubscribe, and re-read the state it watches.
    pub async fn next(&mut self) -> Result<Message, Error> {
        loop {
            match self.pending.pop_front() {
                Some(PendingEvent::Message(message)) => return Ok(message),
                Some(PendingEvent::Done) => return Err(e!(Error::Done)),
                Some(PendingEvent::Error { code }) => return Err(e!(Error::ErrorMessage { code })),
                None => {}
            }
            let Self {
                socket,
                buf,
                pending,
            } = self;
            let mut guard = socket.readable().await.map_err(|err| e!(Error::Io, err))?;
            match guard.try_io(|socket| socket.get_ref().recv(buf)) {
                Ok(Ok(len)) if len > buf.len() => return Err(e!(Error::Truncated)),
                Ok(Ok(len)) => {
                    for frame in message::parse_frames(&buf[..len]) {
                        match frame {
                            Frame::Message { message, .. } => {
                                pending.push_back(PendingEvent::Message(message));
                            }
                            Frame::Done { .. } => pending.push_back(PendingEvent::Done),
                            Frame::Error { code, .. } => {
                                pending.push_back(PendingEvent::Error { code });
                            }
                            Frame::Skip => {}
                        }
                    }
                }
                Ok(Err(err)) => return Err(map_recv_err(err)),
                // Spurious readiness: wait again.
                Err(_would_block) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_link(links: &[LinkMessage]) -> &LinkMessage {
        links
            .iter()
            .find(|link| link.name.as_deref() == Some("lo"))
            .expect("no loopback link")
    }

    #[test]
    fn test_sync_dump_links() {
        let mut conn = Connection::new().unwrap();
        let links = conn.dump_links().unwrap();
        let lo = loopback_link(&links);
        assert!(lo.index >= 1);
        assert_ne!(lo.flags & libc::IFF_LOOPBACK as u32, 0);
    }

    #[test]
    fn test_sync_dump_addresses() {
        let mut conn = Connection::new().unwrap();
        let addresses = conn.dump_addresses().unwrap();
        let localhost = addresses
            .iter()
            .find(|addr| addr.interface_address() == Some(std::net::Ipv4Addr::LOCALHOST.into()))
            .expect("no loopback address");
        assert_eq!(localhost.prefix_len, 8);
        assert_eq!(localhost.family as i32, libc::AF_INET);
    }

    #[test]
    fn test_sync_dump_routes() {
        let mut conn = Connection::new().unwrap();
        // The route table may be empty in minimal namespaces; only assert
        // that dumping works and parses.
        let routes = conn.dump_routes(RouteFamily::Ipv4).unwrap();
        for route in &routes {
            assert_eq!(route.family as i32, libc::AF_INET);
        }
        let _ = conn.dump_routes(RouteFamily::Unspec).unwrap();
    }

    #[tokio::test]
    async fn test_async_dumps_and_link_by_index() {
        let mut conn = AsyncConnection::new().unwrap();
        let links = conn.dump_links().await.unwrap();
        let lo = loopback_link(&links).clone();

        let addresses = conn.dump_addresses().await.unwrap();
        assert!(addresses.iter().any(|addr| addr.index == lo.index));

        let _ = conn.dump_routes(RouteFamily::Ipv6).await.unwrap();

        let link = conn.get_link_by_index(lo.index).await.unwrap().unwrap();
        assert_eq!(link.name.as_deref(), Some("lo"));
    }

    #[tokio::test]
    async fn test_get_link_by_index_missing() {
        let mut conn = AsyncConnection::new().unwrap();
        let res = conn.get_link_by_index(u32::MAX - 7).await;
        assert!(matches!(res, Err(Error::ErrorMessage { .. })));
    }

    #[tokio::test]
    async fn test_event_socket_subscribes() {
        let groups = crate::group_flag(libc::RTNLGRP_IPV4_IFADDR)
            | crate::group_flag(libc::RTNLGRP_IPV6_IFADDR)
            | crate::group_flag(libc::RTNLGRP_IPV4_ROUTE)
            | crate::group_flag(libc::RTNLGRP_IPV6_ROUTE);
        let mut events = EventSocket::subscribe(groups).unwrap();
        // No events are expected in an idle test environment; just make
        // sure waiting does not error out immediately.
        let next = tokio::time::timeout(Duration::from_millis(50), events.next()).await;
        assert!(next.is_err(), "unexpected event: {next:?}");
    }
}
