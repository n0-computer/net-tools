//! UDP socket for wasm in the browser, backed by [`webview_sockets`].
//!
//! Only compiled with `--cfg webview_sockets`. The socket lives in the app
//! that embeds the webview; the page reaches it over a WebSocket. The app must
//! call [`webview_sockets::init`] before binding.
//!
//! The API mirrors the native `UdpSocket`, with these differences:
//!
//! - Binding returns before the host confirmed it. Until then
//!   [`UdpSocket::local_addr`] reports the requested address, GSO and GRO are
//!   off and sends are queued. [`UdpSocket::bound`] waits for the confirmation.
//! - A refused bind (e.g. the port is taken) shows up as an error on the first
//!   poll, not from the bind call.
//! - No socket options: [`BindOptions`] has no hook, buffer sizes and
//!   `only_v6` are up to the host.
//! - ECN, source IP selection, destination IP, interface index and timestamps
//!   are not supported. [`UdpSocket::may_fragment`] is always `true`.
//! - [`UdpSocket::rebind`] keeps a healthy socket, since page side network
//!   changes do not affect the host's socket. A failed socket (the WebSocket
//!   closed) is rebound automatically, at most once per second.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock, RwLockReadGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use atomic_waker::AtomicWaker;
use n0_future::time::{Duration, Instant};
use noq_udp::{RecvMeta, Transmit};
use tracing::{debug, trace, warn};

use super::IpFamily;

/// Minimum time between two automatic rebinds of a failed socket.
///
/// Binding always succeeds synchronously and fails later, so without a limit a
/// host that is down would make us open a WebSocket on every poll.
const REBIND_INTERVAL: Duration = Duration::from_secs(1);

/// UDP socket backed by the app that embeds the webview.
#[derive(Debug)]
pub struct UdpSocket {
    socket: RwLock<SocketState>,
    recv_waker: AtomicWaker,
    send_waker: AtomicWaker,
    /// Set when the socket failed and needs a rebind.
    is_broken: AtomicBool,
    /// Set when the host refused the bound port, so the next rebind uses port 0.
    addr_in_use: AtomicBool,
    /// Earliest time the next automatic rebind may run.
    next_rebind: Mutex<Option<Instant>>,
}

/// Options to bind a [`UdpSocket`] with.
///
/// On wasm there are no options, this exists to keep the API of the native
/// `UdpSocket`.
#[derive(Debug, Default, Clone)]
pub struct BindOptions {}

impl BindOptions {
    /// Creates the default options.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Which readiness an I/O operation waits for.
#[derive(Debug, Clone, Copy)]
enum Direction {
    Recv,
    Send,
}

impl UdpSocket {
    /// Bind only Ipv4 on any interface.
    pub fn bind_v4(port: u16) -> io::Result<Self> {
        Self::bind(IpFamily::V4, port)
    }

    /// Bind only Ipv6 on any interface.
    pub fn bind_v6(port: u16) -> io::Result<Self> {
        Self::bind(IpFamily::V6, port)
    }

    /// Bind only Ipv4 on localhost.
    pub fn bind_local_v4(port: u16) -> io::Result<Self> {
        Self::bind_local(IpFamily::V4, port)
    }

    /// Bind only Ipv6 on localhost.
    pub fn bind_local_v6(port: u16) -> io::Result<Self> {
        Self::bind_local(IpFamily::V6, port)
    }

    /// Bind to the given port only on localhost.
    pub fn bind_local(network: IpFamily, port: u16) -> io::Result<Self> {
        let addr = SocketAddr::new(network.local_addr(), port);
        Self::bind_with(addr, BindOptions::default())
    }

    /// Bind to the given port and listen on all interfaces.
    pub fn bind(network: IpFamily, port: u16) -> io::Result<Self> {
        let addr = SocketAddr::new(network.unspecified_addr(), port);
        Self::bind_with(addr, BindOptions::default())
    }

    /// Bind to any provided [`SocketAddr`].
    pub fn bind_full(addr: impl Into<SocketAddr>) -> io::Result<Self> {
        Self::bind_with(addr, BindOptions::default())
    }

    /// Bind to any provided [`SocketAddr`], using the given [`BindOptions`].
    pub fn bind_with(addr: impl Into<SocketAddr>, _opts: BindOptions) -> io::Result<Self> {
        let socket = SocketState::bind(addr.into())?;

        Ok(UdpSocket {
            socket: RwLock::new(socket),
            recv_waker: AtomicWaker::default(),
            send_waker: AtomicWaker::default(),
            is_broken: AtomicBool::new(false),
            addr_in_use: AtomicBool::new(false),
            next_rebind: Mutex::new(None),
        })
    }

    /// Waits until the host confirmed the bind.
    ///
    /// Fails if the host refused the bind or the connection to it closed.
    /// Afterwards [`UdpSocket::local_addr`] reports the bound address.
    pub async fn bound(&self) -> io::Result<()> {
        let socket = self
            .socket
            .read()
            .unwrap()
            .try_get_connected()?
            .try_clone()?;
        socket.bound().await
    }

    /// Returns the host's interface addresses with the bound port.
    ///
    /// Empty until the bind is confirmed, and when the socket is closed.
    pub fn interface_addrs(&self) -> Vec<SocketAddr> {
        match &*self.socket.read().unwrap() {
            SocketState::Connected { socket } => socket.interface_addrs(),
            SocketState::Closed { .. } => Vec::new(),
        }
    }

    /// Is the socket broken and needs a rebind?
    pub fn is_broken(&self) -> bool {
        self.is_broken.load(Ordering::Acquire)
    }

    /// Marks this socket as needing a rebind
    fn mark_broken(&self) {
        self.is_broken.store(true, Ordering::Release);
    }

    /// Rebind the underlying socket.
    ///
    /// Does nothing if the socket is open and has not failed.
    pub fn rebind(&self) -> io::Result<()> {
        {
            let mut guard = self.socket.write().unwrap();
            if !self.is_broken() && guard.is_healthy() {
                trace!("socket healthy, skipping rebind");
                return Ok(());
            }
            self.set_next_rebind();
            guard.rebind(self.addr_in_use.swap(false, Ordering::AcqRel))?;

            // Clear errors
            self.is_broken.store(false, Ordering::Release);

            drop(guard);
        }

        // wakeup
        self.wake_all();

        Ok(())
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    /// If a message is too long to fit in the supplied buffer, excess bytes are
    /// discarded.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// [`connect`]: method@Self::connect
    pub fn recv<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFut<'a, 'b> {
        RecvFut {
            socket: self,
            buffer,
        }
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    ///
    /// If a message is too long to fit in the supplied buffer, excess bytes are
    /// discarded.
    pub fn recv_from<'a, 'b>(&'b self, buffer: &'a mut [u8]) -> RecvFromFut<'a, 'b> {
        RecvFromFut {
            socket: self,
            buffer,
        }
    }

    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// [`connect`]: method@Self::connect
    pub fn send<'a, 'b>(&'b self, buffer: &'a [u8]) -> SendFut<'a, 'b> {
        SendFut {
            socket: self,
            buffer,
        }
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    pub fn send_to<'a, 'b>(&'b self, buffer: &'a [u8], to: SocketAddr) -> SendToFut<'a, 'b> {
        SendToFut {
            socket: self,
            buffer,
            to,
        }
    }

    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via `recv` from the address specified in
    /// `addr`.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        trace!(%addr, "connecting");
        let guard = self.socket.read().unwrap();
        guard.try_get_connected()?.connect(addr)
    }

    /// Returns the local address of this socket.
    ///
    /// This is the requested address until the host confirmed the bind.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.socket.read().unwrap();
        guard.try_get_connected()?.local_addr()
    }

    /// Closes the socket.
    ///
    /// Queued datagrams are still handed to the host.
    #[allow(clippy::unused_async, reason = "same signature as on native")]
    pub async fn close(&self) {
        let socket = self.socket.write().unwrap().close();
        self.wake_all();
        drop(socket);
    }

    /// Check if this socket is closed.
    pub fn is_closed(&self) -> bool {
        self.socket.read().unwrap().is_closed()
    }

    /// Handle potential errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None`.
    fn handle_error(&self, error: io::Error) -> Option<io::Error> {
        match error.kind() {
            // The WebSocket to the host closed: host restart, idle close or an
            // I/O error on the host. If access was revoked, the rebind is
            // refused with `PermissionDenied`, which is fatal.
            io::ErrorKind::ConnectionAborted => {
                debug!(%error, "udp socket failed, rebinding");
                self.mark_broken();
                None
            }
            io::ErrorKind::AddrInUse => {
                debug!(%error, "udp port taken, rebinding to any port");
                self.addr_in_use.store(true, Ordering::Release);
                self.mark_broken();
                None
            }
            _ => Some(error),
        }
    }

    /// Try to get a read lock for the sockets, but don't block for trying to acquire it.
    fn poll_read_socket(
        &self,
        waker: &AtomicWaker,
        cx: &mut Context<'_>,
    ) -> Poll<RwLockReadGuard<'_, SocketState>> {
        let guard = match self.socket.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
            Err(TryLockError::WouldBlock) => {
                waker.register(cx.waker());

                match self.socket.try_read() {
                    Ok(guard) => {
                        // we're actually fine, no need to cause a spurious wakeup
                        waker.take();
                        guard
                    }
                    Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
                    Err(TryLockError::WouldBlock) => return Poll::Pending,
                }
            }
        };
        Poll::Ready(guard)
    }

    fn wake_all(&self) {
        self.recv_waker.wake();
        self.send_waker.wake();
    }

    /// Returns how long to wait before the next automatic rebind may run.
    fn rebind_delay(&self) -> Option<Duration> {
        let next = (*self.next_rebind.lock().unwrap())?;
        next.checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
    }

    fn set_next_rebind(&self) {
        *self.next_rebind.lock().unwrap() = Some(Instant::now() + REBIND_INTERVAL);
    }

    /// Checks if the socket needs a rebind, and if so does it.
    ///
    /// Returns [`io::ErrorKind::WouldBlock`] if the last rebind was too recent,
    /// and an error if the rebind is needed, but failed.
    fn maybe_rebind(&self) -> io::Result<()> {
        if !self.is_broken() {
            return Ok(());
        }
        if self.rebind_delay().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "waiting to rebind",
            ));
        }

        let mut guard = self.socket.write().unwrap_or_else(|e| e.into_inner());

        // Re-check after acquiring the write lock, another caller may have
        // already completed the rebind while we were waiting.
        if !self.is_broken() {
            return Ok(());
        }

        self.set_next_rebind();
        guard.rebind(self.addr_in_use.swap(false, Ordering::AcqRel))?;
        self.is_broken.store(false, Ordering::Release);
        drop(guard);
        self.wake_all();
        Ok(())
    }

    /// Like [`Self::maybe_rebind`], but waits for the rebind interval.
    fn poll_maybe_rebind(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.is_broken() {
            return Poll::Ready(Ok(()));
        }
        if let Some(delay) = self.rebind_delay() {
            trace!(?delay, "waiting to rebind");
            wake_after(cx.waker().clone(), delay);
            return Poll::Pending;
        }
        Poll::Ready(self.maybe_rebind())
    }

    /// Waits for readiness in `direction` and runs `op` on the socket.
    ///
    /// Retries `op` on [`io::ErrorKind::WouldBlock`] and rebinds on recoverable
    /// errors.
    fn poll_io<T>(
        &self,
        cx: &mut Context<'_>,
        direction: Direction,
        mut op: impl FnMut(&webview_sockets::UdpSocket) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        let waker = match direction {
            Direction::Recv => &self.recv_waker,
            Direction::Send => &self.send_waker,
        };
        loop {
            n0_future::ready!(self.poll_maybe_rebind(cx))?;

            let guard = n0_future::ready!(self.poll_read_socket(waker, cx));
            let socket = guard.try_get_connected()?;

            let ready = match direction {
                Direction::Recv => socket.poll_recv_ready(cx),
                Direction::Send => socket.poll_send_ready(cx),
            };
            let res = match ready {
                Poll::Pending => {
                    waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => op(socket),
                Poll::Ready(Err(err)) => Err(err),
            };
            match res {
                Ok(value) => return Poll::Ready(Ok(value)),
                // ignore spurious wakeups
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => {
                    if let Some(err) = self.handle_error(err) {
                        return Poll::Ready(Err(err));
                    }
                }
            }
        }
    }

    /// Poll for writable
    pub fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_io(cx, Direction::Send, |_| Ok(()))
    }

    /// Send a noq based `Transmit`.
    pub fn try_send_noq(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        loop {
            self.maybe_rebind()?;

            let guard = match self.socket.try_read() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(e)) => {
                    panic!("lock poisoned: {e:?}");
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "locked"));
                }
            };
            let socket = guard.try_get_connected()?;

            match send_transmit(socket, transmit) {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Err(err),
                Err(err) => {
                    if let Some(err) = self.handle_error(err) {
                        return Err(err);
                    }
                }
            }
        }
    }

    /// poll send a noq based `Transmit`.
    pub fn poll_send_noq(&self, cx: &mut Context, transmit: &Transmit<'_>) -> Poll<io::Result<()>> {
        self.poll_io(cx, Direction::Send, |socket| {
            send_transmit(socket, transmit)
        })
    }

    /// noq based `poll_recv`
    ///
    /// Fills one buffer per datagram batch (GRO) while datagrams are queued.
    pub fn poll_recv_noq(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = n0_future::ready!(self.poll_io(cx, Direction::Recv, |socket| {
            let mut count = 0;
            for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()) {
                match socket.recv_from_segmented(buf) {
                    Ok((len, addr, stride)) => {
                        let mut m = RecvMeta::default();
                        m.addr = addr;
                        m.len = len;
                        m.stride = stride;
                        *meta = m;
                        count += 1;
                    }
                    // Report what we have, the error shows up again on the next poll.
                    Err(err) if count > 0 || err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err),
                }
            }
            if count == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(count)
        }))?;
        for meta in meta.iter().take(count) {
            trace!(
                src = %meta.addr,
                len = meta.len,
                count = meta.len.checked_div(meta.stride).unwrap_or(0),
                "UDP recv"
            );
        }
        Poll::Ready(Ok(count))
    }

    /// Creates a [`UdpSender`] sender.
    pub fn create_sender(self: Arc<Self>) -> UdpSender {
        UdpSender::new(self)
    }

    /// Whether transmitted datagrams might get fragmented by the IP layer
    ///
    /// Always `true` on wasm: the host does not report whether it sets
    /// `IPV6_DONTFRAG`.
    pub fn may_fragment(&self) -> bool {
        true
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// Reported by the host, 1 until the bind is confirmed.
    pub fn max_gso_segments(&self) -> NonZeroUsize {
        let guard = self.socket.read().unwrap();
        guard.max_gso_segments()
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Reported by the host, 1 until the bind is confirmed.
    pub fn gro_segments(&self) -> NonZeroUsize {
        let guard = self.socket.read().unwrap();
        guard.gro_segments()
    }
}

/// Sends a noq `Transmit` in one go, as a GSO batch if it has a segment size.
///
/// ECN and the source IP are not supported and ignored.
fn send_transmit(socket: &webview_sockets::UdpSocket, transmit: &Transmit<'_>) -> io::Result<()> {
    socket
        .send_to_segmented(
            transmit.contents,
            transmit.destination,
            transmit.segment_size.unwrap_or(0),
        )
        .map(|_| ())
}

/// Wakes `waker` after `delay`.
fn wake_after(waker: Waker, delay: Duration) {
    // Detached, the task only holds the waker.
    drop(n0_future::task::spawn(async move {
        n0_future::time::sleep(delay).await;
        waker.wake();
    }));
}

/// Receive future
#[derive(Debug)]
pub struct RecvFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a mut [u8],
}

impl Future for RecvFut<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;
        socket.poll_io(cx, Direction::Recv, |s| s.recv(buffer))
    }
}

/// Receive future
#[derive(Debug)]
pub struct RecvFromFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a mut [u8],
}

impl Future for RecvFromFut<'_, '_> {
    type Output = io::Result<(usize, SocketAddr)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;
        socket.poll_io(cx, Direction::Recv, |s| s.recv_from(buffer))
    }
}

/// Send future
#[derive(Debug)]
pub struct SendFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a [u8],
}

impl Future for SendFut<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.socket
            .poll_io(cx, Direction::Send, |s| s.send(self.buffer))
    }
}

/// Send future
#[derive(Debug)]
pub struct SendToFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a [u8],
    to: SocketAddr,
}

impl Future for SendToFut<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.socket
            .poll_io(cx, Direction::Send, |s| s.send_to(self.buffer, self.to))
    }
}

#[derive(Debug)]
enum SocketState {
    Connected {
        socket: webview_sockets::UdpSocket,
    },
    Closed {
        /// The addr to rebind to when recovering.
        addr: SocketAddr,
        last_max_gso_segments: NonZeroUsize,
        last_gro_segments: NonZeroUsize,
    },
}

impl SocketState {
    fn try_get_connected(&self) -> io::Result<&webview_sockets::UdpSocket> {
        match self {
            Self::Connected { socket } => Ok(socket),
            Self::Closed { .. } => {
                warn!("socket closed");
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"))
            }
        }
    }

    fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = webview_sockets::UdpSocket::bind(addr)?;
        debug!(%addr, "udp socket binding through host");
        Ok(Self::Connected { socket })
    }

    /// Whether the socket is open and has not failed.
    fn is_healthy(&self) -> bool {
        match self {
            Self::Connected { socket } => {
                let mut cx = Context::from_waker(Waker::noop());
                // Checks the failure state first, no waker is kept unless the
                // send queue is full.
                !matches!(socket.poll_send_ready(&mut cx), Poll::Ready(Err(_)))
            }
            Self::Closed { .. } => false,
        }
    }

    /// Replaces the socket with a new one bound to the same address.
    ///
    /// With `any_port` the new socket binds to port 0.
    fn rebind(&mut self, any_port: bool) -> io::Result<()> {
        let mut addr = match self {
            // The bound address once the host confirmed, else the requested one.
            Self::Connected { socket } => socket.local_addr()?,
            Self::Closed { addr, .. } => *addr,
        };
        if any_port {
            addr.set_port(0);
        }
        debug!("rebinding {}", addr);

        // Transition to Closed first to drop the old socket and its WebSocket.
        self.close();
        if let Self::Closed {
            addr: closed_addr, ..
        } = self
        {
            *closed_addr = addr;
        }

        match Self::bind(addr) {
            Ok(new_state) => {
                *self = new_state;
                Ok(())
            }
            Err(err) => {
                // Stay in Closed state but allow future rebind attempts
                debug!("rebind failed, will retry on next attempt: {}", err);
                Err(err)
            }
        }
    }

    fn is_closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }

    fn close(&mut self) -> Option<webview_sockets::UdpSocket> {
        let Self::Connected { socket } = self else {
            return None;
        };
        let s = Self::Closed {
            addr: socket.local_addr().unwrap_or_else(|_| unspecified()),
            last_max_gso_segments: non_zero(socket.max_gso_segments()),
            last_gro_segments: non_zero(socket.gro_segments()),
        };
        let Self::Connected { socket } = std::mem::replace(self, s) else {
            unreachable!("just checked");
        };
        Some(socket)
    }

    fn max_gso_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { socket } => non_zero(socket.max_gso_segments()),
            Self::Closed {
                last_max_gso_segments,
                ..
            } => *last_max_gso_segments,
        }
    }

    fn gro_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { socket } => non_zero(socket.gro_segments()),
            Self::Closed {
                last_gro_segments, ..
            } => *last_gro_segments,
        }
    }
}

fn non_zero(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN)
}

fn unspecified() -> SocketAddr {
    SocketAddr::new(IpFamily::V4.unspecified_addr(), 0)
}

/// Sender half of a [`UdpSocket`], for noq `Transmit`s.
#[derive(Debug, Clone)]
pub struct UdpSender {
    socket: Arc<UdpSocket>,
}

impl UdpSender {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    /// Async sending
    pub fn send<'a, 'b>(&self, transmit: &'a Transmit<'b>) -> SendFutNoq<'a, 'b> {
        SendFutNoq {
            socket: self.socket.clone(),
            transmit,
        }
    }

    /// Poll send
    pub fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        self.socket.poll_send_noq(cx, transmit)
    }

    /// Best effort sending
    pub fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.socket.try_send_noq(transmit)
    }
}

/// Send future noq
#[derive(Debug)]
pub struct SendFutNoq<'a, 'b> {
    socket: Arc<UdpSocket>,
    transmit: &'a Transmit<'b>,
}

impl Future for SendFutNoq<'_, '_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.socket.poll_send_noq(cx, self.transmit)
    }
}
