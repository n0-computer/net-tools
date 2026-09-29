#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::{AsSocket, BorrowedSocket};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex, RwLock, RwLockReadGuard, TryLockError, atomic::AtomicBool},
    task::{Context, Poll},
};

use atomic_waker::AtomicWaker;
use n0_future::time::{self, Duration, Instant, Sleep};
use noq_udp::Transmit;
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use super::IpFamily;

/// Wrapper around a tokio UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    socket: RwLock<SocketState>,
    recv_waker: AtomicWaker,
    send_waker: AtomicWaker,
    /// Set to true, when an error occurred, that means we need to rebind the socket.
    is_broken: AtomicBool,
}

/// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
/// is the max supported by a default configuration of macOS. Some platforms will silently clamp the value.
const SOCKET_BUFFER_SIZE: usize = 7 << 20;

/// Delay before the first retry of a failed rebind.
const REBIND_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(10);

/// Maximum delay between retries of a failed rebind.
///
/// The socket retries a failed rebind until the bind succeeds or the socket is closed.
/// After each failure, the delay doubles, up to this maximum. When the delay reaches
/// this maximum, it stays at this value.
const REBIND_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);

/// A socket that is about to be bound, handed to the hook set with
/// [`BindOptions::configure_socket`].
///
/// It implements [`AsFd`] on unix and [`AsSocket`] on Windows, which is what
/// socket wrappers take, so the hook can set options with the socket crate of
/// its choice: `socket2::SockRef::from(&socket)`, or plain `libc::setsockopt`
/// on the raw fd.
#[derive(Debug)]
pub struct SocketRef<'a>(&'a socket2::Socket);

#[cfg(unix)]
impl AsFd for SocketRef<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(windows)]
impl AsSocket for SocketRef<'_> {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.0.as_socket()
    }
}

/// The hook set with [`BindOptions::configure_socket`].
type Configurator = Arc<dyn Fn(SocketRef<'_>, IpFamily) -> io::Result<()> + Send + Sync>;

/// Options to bind a [`UdpSocket`] with.
///
/// Used by [`UdpSocket::bind_with`]. The default options match what the other
/// `bind_*` constructors use.
#[derive(derive_more::Debug, Default, Clone)]
pub struct BindOptions {
    #[debug(skip)]
    configure: Option<Configurator>,
}

impl BindOptions {
    /// Creates the default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a hook to run on the socket just before it is bound.
    ///
    /// This is the escape hatch for socket options this crate does not model
    /// itself, like `SO_MARK` on Linux or `IP_BOUND_IF` on Apple platforms. The
    /// hook runs on every bind, including the rebinds [`UdpSocket`] does to
    /// recover from network changes, since each of those creates a new socket.
    /// That also lets the hook pick up state that changed in between, like the
    /// interface the default route now points at.
    ///
    /// An error from the hook fails the bind, rather than leaving a socket that
    /// silently missed its configuration.
    ///
    /// ```no_run
    /// use std::net::{Ipv4Addr, SocketAddr};
    ///
    /// use netwatch::{BindOptions, UdpSocket};
    ///
    /// let opts = BindOptions::new().configure_socket(|socket, _family| {
    ///     socket2::SockRef::from(&socket).set_recv_buffer_size(1 << 20)
    /// });
    /// let socket = UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), opts)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn configure_socket(
        mut self,
        configure: impl Fn(SocketRef<'_>, IpFamily) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.configure = Some(Arc::new(configure));
        self
    }
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
    pub fn bind_with(addr: impl Into<SocketAddr>, opts: BindOptions) -> io::Result<Self> {
        let socket = SocketState::bind(addr.into(), opts.configure)?;

        Ok(UdpSocket {
            socket: RwLock::new(socket),
            recv_waker: AtomicWaker::default(),
            send_waker: AtomicWaker::default(),
            is_broken: AtomicBool::new(false),
        })
    }

    /// Is the socket broken and needs a rebind?
    pub fn is_broken(&self) -> bool {
        self.is_broken.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Marks this socket as needing a rebind
    fn mark_broken(&self) {
        self.is_broken
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Rebind the underlying socket.
    ///
    /// This binds a new socket to the same address. If the bind fails, the socket stays
    /// unbound, and retries the bind later. After each failure, the delay before the next
    /// retry doubles, up to a maximum.
    ///
    /// While the socket is not bound, receives and sends behave differently:
    ///
    /// - A receive waits until the socket is bound again. While it waits, it runs each
    ///   retry when the retry is due.
    /// - A send fails with [`io::ErrorKind::NotConnected`]. If a retry is due, the send
    ///   runs it first, and continues if the bind succeeds.
    ///
    /// Sends fail and do not wait, because the socket cannot wake each send that waits.
    /// For UDP, a send that fails has the same effect as a datagram that the network
    /// drops.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is closed, or if the bind fails. After a failed bind,
    /// the socket starts the retries.
    pub fn rebind(&self) -> io::Result<()> {
        self.rebind_inner(true)
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
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
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
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
    ///
    /// # Return
    ///
    /// On success, the number of bytes sent is returned, otherwise, the
    /// encountered error is returned.
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
        let (socket_tokio, _state) = guard.try_get()?;

        let sock_ref = socket2::SockRef::from(&socket_tokio);
        sock_ref.connect(&socket2::SockAddr::from(addr))?;

        Ok(())
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.socket.read().unwrap();
        let (socket, _state) = guard.try_get()?;

        socket.local_addr()
    }

    /// Closes the socket, and waits for the underlying `libc::close` call to be finished.
    pub async fn close(&self) {
        let socket = self.socket.write().unwrap().close();
        self.is_broken
            .store(false, std::sync::atomic::Ordering::Release);
        self.wake_all();
        if let Some((sock, _)) = socket {
            let std_sock = sock.into_std();
            let res = tokio::runtime::Handle::current()
                .spawn_blocking(move || {
                    // Calls libc::close, which can block
                    drop(std_sock);
                })
                .await;
            if let Err(err) = res {
                warn!("failed to close socket: {:?}", err);
            }
        }
    }

    /// Check if this socket is closed.
    pub fn is_closed(&self) -> bool {
        self.socket.read().unwrap().is_closed()
    }

    /// Handle potential read errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None.
    fn handle_read_error(&self, error: io::Error) -> Option<io::Error> {
        match error.kind() {
            io::ErrorKind::NotConnected => {
                // This indicates the underlying socket is broken, and we should attempt to rebind it
                self.mark_broken();
                None
            }
            // A transient receive error leaves the socket healthy with the next datagram still queued,
            // so we drop the error poll again rather than surface a spurious failure.
            _ if is_transient_read_error(&error) => None,
            _ => Some(error),
        }
    }

    /// Handle potential write errors, updating internal state.
    ///
    /// Returns `Some(error)` if the error is fatal otherwise `None.
    fn handle_write_error(&self, error: io::Error) -> Option<io::Error> {
        match error.kind() {
            io::ErrorKind::BrokenPipe => {
                // This indicates the underlying socket is broken, and we should attempt to rebind it
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
        cx: &mut std::task::Context<'_>,
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
                    Err(TryLockError::WouldBlock) => {
                        // Ok fine, we registered our waker, the lock is really closed,
                        // we can return pending.
                        return Poll::Pending;
                    }
                }
            }
        };
        Poll::Ready(guard)
    }

    fn wake_all(&self) {
        self.recv_waker.wake();
        self.send_waker.wake();
    }

    /// Checks if the socket needs a rebind, and if so does it.
    ///
    /// Returns an error if the rebind is needed, but failed.
    fn maybe_rebind(&self) -> io::Result<()> {
        if !self.is_broken() {
            return Ok(());
        }

        // Check under a read lock whether a retry is due. `try_read` does not wait for the
        // lock. If the retry is not due, do not take the write lock.
        if let Ok(guard) = self.socket.try_read()
            && !guard.is_rebind_due()
        {
            return Ok(());
        }

        // Take the write lock, and rebind if a rebind is still necessary.
        self.rebind_inner(false)
    }

    /// Rebinds the socket under the write lock.
    ///
    /// A forced rebind always binds. Otherwise this binds only if the socket is broken and
    /// [`SocketState::is_rebind_due`] is true.
    fn rebind_inner(&self, force: bool) -> io::Result<()> {
        let (was_unbound, is_closed, res) = {
            let mut guard = self.socket.write().expect("poisoned");

            let was_unbound = guard.is_unbound();
            let is_closed = guard.is_closed();
            let res = if is_closed {
                // Do not rebind a closed socket.
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"))
            } else if !force && (!self.is_broken() || !guard.is_rebind_due()) {
                // Do nothing if the rebind is not forced, and the socket is not broken or
                // the retry is not due.
                Ok(())
            } else {
                let res = guard.rebind();
                self.is_broken
                    .store(guard.is_unbound(), std::sync::atomic::Ordering::Release);
                res
            };
            (was_unbound, is_closed, res)
        };

        // Wake all tasks in every case, and only after the lock is free. If a poll could
        // not get the lock, it waits for this wake. After a failed bind, a receive that
        // waits must poll the new retry timer.
        self.wake_all();

        match res {
            Ok(()) => Ok(()),
            Err(err) if !was_unbound && !is_closed => {
                warn!("rebind failed, retrying with backoff: {err:#}");
                Err(err)
            }
            // A failed retry is not an error for the send or receive that caused it.
            Err(_) if !force && was_unbound => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Poll for writable
    pub fn poll_writable(&self, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = std::task::ready!(self.poll_read_socket(&self.send_waker, cx));
            // Sends fail while the socket is not bound. See `SocketState::try_get` for why.
            let (socket, _state) = guard.try_get()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
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
            let (socket, state) = guard.try_get()?;

            let res = socket.try_io(Interest::WRITABLE, || state.send(socket.into(), transmit));

            match res {
                Ok(()) => return Ok(()),
                Err(err) => match self.handle_write_error(err) {
                    Some(err) => return Err(err),
                    None => {
                        continue;
                    }
                },
            }
        }
    }

    /// poll send a noq based `Transmit`.
    pub fn poll_send_noq(&self, cx: &mut Context, transmit: &Transmit<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(self.poll_read_socket(&self.send_waker, cx));
            // Sends fail while the socket is not bound. See `SocketState::try_get` for why.
            let (socket, state) = guard.try_get()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res =
                        socket.try_io(Interest::WRITABLE, || state.send(socket.into(), transmit));
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }

                        if let Some(err) = self.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }

    /// noq based `poll_recv`
    pub fn poll_recv_noq(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Err(err) = self.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(self.poll_read_socket(&self.recv_waker, cx));

            let (socket, state) = n0_future::ready!(guard.poll_for_recv(&self.recv_waker, cx)?);

            match socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    // We are ready to read, continue
                }
                Poll::Ready(Err(err)) => match self.handle_read_error(err) {
                    Some(err) => return Poll::Ready(Err(err)),
                    None => {
                        continue;
                    }
                },
            }

            let res = socket.try_io(Interest::READABLE, || state.recv(socket.into(), bufs, meta));
            match res {
                Ok(count) => {
                    for meta in meta.iter().take(count) {
                        trace!(
                            src = %meta.addr,
                            len = meta.len,
                            count = meta.len.checked_div(meta.stride).unwrap_or(0),
                            dst = %meta.dst_ip.map(|x| x.to_string()).unwrap_or_default(),
                            "UDP recv"
                        );
                    }
                    return Poll::Ready(Ok(count));
                }
                Err(err) => {
                    // ignore spurious wakeups
                    if err.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    match self.handle_read_error(err) {
                        Some(err) => return Poll::Ready(Err(err)),
                        None => {
                            continue;
                        }
                    }
                }
            }
        }
    }

    /// Creates a [`UdpSender`] sender.
    pub fn create_sender(self: Arc<Self>) -> UdpSender {
        UdpSender::new(self)
    }

    /// Whether transmitted datagrams might get fragmented by the IP layer
    ///
    /// Returns `false` on targets which employ e.g. the `IPV6_DONTFRAG` socket option.
    pub fn may_fragment(&self) -> bool {
        let guard = self.socket.read().unwrap();
        guard.may_fragment()
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    pub fn max_gso_segments(&self) -> NonZeroUsize {
        let guard = self.socket.read().unwrap();
        guard.max_gso_segments()
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    pub fn gro_segments(&self) -> NonZeroUsize {
        let guard = self.socket.read().unwrap();
        guard.gro_segments()
    }
}

/// `WSAENETRESET` (Winsock error 10052).
///
/// On a UDP socket Windows returns this from a recv when a previously sent datagram
/// could not be delivered because its TTL expired in transit, which the network
/// reports back as an ICMP Time Exceeded message. It describes the fate of that one
/// datagram, not the state of the socket: the socket stays usable and the error is
/// cleared once read, so the next recv proceeds normally. The Rust standard library
/// does not map this code to an [`io::ErrorKind`] (unlike `WSAECONNRESET`), so we match
/// it by its raw OS value.
#[cfg(windows)]
const WSAENETRESET: i32 = 10052;

/// Whether a read error is a transient condition that should be retried rather than
/// surfaced to the caller as a failure.
///
/// On Windows the stack reports the fate of a *previously sent* datagram against the
/// next recv on the same socket, so an ICMP reply surfaces as a recv error even though
/// the socket is healthy. `WSAECONNRESET` reports an ICMP Port Unreachable, meaning the
/// destination had no listener. `WSAENETRESET` reports an ICMP Time Exceeded, meaning a
/// datagram's TTL expired in transit. Both are transient for the same reason: each
/// describes a single datagram and is delivered exactly once, so reading it clears the
/// condition and the following recv returns real data.
///
/// We treat `ConnectionReset` as transient on every platform, not only Windows:
/// ECONNRESET is undefined in QUIC and can be injected by an attacker, so
/// it must never tear down the receive path.
fn is_transient_read_error(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::ConnectionReset {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(WSAENETRESET) {
        return true;
    }
    false
}

/// Receive future
#[derive(Debug)]
pub struct RecvFut<'a, 'b> {
    socket: &'b UdpSocket,
    buffer: &'a mut [u8],
}

impl Future for RecvFut<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;

        loop {
            if let Err(err) = socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(socket.poll_read_socket(&socket.recv_waker, cx));

            let (inner_socket, _state) =
                n0_future::ready!(guard.poll_for_recv(&socket.recv_waker, cx)?);

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.socket.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = inner_socket.try_recv(buffer);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = socket.handle_read_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = socket.handle_read_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
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

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let Self { socket, buffer } = &mut *self;

        loop {
            if let Err(err) = socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard = n0_future::ready!(socket.poll_read_socket(&socket.recv_waker, cx));

            let (inner_socket, _state) =
                n0_future::ready!(guard.poll_for_recv(&socket.recv_waker, cx)?);

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
                    self.socket.recv_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = inner_socket.try_recv_from(buffer);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = socket.handle_read_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = socket.handle_read_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
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

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            // Sends fail while the socket is not bound. See `SocketState::try_get` for why.
            let (socket, _state) = guard.try_get()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_send(self.buffer);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
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

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            // Sends fail while the socket is not bound. See `SocketState::try_get` for why.
            let (socket, _state) = guard.try_get()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_send_to(self.buffer, self.to);
                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }

                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

#[derive(derive_more::Debug)]
enum SocketState {
    /// The socket is bound.
    Connected {
        socket: tokio::net::UdpSocket,
        state: noq_udp::UdpSocketState,
        /// The addr we are binding to.
        addr: SocketAddr,
        /// The hook to rerun when rebinding, if any.
        #[debug(skip)]
        configure: Option<Configurator>,
    },
    /// A rebind failed. The next retry occurs when `retry.at` passes.
    Rebinding {
        /// The addr to rebind to when recovering.
        addr: SocketAddr,
        /// The hook to rerun when rebinding, if any.
        #[debug(skip)]
        configure: Option<Configurator>,
        last_max_gso_segments: NonZeroUsize,
        last_gro_segments: NonZeroUsize,
        last_may_fragment: bool,
        retry: Retry,
    },
    /// The socket is closed. It does not rebind again.
    Closed {
        last_max_gso_segments: NonZeroUsize,
        last_gro_segments: NonZeroUsize,
        last_may_fragment: bool,
    },
}

/// When to retry a failed rebind.
#[derive(Debug)]
struct Retry {
    at: Instant,
    delay: Duration,
    /// Wakes the receive that waits, when the retry is due.
    ///
    /// Only receives poll this timer, see [`SocketState::poll_for_recv`]. The first poll
    /// creates the timer. Thus the code never creates a `Sleep` outside a tokio runtime.
    /// The mutex is necessary because receives only hold a read lock on the socket state.
    timer: Mutex<Option<Pin<Box<Sleep>>>>,
}

impl Retry {
    fn after(delay: Duration) -> Self {
        Self {
            at: Instant::now() + delay,
            delay,
            timer: Mutex::new(None),
        }
    }
}

impl SocketState {
    /// Returns the socket and its state, if the socket is bound.
    ///
    /// Fails if the socket is closed, or if a failed rebind waits for its retry. Use this
    /// for sends, and for all other calls that do not wait. Receives use
    /// [`Self::poll_for_recv`] instead.
    ///
    /// Sends do not wait for a rebind, because the socket cannot wake them reliably:
    ///
    /// - `send_waker` holds one waker. A socket has many senders, for example one for
    ///   each task, so only the last send that waits gets the wake.
    /// - The retry timer also holds one waker, and it belongs to the receive. A send that
    ///   polls the timer replaces the waker of the receive.
    ///
    /// Sends that wait need a wake for each send, for example with `tokio::sync::Notify`.
    /// They also need their own retry timers, so that a retry runs when only sends wait.
    fn try_get(&self) -> io::Result<(&tokio::net::UdpSocket, &noq_udp::UdpSocketState)> {
        match self {
            Self::Connected {
                socket,
                state,
                addr: _,
                configure: _,
            } => Ok((socket, state)),
            Self::Rebinding { .. } => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "socket failed to rebind, waiting to retry",
            )),
            Self::Closed { .. } => {
                warn!("socket closed");
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"))
            }
        }
    }

    /// Returns the socket and its state, or `Pending` while a failed rebind waits.
    ///
    /// Only receives call this. The retry timer holds only one waker, so a second caller
    /// would replace the waker of the receive. Sends use [`Self::try_get`], and fail while
    /// the socket is not bound.
    ///
    /// Registers `cx` with the retry timer, and registers `waker` for the wake after a bind
    /// attempt. Both registrations occur under the read lock. Thus no bind attempt can
    /// occur between them.
    fn poll_for_recv(
        &self,
        waker: &AtomicWaker,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(&tokio::net::UdpSocket, &noq_udp::UdpSocketState)>> {
        let retry = match self {
            SocketState::Connected { socket, state, .. } => {
                return Poll::Ready(Ok((socket, state)));
            }
            SocketState::Closed { .. } => {
                let err = Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"));
                return Poll::Ready(err);
            }
            SocketState::Rebinding { retry, .. } => retry,
        };
        let mut timer = retry.timer.lock().expect("poisoned");
        let timer = timer.get_or_insert_with(|| Box::pin(time::sleep_until(retry.at)));
        if timer.as_mut().poll(cx).is_ready() {
            // The retry is due. Poll again, so that `maybe_rebind` runs the retry.
            cx.waker().wake_by_ref();
        }
        waker.register(cx.waker());
        Poll::Pending
    }

    /// Returns whether the socket can rebind now.
    ///
    /// A bound socket can always rebind. An unbound socket can rebind when the retry is
    /// due. A closed socket never rebinds.
    fn is_rebind_due(&self) -> bool {
        match self {
            Self::Connected { .. } => true,
            Self::Rebinding { retry, .. } => retry.at <= Instant::now(),
            Self::Closed { .. } => false,
        }
    }

    fn is_unbound(&self) -> bool {
        matches!(self, Self::Rebinding { .. })
    }

    fn bind(addr: SocketAddr, configure: Option<Configurator>) -> io::Result<Self> {
        let network = IpFamily::from(addr.ip());
        let socket = socket2::Socket::new(
            network.into(),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        if let Err(err) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
            debug!(
                "failed to set recv_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        if let Err(err) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
            debug!(
                "failed to set send_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        if network == IpFamily::V6 {
            // Avoid dualstack
            socket.set_only_v6(true)?;
        }

        // Let the caller configure the socket before it is bound. An error here
        // fails the bind: a socket that silently missed its configuration would
        // send traffic where the caller did not want it.
        if let Some(configure) = &configure {
            configure(SocketRef(&socket), network)?;
        }

        // Binding must happen before calling noq, otherwise `local_addr`
        // is not yet available on all OSes.
        socket.bind(&addr.into())?;

        // Ensure nonblocking
        socket.set_nonblocking(true)?;

        let socket: std::net::UdpSocket = socket.into();

        // Convert into tokio UdpSocket
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        let socket_ref = noq_udp::UdpSockRef::from(&socket);
        let socket_state = noq_udp::UdpSocketState::new(socket_ref)?;

        let local_addr = socket.local_addr()?;
        if addr.port() != 0 && local_addr.port() != addr.port() {
            return Err(io::Error::other(format!(
                "wrong port bound: {:?}: wanted: {} got {}",
                network,
                addr.port(),
                local_addr.port(),
            )));
        }

        Ok(Self::Connected {
            socket,
            state: socket_state,
            addr: local_addr,
            configure,
        })
    }

    fn rebind(&mut self) -> io::Result<()> {
        let (addr, configure, delay) = match self {
            Self::Connected {
                addr, configure, ..
            } => (*addr, configure.clone(), REBIND_RETRY_INITIAL_DELAY),
            Self::Rebinding {
                addr,
                configure,
                retry,
                ..
            } => (
                *addr,
                configure.clone(),
                (retry.delay * 2).min(REBIND_RETRY_MAX_DELAY),
            ),
            Self::Closed { .. } => {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"));
            }
        };
        debug!("rebinding {}", addr);

        // Change to the Rebinding state first, to drop the old socket.
        // This is needed so the port is released before we try to bind again.
        // Schedule the retry now, in case this bind fails.
        if let Self::Connected { state, .. } = self {
            *self = SocketState::Rebinding {
                addr,
                configure: configure.clone(),
                last_max_gso_segments: state.max_gso_segments(),
                last_gro_segments: state.gro_segments(),
                last_may_fragment: state.may_fragment(),
                retry: Retry::after(delay),
            };
        } else if let Self::Rebinding { retry, .. } = self {
            *retry = Retry::after(delay);
        }

        match Self::bind(addr, configure) {
            Ok(new_state) => {
                *self = new_state;
                Ok(())
            }
            Err(err) => {
                // Stay in the Rebinding state. A send or receive retries the bind after
                // `delay`.
                debug!("rebind failed, will retry on next attempt: {}", err);
                Err(err)
            }
        }
    }

    fn is_closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }

    fn close(&mut self) -> Option<(tokio::net::UdpSocket, noq_udp::UdpSocketState)> {
        match self {
            Self::Connected { state, .. } => {
                let s = SocketState::Closed {
                    last_max_gso_segments: state.max_gso_segments(),
                    last_gro_segments: state.gro_segments(),
                    last_may_fragment: state.may_fragment(),
                };
                let Self::Connected { socket, state, .. } = std::mem::replace(self, s) else {
                    unreachable!("just checked");
                };
                Some((socket, state))
            }
            Self::Rebinding {
                last_max_gso_segments,
                last_gro_segments,
                last_may_fragment,
                ..
            } => {
                *self = SocketState::Closed {
                    last_max_gso_segments: *last_max_gso_segments,
                    last_gro_segments: *last_gro_segments,
                    last_may_fragment: *last_may_fragment,
                };
                None
            }
            Self::Closed { .. } => None,
        }
    }

    fn may_fragment(&self) -> bool {
        match self {
            Self::Connected { state, .. } => state.may_fragment(),
            Self::Rebinding {
                last_may_fragment, ..
            }
            | Self::Closed {
                last_may_fragment, ..
            } => *last_may_fragment,
        }
    }

    fn max_gso_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { state, .. } => state.max_gso_segments(),
            Self::Rebinding {
                last_max_gso_segments,
                ..
            }
            | Self::Closed {
                last_max_gso_segments,
                ..
            } => *last_max_gso_segments,
        }
    }

    fn gro_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { state, .. } => state.gro_segments(),
            Self::Rebinding {
                last_gro_segments, ..
            }
            | Self::Closed {
                last_gro_segments, ..
            } => *last_gro_segments,
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if let Some((socket, _)) = self.socket.write().unwrap().close()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            // No wakeup after dropping write lock here, since we're getting dropped.
            // this will be empty if `close` was called before
            let std_sock = socket.into_std();
            handle.spawn_blocking(move || {
                // Calls libc::close, which can block
                drop(std_sock);
            });
        }
    }
}

pin_project_lite::pin_project! {
    pub struct UdpSender {
        socket: Arc<UdpSocket>,
        #[pin]
        fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync + 'static>>>,
    }
}

impl Clone for UdpSender {
    fn clone(&self) -> Self {
        self.socket.clone().create_sender()
    }
}

impl std::fmt::Debug for UdpSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UdpSender")
    }
}

impl UdpSender {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket, fut: None }
    }

    /// Async sending
    pub fn send<'a, 'b>(&self, transmit: &'a noq_udp::Transmit<'b>) -> SendFutNoq<'a, 'b> {
        SendFutNoq {
            socket: self.socket.clone(),
            transmit,
        }
    }

    /// Poll send
    pub fn poll_send(
        self: Pin<&mut Self>,
        transmit: &noq_udp::Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            if let Err(err) = this.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            if this.fut.is_none() {
                let socket = this.socket.clone();
                this.fut.set(Some(Box::pin(async move {
                    n0_future::future::poll_fn(|cx| socket.poll_writable(cx)).await
                })));
            }
            // We're forced to `unwrap` here because `Fut` may be `!Unpin`, which means we can't safely
            // obtain an `&mut Fut` after storing it in `this.fut` when `this` is already behind `Pin`,
            // and if we didn't store it then we wouldn't be able to keep it alive between
            // `poll_writable` calls.
            let result = n0_future::ready!(this.fut.as_mut().as_pin_mut().unwrap().poll(cx));

            // Polling an arbitrary `Future` after it becomes ready is a logic error, so arrange for
            // a new `Future` to be created on the next call.
            this.fut.set(None);

            // If .writable() fails, propagate the error
            result?;

            // Take the read lock only now. `poll_writable` may rebind the socket, which takes
            // the write lock. If this thread holds the read lock, that causes a deadlock.
            let guard =
                n0_future::ready!(this.socket.poll_read_socket(&this.socket.send_waker, cx));
            let (socket, state) = guard.try_get()?;
            let result = socket.try_io(Interest::WRITABLE, || state.send(socket.into(), transmit));

            match result {
                // We thought the socket was writable, but it wasn't, then retry so that either another
                // `writable().await` call determines that the socket is indeed not writable and
                // registers us for a wakeup, or the send succeeds if this really was just a
                // transient failure.
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                // In all other cases, either propagate the error or we're Ok
                _ => return Poll::Ready(result),
            }
        }
    }

    /// Best effort sending
    pub fn try_send(&self, transmit: &noq_udp::Transmit) -> io::Result<()> {
        self.socket.maybe_rebind()?;

        match self.socket.socket.try_read() {
            Ok(guard) => {
                let (socket, state) = guard.try_get()?;
                socket.try_io(Interest::WRITABLE, || state.send(socket.into(), transmit))
            }
            Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
            Err(TryLockError::WouldBlock) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "locked"))
            }
        }
    }
}

/// Send future noq
#[derive(Debug)]
pub struct SendFutNoq<'a, 'b> {
    socket: Arc<UdpSocket>,
    transmit: &'a noq_udp::Transmit<'b>,
}

impl Future for SendFutNoq<'_, '_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Err(err) = self.socket.maybe_rebind() {
                return Poll::Ready(Err(err));
            }

            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.send_waker, cx));
            // Sends fail while the socket is not bound. See `SocketState::try_get` for why.
            let (socket, state) = guard.try_get()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
                    self.socket.send_waker.register(cx.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    let res = socket.try_io(Interest::WRITABLE, || {
                        state.send(socket.into(), self.transmit)
                    });

                    if let Err(err) = res {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                        if let Some(err) = self.socket.handle_write_error(err) {
                            return Poll::Ready(Err(err));
                        }
                        continue;
                    }
                    return Poll::Ready(res);
                }
                Poll::Ready(Err(err)) => {
                    if let Some(err) = self.socket.handle_write_error(err) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use n0_future::task::{self, AbortOnDropHandle};
    use testresult::TestResult;

    use super::*;

    #[tokio::test]
    async fn test_reconnect() -> TestResult {
        let (s_b, mut r_b) = tokio::sync::mpsc::channel(16);
        let handle_a = tokio::task::spawn(async move {
            let socket = UdpSocket::bind_local(IpFamily::V4, 0)?;
            let addr = socket.local_addr()?;
            s_b.send(addr).await?;
            println!("socket bound to {addr:?}");

            let mut buffer = [0u8; 16];
            for i in 0..100 {
                println!("-- tick {i}");
                let read = socket.recv_from(&mut buffer).await;
                match read {
                    Ok((count, addr)) => {
                        println!("got {:?}", &buffer[..count]);
                        println!("sending {:?} to {:?}", &buffer[..count], addr);
                        socket.send_to(&buffer[..count], addr).await?;
                    }
                    Err(err) => {
                        eprintln!("error reading: {err:?}");
                    }
                }
            }
            socket.close().await;
            Ok::<_, testresult::TestError>(())
        });

        let socket = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let first_addr = socket.local_addr()?;
        println!("socket2 bound to {:?}", socket.local_addr()?);
        let addr = r_b.recv().await.unwrap();

        let mut buffer = [0u8; 16];
        for i in 0u8..100 {
            println!("round one - {i}");
            socket.send_to(&[i][..], addr).await?;
            let (count, from) = socket.recv_from(&mut buffer).await?;
            assert_eq!(addr, from);
            assert_eq!(count, 1);
            assert_eq!(buffer[0], i);

            // check for errors
            assert!(!socket.is_broken());

            // rebind
            socket.rebind()?;

            // check that the socket has the same address as before
            assert_eq!(socket.local_addr()?, first_addr);
        }

        handle_a.await.ok();

        Ok(())
    }

    #[tokio::test]
    async fn test_configure_socket_runs_on_every_bind() -> TestResult {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let opts = BindOptions::new().configure_socket(move |socket, family| {
            assert_eq!(family, IpFamily::V4);
            // The hook gets a real socket, before it is bound.
            socket2::SockRef::from(&socket).set_reuse_address(true)?;
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let socket = UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), opts)?;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hook did not run on bind");

        socket.rebind()?;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "hook did not run again on rebind"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_configure_socket_error_fails_the_bind() -> TestResult {
        let opts =
            BindOptions::new().configure_socket(|_socket, _family| Err(io::Error::other("nope")));

        assert!(
            UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), opts).is_err(),
            "a failing hook must fail the bind"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_udp_mark_broken() -> TestResult {
        let socket_a = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let addr_a = socket_a.local_addr()?;
        println!("socket bound to {addr_a:?}");

        let socket_b = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let addr_b = socket_b.local_addr()?;
        println!("socket bound to {addr_b:?}");

        let handle = tokio::task::spawn(async move {
            let mut buffer = [0u8; 16];
            for _ in 0..2 {
                match socket_b.recv_from(&mut buffer).await {
                    Ok((count, addr)) => {
                        println!("got {:?} from {:?}", &buffer[..count], addr);
                    }
                    Err(err) => {
                        eprintln!("error recv: {err:?}");
                    }
                }
            }
        });
        socket_a.send_to(&[0][..], addr_b).await?;
        socket_a.mark_broken();
        assert!(socket_a.is_broken());
        socket_a.send_to(&[0][..], addr_b).await?;
        assert!(!socket_a.is_broken());

        handle.await?;
        Ok(())
    }

    /// A bind hook that fails on request, and counts the bind attempts.
    #[derive(Debug, Default)]
    struct FlakyBind {
        fail: AtomicBool,
        attempts: AtomicUsize,
    }

    impl FlakyBind {
        /// Binds a socket on localhost. Each bind and rebind of the socket calls this hook.
        fn bind(self: &Arc<Self>) -> io::Result<UdpSocket> {
            let this = self.clone();
            let opts = BindOptions::new().configure_socket(move |_socket, _family| {
                this.attempts.fetch_add(1, Ordering::SeqCst);
                if this.fail.load(Ordering::SeqCst) {
                    Err(io::Error::other("bind failure for testing"))
                } else {
                    Ok(())
                }
            });
            UdpSocket::bind_with(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), opts)
        }

        fn set_failing(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    /// Sends `msg` from `from` to `to` every 20ms, until the caller drops the handle.
    ///
    /// A datagram that arrives while the target socket is not bound is lost. Thus one send
    /// is not enough when the test does not know when the target socket binds again.
    fn send_repeatedly(
        from: Arc<UdpSocket>,
        msg: &'static [u8],
        to: SocketAddr,
    ) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(task::spawn(async move {
            loop {
                from.send_to(msg, to).await.ok();
                time::sleep(Duration::from_millis(20)).await;
            }
        }))
    }

    /// A rebind fails, and the socket recovers when binds work again.
    ///
    /// While the socket is not bound, sends fail and receives wait. When binds work again,
    /// a retry binds the socket to the same address. Then the receive that waits gets its
    /// datagram, and sends work again.
    #[tokio::test]
    async fn test_failed_rebind_recovers() -> TestResult {
        let flaky = Arc::new(FlakyBind::default());
        let socket = flaky.bind()?;
        let addr = socket.local_addr()?;
        let peer = Arc::new(UdpSocket::bind_local(IpFamily::V4, 0)?);
        let peer_addr = peer.local_addr()?;

        flaky.set_failing(true);
        assert!(socket.rebind().is_err());
        assert!(socket.is_broken());

        // Sends fail, and receives wait. The receive retries the bind while it waits.
        let err = socket.send_to(b"pong", peer_addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        let mut buffer = [0u8; 16];
        let mut recv = socket.recv_from(&mut buffer);
        assert!(
            time::timeout(Duration::from_millis(400), &mut recv)
                .await
                .is_err()
        );
        assert!(flaky.attempts() > 2, "the receive did not retry the bind");

        // Binds work again. A retry binds the socket, and the receive gets the datagram.
        flaky.set_failing(false);
        let _ping = send_repeatedly(peer.clone(), b"ping", addr);
        let (count, from) = time::timeout(Duration::from_secs(10), recv).await??;
        assert_eq!((&buffer[..count], from), (&b"ping"[..], peer_addr));
        assert!(!socket.is_broken());
        assert_eq!(socket.local_addr()?, addr);

        socket.send_to(b"pong", peer_addr).await?;
        let mut peer_buffer = [0u8; 16];
        let (count, from) =
            time::timeout(Duration::from_secs(5), peer.recv_from(&mut peer_buffer)).await??;
        assert_eq!((&peer_buffer[..count], from), (&b"pong"[..], addr));
        Ok(())
    }

    /// The delay between retries starts at `REBIND_RETRY_INITIAL_DELAY`, and doubles up to
    /// `REBIND_RETRY_MAX_DELAY`.
    ///
    /// Each retry occurs exactly when its delay passes. When no task polls the socket, no
    /// retries occur.
    #[tokio::test(start_paused = true)]
    async fn test_rebind_retries_back_off() -> TestResult {
        let flaky = Arc::new(FlakyBind::default());
        let socket = Arc::new(flaky.bind()?);
        flaky.set_failing(true);
        assert!(socket.rebind().is_err());
        assert_eq!(flaky.attempts(), 2);

        // A receive that waits polls the retry timer.
        let recv = AbortOnDropHandle::new(task::spawn({
            let socket = socket.clone();
            async move {
                let mut buffer = [0u8; 16];
                socket.recv_from(&mut buffer).await.ok();
            }
        }));
        tokio::task::yield_now().await;

        // The schedule ends after two retries with the maximum delay.
        let mut delays = vec![REBIND_RETRY_INITIAL_DELAY];
        while !delays.ends_with(&[REBIND_RETRY_MAX_DELAY; 2]) {
            let last = *delays.last().expect("not empty");
            delays.push((last * 2).min(REBIND_RETRY_MAX_DELAY));
        }

        let one_ms = Duration::from_millis(1);
        for (i, delay) in delays.iter().enumerate() {
            tokio::time::advance(*delay - one_ms).await;
            tokio::task::yield_now().await;
            assert_eq!(flaky.attempts(), 2 + i, "retried before {delay:?}");
            tokio::time::advance(one_ms).await;
            tokio::task::yield_now().await;
            assert_eq!(flaky.attempts(), 3 + i, "did not retry after {delay:?}");
        }

        drop(recv);
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_eq!(flaky.attempts(), 2 + delays.len());
        Ok(())
    }

    /// An I/O error starts a rebind, and the bind fails.
    ///
    /// The send that starts the rebind returns the bind error. Until the retry is due,
    /// sends fail and do not try to bind. After the delay, a send binds the socket again.
    #[tokio::test]
    async fn test_failed_rebind_after_error_recovers_by_sender() -> TestResult {
        let flaky = Arc::new(FlakyBind::default());
        let socket = flaky.bind()?;
        let addr = socket.local_addr()?;
        let peer = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let peer_addr = peer.local_addr()?;

        flaky.set_failing(true);
        socket.mark_broken();
        assert!(socket.send_to(b"hello", peer_addr).await.is_err());
        assert_eq!(flaky.attempts(), 2);

        let err = socket.send_to(b"hello", peer_addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        assert_eq!(flaky.attempts(), 2);

        flaky.set_failing(false);
        time::sleep(Duration::from_millis(150)).await;
        socket.send_to(b"hello", peer_addr).await?;
        assert!(!socket.is_broken());
        let mut buffer = [0u8; 16];
        let (count, from) =
            time::timeout(Duration::from_secs(5), peer.recv_from(&mut buffer)).await??;
        assert_eq!((&buffer[..count], from), (&b"hello"[..], addr));
        Ok(())
    }

    /// Regression test for a lost wakeup of a receive that waits.
    ///
    /// Other threads send on the socket while binds fail. These sends take the socket lock
    /// often. A receive that finds the lock taken must still wake when a retry is due. The
    /// senders stop before the test ends, so only the timer of the receive can retry the
    /// bind. The race is rare, so the test runs 20 times.
    #[tokio::test]
    async fn test_unbound_receiver_wakes_under_send_load() -> TestResult {
        for _ in 0..20 {
            let flaky = Arc::new(FlakyBind::default());
            let socket = Arc::new(flaky.bind()?);
            let addr = socket.local_addr()?;
            let peer = Arc::new(UdpSocket::bind_local(IpFamily::V4, 0)?);
            let transmit_to = peer.local_addr()?;
            flaky.set_failing(true);
            socket.rebind().ok();

            let stop = Arc::new(AtomicBool::new(false));
            let senders: Vec<_> = (0..3)
                .map(|_| {
                    let socket = socket.clone();
                    let stop = stop.clone();
                    let runtime = tokio::runtime::Handle::current();
                    std::thread::spawn(move || {
                        // A send can bind the socket, which needs the runtime.
                        let _guard = runtime.enter();
                        let transmit = noq_udp::Transmit {
                            destination: transmit_to,
                            ecn: None,
                            contents: b"x",
                            segment_size: None,
                            src_ip: None,
                        };
                        while !stop.load(Ordering::SeqCst) {
                            socket.try_send_noq(&transmit).ok();
                        }
                    })
                })
                .collect();

            let recv = task::spawn({
                let socket = socket.clone();
                async move {
                    let mut buffer = [0u8; 16];
                    socket.recv_from(&mut buffer).await.map(|(n, _)| n)
                }
            });
            time::sleep(Duration::from_millis(150)).await;
            flaky.set_failing(false);
            time::sleep(Duration::from_millis(50)).await;
            stop.store(true, Ordering::SeqCst);
            for sender in senders {
                sender.join().expect("sender thread panicked");
            }

            let _ping = send_repeatedly(peer, b"hi", addr);
            let count = time::timeout(Duration::from_secs(10), recv).await???;
            assert_eq!(count, 2);
        }
        Ok(())
    }

    /// Regression test: a send must not strand a receive that waits.
    ///
    /// The retry timer holds only one waker. If a send polls the timer, it replaces the
    /// waker of the receive. If the task of the send then stops, no task retries the bind,
    /// and the receive waits forever.
    #[tokio::test]
    async fn test_send_does_not_strand_waiting_receive() -> TestResult {
        let flaky = Arc::new(FlakyBind::default());
        let socket = Arc::new(flaky.bind()?);
        let addr = socket.local_addr()?;
        let peer = Arc::new(UdpSocket::bind_local(IpFamily::V4, 0)?);
        flaky.set_failing(true);
        assert!(socket.rebind().is_err());

        let recv = task::spawn({
            let socket = socket.clone();
            async move {
                let mut buffer = [0u8; 16];
                socket.recv_from(&mut buffer).await.map(|(n, _)| n)
            }
        });
        time::sleep(Duration::from_millis(50)).await;

        // Poll each kind of send one time, from a task that does not poll again.
        let peer_addr = peer.local_addr()?;
        let transmit = noq_udp::Transmit {
            destination: peer_addr,
            ecn: None,
            contents: b"x",
            segment_size: None,
            src_ip: None,
        };
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut sender = std::pin::pin!(socket.clone().create_sender());
        let sends = [
            socket
                .poll_send_noq(&mut cx, &transmit)
                .map(|res| res.map(|_| ())),
            std::pin::pin!(socket.send(b"x"))
                .poll(&mut cx)
                .map(|res| res.map(|_| ())),
            std::pin::pin!(socket.send_to(b"x", peer_addr))
                .poll(&mut cx)
                .map(|res| res.map(|_| ())),
            std::pin::pin!(sender.send(&transmit)).poll(&mut cx),
            sender.as_mut().poll_send(&transmit, &mut cx),
        ];
        for (i, send) in sends.into_iter().enumerate() {
            assert!(matches!(send, Poll::Ready(Err(_))), "send {i} did not fail");
        }

        flaky.set_failing(false);
        let _ping = send_repeatedly(peer, b"hi", addr);
        let count = time::timeout(Duration::from_secs(10), recv).await???;
        assert_eq!(count, 2);
        Ok(())
    }

    /// Regression test for a deadlock between a rebind and [`UdpSender::poll_send`].
    ///
    /// The sender held the read lock while it waited for the socket to become writable.
    /// That wait rebinds a broken socket, which takes the write lock on the same thread. A
    /// deadlock stops the runtime thread, so a second thread checks for it.
    #[test]
    fn test_rebind_during_send_does_not_deadlock() {
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(send_while_rebinding());
            done_tx.send(()).ok();
        });
        done_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("sending deadlocked against a rebind");
    }

    /// Sends on a socket, while a second thread marks the socket as broken and rebinds it.
    async fn send_while_rebinding() {
        let socket = Arc::new(UdpSocket::bind_local(IpFamily::V4, 0).expect("bind"));
        let peer = UdpSocket::bind_local(IpFamily::V4, 0).expect("bind");
        let transmit = noq_udp::Transmit {
            destination: peer.local_addr().expect("local addr"),
            ecn: None,
            contents: b"hello",
            segment_size: None,
            src_ip: None,
        };
        let rebinder = std::thread::spawn({
            let socket = socket.clone();
            let runtime = tokio::runtime::Handle::current();
            move || {
                let _guard = runtime.enter();
                for _ in 0..2_000 {
                    socket.mark_broken();
                    socket.rebind().ok();
                }
            }
        });
        let mut sender = std::pin::pin!(socket.clone().create_sender());
        while !rebinder.is_finished() {
            n0_future::future::poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx))
                .await
                .ok();
        }
    }

    /// A closed socket stays closed. A rebind fails, and receives fail.
    #[tokio::test]
    async fn test_close_is_final() -> TestResult {
        let socket = UdpSocket::bind_local(IpFamily::V4, 0)?;
        socket.close().await;
        assert!(socket.is_closed());
        assert!(!socket.is_broken());
        assert!(socket.rebind().is_err());
        assert!(socket.is_closed());
        let mut buffer = [0u8; 16];
        let recv = time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer));
        assert!(recv.await?.is_err());
        Ok(())
    }

    /// Regression test for the Windows behavior handled by [`is_transient_read_error`].
    ///
    /// A recv call must survive an ICMP error caused by an earlier send on the same socket.
    ///
    /// On Windows, sending a UDP datagram to a port with no listener draws an ICMP
    /// port-unreachable, and the OS reports it against the *next* recv on that socket as
    /// WSAECONNRESET. Before the fix our recv loop surfaced that error, so a perfectly
    /// good datagram waiting behind it was lost and the recv failed. After the fix the
    /// error is ignored and the real datagram is delivered.
    ///
    /// This only exercises the bug on Windows. Other platforms do not deliver the ICMP
    /// error to an unconnected recv, so the recv just returns the datagram and the test
    /// passes whether or not the fix is present.
    #[tokio::test]
    async fn test_recv_survives_icmp_unreachable_from_prior_send() -> TestResult {
        use std::time::Duration;

        // The socket under test, plus a legitimate peer to deliver a real datagram.
        let receiver = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let receiver_addr = receiver.local_addr()?;
        let sender = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let sender_addr = sender.local_addr()?;

        // A definitely-closed port: bind a socket, take its address, then close it.
        let closed_addr = {
            let tmp = UdpSocket::bind_local(IpFamily::V4, 0)?;
            let addr = tmp.local_addr()?;
            tmp.close().await;
            addr
        };

        // The receiver pokes the closed port. On Windows the ICMP port-unreachable that
        // comes back arms WSAECONNRESET against the receiver's next recv.
        receiver.send_to(b"void", closed_addr).await?;

        // Give the ICMP reply time to arrive, so the error is pending before the real
        // datagram and the recv.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The peer sends a real datagram that the receiver must deliver.
        sender.send_to(b"hello", receiver_addr).await?;

        // Before the fix this recv returns WSAECONNRESET on Windows instead of "hello".
        let mut buf = [0u8; 16];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut buf))
            .await
            .expect("recv must not hang")?;

        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, sender_addr);

        Ok(())
    }
}
