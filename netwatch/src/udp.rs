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
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use atomic_waker::AtomicWaker;
use noq_udp::Transmit;
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use super::IpFamily;

/// Wrapper around a tokio UDP socket.
#[derive(Debug)]
pub struct UdpSocket {
    socket: RwLock<SocketState>,
    wakers: Arc<SocketWakers>,
    rebind_retry: Mutex<Option<RebindRetry>>,
    /// Set to true, when an error occurred, that means we need to rebind the socket.
    is_broken: AtomicBool,
}

// A retry timer wakes both directions; polling one must not replace the
// other direction's wakeup. The timer is owned by the socket, with no task.
#[derive(Debug, Default)]
struct SocketWakers {
    recv: AtomicWaker,
    send: AtomicWaker,
}

impl Wake for SocketWakers {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.recv.wake();
        self.send.wake();
    }
}

#[derive(Debug)]
struct RebindRetry {
    delay: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

/// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
/// is the max supported by a default configuration of macOS. Some platforms will silently clamp the value.
const SOCKET_BUFFER_SIZE: usize = 7 << 20;

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
            wakers: Arc::default(),
            rebind_retry: Mutex::default(),
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
    /// A failed bind is retried by subsequent I/O with backoff. Async I/O
    /// remains pending during recovery; nonblocking sends return `WouldBlock`.
    /// Calling [`Self::close`] cancels automatic recovery.
    pub fn rebind(&self) -> io::Result<()> {
        let result = {
            let mut retry = self.rebind_retry.lock().unwrap();
            // An explicit network change may make the address usable now.
            *retry = None;
            self.rebind_with_retry(&mut retry)
        };
        // Wake idle receivers even when the bind failed, to arm the timer.
        self.wake_all();
        result
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
        let (socket_tokio, _state) = guard.try_get_connected()?;

        let sock_ref = socket2::SockRef::from(&socket_tokio);
        sock_ref.connect(&socket2::SockAddr::from(addr))?;

        Ok(())
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.socket.read().unwrap();
        let (socket, _state) = guard.try_get_connected()?;

        socket.local_addr()
    }

    /// Closes the socket, and waits for the underlying `libc::close` call to be finished.
    pub async fn close(&self) {
        let socket = {
            let mut retry = self.rebind_retry.lock().unwrap();
            let socket = self.socket.write().unwrap().close();
            self.is_broken
                .store(false, std::sync::atomic::Ordering::Release);
            *retry = None;
            socket
        };
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
        let recovering = self.maybe_rebind().is_err();
        // Automatic rebind wakes (and consumes) the stored wakers, so register
        // this poll after it before inspecting either the timer or socket.
        waker.register(cx.waker());
        if recovering {
            let mut retry = self.rebind_retry.lock().unwrap();
            if let Some(retry) = retry.as_mut() {
                let wake_both = Waker::from(self.wakers.clone());
                let mut timer_cx = Context::from_waker(&wake_both);
                if retry.sleep.as_mut().poll(&mut timer_cx).is_pending() {
                    return Poll::Pending;
                }
            }
            // The deadline elapsed, or an explicit rebind/close raced us.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let guard = match self.socket.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(e)) => panic!("socket lock poisoned: {e}"),
            Err(TryLockError::WouldBlock) => return Poll::Pending,
        };
        if guard.is_closed() && self.is_broken() {
            // A rebind failed after maybe_rebind but before the read lock.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(guard)
    }

    fn wake_all(&self) {
        self.wakers.wake_by_ref();
    }

    // The retry lock serializes explicit/automatic rebind and close. The
    // existing atomic flag keeps healthy I/O off this lock.
    fn rebind_with_retry(&self, retry: &mut Option<RebindRetry>) -> io::Result<()> {
        let mut socket = self.socket.write().unwrap();
        let result = socket.rebind();
        self.is_broken
            .store(result.is_err(), std::sync::atomic::Ordering::Release);
        drop(socket);
        match &result {
            Ok(()) => {
                *retry = None;
                debug!("UDP socket rebound");
            }
            Err(err) => {
                warn!("failed to rebind UDP socket: {err:?}");
                let delay = retry.as_ref().map_or(Duration::from_millis(100), |retry| {
                    (retry.delay * 2).min(Duration::from_secs(5))
                });
                *retry = Some(RebindRetry {
                    delay,
                    sleep: Box::pin(tokio::time::sleep(delay)),
                });
            }
        }
        result
    }

    /// Retry a broken socket when its backoff expires. Synchronous callers
    /// observe WouldBlock during recovery, not a fatal socket error.
    fn maybe_rebind(&self) -> io::Result<()> {
        if !self.is_broken() {
            return Ok(());
        }
        let mut retry = self.rebind_retry.lock().unwrap();
        if !self.is_broken() {
            return Ok(());
        }
        if retry
            .as_ref()
            .is_some_and(|retry| retry.sleep.deadline() > tokio::time::Instant::now())
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let result = self.rebind_with_retry(&mut retry);
        drop(retry);
        self.wake_all();
        result.map_err(|_| io::ErrorKind::WouldBlock.into())
    }

    /// Poll for writable
    pub fn poll_writable(&self, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let guard = std::task::ready!(self.poll_read_socket(&self.wakers.send, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
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
            let (socket, state) = guard.try_get_connected()?;

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
            let guard = n0_future::ready!(self.poll_read_socket(&self.wakers.send, cx));
            let (socket, state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
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
            let guard = n0_future::ready!(self.poll_read_socket(&self.wakers.recv, cx));
            let (socket, state) = guard.try_get_connected()?;

            match socket.poll_recv_ready(cx) {
                Poll::Pending => {
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
            let guard = n0_future::ready!(socket.poll_read_socket(&socket.wakers.recv, cx));
            let (inner_socket, _state) = guard.try_get_connected()?;

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
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
            let guard = n0_future::ready!(socket.poll_read_socket(&socket.wakers.recv, cx));
            let (inner_socket, _state) = guard.try_get_connected()?;

            match inner_socket.poll_recv_ready(cx) {
                Poll::Pending => {
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
            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.wakers.send, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
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
            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.wakers.send, cx));
            let (socket, _state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
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
    Connected {
        socket: tokio::net::UdpSocket,
        state: noq_udp::UdpSocketState,
        /// The addr we are binding to.
        addr: SocketAddr,
        /// The hook to rerun when rebinding, if any.
        #[debug(skip)]
        configure: Option<Configurator>,
    },
    Closed {
        /// The addr to rebind to when recovering.
        addr: SocketAddr,
        /// The hook to rerun when rebinding, if any.
        #[debug(skip)]
        configure: Option<Configurator>,
        last_max_gso_segments: NonZeroUsize,
        last_gro_segments: NonZeroUsize,
        last_may_fragment: bool,
    },
}

impl SocketState {
    fn try_get_connected(&self) -> io::Result<(&tokio::net::UdpSocket, &noq_udp::UdpSocketState)> {
        match self {
            Self::Connected {
                socket,
                state,
                addr: _,
                configure: _,
            } => Ok((socket, state)),
            Self::Closed { .. } => {
                warn!("socket closed");
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "socket closed"))
            }
        }
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
        let (addr, configure) = match self {
            Self::Connected {
                addr, configure, ..
            }
            | Self::Closed {
                addr, configure, ..
            } => (*addr, configure.clone()),
        };
        debug!("rebinding {}", addr);

        // Transition to Closed first to drop the old socket.
        // This is needed so the port is released before we try to bind again.
        if let Self::Connected { state, .. } = self {
            *self = SocketState::Closed {
                addr,
                configure: configure.clone(),
                last_max_gso_segments: state.max_gso_segments(),
                last_gro_segments: state.gro_segments(),
                last_may_fragment: state.may_fragment(),
            };
        }

        match Self::bind(addr, configure) {
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

    fn close(&mut self) -> Option<(tokio::net::UdpSocket, noq_udp::UdpSocketState)> {
        match self {
            Self::Connected {
                state,
                addr,
                configure,
                ..
            } => {
                let s = SocketState::Closed {
                    addr: *addr,
                    configure: configure.clone(),
                    last_max_gso_segments: state.max_gso_segments(),
                    last_gro_segments: state.gro_segments(),
                    last_may_fragment: state.may_fragment(),
                };
                let Self::Connected { socket, state, .. } = std::mem::replace(self, s) else {
                    unreachable!("just checked");
                };
                Some((socket, state))
            }
            Self::Closed { .. } => None,
        }
    }

    fn may_fragment(&self) -> bool {
        match self {
            Self::Connected { state, .. } => state.may_fragment(),
            Self::Closed {
                last_may_fragment, ..
            } => *last_may_fragment,
        }
    }

    fn max_gso_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { state, .. } => state.max_gso_segments(),
            Self::Closed {
                last_max_gso_segments,
                ..
            } => *last_max_gso_segments,
        }
    }

    fn gro_segments(&self) -> NonZeroUsize {
        match self {
            Self::Connected { state, .. } => state.gro_segments(),
            Self::Closed {
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

            let guard =
                n0_future::ready!(this.socket.poll_read_socket(&this.socket.wakers.send, cx));
            let (socket, state) = guard.try_get_connected()?;
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
                let (socket, state) = guard.try_get_connected()?;
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
            let guard =
                n0_future::ready!(self.socket.poll_read_socket(&self.socket.wakers.send, cx));
            let (socket, state) = guard.try_get_connected()?;

            match socket.poll_send_ready(cx) {
                Poll::Pending => {
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

    use testresult::TestResult;

    use super::*;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn rebind_fault() -> (Arc<UdpSocket>, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let fail = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicUsize::new(0));
        let options = BindOptions::new().configure_socket({
            let fail = fail.clone();
            let attempts = attempts.clone();
            move |_, _| {
                attempts.fetch_add(1, Ordering::SeqCst);
                if fail.load(Ordering::SeqCst) {
                    Err(io::ErrorKind::AddrInUse.into())
                } else {
                    Ok(())
                }
            }
        });
        let socket = Arc::new(
            UdpSocket::bind_with("127.0.0.1:0".parse::<SocketAddr>().unwrap(), options).unwrap(),
        );
        (socket, fail, attempts)
    }

    #[tokio::test(start_paused = true)]
    async fn failed_rebind_backs_off_and_wakes_both_directions() {
        let (socket, fail, attempts) = rebind_fault();
        let address = socket.local_addr().unwrap();
        let receiver = Arc::new(WakeCount::default());
        let sender = Arc::new(WakeCount::default());
        let recv_waker = Waker::from(receiver.clone());
        let send_waker = Waker::from(sender.clone());
        let mut recv_cx = Context::from_waker(&recv_waker);
        let mut send_cx = Context::from_waker(&send_waker);
        let mut storage = [0u8; 64];
        let mut bufs = [io::IoSliceMut::new(&mut storage)];
        let mut metas = [noq_udp::RecvMeta::default()];
        assert!(
            socket
                .poll_recv_noq(&mut recv_cx, &mut bufs, &mut metas)
                .is_pending()
        );
        let _ = socket.poll_writable(&mut send_cx);
        fail.store(true, Ordering::SeqCst);
        assert_eq!(
            socket.rebind().unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(receiver.0.load(Ordering::SeqCst) > 0);
        assert!(sender.0.load(Ordering::SeqCst) > 0);
        assert!(socket.is_broken());
        let transmit = Transmit {
            destination: address,
            ecn: None,
            contents: b"ping",
            segment_size: None,
            src_ip: None,
        };
        let udp_sender = socket.clone().create_sender();
        for delay in [100, 200, 400, 800, 1600, 3200, 5000, 5000] {
            let before = attempts.load(Ordering::SeqCst);
            for _ in 0..32 {
                assert!(
                    socket
                        .poll_recv_noq(&mut recv_cx, &mut bufs, &mut metas)
                        .is_pending()
                );
                assert!(socket.poll_writable(&mut send_cx).is_pending());
                assert_eq!(
                    socket.try_send_noq(&transmit).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                assert_eq!(
                    udp_sender.try_send(&transmit).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
            assert_eq!(attempts.load(Ordering::SeqCst), before);
            receiver.0.store(0, Ordering::SeqCst);
            sender.0.store(0, Ordering::SeqCst);
            tokio::time::advance(Duration::from_millis(delay - 1)).await;
            tokio::task::yield_now().await;
            assert_eq!(receiver.0.load(Ordering::SeqCst), 0);
            assert_eq!(sender.0.load(Ordering::SeqCst), 0);
            tokio::time::advance(Duration::from_millis(2)).await;
            tokio::task::yield_now().await;
            assert!(receiver.0.load(Ordering::SeqCst) > 0);
            assert!(sender.0.load(Ordering::SeqCst) > 0);
            assert!(
                socket
                    .poll_recv_noq(&mut recv_cx, &mut bufs, &mut metas)
                    .is_pending()
            );
            assert_eq!(attempts.load(Ordering::SeqCst), before + 1);
        }
        fail.store(false, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(
            socket
                .poll_recv_noq(&mut recv_cx, &mut bufs, &mut metas)
                .is_pending()
        );
        assert!(!socket.is_broken());
        assert_eq!(socket.local_addr().unwrap(), address);
        receiver.0.store(0, Ordering::SeqCst);
        socket.rebind().unwrap();
        assert!(receiver.0.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test]
    async fn failed_rebind_recovers_pending_receive_without_another_notification() {
        let (socket, fail, _) = rebind_fault();
        let address = socket.local_addr().unwrap();
        fail.store(true, Ordering::SeqCst);
        assert!(socket.rebind().is_err());
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let send = tokio::spawn({
            let socket = socket.clone();
            let destination = peer.local_addr().unwrap();
            async move {
                let transmit = Transmit {
                    destination,
                    ecn: None,
                    contents: b"reply",
                    segment_size: None,
                    src_ip: None,
                };
                let mut sender = Box::pin(socket.create_sender());
                std::future::poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx))
                    .await
                    .unwrap();
            }
        });
        let receive = tokio::spawn({
            let socket = socket.clone();
            async move {
                let mut buffer = [0; 64];
                let (n, _) = socket.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..n], b"recovered");
            }
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        fail.store(false, Ordering::SeqCst);
        for _ in 0..50 {
            peer.send_to(b"recovered", address).await.unwrap();
            if receive.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::timeout(Duration::from_secs(1), receive)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), send)
            .await
            .unwrap()
            .unwrap();
        let mut reply = [0; 64];
        let n = tokio::time::timeout(Duration::from_secs(1), peer.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..n], b"reply");
    }

    #[tokio::test(start_paused = true)]
    async fn close_cancels_failed_rebind_recovery() {
        let (socket, fail, attempts) = rebind_fault();
        let address = socket.local_addr().unwrap();
        fail.store(true, Ordering::SeqCst);
        assert!(socket.rebind().is_err());
        let mut buffer = [0; 64];
        let mut receive = Box::pin(socket.recv_from(&mut buffer));
        let waker = Waker::from(Arc::new(WakeCount::default()));
        let mut cx = Context::from_waker(&waker);
        assert!(receive.as_mut().poll(&mut cx).is_pending());
        socket.close().await;
        fail.store(false, Ordering::SeqCst);
        let before = attempts.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(receive.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            socket.send_to(b"closed", address).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(attempts.load(Ordering::SeqCst), before);
        assert!(socket.is_closed());
        assert!(!socket.is_broken());
    }

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
