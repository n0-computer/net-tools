//! Recovery must be bounded independently of caller traffic.

use std::{future::poll_fn, net::Ipv4Addr, task::Context, time::Duration};

use super::*;

#[derive(Default)]
struct WakeCount(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn break_binding(socket: &UdpSocket) {
    let mut state = socket.socket.write().unwrap();
    state.close();
    if let SocketState::Closed { addr, .. } = &mut *state {
        *addr = "192.0.2.1:9".parse().unwrap();
    }
}

fn restore_address(socket: &UdpSocket) {
    if let SocketState::Closed { addr, .. } = &mut *socket.socket.write().unwrap() {
        *addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn persistent_failure_stops_retrying_and_remains_terminal() {
    let socket = UdpSocket::bind_local_v4(0).unwrap();
    break_binding(&socket);
    assert!(socket.rebind().is_err());
    let started = tokio::time::Instant::now();
    let error = poll_fn(|cx| socket.poll_writable(cx)).await.unwrap_err();
    assert!(started.elapsed() >= Duration::from_secs(3));
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    restore_address(&socket);
    assert!(poll_fn(|cx| socket.poll_writable(cx)).await.is_err());
    assert!(
        socket.is_closed(),
        "traffic must not restart exhausted recovery"
    );
    socket.rebind().unwrap();
    assert!(
        !socket.is_closed(),
        "only the owner may explicitly restart recovery"
    );
}

#[tokio::test(start_paused = true)]
async fn busy_callers_cannot_accelerate_or_reset_recovery() {
    let socket = UdpSocket::bind_local_v4(0).unwrap();
    break_binding(&socket);
    assert!(socket.rebind().is_err());
    restore_address(&socket);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for _ in 0..100 {
        assert!(socket.poll_writable(&mut cx).is_pending());
        assert_eq!(
            socket.rebind().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    assert!(socket.is_closed(), "no bind before the scheduled retry");
    tokio::time::advance(Duration::from_millis(100)).await;
    poll_fn(|cx| socket.poll_writable(cx)).await.unwrap();
    assert!(!socket.is_broken());
    assert!(!socket.is_closed());
}

#[tokio::test(start_paused = true)]
async fn deliberate_close_cancels_pending_recovery() {
    let socket = UdpSocket::bind_local_v4(0).unwrap();
    break_binding(&socket);
    assert!(socket.rebind().is_err());
    socket.close().await;
    restore_address(&socket);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(poll_fn(|cx| socket.poll_writable(cx)).await.is_err());
    assert_eq!(
        socket.rebind().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(socket.is_closed());
    assert!(!socket.is_broken());
}

#[tokio::test(start_paused = true)]
async fn idle_callers_cannot_extend_the_recovery_deadline() {
    let socket = UdpSocket::bind_local_v4(0).unwrap();
    break_binding(&socket);
    assert!(socket.rebind().is_err());
    restore_address(&socket);
    tokio::time::advance(Duration::from_secs(6)).await;
    let error = poll_fn(|cx| socket.poll_writable(cx)).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        socket.is_closed(),
        "expired recovery must not bind a late socket"
    );
    assert!(!socket.is_broken());
}

#[tokio::test(start_paused = true)]
async fn nonblocking_operations_observe_the_same_terminal_deadline() {
    let socket = UdpSocket::bind_local_v4(0).unwrap();
    break_binding(&socket);
    assert!(socket.rebind().is_err());
    for _ in 0..100 {
        assert_eq!(
            socket.maybe_rebind().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    restore_address(&socket);
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        socket.maybe_rebind().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(socket.is_closed());
    assert!(!socket.is_broken());
}

#[tokio::test(start_paused = true)]
async fn recovery_timer_wakes_both_reader_and_writer() {
    let socket = UdpSocket::bind_local_v4(0).unwrap();
    break_binding(&socket);
    assert!(socket.rebind().is_err());
    restore_address(&socket);
    let reader = Arc::new(WakeCount::default());
    let writer = Arc::new(WakeCount::default());
    let read_waker = Waker::from(Arc::clone(&reader));
    let write_waker = Waker::from(Arc::clone(&writer));
    let mut bytes = [0; 1];
    let mut recv = std::pin::pin!(socket.recv_from(&mut bytes));
    assert!(
        recv.as_mut()
            .poll(&mut Context::from_waker(&read_waker))
            .is_pending()
    );
    assert!(
        socket
            .poll_writable(&mut Context::from_waker(&write_waker))
            .is_pending()
    );
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert!(reader.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
    assert!(writer.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
    poll_fn(|cx| socket.poll_writable(cx)).await.unwrap();
}

#[tokio::test]
async fn failed_rebind_can_be_requested_outside_the_runtime() {
    let socket = Arc::new(UdpSocket::bind_local_v4(0).unwrap());
    break_binding(&socket);
    let caller = Arc::clone(&socket);
    let result = std::thread::spawn(move || caller.rebind()).join().unwrap();
    assert!(result.is_err());
    socket.close().await;
}

#[tokio::test(start_paused = true)]
async fn terminal_polls_do_not_schedule_more_work() {
    let socket = UdpSocket::bind_local_v4(0).unwrap();
    break_binding(&socket);
    assert!(socket.rebind().is_err());
    tokio::time::advance(Duration::from_secs(6)).await;
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    assert!(socket.poll_writable(&mut cx).is_ready());
    counter.0.store(0, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..100 {
        assert!(socket.poll_writable(&mut cx).is_ready());
    }
    assert_eq!(counter.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}
