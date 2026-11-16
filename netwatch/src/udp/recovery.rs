//! One bounded recovery episode shared by every socket user.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::time::{Instant, Sleep, sleep_until};

const MAX_FAILED_BINDS: u32 = 6;
const INITIAL_DELAY: Duration = Duration::from_millis(100);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct Recovery {
    phase: Phase,
    failures: u32,
    deadline: Option<Instant>,
    runtime: tokio::runtime::Handle,
}

#[derive(Debug, Default)]
enum Phase {
    #[default]
    Idle,
    Waiting(Pin<Box<Sleep>>),
    Failed(io::Error),
    Closed,
}

impl Recovery {
    pub(super) fn new() -> Self {
        Self {
            phase: Phase::Idle,
            failures: 0,
            deadline: None,
            runtime: tokio::runtime::Handle::current(),
        }
    }

    pub(super) fn begin_explicit(&mut self) -> io::Result<()> {
        self.expire();
        match self.phase {
            Phase::Waiting(_) => Err(Self::pending()),
            Phase::Closed => Err(Self::closed()),
            Phase::Idle | Phase::Failed(_) => {
                self.succeeded();
                Ok(())
            }
        }
    }

    pub(super) fn request(&mut self) {
        if matches!(self.phase, Phase::Idle) {
            self.deadline = Some(Instant::now() + RECOVERY_TIMEOUT);
            self.schedule(INITIAL_DELAY);
        }
    }

    pub(super) fn failed(&mut self, error: &io::Error) {
        self.failures += 1;
        if self.failures == MAX_FAILED_BINDS {
            self.phase = Phase::Failed(Self::copy_error(error));
        } else {
            self.deadline
                .get_or_insert_with(|| Instant::now() + RECOVERY_TIMEOUT);
            let delay = INITIAL_DELAY * (1 << (self.failures - 1));
            self.schedule(delay);
        }
    }

    pub(super) fn succeeded(&mut self) {
        self.phase = Phase::Idle;
        self.failures = 0;
        self.deadline = None;
    }

    pub(super) fn close(&mut self) {
        self.phase = Phase::Closed;
    }

    pub(super) fn is_terminal(&self) -> bool {
        matches!(self.phase, Phase::Failed(_) | Phase::Closed)
    }

    pub(super) fn check(&mut self) -> io::Result<()> {
        self.expire();
        match &self.phase {
            Phase::Idle => Ok(()),
            Phase::Waiting(_) => Err(Self::pending()),
            Phase::Failed(error) => Err(Self::copy_error(error)),
            Phase::Closed => Err(Self::closed()),
        }
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        self.expire();
        match &mut self.phase {
            Phase::Waiting(timer) => timer.as_mut().poll(cx).map(|()| Ok(true)),
            _ => Poll::Ready(self.check().map(|()| false)),
        }
    }

    fn expire(&mut self) {
        if matches!(self.phase, Phase::Waiting(_))
            && self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.phase = Phase::Failed(io::Error::new(
                io::ErrorKind::TimedOut,
                "socket rebind recovery deadline exceeded",
            ));
        }
    }

    fn schedule(&mut self, delay: Duration) {
        let deadline = self.deadline.expect("recovery has a deadline");
        let _runtime = self.runtime.enter();
        self.phase = Phase::Waiting(Box::pin(sleep_until(
            (Instant::now() + delay).min(deadline),
        )));
    }

    fn pending() -> io::Error {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "socket rebind recovery is pending",
        )
    }

    fn closed() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "socket deliberately closed")
    }

    fn copy_error(error: &io::Error) -> io::Error {
        match error.raw_os_error() {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(error.kind(), error.to_string()),
        }
    }
}
