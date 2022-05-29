use futures::{future::FutureExt, pin_mut, select};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;

#[derive(Debug)]
struct DetermineNatMappingSession {
    timeout: Option<Instant>,
    received: bool,
}

impl DetermineNatMappingSession {
    fn new() -> Self {
        Self {
            timeout: None,
            received: false,
        }
    }
}

const TIMEOUT_SECS: Duration = Duration::from_secs(3);

impl StunSession for DetermineNatMappingSession {
    fn proceed(&mut self, now: Instant) -> Result<Instructions, SessionError> {
        if self.received {
            return Ok(Instructions::Done);
        }

        match self.timeout {
            Some(t) if t <= now => Err(SessionError::TimeoutOccurred),
            Some(t) => Ok(Instructions::Continue(t - now)),
            None => {
                self.timeout = Some(now + TIMEOUT_SECS);
                Ok(Instructions::Continue(TIMEOUT_SECS))
            }
        }
    }

    fn recv(&mut self) {
        self.received = true;
    }
}

enum Instructions {
    Done,
    Continue(Duration),
}

#[derive(Debug)]
enum SessionError {
    TimeoutOccurred,
}

trait StunSession {
    fn proceed(&mut self, now: Instant) -> Result<Instructions, SessionError>;
    fn recv(&mut self);
}

async fn run_session<S: StunSession + core::fmt::Debug>(
    mut sess: S,
    mut incoming: mpsc::Receiver<()>,
) -> Result<(), SessionError> {
    loop {
        let timeout = match sess.proceed(Instant::now()) {
            Ok(Instructions::Done) => break Ok(()),
            Ok(Instructions::Continue(timeout)) => timeout,
            Err(e) => break Err(e),
        };

        /*
        for outgoing_msg in instructions.outgoing {
            outgoing_msg.serialize(&mut outgoing_buffer);
            outgoing_channel.send(SendInfo {
                destination: outgoing_msg.destination,
                buf: outgoing_buffer,
            });
        }
        */

        let recv_fut = incoming.recv().fuse();
        let timeout_fut = sleep(timeout).fuse();
        pin_mut!(recv_fut, timeout_fut);

        select! {
            _ = recv_fut => sess.recv(),
            _ = timeout_fut => {},
        };
    }
}

#[tokio::main]
async fn main() {
    let session = DetermineNatMappingSession::new();
    let (send, recv) = mpsc::channel::<()>(10);
    tokio::spawn(async move {
        sleep(Duration::from_secs(1)).await;
        send.send(());
    });
    let result = run_session(session, recv).await;

    println!("Done: {:?}", result);
}
