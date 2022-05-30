use crate::sessions::{DetermineMappingSession, Instructions, StunSession};
use futures::{future::FutureExt, pin_mut, select};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;

mod sessions;

async fn run_session<S: StunSession + core::fmt::Debug>(
    mut sess: S,
    mut incoming: mpsc::Receiver<()>,
) -> Result<(), S::Error> {
    loop {
        let timeout = match sess.process(Instant::now()) {
            Ok(Instructions::Done) => break Ok(()),
            Ok(Instructions::Continue(timeout)) => timeout,
            Err(e) => break Err(e),
        };

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
    let session = DetermineMappingSession::new();
    let (send, recv) = mpsc::channel::<()>(10);
    tokio::spawn(async move {
        sleep(Duration::from_secs(1)).await;
        println!("Sending through 'send'");
        send.send(()).await.unwrap();
    });
    println!("Starting session");
    let result = run_session(session, recv).await;

    println!("Done: {:?}", result);
}
