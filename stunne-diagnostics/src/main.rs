use futures::{future::FutureExt, pin_mut, select};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;

mod sessions;
use sessions::{DetermineMappingSession, StunEvent, StunSession};

async fn run_session<S: StunSession>(sess: S, mut incoming: mpsc::Receiver<()>) {
    let mut state = sess;
    let mut event = StunEvent::Idle {
        now: Instant::now(),
    };

    loop {
        println!("Session State: {:?}", sess);
        println!("Event: {:?}", event);
        let (new_state, outgoing, messages) = state.process(event);
        println!("\tNew Session:        {:?}", outgoing);
        println!("\tOutgoing Datagrams: {:?}", outgoing);
        println!("\tMessages:           {:?}", messages);

        let timeout_duration = match new_state.timeout() {
            Some(instant) => instant - Instant::now(),
            None => break,
        };
        let timeout_fut = sleep(timeout_duration).fuse();
        let recv_fut = incoming.recv().fuse();
        pin_mut!(recv_fut, timeout_fut);

        event = select! {
            _ = recv_fut => StunEvent::DatagramReceived,
            _ = timeout_fut => StunEvent::Idle { now: Instant::now() },
        };

        state = new_state;
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
