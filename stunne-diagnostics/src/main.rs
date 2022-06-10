use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::Instant;

mod sessions;
use sessions::{DetermineMappingSession, StunEvent, StunSession, StunSessionStatus};

const BUF_SIZE: usize = 1024;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut session = StunSession::new(DetermineMappingSession::default());
    let mut event = StunEvent::Idle {
        now: Instant::now(),
    };
    let mut buf = [0; BUF_SIZE];

    let result = loop {
        println!("Loop Start");
        println!("\tSession : {:?}", session);
        println!("\tEvent   : {:?}", event);
        let outgoing = session.process(&event);
        println!("After Processing:");
        println!("\tSession : {:?}", session);
        println!("\tOutgoing: {:?}", outgoing);

        // TODO: Send out outgoing

        let status = session.status();
        println!("\tStatus  : {:?}", status);
        match status {
            StunSessionStatus::Waiting { timeout } => {
                socket.set_read_timeout(Some(timeout - Instant::now()))?;
            }
            StunSessionStatus::Complete { result } => break result,
        }

        event = match socket.recv_from(&mut buf) {
            Ok((bytes, _src_addr)) => StunEvent::DatagramReceived {
                bytes: &buf[0..bytes],
            },
            Err(e) if e.kind() == ErrorKind::WouldBlock => StunEvent::Idle {
                now: Instant::now(),
            },
            Err(e) => {
                panic!("Unknown error occurred: {:?}", e);
            }
        };

        println!();
    };

    println!("Done: {:?}", result);
    Ok(())
}
