mod protocol;

use crate::protocol::*;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    // Cryptographically-safe RNG
    let mut rng = ChaCha20Rng::from_entropy();

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let req = StunRequest::new(&mut rng);
    socket.connect("127.0.0.1:3478")?;
    socket.send(req.bytes())?;

    let mut incoming_buf = [0; 1024];
    let (amt, _src) = socket.recv_from(&mut incoming_buf)?;
    println!("Received {} bytes: {:02X?}", amt, incoming_buf);
    let msg = StunMessage::from_bytes(&incoming_buf);
    println!("Message: {:?}", msg);
    Ok(())
}
