use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::net::UdpSocket;
use stunne_protocol::*;

fn main() -> std::io::Result<()> {
    // Cryptographically-safe RNG
    let mut rng = ChaCha20Rng::from_entropy();

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("127.0.0.1:3478")?;

    let req = StunRequest::new(&mut rng);
    socket.send(req.bytes())?;

    let mut incoming_buf = [0; 1024];
    let amt = socket.recv(&mut incoming_buf)?;
    println!("Received {} bytes: {:02X?}", amt, &incoming_buf[0..amt]);
    let (header, _remaining_bytes) = StunHeader::from_bytes(&incoming_buf[0..amt]).unwrap();
    println!("Header: {:#?}", header);
    Ok(())
}
