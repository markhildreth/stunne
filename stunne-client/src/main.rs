use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::net::UdpSocket;

static BINDING_REQUEST: [u8; 2] = [0x00, 0x01];

/// Magic data that must be included in all STUN messages to clarify that the STUN message
/// uses rfc5389, rather than the outdated rfc3489.
static STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

// TODO: Generate randomly
static TX_ID: [u8; 12] = [
    0xeb, 0x68, 0xe6, 0x28, 0xbd, 0x0a, 0xe8, 0x27, 0x45, 0x23, 0xa8, 0x3f,
];

fn main() -> std::io::Result<()> {
    // Cryptographically-safe RNG
    let mut rng = ChaCha20Rng::from_entropy();
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("127.0.0.1:3478")?;

    let mut buf = [0u8; 20];
    buf[0] |= BINDING_REQUEST[0];
    buf[1] |= BINDING_REQUEST[1];
    buf[4..8].copy_from_slice(&STUN_MAGIC);
    let mut tx_id = [0u8; 12];
    rng.fill(&mut tx_id[..]);
    buf[8..20].copy_from_slice(&tx_id);
    println!("Sending: {:?}", buf);
    socket.send(&buf)?;

    let mut incoming_buf = [0; 1024];
    let (amt, src) = socket.recv_from(&mut incoming_buf)?;
    println!("Received {} bytes: {:?}", amt, src);
    Ok(())
}
