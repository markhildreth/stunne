use bytes::BytesMut;
use std::net::SocketAddr;
use std::net::UdpSocket;
use stunne_protocol::encodings::{MappedAddress, XorMappedAddress};
use stunne_protocol::{MessageClass, MessageHeader, MessageMethod, StunDecoder, StunEncoder};

const SOFTWARE: u16 = 0x8022;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;

fn main() -> std::io::Result<()> {
    let address: SocketAddr = std::env::args()
        .nth(1)
        .expect("Must provide address and port of server (e.g., '127.0.0.1:1234')")
        .parse()
        .expect("Address one is not a valid address");

    let socket = UdpSocket::bind(address)?;
    let mut buf = [0; 1024];

    loop {
        let (bytes, origin) = socket.recv_from(&mut buf).expect("Error reading");
        let msg = StunDecoder::new(&buf[0..=bytes]).unwrap();
        match (msg.class(), msg.method()) {
            (MessageClass::Request, MessageMethod::BINDING) => {
                let response_buf = BytesMut::with_capacity(1024);
                let bytes = StunEncoder::new(response_buf)
                    .encode_header(MessageHeader {
                        class: MessageClass::SuccessResponse,
                        method: MessageMethod::BINDING,
                        tx_id: msg.tx_id(),
                    })
                    .add_attribute(MAPPED_ADDRESS, &MappedAddress::encoder(origin))
                    .add_attribute(
                        XOR_MAPPED_ADDRESS,
                        &XorMappedAddress::encoder(origin, msg.tx_id()),
                    )
                    .add_attribute(SOFTWARE, &"stunne-server")
                    .finish();
                socket.send_to(bytes.as_ref(), origin)?;
            }
            _ => {}
        }
    }
}
