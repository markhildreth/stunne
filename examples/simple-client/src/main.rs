use bytes::BytesMut;
use std::net::UdpSocket;
use std::time::Duration;
use stunne_protocol::encodings::{
    ChangeRequest, ChangeRequestDecoder, MappedAddress, Utf8Decoder, XorMappedAddress,
};
use stunne_protocol::*;

const READ_TIMEOUT: Duration = Duration::from_secs(3);

const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const XOR_MAPPED_ADDRESS_TEXT: &str = "XOR-MAPPED-ADDRESS";

const MAPPED_ADDRESS: u16 = 0x0001;
const MAPPED_ADDRESS_TEXT: &str = "MAPPED-ADDRESS";

const RESPONSE_ORIGIN: u16 = 0x802B;
const RESPONSE_ORIGIN_TEXT: &str = "RESPONSE-ORIGIN";

const OTHER_ADDRESS: u16 = 0x802C;
const OTHER_ADDRESS_TEXT: &str = "OTHER-ADDRESS";

const SOFTWARE: u16 = 0x8022;
const SOFTWARE_TEXT: &str = "SOFTWARE";

const CHANGE_REQUEST: u16 = 0x0003;
const CHANGE_REQUEST_TEXT: &str = "CHANGE-REQUEST";

const UNKNOWN_TEXT: &str = "UNKNOWN";

fn main() -> std::io::Result<()> {
    let address = std::env::args()
        .nth(1)
        .expect("Must provide one argument: address of server");
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(address)?;

    let buf = BytesMut::with_capacity(1024);
    let bytes = StunEncoder::new(buf)
        .encode_header(MessageHeader {
            class: MessageClass::Request,
            method: MessageMethod::BINDING,
            tx_id: TransactionId::random(),
        })
        .add_attribute(
            CHANGE_REQUEST,
            &ChangeRequest {
                change_ip: false,
                change_port: true,
            },
        )
        .add_attribute(SOFTWARE, &"stunne")
        .finish();
    socket.send(bytes.as_ref())?;
    println!("Waiting for response...");

    let mut incoming_buf = [0; 1024];
    socket.set_read_timeout(Some(READ_TIMEOUT))?;
    let amt = socket
        .recv(&mut incoming_buf)
        .expect("Timeout while waiting for response");
    let msg = StunDecoder::new(&incoming_buf[0..amt]).unwrap();

    println!("");
    println!("## Header ##");
    println!("* Class:  {:?}", msg.class());
    println!("* Method: {:?}", msg.method());
    println!("* Tx ID:  {:?}", msg.tx_id());
    println!("");
    println!("## Attributes ##");
    for attribute in msg.attributes() {
        match attribute {
            Ok(attr) => {
                print!(
                    "* {: <20}",
                    match attr.attribute_type() {
                        XOR_MAPPED_ADDRESS => XOR_MAPPED_ADDRESS_TEXT,
                        MAPPED_ADDRESS => MAPPED_ADDRESS_TEXT,
                        RESPONSE_ORIGIN => RESPONSE_ORIGIN_TEXT,
                        OTHER_ADDRESS => OTHER_ADDRESS_TEXT,
                        CHANGE_REQUEST => CHANGE_REQUEST_TEXT,
                        SOFTWARE => SOFTWARE_TEXT,
                        _ => UNKNOWN_TEXT,
                    }
                );

                match attr.attribute_type() {
                    MAPPED_ADDRESS => {
                        let decoder = MappedAddress::decoder();
                        println!("{:?}", attr.decode(&decoder));
                    }
                    XOR_MAPPED_ADDRESS => {
                        let decoder = XorMappedAddress::decoder(msg.header().tx_id);
                        println!("{:?}", attr.decode(&decoder));
                    }
                    RESPONSE_ORIGIN => {
                        let decoder = MappedAddress::decoder();
                        println!("{:?}", attr.decode(&decoder));
                    }
                    OTHER_ADDRESS => {
                        let decoder = MappedAddress::decoder();
                        println!("{:?}", attr.decode(&decoder));
                    }
                    CHANGE_REQUEST => {
                        let decoder = ChangeRequestDecoder::default();
                        println!("{:?}", attr.decode(&decoder));
                    }
                    SOFTWARE => {
                        let decoder = Utf8Decoder::default();
                        println!("{:?}", attr.decode(&decoder));
                    }
                    _ => {
                        println!("{:?}", attr);
                    }
                };
            }
            Err(e) => {
                println!("Error reading attribute: {:#?}", e);
            }
        }
    }

    Ok(())
}
