use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::net::UdpSocket;
use stunne_protocol::*;

const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const XOR_MAPPED_ADDRESS_TEXT: &str = "XOR-MAPPED-ADDRESS";

const MAPPED_ADDRESS: u16 = 0x0001;
const MAPPED_ADDRESS_TEXT: &str = "MAPPED-ADDRESS";

const SOFTWARE: u16 = 0x8022;
const SOFTWARE_TEXT: &str = "SOFTWARE";

const UNKNOWN_TEXT: &str = "UNKNOWN";

fn main() -> std::io::Result<()> {
    // Cryptographically-safe RNG
    let mut rng = ChaCha20Rng::from_entropy();

    let socket = UdpSocket::bind("[::]:0")?;
    socket.connect("[::1]:3478")?;

    let req = StunRequest::new(&mut rng);
    socket.send(req.bytes())?;

    let mut incoming_buf = [0; 1024];
    let amt = socket.recv(&mut incoming_buf)?;
    let (header, remaining_bytes) = StunHeader::from_bytes(&incoming_buf[0..amt]).unwrap();
    let iter = StunAttributeIterator::from_bytes(&remaining_bytes);

    println!("Header: {:#?}", header);
    println!("Attributes:");
    for attribute in iter {
        //println!("Attribute: {:#?}", attribute);
        match attribute {
            Ok(StunAttribute {
                attribute_type,
                data,
            }) => {
                print!(
                    "* {: <20}",
                    match attribute_type {
                        XOR_MAPPED_ADDRESS => XOR_MAPPED_ADDRESS_TEXT,
                        MAPPED_ADDRESS => MAPPED_ADDRESS_TEXT,
                        SOFTWARE => SOFTWARE_TEXT,
                        _ => UNKNOWN_TEXT,
                    }
                );

                match attribute_type {
                    XOR_MAPPED_ADDRESS => {
                        println!(
                            "{:?}",
                            parse_xor_mapped_address(data, header.transaction_id)
                        );
                    }
                    MAPPED_ADDRESS => {
                        println!("{:?}", parse_mapped_address(data));
                    }
                    SOFTWARE => {
                        println!("{:?}", String::from_utf8_lossy(data));
                    }
                    _ => {
                        println!("{:?}", data);
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
