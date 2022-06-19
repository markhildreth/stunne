use bytes::BytesMut;
use std::net::SocketAddr;
use stunne_protocol::{
    encodings::MappedAddress, ext::SocketAddrExt, MessageClass, MessageHeader, MessageMethod,
    StunDecoder, StunEncoder, TransactionId,
};

const MAPPED_ADDRESS: u16 = 0x01;

#[test]
pub fn simple_test() {
    let buf = BytesMut::with_capacity(1024);
    let header = MessageHeader {
        class: MessageClass::Request,
        method: MessageMethod::BINDING,
        tx_id: TransactionId::random(),
    };
    let address: SocketAddr = "127.0.0.1:8000".parse().unwrap();

    let bytes = StunEncoder::new(buf)
        .encode_header(header.clone())
        .add_attribute(MAPPED_ADDRESS, &address.as_mapped_address())
        .finish();

    let decoded_message = StunDecoder::new(bytes.as_ref()).unwrap();
    let decoded_header = decoded_message.header();
    assert_eq!(header.class, decoded_header.class);
    assert_eq!(header.method, decoded_header.method);
    assert_eq!(header.tx_id, decoded_header.tx_id);

    let mut attribute_iterator = decoded_message.attributes();
    let first_attribute = attribute_iterator.next().unwrap().unwrap();
    assert_eq!(first_attribute.attribute_type(), MAPPED_ADDRESS);

    let decoded_address = first_attribute.decode(&MappedAddress::decoder()).unwrap();
    assert_eq!(decoded_address, address);

    assert!(attribute_iterator.next().is_none());
}
