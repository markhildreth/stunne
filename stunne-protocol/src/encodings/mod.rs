mod change_request;
mod mapped_address;

use bytes::{BufMut, BytesMut};
use std::str::{from_utf8, Utf8Error};

pub use change_request::{ChangeRequest, ChangeRequestDecoder};
pub use mapped_address::{
    MappedAddress, MappedAddressDecoder, MappedAddressEncoder, XorMappedAddress,
    XorMappedAddressDecoder, XorMappedAddressEncoder,
};

pub trait AttributeEncoder {
    fn encode(&self, dst: &mut BytesMut);
}

pub trait AttributeDecoder<'buf> {
    type Item;
    type Error;

    fn decode(&self, buf: &'buf [u8]) -> Result<Self::Item, Self::Error>;
}

impl AttributeEncoder for &str {
    fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(self.len());
        dst.put(self.as_bytes());
    }
}

#[derive(Default)]
pub struct Utf8Decoder;

impl<'buf> AttributeDecoder<'buf> for Utf8Decoder {
    type Item = &'buf str;
    type Error = Utf8Error;

    fn decode(&self, buf: &'buf [u8]) -> Result<Self::Item, Self::Error> {
        from_utf8(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encoding(expected_string: &str, expected_bytes: &[u8]) {
        // Use zero capacity to ensure that more capacity is reserved if needed.
        let mut buf = BytesMut::with_capacity(0);
        expected_string.encode(&mut buf);
        assert_eq!(&buf, expected_bytes);

        let actual_string = Utf8Decoder::default().decode(expected_bytes).unwrap();
        assert_eq!(actual_string, expected_string);
    }

    #[test]
    fn test_utf8_encoding() {
        test_encoding("test", &[0x74, 0x65, 0x73, 0x74]);
        test_encoding("𓄁", &[0xf0, 0x93, 0x84, 0x81]);
    }

    #[test]
    fn test_invalid_utf8_encoding() {
        const INVALID_UTF8_BYTES: [u8; 1] = [0xf0];
        let result = Utf8Decoder::default().decode(&INVALID_UTF8_BYTES);
        assert!(matches!(result, Err(Utf8Error { .. })));
    }
}
