use crate::errors::MessageDecodeError;
use crate::utils::{decode_message_type, encode_message_type};
use crate::{MessageClass, MessageMethod, TransactionId, MAGIC_COOKIE, STUN_HEADER_BYTES};
use bytes::{BufMut, BytesMut};

/// Represents contextual values in a STUN header.
///
/// This represents data that a user might wish to know about in the STUN header. Info in the
/// header data is [defined in RFC 5389][]. Only contextual data (e.g., message class, method, and
/// transaction id) are represented for the user of this library to interact with, while
/// protocol-specific values (e.g., the magic cookie and message length) are abstracted away.
///
/// [defined in RFC 5389]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeader {
    pub class: MessageClass,
    pub method: MessageMethod,
    pub tx_id: TransactionId,
}

impl MessageHeader {
    /// Encodes the header into a buffer. Note that the header includes a length, but we will not
    /// have the ability to write the length currently since we don't know what it is.
    pub(crate) fn encode_with_length(&self, buf: &mut BytesMut, data_length: u16) {
        buf.reserve(STUN_HEADER_BYTES);
        buf.extend_from_slice(&encode_message_type(self.class, self.method));
        buf.put_u16(data_length);
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(&self.tx_id.as_ref());
    }

    /// Decodes the header from a packet. Returns information in the header, including the length
    /// of the attribute size separately.
    pub(crate) fn decode_with_length(
        buf: &[u8; STUN_HEADER_BYTES],
    ) -> Result<(MessageHeader, u16), MessageDecodeError> {
        if (buf[0] & 0b1100_0000) != 0 {
            return Err(MessageDecodeError::NonZeroStartingBits);
        }

        if buf[4..8] != MAGIC_COOKIE {
            return Err(MessageDecodeError::InvalidMagicCookie);
        }

        let (class, method) = decode_message_type(buf[0..=1].try_into().unwrap())?;
        let length = u16::from_be_bytes(buf[2..=3].try_into().unwrap());
        let tx_id = TransactionId::from_bytes(&buf[8..20]);

        Ok((
            MessageHeader {
                class,
                method,
                tx_id,
            },
            length,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_valid_encoding {
        ($expected_header:expr, $expected_length:expr, $expected_bytes:expr) => {{
            let mut buf = BytesMut::with_capacity(1024);
            $expected_header.encode_with_length(&mut buf, $expected_length);
            assert_eq!(
                buf.as_ref(),
                $expected_bytes.as_ref(),
                "\nActual encoded bytes (left) did not meet expected (right)"
            );

            let (decoded_header, decoded_length) =
                MessageHeader::decode_with_length(&$expected_bytes).unwrap();
            assert_eq!(decoded_header, $expected_header);
            assert_eq!(decoded_length, $expected_length);
        }};
    }

    #[test]
    fn test_valid() {
        // Normal encoding
        #[rustfmt::skip]
        test_valid_encoding!(
            MessageHeader {
                class: MessageClass::Request,
                method: MessageMethod::BINDING,
                tx_id: TransactionId::from_bytes(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
            },
            0,
            [
                // Type
                0x00, 0x01,
                // Length
                0, 0,
                // Magic cookie
                0x21, 0x12, 0xa4, 0x42,
                // TX id
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            ]
        );

        // Change up class and type
        #[rustfmt::skip]
        test_valid_encoding!(
            MessageHeader {
                class: MessageClass::ErrorResponse,
                method: MessageMethod::try_from_u16(0b1010_0101).unwrap(),
                tx_id: TransactionId::from_bytes(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
            },
            0,
            [
                // Type
                0b11, 0b0101_0101,
                // Length
                0, 0,
                // Magic cookie
                0x21, 0x12, 0xa4, 0x42,
                // TX id
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            ]
        );

        // Change up length
        #[rustfmt::skip]
        test_valid_encoding!(
            MessageHeader {
                class: MessageClass::Request,
                method: MessageMethod::BINDING,
                tx_id: TransactionId::from_bytes(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
            },
            u16::MAX,
            [
                // Type
                0x00, 0x01,
                // Length
                0xff, 0xff,
                // Magic cookie
                0x21, 0x12, 0xa4, 0x42,
                // TX id
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            ]
        );

        // Change up the TX id
        #[rustfmt::skip]
        test_valid_encoding!(
            MessageHeader {
                class: MessageClass::ErrorResponse,
                method: MessageMethod::try_from_u16(0b1010_0101).unwrap(),
                tx_id: TransactionId::from_bytes(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
            },
            0,
            [
                // Type
                0b11, 0b0101_0101,
                // Length
                0, 0,
                // Magic cookie
                0x21, 0x12, 0xa4, 0x42,
                // TX id
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            ]
        );
    }

    #[test]
    fn test_non_zero_msbs() {
        #[rustfmt::skip]
        let bytes = [
            // Zero-padding & Message Type. Note a 1 in the first bit.
            0b1000_0000, 0,
            // Message Length
            0, 0,
            // Cookie
            0x21, 0x12, 0xA4, 0x42,
            // Transaction ID
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(
            MessageHeader::decode_with_length(&bytes),
            Err(MessageDecodeError::NonZeroStartingBits)
        ));

        #[rustfmt::skip]
        let bytes = [
            // Zero-padding & Message Type. Note a 1 in the second bit.
            0b0100_0000, 0,
            // Message Length
            0, 0,
            // Cookie
            0x21, 0x12, 0xA4, 0x42,
            // Transaction ID
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(
            MessageHeader::decode_with_length(&bytes),
            Err(MessageDecodeError::NonZeroStartingBits)
        ));

        #[rustfmt::skip]
        let bytes = [
            0b1100_0000, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ];
        assert!(matches!(
            MessageHeader::decode_with_length(&bytes),
            Err(MessageDecodeError::NonZeroStartingBits)
        ));
    }

    #[test]
    fn test_invalid_magic_cookie() {
        #[rustfmt::skip]
        let bytes = [
            // Zero bits and type
            0, 1,
            // Message Length
            0, 0,
            // Cookie
            0x21, 0x12, 0xA4, 0x42,
            // Transaction ID
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Loop over every possible bit that could be flipped. Flip that bit and test.
        for x in 0..32 {
            let mut test_bytes = bytes.clone();
            let change_mask = (1u32 << x).to_be_bytes();
            test_bytes[4] ^= change_mask[0];
            test_bytes[5] ^= change_mask[1];
            test_bytes[6] ^= change_mask[2];
            test_bytes[7] ^= change_mask[3];
            assert!(
                matches!(
                    MessageHeader::decode_with_length(&test_bytes),
                    Err(MessageDecodeError::InvalidMagicCookie)
                ),
                "Did not receive error with bytes {:?} (changed with mask {:?}",
                &bytes,
                change_mask
            );
        }
    }
}
