use rand::prelude::*;

static BINDING_REQUEST: [u8; 2] = [0x00, 0x01];

/// Magic data that must be included in all STUN messages to clarify that the STUN message
/// uses rfc5389, rather than the outdated rfc3489.
static MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// The class for a given STUN message.
#[derive(Debug)]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

pub struct StunRequest {
    buf: [u8; 20],
}

impl StunRequest {
    pub fn new<T: RngCore>(rng: &mut T) -> Self {
        // Crreate the header
        let mut buf = [0u8; 20];
        buf[0..2].copy_from_slice(&BINDING_REQUEST);
        buf[4..8].copy_from_slice(&MAGIC_COOKIE);

        // Generate the transaction ID randomly
        let mut tx_id = [0u8; 12];
        rng.fill(&mut tx_id[..]);
        buf[8..20].copy_from_slice(&tx_id);

        StunRequest { buf }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
}

#[derive(Debug)]
pub enum HeaderParseError {
    /// Every STUN header must start with two zero bits. This error is raised if either of those
    /// two bits are set.
    NonZeroStartingBits,

    /// The byte slice that the header was to be parsed from was too small.
    ///
    /// Each STUN header is 20 bytes. Therefore, attempting to read bytes from a
    /// slice less than 20 bytes in size will never succeed, and instead we will
    /// fail with this error.
    InvalidSize,

    /// The magic cookie field did not have the fixed value of 0x2112A442.
    InvalidMagicCookie,
}

#[derive(Debug)]
pub struct StunHeader {
    pub class: StunClass,
    pub method: u16,
    pub length: u16,
    pub message_type: u16,
}

const STUN_HEADER_SIZE: usize = 20;

impl StunHeader {
    // NOTE: This bit manipulation was a quick first attempt. More performant manipulations
    // are likely.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, HeaderParseError> {
        if buf.len() < STUN_HEADER_SIZE {
            return Err(HeaderParseError::InvalidSize);
        }

        if (u8::from_be_bytes(buf[0..1].try_into().unwrap()) & 0b1100_0000) != 0 {
            return Err(HeaderParseError::NonZeroStartingBits);
        }

        if buf[4..8] != MAGIC_COOKIE {
            return Err(HeaderParseError::InvalidMagicCookie);
        }

        let (message_type_bytes, rest) = buf.split_at(std::mem::size_of::<u16>());
        let (size_bytes, rest) = rest.split_at(std::mem::size_of::<u16>());
        let (_magic_bytes, _rest) = rest.split_at(std::mem::size_of::<u16>());

        // See RFC notes re: backwards compatability with RFC 3489. The message type
        // is made up of 11 bits, from 2-15, skipping 7 and 11. Bits 7 and 11 are what
        // make up the class. Thus, strange bit manipulation must be done to convert these.
        // Thus, some strange bit manipulation must be done.
        let message_type = u16::from_be_bytes(message_type_bytes.try_into().unwrap());

        let class_bit_one = (message_type & 0b0000_0000_0001_0000_0000) >> 7;
        let class_bit_two = (message_type & 0b0000_0000_0000_0001_0000) >> 4;
        let class = match class_bit_one | class_bit_two {
            0b00 => StunClass::Request,
            0b01 => StunClass::Indication,
            0b10 => StunClass::SuccessResponse,
            0b11 => StunClass::ErrorResponse,
            _ => {
                unreachable!()
            }
        };

        let message_type_first_bits = message_type & 0b0000_0000_0000_1111;
        let message_type_second_bits = (message_type & 0b0000_0000_1110_0000) >> 1;
        let message_type_third_bits = (message_type & 0b0011_1110_0000_0000) >> 2;
        let message_type =
            message_type_first_bits | message_type_second_bits | message_type_third_bits;

        let length = u16::from_be_bytes(size_bytes.try_into().unwrap());

        Ok(StunHeader {
            method: 0,
            length,
            class,
            message_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_size() {
        let result = StunHeader::from_bytes(&[0, 0]);
        assert!(matches!(result, Err(HeaderParseError::InvalidSize)));
    }

    #[test]
    fn test_non_zero_msbs() {
        #[rustfmt::skip]
        let result = StunHeader::from_bytes(&[
            0b1000_0000, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ]);
        assert!(matches!(result, Err(HeaderParseError::NonZeroStartingBits)));

        #[rustfmt::skip]
        let result = StunHeader::from_bytes(&[
            0b0100_0000, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ]);
        assert!(matches!(result, Err(HeaderParseError::NonZeroStartingBits)));

        #[rustfmt::skip]
        let result = StunHeader::from_bytes(&[
            0b1100_0000, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ]);
        assert!(matches!(result, Err(HeaderParseError::NonZeroStartingBits)));
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let result = StunHeader::from_bytes(&[
            0, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x20, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ]);
        assert!(matches!(result, Err(HeaderParseError::InvalidMagicCookie)));

        let result = StunHeader::from_bytes(&[
            0, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x41, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ]);
        assert!(matches!(result, Err(HeaderParseError::InvalidMagicCookie)));

        let result = StunHeader::from_bytes(&[
            0, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xB4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ]);
        assert!(matches!(result, Err(HeaderParseError::InvalidMagicCookie)));
    }

    #[test]
    fn test_zeroes() {
        let header = StunHeader::from_bytes(&[
            0, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert!(matches!(header.class, StunClass::Request));
        assert_eq!(header.method, 0);
        assert_eq!(header.length, 0);
    }

    #[test]
    fn test_message_length() {
        #[rustfmt::skip]
        let header = StunHeader::from_bytes(&[
            0, 0, // Zero-padding & Message Type
            0b1000_0000, 0b0000_0001, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert_eq!(header.length, 32769);
    }

    #[test]
    fn test_class_indication() {
        #[rustfmt::skip]
        let header = StunHeader::from_bytes(&[
            0b0000_0000, 0b0001_0000, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert!(matches!(header.class, StunClass::Indication));
    }

    #[test]
    fn test_class_success_response() {
        #[rustfmt::skip]
        let header = StunHeader::from_bytes(&[
            0b0000_0001, 0b0000_0000, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert!(matches!(header.class, StunClass::SuccessResponse));
    }

    #[test]
    fn test_class_error_response() {
        #[rustfmt::skip]
        let header = StunHeader::from_bytes(&[
            0b0000_0001, 0b0001_0000, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert!(matches!(header.class, StunClass::ErrorResponse));
    }

    #[test]
    fn test_max_message_type() {
        #[rustfmt::skip]
        let header = StunHeader::from_bytes(&[
            0b0011_1110, 0b1110_1111, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert_eq!(header.message_type, 0b0000_1111_1111_1111);
    }

    #[test]
    fn test_message_type() {
        #[rustfmt::skip]
        let header = StunHeader::from_bytes(&[
            0b0001_1110, 0b1010_1101, // Zero-padding & Message Type
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert_eq!(header.message_type, 0b0000_0111_1101_1101);
    }
}
