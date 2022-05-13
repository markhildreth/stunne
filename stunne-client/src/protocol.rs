use rand::prelude::*;

static BINDING_REQUEST: [u8; 2] = [0x00, 0x01];

/// Magic data that must be included in all STUN messages to clarify that the STUN message
/// uses rfc5389, rather than the outdated rfc3489.
static STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

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
        buf[4..8].copy_from_slice(&STUN_MAGIC);

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
    /// The byte slice that the header was to be parsed from was too small.
    ///
    /// Each STUN header is 20 bytes. Therefore, attempting to read bytes from a
    /// slice less than 20 bytes in size will never succeed, and instead we will
    /// fail with this error.
    InvalidSize,
}

#[derive(Debug)]
pub struct StunHeader {
    pub class: StunClass,
    pub method: u16,
    pub length: u16,
}

const STUN_HEADER_SIZE: usize = 20;

impl StunHeader {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, HeaderParseError> {
        if buf.len() < STUN_HEADER_SIZE {
            return Err(HeaderParseError::InvalidSize);
        }

        let (method_bytes, rest) = buf.split_at(std::mem::size_of::<u16>());
        let (size_bytes, rest) = rest.split_at(std::mem::size_of::<u16>());
        let (cookie_bytes, rest) = rest.split_at(std::mem::size_of::<u16>());
        let method = u16::from_be_bytes(method_bytes.try_into().unwrap());
        let length = u16::from_be_bytes(size_bytes.try_into().unwrap());

        Ok(StunHeader {
            method: 0,
            length,
            class: StunClass::Request,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_size() {
        let result = StunHeader::from_bytes(&[0, 0]);
        assert!(matches!(result, Err(HeaderParseError::InvalidSize)));
    }

    #[test]
    fn test_zeroes() {
        let header = StunHeader::from_bytes(&[
            0, 0, // Zero-padding & Message Type
            0, 0, // Message Length
            0, 0, 0, 0, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert!(matches!(header.class, StunClass::Request));
        assert_eq!(header.method, 0);
        assert_eq!(header.length, 0);
    }

    #[test]
    fn test_message_length() {
        let header = StunHeader::from_bytes(&[
            0, 0, // Zero-padding & Message Type
            0b10000000, 0b00000001, // Message Length
            0, 0, 0, 0, // Cookie
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID
        ])
        .unwrap();
        assert_eq!(header.length, 32769);
    }
}
