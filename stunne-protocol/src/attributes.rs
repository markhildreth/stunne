use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct StunAttribute<'a> {
    pub attribute_type: u16,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub enum StunAttributeError {
    /// While reading through the bytes to parse out attributes, the bytes left in the slice ended.
    /// This probably indicates a malformed STUN message is being parsed.
    UnexpectedEndOfBytes,
}

pub struct StunAttributeIterator<'a> {
    data: &'a [u8],
}

const ATTRIBUTE_TYPE_LENGTH_BYTES: usize = 4;

/// Iterates over the bytes representing attributes, yielding a `StunAttribute` for each attribute
/// found.
///
/// If at any point in the iteration some problem is discovered (e.g., the byte stream ends early),
/// then an error is yielded. Any subsuquent call to `next()` will return `None` after such an
/// error.
impl<'a> Iterator for StunAttributeIterator<'a> {
    type Item = Result<StunAttribute<'a>, StunAttributeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() == 0 {
            return None;
        }

        if self.data.len() < ATTRIBUTE_TYPE_LENGTH_BYTES {
            self.data = &self.data[0..0];
            return Some(Err(StunAttributeError::UnexpectedEndOfBytes));
        }

        let type_bytes = &self.data[0..=1];
        let length_bytes = &self.data[2..=3];

        let attribute_type = u16::from_be_bytes(type_bytes.try_into().unwrap());
        let length: usize = u16::from_be_bytes(length_bytes.try_into().unwrap()).into();
        let next_attribute_byte = ATTRIBUTE_TYPE_LENGTH_BYTES + length;

        if next_attribute_byte > self.data.len() {
            self.data = &self.data[0..0];
            return Some(Err(StunAttributeError::UnexpectedEndOfBytes));
        }

        let data = &self.data[ATTRIBUTE_TYPE_LENGTH_BYTES..next_attribute_byte];
        self.data = &self.data[next_attribute_byte..];

        return Some(Ok(StunAttribute {
            attribute_type,
            data,
        }));
    }
}

impl<'a> StunAttributeIterator<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Self {
        return Self { data };
    }
}

/// Gives the reason that a MAPPED-ADDRESS attribute's value could not be parsed.
#[derive(Debug)]
pub enum MappedAddressParseError {
    /// RFC 5389 states that the first byte of a mapped address MUST be zero.
    /// This error is returned if the first byte of the attribute's data is non-zero.
    NonZeroFirstByte,

    /// Returned if the address family in the attribute data is not known.
    ///
    /// RFC 5389 defines only two families: IPv4 and IPv6.
    UnknownFamily,
}

pub fn parse_mapped_address(bytes: &[u8]) -> Result<SocketAddr, MappedAddressParseError> {
    if bytes[0] != 0 {
        return Err(MappedAddressParseError::NonZeroFirstByte);
    }

    let port = u16::from_be_bytes(bytes[2..=3].try_into().unwrap());
    let ip_addr = match bytes[1] {
        0x01 => IpAddr::from(TryInto::<[u8; 4]>::try_into(&bytes[4..=7]).unwrap()),
        0x02 => IpAddr::from(TryInto::<[u8; 16]>::try_into(&bytes[4..=19]).unwrap()),
        _ => return Err(MappedAddressParseError::UnknownFamily),
    };

    Ok(SocketAddr::new(ip_addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_bytes() {
        let bytes: [u8; 0] = [];
        let mut iter = StunAttributeIterator::from_bytes(&bytes);
        assert!(matches!(iter.next(), None));
    }

    #[test]
    fn test_single_attribute() {
        #[rustfmt::skip]
        let bytes: [u8; 8] = [
            1, 5, // Type
            0, 4, // Length. Note that data must be padded to fit 32 bits, so four bytes
                  // is the smaller possible data format.
            1, 2, 3, 4 // Data
        ];

        let mut iter = StunAttributeIterator::from_bytes(&bytes);
        let first = iter.next();
        assert!(matches!(
            first,
            Some(Ok(StunAttribute {
                attribute_type: 0x0105,
                data: &[1, 2, 3, 4]
            }))
        ));

        let second = iter.next();
        assert!(matches!(second, None));
    }

    #[test]
    fn test_longer_attribute() {
        #[rustfmt::skip]
        let bytes: [u8; 12] = [
            0, 1,  // Type,
            0, 8, // Length
            1, 2, 3, 4, 5, 6, 7, 8
        ];

        let mut iter = StunAttributeIterator::from_bytes(&bytes);
        let first = iter.next();
        assert!(matches!(
            first,
            Some(Ok(StunAttribute {
                attribute_type: 1,
                data: &[1, 2, 3, 4, 5, 6, 7, 8]
            }))
        ));

        let second = iter.next();
        assert!(matches!(second, None));
    }

    #[test]
    fn test_multiple_attributes() {
        #[rustfmt::skip]
        let bytes: [u8; 20] = [
            0, 1,  // Type,
            0, 4, // Length
            1, 2, 3, 4,

            0, 2,  // Type,
            0, 8, // Length
            5, 6, 7, 8, 9, 10, 11, 12
        ];

        let mut iter = StunAttributeIterator::from_bytes(&bytes);
        let first = iter.next();
        assert!(matches!(
            first,
            Some(Ok(StunAttribute {
                attribute_type: 1,
                data: &[1, 2, 3, 4]
            }))
        ));

        let second = iter.next();
        assert!(matches!(
            second,
            Some(Ok(StunAttribute {
                attribute_type: 2,
                data: &[5, 6, 7, 8, 9, 10, 11, 12]
            }))
        ));

        let third = iter.next();
        assert!(matches!(third, None));
    }

    #[test]
    fn test_error_when_not_enough_data_for_attribute_type_or_value() {
        #[rustfmt::skip]
        let bytes: [u8; 3] = [
            0, 1, // Type,
            0,    // What the? The length is cut off?
        ];

        let mut iter = StunAttributeIterator::from_bytes(&bytes);
        let first = iter.next();
        assert!(matches!(
            first,
            Some(Err(StunAttributeError::UnexpectedEndOfBytes))
        ));

        let second = iter.next();
        assert!(matches!(second, None));
    }

    #[test]
    fn test_error_when_not_enough_data_for_attribute_length() {
        #[rustfmt::skip]
        let bytes: [u8; 8] = [
            0, 1, // Type
            0, 8, // This attribute should be 8 bytes
            1, 2, 3, 4 // However, there is only four bytes here. Thus, an error
        ];

        let mut iter = StunAttributeIterator::from_bytes(&bytes);
        let first = iter.next();
        assert!(matches!(
            first,
            Some(Err(StunAttributeError::UnexpectedEndOfBytes))
        ));

        let second = iter.next();
        assert!(matches!(second, None));
    }

    #[test]
    fn test_parse_mapped_address_attribute_for_ipv4() {
        #[rustfmt::skip]
        let bytes = [
            0x00, // Zeroes
            0x01, // IPv4,
            0x1F, 0x40, // Port 8000
            0x7F, 0x00, 0x00, 0x01 // 127.0.0.1
        ];
        assert_eq!(
            parse_mapped_address(&bytes).unwrap(),
            "127.0.0.1:8000".parse().unwrap()
        );

        #[rustfmt::skip]
        let bytes = [
            0x00, // Zeroes
            0x01, // IPv4
            0x04, 0xD2, // Port 1234
            0x01, 0x02, 0x03, 0x04 // 1.2.3.4
        ];
        assert_eq!(
            parse_mapped_address(&bytes).unwrap(),
            "1.2.3.4:1234".parse().unwrap()
        );
    }

    #[test]
    fn test_parse_mapped_address_attribute_for_ipv6() {
        #[rustfmt::skip]
        let bytes = [
            0x00, // Zeroes
            0x02, // IPv6
            0x04, 0xD2, // Port 1234
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        ];
        assert_eq!(
            parse_mapped_address(&bytes).unwrap(),
            "[0001:0203:0405:0607:0809:0A0B:0C0D:0E0F]:1234"
                .parse()
                .unwrap()
        );

        #[rustfmt::skip]
        let bytes = [
            0x00, // Zeroes
            0x02, // IPv6
            0x1F, 0x40, // Port 8000
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        ];
        assert_eq!(
            parse_mapped_address(&bytes).unwrap(),
            "[::1]:8000".parse().unwrap()
        );
    }

    #[test]
    fn test_parse_unknown_addressing_scheme() {
        #[rustfmt::skip]
        let bytes = [
            0x00, // Zeroes
            0x03, // Unknown Scheme
            0x1F, 0x40, // Port 8000
            0x00, 0x00, // Some weird bytes for an address scheme that we don't know
        ];
        let result = parse_mapped_address(&bytes);
        assert!(matches!(
            result,
            Err(MappedAddressParseError::UnknownFamily)
        ));
    }

    #[test]
    fn test_parse_address_with_non_zero_first_byte() {
        #[rustfmt::skip]
        let bytes = [
            0x01, // According to RFC 5389, this MUST be zero. We will treat a non-zero as invalid.
            0x01, // IPv4
            0x04, 0xD2, // Port 1234
            0x01, 0x02, 0x03, 0x04 // 1.2.3.4
        ];
        let result = parse_mapped_address(&bytes);
        assert!(matches!(
            result,
            Err(MappedAddressParseError::NonZeroFirstByte)
        ));
    }
}
