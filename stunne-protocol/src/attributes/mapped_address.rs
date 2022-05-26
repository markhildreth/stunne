use std::net::{IpAddr, SocketAddr};

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
