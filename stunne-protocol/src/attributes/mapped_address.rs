use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

    /// The length of the byte slice given did not match the expected number of bytes required
    /// to parse the address. Either too few or too many bytes were given.
    UnexpectedEndOfSlice,
}

/// Number of bytes to read the zero byte, family byte, and port.
const MAPPED_ADDRESS_HEADER_BYTES: usize = 4;

const IPV4_FAMILY: u8 = 0x01;
const IPV6_FAMILY: u8 = 0x02;

/// Number of bytes needed to store the IP address portion of an IPv4 Address
const IPV4_BYTE_LENGTH: usize = 4;

/// Number of bytes needed to store the IP address portion of an IPv6 Address
const IPV6_BYTE_LENGTH: usize = 16;

/// The most significant 16 bits of the magic cookie. Used for XORing against the port.
const MAGIC_COOKIE_MSB: u16 = 0x2112;
const MAGIC_COOKIE_FULL: u32 = 0x2112A442;

pub fn parse_mapped_address(bytes: &[u8]) -> Result<SocketAddr, MappedAddressParseError> {
    if bytes.len() < MAPPED_ADDRESS_HEADER_BYTES {
        return Err(MappedAddressParseError::UnexpectedEndOfSlice);
    }

    let (header_bytes, address_bytes) = bytes.split_at(MAPPED_ADDRESS_HEADER_BYTES);
    if header_bytes[0] != 0 {
        return Err(MappedAddressParseError::NonZeroFirstByte);
    }
    let port = u16::from_be_bytes(header_bytes[2..=3].try_into().unwrap());

    let ip_addr = match header_bytes[1] {
        IPV4_FAMILY => {
            if address_bytes.len() != IPV4_BYTE_LENGTH {
                return Err(MappedAddressParseError::UnexpectedEndOfSlice);
            }
            let array: [u8; IPV4_BYTE_LENGTH] = address_bytes.try_into().unwrap();
            IpAddr::from(array)
        }
        IPV6_FAMILY => {
            if address_bytes.len() != IPV6_BYTE_LENGTH {
                return Err(MappedAddressParseError::UnexpectedEndOfSlice);
            }
            let data: [u8; IPV6_BYTE_LENGTH] = address_bytes.try_into().unwrap();
            IpAddr::from(data)
        }
        _ => return Err(MappedAddressParseError::UnknownFamily),
    };

    Ok(SocketAddr::new(ip_addr, port))
}

pub fn parse_xor_mapped_address(
    bytes: &[u8],
    transaction_id: u128,
) -> Result<SocketAddr, MappedAddressParseError> {
    let addr = parse_mapped_address(bytes)?;
    let processed_ip = match addr.ip() {
        IpAddr::V4(ip) => {
            let address: u32 = ip.into();
            let new_address = address ^ MAGIC_COOKIE_FULL;
            IpAddr::V4(Ipv4Addr::from(new_address))
        }
        IpAddr::V6(ip) => {
            let address: u128 = ip.into();
            let xor_mask: u128 = ((MAGIC_COOKIE_FULL as u128) << 96) + transaction_id;
            let new_address: u128 = address ^ xor_mask;
            IpAddr::V6(Ipv6Addr::from(new_address))
        }
    };
    let processed_port = addr.port() ^ MAGIC_COOKIE_MSB;

    Ok(SocketAddr::new(processed_ip, processed_port))
}

#[cfg(test)]
mod test_mapped_address {
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

    #[test]
    fn test_parse_mapped_address_invalid_number_of_bytes() {
        assert!(matches!(
            parse_mapped_address(&[]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(matches!(
            parse_mapped_address(&[0x00]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(matches!(
            parse_mapped_address(&[0x00, 0x01]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(matches!(
            parse_mapped_address(&[0x00, 0x01, 0x00]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(matches!(
            parse_mapped_address(&[0x00, 0x01, 0x04, 0xD2]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(matches!(
            parse_mapped_address(&[0x00, 0x01, 0x04, 0xD2, 0x00]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(matches!(
            parse_mapped_address(&[0x00, 0x01, 0x04, 0xD2, 0x00, 0x00]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(matches!(
            parse_mapped_address(&[0x00, 0x01, 0x04, 0xD2, 0x00, 0x00, 0x00]),
            Err(MappedAddressParseError::UnexpectedEndOfSlice)
        ));

        assert!(
            // note change to IPv6
            matches!(
                parse_mapped_address(&[0x00, 0x02, 0x04, 0xD2, 0x00, 0x00, 0x00, 0x00]),
                Err(MappedAddressParseError::UnexpectedEndOfSlice)
            )
        );
    }
}

#[cfg(test)]
mod test_xor_mapped_address {
    use super::*;

    #[test]
    fn test_for_ipv4() {
        // Transaction ID is not used for IPv4 mappings, but still a required argument as it
        // may be needed for IPv6.
        let transaction_id = 0x5ddc50d9f58f88fd37b31bc1;
        #[rustfmt::skip]
        let bytes = [
           0x00, // Zeroes
           0x01, // IPv4
           0x9e, 0x57, // XOR Port of 48965
           0x5e, 0x12, 0xa4, 0x43, //XORed IP address of 127.0.0.1
        ];
        assert_eq!(
            parse_xor_mapped_address(&bytes, transaction_id).unwrap(),
            "127.0.0.1:48965".parse().unwrap()
        );
    }

    #[test]
    fn test_for_ipv6() {
        let transaction_id = 0x5ddc50d9f58f88fd37b31bc1;
        #[rustfmt::skip]
        let bytes = [
            0x00, // Zeroes
            0x02, // IPv6
            0xbd, 0x5f, // XOR Port of 40013
            // IP address of ::1, made from xoring magic cookie and
            // transaction id 0x5ddc50d9f58f88fd37b31bc1.
            0x21, 0x12, 0xa4, 0x42, 0x5d, 0xdc, 0x50, 0xd9,
            0xf5, 0x8f, 0x88, 0xfd, 0x37, 0xb3, 0x1b, 0xc0
        ];
        assert_eq!(
            parse_xor_mapped_address(&bytes, transaction_id).unwrap(),
            "[::1]:40013".parse().unwrap()
        );
    }
}
