use super::{AttributeDecoder, AttributeEncoder};
use crate::utils::xor;
use crate::TransactionId;
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub struct MappedAddress;

impl MappedAddress {
    pub fn encoder(addr: SocketAddr) -> MappedAddressEncoder {
        MappedAddressEncoder::new(addr)
    }

    pub fn decoder() -> MappedAddressDecoder {
        MappedAddressDecoder::default()
    }
}

pub struct XorMappedAddress;

impl XorMappedAddress {
    pub fn encoder(addr: SocketAddr, tx_id: TransactionId) -> XorMappedAddressEncoder {
        XorMappedAddressEncoder::new(addr, tx_id)
    }

    pub fn decoder(tx_id: TransactionId) -> XorMappedAddressDecoder {
        XorMappedAddressDecoder::new(tx_id)
    }
}

pub struct MappedAddressEncoder {
    addr: SocketAddr,
}

impl MappedAddressEncoder {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl AttributeEncoder for MappedAddressEncoder {
    fn encode(&self, dst: &mut BytesMut) {
        match self.addr {
            SocketAddr::V4(addr) => {
                dst.reserve(8);
                dst.put_u8(0);
                dst.put_u8(IPV4_FAMILY);
                dst.put_u16(addr.port());
                dst.extend_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                dst.reserve(20);
                dst.put_u8(0);
                dst.put_u8(IPV6_FAMILY);
                dst.put_u16(addr.port());
                dst.extend_from_slice(&addr.ip().octets());
            }
        }
    }
}

#[derive(Default)]
pub struct MappedAddressDecoder;

impl AttributeDecoder<'_> for MappedAddressDecoder {
    type Item = SocketAddr;
    type Error = MappedAddressDecodeError;

    fn decode(&self, buf: &[u8]) -> Result<Self::Item, Self::Error> {
        parse_mapped_address(buf)
    }
}

/// Gives the reason that a MAPPED-ADDRESS attribute's value could not be decoded.
#[derive(Debug)]
pub enum MappedAddressDecodeError {
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

/// The entire magic cookie stored as an array of bytes.
const MAGIC_COOKIE_FULL: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

pub struct XorMappedAddressEncoder {
    addr: SocketAddr,
    tx_id: TransactionId,
}

impl XorMappedAddressEncoder {
    pub fn new(addr: SocketAddr, tx_id: TransactionId) -> Self {
        Self { addr, tx_id }
    }
}

impl AttributeEncoder for XorMappedAddressEncoder {
    fn encode(&self, dst: &mut BytesMut) {
        let processed_ip = match self.addr.ip() {
            IpAddr::V4(ip) => {
                let mut octets = ip.octets();
                xor(&mut octets, &MAGIC_COOKIE_FULL);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            IpAddr::V6(ip) => {
                let mut octets = ip.octets();
                let mut mask: [u8; 16] = Default::default();
                mask[0..4].copy_from_slice(&MAGIC_COOKIE_FULL);
                mask[4..].copy_from_slice(self.tx_id.as_ref());
                xor(&mut octets, &mask);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let processed_port = self.addr.port() ^ MAGIC_COOKIE_MSB;

        let processed_address = SocketAddr::new(processed_ip, processed_port);
        MappedAddressEncoder::new(processed_address).encode(dst);
    }
}

pub struct XorMappedAddressDecoder {
    tx_id: TransactionId,
}

impl XorMappedAddressDecoder {
    pub fn new(tx_id: TransactionId) -> Self {
        Self { tx_id }
    }
}

impl AttributeDecoder<'_> for XorMappedAddressDecoder {
    type Item = SocketAddr;
    type Error = MappedAddressDecodeError;

    fn decode(&self, buf: &[u8]) -> Result<Self::Item, Self::Error> {
        let addr = parse_mapped_address(buf)?;
        let processed_ip = match addr.ip() {
            IpAddr::V4(ip) => {
                let mut octets = ip.octets();
                xor(&mut octets, &MAGIC_COOKIE_FULL);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            IpAddr::V6(ip) => {
                let mut octets = ip.octets();
                let mut mask: [u8; 16] = Default::default();
                mask[0..4].copy_from_slice(&MAGIC_COOKIE_FULL);
                mask[4..].copy_from_slice(self.tx_id.as_ref());
                xor(&mut octets, &mask);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let processed_port = addr.port() ^ MAGIC_COOKIE_MSB;

        Ok(SocketAddr::new(processed_ip, processed_port))
    }
}

fn parse_mapped_address(bytes: &[u8]) -> Result<SocketAddr, MappedAddressDecodeError> {
    if bytes.len() < MAPPED_ADDRESS_HEADER_BYTES {
        return Err(MappedAddressDecodeError::UnexpectedEndOfSlice);
    }

    let (header_bytes, address_bytes) = bytes.split_at(MAPPED_ADDRESS_HEADER_BYTES);
    if header_bytes[0] != 0 {
        return Err(MappedAddressDecodeError::NonZeroFirstByte);
    }
    let port = u16::from_be_bytes(header_bytes[2..=3].try_into().unwrap());

    let ip_addr = match header_bytes[1] {
        IPV4_FAMILY => {
            if address_bytes.len() != IPV4_BYTE_LENGTH {
                return Err(MappedAddressDecodeError::UnexpectedEndOfSlice);
            }
            let array: [u8; IPV4_BYTE_LENGTH] = address_bytes.try_into().unwrap();
            IpAddr::from(array)
        }
        IPV6_FAMILY => {
            if address_bytes.len() != IPV6_BYTE_LENGTH {
                return Err(MappedAddressDecodeError::UnexpectedEndOfSlice);
            }
            let data: [u8; IPV6_BYTE_LENGTH] = address_bytes.try_into().unwrap();
            IpAddr::from(data)
        }
        _ => return Err(MappedAddressDecodeError::UnknownFamily),
    };

    Ok(SocketAddr::new(ip_addr, port))
}

#[cfg(test)]
mod test_mapped_address {
    use super::*;

    macro_rules! test_address {
        ($addr:expr, $bytes:expr) => {{
            // Use a zero capacity to ensure that capacity will grow as necessary.
            let mut buf = BytesMut::with_capacity(0);

            let expected_bytes = $bytes;
            let expected_addr: SocketAddr = $addr.parse().unwrap();

            let encoder = MappedAddressEncoder::new(expected_addr);
            encoder.encode(&mut buf);
            assert_eq!(
                &expected_bytes,
                buf.as_ref(),
                "\n\nIncorrectly encoded from addr:\n\t{:?}\n",
                expected_addr
            );

            let decoder = MappedAddressDecoder::default();
            let result = decoder.decode(&expected_bytes);
            match result {
                Ok(addr) => {
                    assert_eq!(
                        expected_addr, addr,
                        "\n\nIncorrectly decoded from bytes:\n\t{:?}\n",
                        expected_bytes
                    );
                }
                Err(e) => {
                    panic!(
                        "\n\nUnexpected error ({:?}) when decoding from bytes:\n\t{:?}\n",
                        e, expected_bytes
                    );
                }
            }
        }};
    }

    #[test]
    fn test_ipv4() {
        test_address!(
            "127.0.0.1:8000",
            [
                0x00, // Zeroes
                0x01, // IPv4
                0x1F, 0x40, // Port 8000
                0x7F, 0x00, 0x00, 0x01 // 127.0.0.1
            ]
        );

        test_address!(
            "1.2.3.4:1234",
            [
                0x00, // Zeroes
                0x01, // IPv4
                0x04, 0xD2, // Port 1234
                0x01, 0x02, 0x03, 0x04 // 1.2.3.4
            ]
        );
    }

    #[test]
    fn test_ipv6() {
        test_address!(
            "[0001:0203:0405:0607:0809:0A0B:0C0D:0E0F]:1234",
            [
                0x00, // Zeroes
                0x02, // IPv6
                0x04, 0xD2, // Port 1234
                // IPv6 Address bytes
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F
            ]
        );

        test_address!(
            "[::1]:8000",
            [
                0x00, // Zeroes
                0x02, // IPv6
                0x1F, 0x40, // Port 8000
                // IPv6 Address bytes
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ]
        );
    }

    #[test]
    fn test_decode_unknown_address_scheme() {
        let bytes = [
            0x00, // Zeroes
            0x03, // Unknown Scheme
            0x1F, 0x40, // Port 8000
            0x00, 0x00, // Some weird bytes for an address scheme that we don't know
        ];

        assert!(matches!(
            MappedAddressDecoder::default().decode(&bytes),
            Err(MappedAddressDecodeError::UnknownFamily)
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
        assert!(matches!(
            MappedAddressDecoder::default().decode(&bytes),
            Err(MappedAddressDecodeError::NonZeroFirstByte)
        ));
    }

    #[test]
    fn test_parse_mapped_address_invalid_number_of_bytes() {
        let decoder = MappedAddressDecoder::default();
        #[rustfmt::skip]
        let test_cases = [
            vec![],
            vec![0x00],
            vec![0x00, 0x01],
            vec![0x00, 0x01, 0x00],
            vec![0x00, 0x01, 0x04, 0xD2],
            vec![0x00, 0x01, 0x04, 0xD2, 0x00],
            vec![0x00, 0x01, 0x04, 0xD2, 0x00, 0x00],
            vec![0x00, 0x01, 0x04, 0xD2, 0x00, 0x00, 0x00],
            // Valid number of bytes for a ipv4, but this is labeled as ipv6
            vec![0x00, 0x02, 0x04, 0xD2, 0x00, 0x00, 0x00, 0x00],
            // The rest are ipv6 cases
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        for test_case in &test_cases {
            assert!(
                matches!(
                    decoder.decode(&[]),
                    Err(MappedAddressDecodeError::UnexpectedEndOfSlice)
                ),
                "\n\nTest case {:?} failed\n",
                &test_case
            );
        }
    }
}

#[cfg(test)]
mod test_xor_mapped_address {
    use super::*;

    fn test_address(addr: &str, tx_id: TransactionId, expected_bytes: &[u8]) {
        // Use a zero capacity to ensure that capacity will grow as necessary.
        let mut buf = BytesMut::with_capacity(0);

        let expected_addr: SocketAddr = addr.parse().unwrap();

        let encoder = XorMappedAddressEncoder::new(expected_addr, tx_id);
        encoder.encode(&mut buf);
        assert_eq!(
            expected_bytes,
            buf.as_ref(),
            "\n\nIncorrectly encoded from addr:\n\t{:?}\n",
            expected_addr
        );

        let decoder = XorMappedAddressDecoder::new(tx_id);
        let result = decoder.decode(&expected_bytes);
        match result {
            Ok(addr) => {
                assert_eq!(
                    expected_addr, addr,
                    "\n\nIncorrectly decoded from bytes:\n\t{:?}\n",
                    expected_bytes
                );
            }
            Err(e) => {
                panic!(
                    "\n\nUnexpected error ({:?}) when decoding from bytes:\n\t{:?}\n",
                    e, expected_bytes
                );
            }
        }
    }

    #[test]
    fn test_for_ipv4() {
        // Note that this is not used for anything in this test since this is an IPv4. However, the
        // argument is still required.
        let tx_id = TransactionId::from_bytes(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        test_address(
            "127.0.0.1:48965",
            tx_id,
            &[
                0x00, // Zeroes
                0x01, // IPv4
                0x9e, 0x57, // 48965 XORed with 0x2112 (MSBs of magic cookie)
                0x5e, 0x12, 0xa4, 0x43, //XORed IP address of 127.0.0.1 w/ magic cookie
            ],
        );

        test_address(
            "1.2.3.4:1234",
            tx_id,
            &[
                0x00, // Zeroes
                0x01, // IPv4
                0x25, 0xc0, // 1234 XORd with 0x2112 (MSBs of magic cookie)
                0x20, 0x10, 0xa7, 0x46, // XORed IP Address of 1.2.3.4 w/ magic cookie
            ],
        );
    }

    #[test]
    fn test_for_ipv6() {
        let tx_id = TransactionId::from_bytes(&[
            0x5d, 0xdc, 0x50, 0xd9, 0xf5, 0x8f, 0x88, 0xfd, 0x37, 0xb3, 0x1b, 0xc1,
        ]);
        test_address(
            "[::]:0",
            tx_id,
            &[
                0x00, // Zeroes
                0x02, // IPv6
                0x21, 0x12, // Port 0 XORed with 0x2112 (MSBs of magic cookie)
                // The IP address is all zero, so an XOR should just return the mask used, which
                // should be the magic cookie (0x2112a442)...
                0x21, 0x12, 0xa4, 0x42,
                // ...followed by the transaction ID...
                //
                0x5d, 0xdc, 0x50, 0xd9, 0xf5, 0x8f, 0x88, 0xfd, 0x37, 0xb3, 0x1b, 0xc1,
            ],
        );

        test_address(
            "[0102:0304:0506:0708:090a:0b0c:0d0e:0f10]:1234",
            tx_id,
            &[
                0x00, // Zeroes
                0x02, // IPv6
                0x25, 0xc0, // Port 1234 XORed with 0x2112 (MSBs of magic cookie)
                // First four bytes of IP address XOred against magic cookie (0x2112a442)
                0x20, 0x10, 0xa7, 0x46,
                // Remaining 12 bytes of the IP address are XORed against the tx id
                0x58, 0xda, 0x57, 0xd1, 0xfc, 0x85, 0x83, 0xf1, 0x3a, 0xbd, 0x14, 0xd1,
            ],
        );
    }

    #[test]
    fn test_decode_unknown_address_scheme() {
        let tx_id = TransactionId::random();
        let bytes = [
            0x00, // Zeroes
            0x03, // Unknown Scheme
            0x1F, 0x40, // Port 8000
            0x00, 0x00, // Some weird bytes for an address scheme that we don't know
        ];

        assert!(matches!(
            XorMappedAddressDecoder::new(tx_id).decode(&bytes),
            Err(MappedAddressDecodeError::UnknownFamily)
        ));
    }

    #[test]
    fn test_decode_address_with_non_zero_first_byte() {
        let tx_id = TransactionId::random();
        #[rustfmt::skip]
        let bytes = [
            0x01, // According to RFC 5389, this MUST be zero. We will treat a non-zero as invalid.
            0x01, // IPv4
            0x04, 0xD2, // Port 1234
            0x21, 0x12, 0xa4, 0x42 // This would be a valid 0.0.0.0 address.
        ];
        assert!(matches!(
            XorMappedAddressDecoder::new(tx_id).decode(&bytes),
            Err(MappedAddressDecodeError::NonZeroFirstByte)
        ));
    }

    #[test]
    fn test_decode_invalid_number_of_bytes() {
        let tx_id = TransactionId::random();
        let decoder = XorMappedAddressDecoder::new(tx_id);
        #[rustfmt::skip]
        let test_cases = [
            vec![],
            vec![0x00],
            vec![0x00, 0x01],
            vec![0x00, 0x01, 0x00],
            vec![0x00, 0x01, 0x04, 0xd2],
            vec![0x00, 0x01, 0x04, 0xd2, 0x00],
            vec![0x00, 0x01, 0x04, 0xd2, 0x00, 0x00],
            vec![0x00, 0x01, 0x04, 0xd2, 0x00, 0x00, 0x00],

            // Correct number of bytes for a ipv4 address, but the address is encoded for ipv6, so
            // there are not enough bytes
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x02, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        for test_case in &test_cases {
            assert!(
                matches!(
                    decoder.decode(&test_case),
                    Err(MappedAddressDecodeError::UnexpectedEndOfSlice)
                ),
                "\n\nTest case {:?} failed\n",
                &test_case
            );
        }
    }
}
