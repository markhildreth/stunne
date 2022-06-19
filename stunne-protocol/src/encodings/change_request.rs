use crate::encodings::{AttributeDecoder, AttributeEncoder};
use bytes::{BufMut, BytesMut};

const CHANGE_IP: u32 = 0b100;
const CHANGE_PORT: u32 = 0b10;

#[derive(Debug)]
pub enum ChangeRequestDecodeError {
    UnexpectedEndOfData,
    InvalidDataSize,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ChangeRequest {
    pub change_ip: bool,
    pub change_port: bool,
}

impl AttributeEncoder for ChangeRequest {
    fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(4);

        let mut value = 0;
        if self.change_ip {
            value += CHANGE_IP;
        }

        if self.change_port {
            value += CHANGE_PORT;
        }

        dst.put_u32(value);
    }
}

const CHANGE_REQUEST_BYTES: usize = 4;

pub struct ChangeRequestDecoder;

impl Default for ChangeRequestDecoder {
    fn default() -> Self {
        Self {}
    }
}

impl AttributeDecoder<'_> for ChangeRequestDecoder {
    type Item = ChangeRequest;
    type Error = ChangeRequestDecodeError;

    fn decode(&self, buf: &[u8]) -> Result<Self::Item, Self::Error> {
        if buf.len() < CHANGE_REQUEST_BYTES {
            return Err(ChangeRequestDecodeError::UnexpectedEndOfData);
        }

        if buf.len() > CHANGE_REQUEST_BYTES {
            return Err(ChangeRequestDecodeError::InvalidDataSize);
        }

        let value = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let change_ip = (value & CHANGE_IP) != 0;
        let change_port = (value & CHANGE_PORT) != 0;
        Ok(ChangeRequest {
            change_ip,
            change_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encoding(expected_cr: ChangeRequest, expected_bytes: &[u8]) {
        // Use a zero capacity to ensure that capacity will grow as necessary.
        let mut buf = BytesMut::with_capacity(0);

        expected_cr.encode(&mut buf);
        assert_eq!(
            expected_bytes,
            buf.as_ref(),
            "\n\nIncorrectly encoded change request:\n\t{:?}\n",
            expected_cr
        );

        let decoder = ChangeRequestDecoder::default();
        let result = decoder.decode(&expected_bytes);
        match result {
            Ok(cr) => {
                assert_eq!(
                    expected_cr, cr,
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
    fn test_valid_change_request() {
        let examples = [
            (
                ChangeRequest {
                    change_ip: false,
                    change_port: false,
                },
                [0, 0, 0, 0],
            ),
            (
                ChangeRequest {
                    change_ip: false,
                    change_port: true,
                },
                [0, 0, 0, 0b10],
            ),
            (
                ChangeRequest {
                    change_ip: true,
                    change_port: false,
                },
                [0, 0, 0, 0b100],
            ),
            (
                ChangeRequest {
                    change_ip: true,
                    change_port: true,
                },
                [0, 0, 0, 0b110],
            ),
        ];

        for (request, encoded_value) in examples {
            test_encoding(request, &encoded_value);
        }
    }

    #[test]
    fn test_unexpected_end_of_data() {
        let decoder = ChangeRequestDecoder::default();
        let examples = [vec![], vec![0], vec![0, 0], vec![0, 0, 0]];

        for example in examples {
            let result = decoder.decode(&example);
            assert!(
                matches!(result, Err(ChangeRequestDecodeError::UnexpectedEndOfData)),
                "Did not raise error with example {:?}. Returned {:?}",
                example,
                result
            );
        }
    }

    #[test]
    fn test_invalid_data_size_with_larger_than_necessary_slice() {
        let decoder = ChangeRequestDecoder::default();
        let examples = [
            vec![0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];

        for example in examples {
            let result = decoder.decode(&example);
            assert!(
                matches!(result, Err(ChangeRequestDecodeError::InvalidDataSize)),
                "Did not raise error with example {:?}. Returned {:?}",
                example,
                result
            );
        }
    }
}
