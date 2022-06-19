use crate::encodings::AttributeDecoder;
use crate::errors::MessageDecodeError;
use crate::utils::padding_for_attribute_length;

#[derive(Debug)]
pub struct StunAttribute<'a> {
    attribute_type: u16,
    data: &'a [u8],
}

impl<'a> StunAttribute<'a> {
    pub fn attribute_type(&self) -> u16 {
        self.attribute_type
    }

    pub fn decode<T: AttributeDecoder<'a>>(&self, decoder: &T) -> Result<T::Item, T::Error> {
        decoder.decode(self.data)
    }
}

pub struct StunAttributeIterator<'a> {
    pub(crate) data: &'a [u8],
}

const ATTRIBUTE_TYPE_LENGTH_BYTES: usize = 4;

/// Iterates over the bytes representing attributes, yielding a `StunAttribute` for each attribute
/// found.
///
/// If at any point in the iteration some problem is discovered (e.g., the byte stream ends early),
/// then an error is returned. Any subsequent call to `next()` will return `None` after such an
/// error.
impl<'a> Iterator for StunAttributeIterator<'a> {
    type Item = Result<StunAttribute<'a>, MessageDecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        if self.data.len() < ATTRIBUTE_TYPE_LENGTH_BYTES {
            self.data = &self.data[0..0];
            return Some(Err(MessageDecodeError::UnexpectedEndOfData));
        }

        let (attribute_header, remaining) = self.data.split_at(ATTRIBUTE_TYPE_LENGTH_BYTES);
        let type_bytes = &attribute_header[0..=1];
        let length_bytes = &attribute_header[2..=3];

        let attribute_type = u16::from_be_bytes(type_bytes.try_into().unwrap());
        let data_length: usize = u16::from_be_bytes(length_bytes.try_into().unwrap()).into();
        let padded_data_length = data_length + padding_for_attribute_length(data_length);

        if remaining.len() < padded_data_length {
            self.data = &self.data[0..0];
            return Some(Err(MessageDecodeError::UnexpectedEndOfData));
        }

        let (attribute_data, remaining) = remaining.split_at(padded_data_length);
        let data = &attribute_data[..data_length];
        self.data = remaining;

        Some(Ok(StunAttribute {
            attribute_type,
            data,
        }))
    }
}

impl<'a> StunAttributeIterator<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Self {
        Self { data }
    }
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
            Some(Err(MessageDecodeError::UnexpectedEndOfData))
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
            Some(Err(MessageDecodeError::UnexpectedEndOfData))
        ));

        let second = iter.next();
        assert!(matches!(second, None));
    }

    #[test]
    fn test_can_iterate_over_attribute_with_padding() {
        #[rustfmt::skip]
        let bytes = [
            0, 1, // Type
            0, 7, // The attribute is 7 bytes. However, that means that the padding should be eight
                  // bytes.
            1, 2, 3, 4, 5, 6, 7, 0, // This final zero is the padding, and should not be in slice
                                    // for the decoding process
            0, 2, // The next type
            0, 8, // This attribute has 8 bytes in its value; no padding needed
            1, 2, 3, 4, 5, 6, 7, 8 // Data
        ];

        let mut iter = StunAttributeIterator::from_bytes(&bytes);
        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.attribute_type, 0x01);
        assert_eq!(first.data, &[1, 2, 3, 4, 5, 6, 7]);

        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.attribute_type, 0x02);
        assert_eq!(second.data, &[1, 2, 3, 4, 5, 6, 7, 8]);

        assert!(matches!(iter.next(), None));
    }
}
