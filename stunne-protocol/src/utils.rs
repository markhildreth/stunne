use crate::{errors::MessageDecodeError, MessageClass, MessageMethod};

/// Execute an in place XOR operation on `bytes` using bytes from `mask` as the mask.
pub(crate) fn xor<const N: usize>(bytes: &mut [u8; N], mask: &[u8; N]) {
    for (byte, mask) in bytes.iter_mut().zip(mask.iter()) {
        *byte ^= mask;
    }
}

/// Serializes the first two bytes of a Stun packet in big endian form.
// [Stun's message structure] as of RFC5389 requires some interesting manipulation of the class
// and method into the first two bytes of the packet. Specifically:
//   * The first two bits are zero.
//   * The next 14 bits are shared between the class and method, with the class using bits 7 and 11,
//     and the method using the rest.
pub(crate) fn encode_message_type(class: MessageClass, method: MessageMethod) -> [u8; 2] {
    let mut final_value = 0;

    let class_value = u16::from(class);
    final_value += (class_value & 0b10) << 7;
    final_value += (class_value & 0b01) << 4;

    let method_value = u16::from(method);
    final_value += (method_value & 0b0000_1111_1000_0000) << 2;
    final_value += (method_value & 0b0000_0000_0111_0000) << 1;
    final_value += method_value & 0b0000_0000_0000_1111;

    final_value.to_be_bytes()
}

/// Decode the first two bytes of a Stun packet in big endian form into a message class and method
pub(crate) fn decode_message_type(
    bytes: [u8; 2],
) -> Result<(MessageClass, MessageMethod), MessageDecodeError> {
    let type_value = u16::from_be_bytes(bytes);

    let mut class_value = 0;
    class_value += (type_value & 0b0000_0001_0000_0000) >> 7;
    class_value += (type_value & 0b0000_0000_0001_0000) >> 4;

    let mut method_value = 0;
    method_value += (type_value & 0b0011_1110_0000_0000) >> 2;
    method_value += (type_value & 0b0000_0000_1110_0000) >> 1;
    method_value += type_value & 0b0000_0000_0000_1111;

    Ok((
        MessageClass::try_from(class_value)?,
        MessageMethod::try_from(method_value)?,
    ))
}

const ALIGNMENT_BYTES: usize = 4;

/// Given the length of an attribute, determine how many bytes worth of padding must be appended to
/// the end of the attribute data section.
///
/// From the RFC:
/// > Since STUN aligns attributes on 32-bit boundaries, attributes whose content
/// > is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of padding so
/// > that its value contains a multiple of 4 bytes.  The padding bits are ignored,
/// > and may be any value.
pub(crate) fn padding_for_attribute_length(length: usize) -> usize {
    let extra = length % ALIGNMENT_BYTES;
    if extra != 0 {
        ALIGNMENT_BYTES - extra
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let mut orig = [0b0000_1111, 0b0000_1111];
        let the_mask = [0b0101_0101, 0b1010_1010];
        let expected = [0b0101_1010, 0b1010_0101];

        xor(&mut orig, &the_mask);
        assert_eq!(orig, expected,);
    }

    #[test]
    fn test_encode_message_type() {
        assert_eq!(
            encode_message_type(MessageClass::Request, MessageMethod::BINDING),
            [0, 1]
        );

        assert_eq!(
            encode_message_type(MessageClass::Indication, MessageMethod::BINDING),
            [0b00000000, 0b00010001]
        );

        assert_eq!(
            encode_message_type(MessageClass::SuccessResponse, MessageMethod::BINDING),
            [0b00000001, 0b00000001]
        );

        assert_eq!(
            encode_message_type(MessageClass::ErrorResponse, MessageMethod::BINDING),
            [0b00000001, 0b00010001]
        );

        assert_eq!(
            encode_message_type(MessageClass::Request, 2.try_into().unwrap()),
            [0b00000000, 0b00000010]
        );

        assert_eq!(
            encode_message_type(MessageClass::Request, 4095.try_into().unwrap()),
            [0b00111110, 0b11101111]
        );

        assert_eq!(
            encode_message_type(MessageClass::ErrorResponse, 0b1010_0101.try_into().unwrap()),
            [0b0000_0011, 0b0101_0101]
        );
    }

    #[test]
    fn test_decode_message_type() {
        assert!(matches!(
            decode_message_type([0b0000_0000, 0b0000_0001]),
            Ok((MessageClass::Request, MessageMethod::BINDING))
        ));

        assert!(matches!(
            decode_message_type([0b00000000, 0b00010001]),
            Ok((MessageClass::Indication, MessageMethod::BINDING)),
        ));

        assert!(matches!(
            decode_message_type([0b00000001, 0b00000001]),
            Ok((MessageClass::SuccessResponse, MessageMethod::BINDING)),
        ));

        assert!(matches!(
            decode_message_type([0b00000001, 0b00010001]),
            Ok((MessageClass::ErrorResponse, MessageMethod::BINDING))
        ));

        assert_eq!(
            decode_message_type([0b00000000, 0b00000010]),
            Ok((
                MessageClass::Request,
                MessageMethod::try_from_u16(2).unwrap()
            ))
        );

        assert_eq!(
            decode_message_type([0b00111110, 0b11101111]),
            Ok((
                MessageClass::Request,
                MessageMethod::try_from_u16(4095).unwrap()
            )),
        );
    }

    #[test]
    fn test_padding_for_attribute_length() {
        assert_eq!(0, padding_for_attribute_length(0));
        assert_eq!(3, padding_for_attribute_length(1));
        assert_eq!(2, padding_for_attribute_length(2));
        assert_eq!(1, padding_for_attribute_length(3));
        assert_eq!(0, padding_for_attribute_length(4));
        assert_eq!(3, padding_for_attribute_length(5));
        assert_eq!(2, padding_for_attribute_length(6));
        assert_eq!(1, padding_for_attribute_length(7));
        assert_eq!(0, padding_for_attribute_length(8));
    }
}
