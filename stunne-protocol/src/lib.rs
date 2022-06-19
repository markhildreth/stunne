//! This crate provides a simple implementation of some of the Stun protocol in Rust. It has been created as an
//! autodidactic exercise in learning about the Stun protcol, which you can learn more about on the
//! [Github project](https://github.com/markhildreth/stunne).
//!
//! This specific crate implements the in-memory structures that can be used to encode/decode Stun
//! messages into bytes ready to be sent to a socket.
//!
//! ```
//! use bytes::BytesMut;
//! use stunne_protocol::{
//!     encodings::Utf8Decoder, MessageClass, MessageHeader, MessageMethod, StunDecoder, StunEncoder,
//!     TransactionId,
//! };
//!
//! const ATTRIBUTE_SOFTWARE: u16 = 0x8022;
//!
//! // Create a buffer and encode data to the buffer
//! let buf = BytesMut::with_capacity(1000);
//! let tx_id = TransactionId::random();
//! let bytes = StunEncoder::new(buf)
//!     .encode_header(MessageHeader {
//!         class: MessageClass::Request,
//!         method: MessageMethod::BINDING,
//!         tx_id
//!     })
//!     .add_attribute(ATTRIBUTE_SOFTWARE, &"Widget, Inc.")
//!     .finish();
//!
//! // `bytes` is a byte slice that can now be sent to a socket if desired.
//! let message = StunDecoder::new(&bytes).unwrap();
//! assert_eq!(message.class(), MessageClass::Request);
//! assert_eq!(message.method(), MessageMethod::BINDING);
//! assert_eq!(message.tx_id(), tx_id);
//! let attribute = message.attributes().next().unwrap().unwrap();
//! assert_eq!(attribute.attribute_type(), ATTRIBUTE_SOFTWARE);
//! assert_eq!(attribute.decode(&Utf8Decoder::default()).unwrap(), "Widget, Inc.");
//! ```
use rand::prelude::*;

mod attributes;
pub mod encodings;
pub mod errors;
pub mod ext;
mod header;
mod utils;

use attributes::StunAttributeIterator;
use bytes::{BufMut, Bytes, BytesMut};
use encodings::AttributeEncoder;
use errors::MessageDecodeError;
pub use header::MessageHeader;

/// Magic data that must be included in all STUN messages to clarify that the STUN message
/// uses rfc5389, rather than the outdated rfc3489.
static MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

const STUN_HEADER_BYTES: usize = 20;

/// The class for a given STUN message, as [defined in RFC5839][].
///
/// [defined in RFC5839]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    /// Used by clients to request an operation from a server. The client would expect some response.
    Request,
    /// Used by clients to request an operation from a server. The client would NOT necessarily expect some response.
    Indication,
    /// Used by servers on messages containing a successful response to a user request.
    SuccessResponse,
    /// Used by servers on messages containing an response to a user request that indicates the presence of an error.
    ErrorResponse,
}

impl From<MessageClass> for u16 {
    fn from(other: MessageClass) -> u16 {
        match other {
            MessageClass::Request => 0b00,
            MessageClass::Indication => 0b01,
            MessageClass::SuccessResponse => 0b10,
            MessageClass::ErrorResponse => 0b11,
        }
    }
}

impl TryFrom<u16> for MessageClass {
    type Error = MessageDecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageClass::Request),
            1 => Ok(MessageClass::Indication),
            2 => Ok(MessageClass::SuccessResponse),
            3 => Ok(MessageClass::ErrorResponse),
            _ => Err(MessageDecodeError::InvalidMessageClass),
        }
    }
}

/// The method of a STUN message, as [defined in RFC5839][].
///
/// A method can be thought of as a number identifying the specific operation that the user wishes
/// the server to perform. Note that RFC 5839 only defines a single method: [Binding][]. However,
/// the binding value can be any value that can be stored in 12 bits, and additional RFCs can
/// [define their own methods][].
///
/// [defined in RFC5839]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
/// [Binding]: https://datatracker.ietf.org/doc/html/rfc5389#section-3
/// [define their own methods]: https://datatracker.ietf.org/doc/html/rfc5389#section-18.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageMethod(u16);

impl MessageMethod {
    /// Convert a u16 value into a MessageMethod value, erroring if the u16 value is not a valid
    /// method.
    ///
    /// For the purpose of this library, a value is only "valid" if it could be represented in 12
    /// bits (which is the amount of bits [allocated in the STUN protocol] to store the method.
    /// Thus, any value outside of the range of 0..=4095 would convert into a
    /// [InvalidMessageMethod].
    ///
    /// [allocated in the STUN protocol]: https://datatracker.ietf.org/doc/html/rfc5389#section-6
    /// [InvalidMessageMethod]: MessageDecodeError::InvalidMessageMethod
    pub fn try_from_u16(value: u16) -> Result<Self, MessageDecodeError> {
        match value {
            x @ 0..=4095 => Ok(MessageMethod(x)),
            _ => Err(MessageDecodeError::InvalidMessageMethod),
        }
    }

    pub const BINDING: Self = MessageMethod(1);
}

impl From<MessageMethod> for u16 {
    fn from(other: MessageMethod) -> u16 {
        other.0
    }
}

impl TryFrom<u16> for MessageMethod {
    type Error = MessageDecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::try_from_u16(value)
    }
}

/// Represents the 96-bit value of the transaction ID for a STUN message.
///
/// The transaction ID is a 96-bit identifier used to uniquely identify STUN transactions.
/// It is included in each request by a client, and server responses included the supplied
/// Transaction ID in their responses to a client's requests.
///
/// A Transaction ID SHOULD be generated in a cryptographically random way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId {
    bytes: [u8; 12],
}

impl TransactionId {
    /// Generate a random transaction ID.
    ///
    /// NOTE: This currently does NOT generate an ID in a securely random way.
    pub fn random() -> Self {
        // TODO: This is not gauranteed to be a securely generated random value.
        let mut bytes = [0; 12];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0; 12];
        buf.copy_from_slice(&bytes[0..12]);
        Self { bytes: buf }
    }
}

impl AsRef<[u8]> for TransactionId {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Provides an interface that can be used to dynamically encode a stun datagram into a supplied
/// buffer.
///
/// See example usage in [crate documentation](crate).
///
/// Note that the encoder is designed to continually reserve more bytes from the
/// [BytesMut](bytes::BytesMut) buffer value as needed. If it needs to do this, it will allocate a
/// new buffer, which can come with some performance penalty. These additional allocations can be
/// avoided if the buffer is given a sane starting capacity. For example...
///
/// ```
/// # use bytes::BytesMut;
/// let mut buffer = BytesMut::with_capacity(1024);
/// ```
///
/// An encoder using the above buffer now no longer need to allocate memory so long as the number
/// of encoded bytes does not go above 1024. See the [BytesMut] documentation for more info.
pub struct StunEncoder {
    buf: BytesMut,
}

impl StunEncoder {
    /// Create the encoder with the given buffer.
    pub fn new(buf: BytesMut) -> StunEncoder {
        Self { buf }
    }

    /// Associates the given header information to be written to the buffer.
    ///
    /// Note that there is no guarantee that the header is written when this method is called, as
    /// it's impossible to know the length of the data (which must be written alongside the header
    /// data). Instead, it is more likely that the header will be written AFTER the attributes have
    /// been written to the buffer, during the [finish](StunAttributeEncoder::finish) method.
    pub fn encode_header(mut self, header: MessageHeader) -> StunAttributeEncoder {
        self.buf.reserve(STUN_HEADER_BYTES);
        let data_buf = self.buf.split_off(STUN_HEADER_BYTES);
        StunAttributeEncoder {
            header_buf: self.buf,
            buf: data_buf,
            next_attribute_byte: 0,
            header,
        }
    }
}

const PADDING_VALUE: u8 = 0;
const ATTRIBUTE_HEADER_BYTES: usize = 4;

pub struct StunAttributeEncoder {
    header_buf: BytesMut,
    buf: BytesMut,
    next_attribute_byte: usize,
    header: MessageHeader,
}

impl StunAttributeEncoder {
    pub fn add_attribute<T: AttributeEncoder>(mut self, attribute_type: u16, encoder: &T) -> Self {
        // No need for reservation here.
        // By default, `next_attribute_byte` is zero, so this will not panic.
        // After the first attribute is created, `next_attribute_byte` will point to the byte where
        // the writing of bytes has already advanced to, and thus presumed to have been reserved.
        let mut attribute_header = self.buf.split_off(self.next_attribute_byte);
        attribute_header.reserve(ATTRIBUTE_HEADER_BYTES);
        attribute_header.reserve(ATTRIBUTE_HEADER_BYTES);

        let mut attribute_data = attribute_header.split_off(ATTRIBUTE_HEADER_BYTES);
        encoder.encode(&mut attribute_data);
        let attribute_length = attribute_data.len();

        // Add additional padding onto the attribute value if necessary
        let padding_length = utils::padding_for_attribute_length(attribute_length);
        attribute_data.reserve(padding_length);
        attribute_data.put_bytes(PADDING_VALUE, padding_length);

        // Write to the attribute "header"
        attribute_header.put_u16(attribute_type);
        attribute_header.put_u16(attribute_length as u16);

        // Put all of the split items back together again.
        attribute_header.unsplit(attribute_data);
        self.buf.unsplit(attribute_header);
        self.next_attribute_byte += ATTRIBUTE_HEADER_BYTES + attribute_length + padding_length;
        self
    }

    pub fn finish(mut self) -> Bytes {
        self.header
            .encode_with_length(&mut self.header_buf, self.buf.len() as u16);
        self.header_buf.unsplit(self.buf);
        self.header_buf.freeze()
    }
}

/// Used to decode a byte slice into a structure STUN message.
///
/// See example usage in [crate documentation](crate).
pub struct StunDecoder<'a> {
    header: MessageHeader,
    attribute_buf: &'a [u8],
}

impl<'a> StunDecoder<'a> {
    /// Create a new decoder, passing in the byte slice to be decoded.
    ///
    /// This method will immediately try to parse the header from the byte slice. If it encounters
    /// an error in doing so, this will return a [MessageDecodeError].
    ///
    /// Note that we do not perform any read past the header data here. If this method succeeds,
    /// it's still possible that an error might occur if the user were to continue decoding
    /// attributes (see [attributes()](Self::attributes()) below).
    pub fn new(buf: &'a [u8]) -> Result<Self, MessageDecodeError> {
        if buf.len() < STUN_HEADER_BYTES {
            return Err(MessageDecodeError::UnexpectedEndOfData);
        }
        let (header_buf, attribute_buf) = buf.split_at(STUN_HEADER_BYTES);
        let header_buf: &[u8; STUN_HEADER_BYTES] = (header_buf).try_into().unwrap();
        let (header, _attribute_length) = MessageHeader::decode_with_length(header_buf)?;
        Ok(Self {
            header,
            attribute_buf,
        })
    }

    /// Returns the decoded message header.
    pub fn header(&self) -> &MessageHeader {
        &self.header
    }

    /// Returns the [MessageClass] of the decoded message header.
    pub fn class(&self) -> MessageClass {
        self.header.class
    }

    /// Returns the [MessageMethod] of the decoded message header.
    pub fn method(&self) -> MessageMethod {
        self.header.method
    }

    /// Returns the [TransactionId] of the decoded message header.
    pub fn tx_id(&self) -> TransactionId {
        self.header.tx_id
    }

    /// Returns an iterator that can be used to iterate over all of the attributes of the STUN
    /// message.
    ///
    /// While building the iterator itself cannot error, note that each iteration returns a `Result`.
    /// Thus, one needs to be wary that the message might be invalid, but we would only learn that
    /// after we start iterating over attributes. The primary problem that would come up is if the
    /// byte slice was too short to contain the data that an attribute said it should have, or if
    /// the datagram encoded into the byte slice was incorrectly encoded.
    pub fn attributes(&self) -> StunAttributeIterator<'a> {
        StunAttributeIterator {
            data: self.attribute_buf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_simple_message() {
        let buf = BytesMut::new();
        let tx_id_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let finished_buf = StunEncoder::new(buf)
            .encode_header(MessageHeader {
                class: MessageClass::Request,
                method: MessageMethod::BINDING,
                tx_id: TransactionId::from_bytes(&tx_id_bytes),
            })
            .finish();

        #[rustfmt::skip]
        let expected = [
            0, 1,                     // Zero Bits, Stun Message and Method
            0, 0,                     // Message Length: 0 with no attributes
            0x21, 0x12, 0xA4, 0x42,   // Magic Cookie
            1,2,3,4,5,6,7,8,9,10,11,12 // Transaction ID
        ];

        assert_eq!(finished_buf.as_ref(), &expected);
    }

    #[test]
    fn encode_multiple_attributes() {
        let buf = BytesMut::new();
        let tx_id = TransactionId::random();
        let finished_buf = StunEncoder::new(buf)
            .encode_header(MessageHeader {
                class: MessageClass::Request,
                method: MessageMethod::BINDING,
                tx_id,
            })
            .add_attribute(0x00, &"test1")
            .add_attribute(0x01, &"test02")
            .finish();

        #[rustfmt::skip]
        let expected_bytes = [
            // First attribute number
            0, 0,
            // First attribute length
            0, 5,
            // First attribute data (including padding)
            0x74, 0x65, 0x73, 0x74, 0x31, 0, 0, 0,

            // Second attribute number
            0, 1,
            // Second attribute length
            0, 6,
            // Second attribute data
            0x74, 0x65, 0x73, 0x74, 0x30, 0x32, 0, 0,
        ];
        assert_eq!(&finished_buf[20..], &expected_bytes);
    }

    #[test]
    fn decode_simple_message() {
        #[rustfmt::skip]
        let bytes = [
            0, 1, // Zero Bits, Stun Message and Method
            0, 0, // Message Length: 0 with no attributes
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // Transaction ID
        ];

        let tx_id_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let message = StunDecoder::new(&bytes).unwrap();
        assert!(matches!(message.header.class, MessageClass::Request));
        assert!(matches!(message.header.method, MessageMethod::BINDING));
        assert_eq!(message.header.tx_id.as_ref(), &tx_id_bytes);
    }

    #[test]
    fn fail_to_decode_too_small_message() {
        #[rustfmt::skip]
        let valid_bytes = [
            0, 1, // Zero Bits, Stun Message and Method
            0, 0, // Message Length: 0 with no attributes
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // Transaction ID
        ];

        for x in 0..20 {
            let bytes = &valid_bytes[0..x];
            let result = StunDecoder::new(&bytes);
            assert!(matches!(
                result,
                Err(MessageDecodeError::UnexpectedEndOfData)
            ));
        }
    }

    #[test]
    fn fail_to_decode_invalid_header() {
        #[rustfmt::skip]
        let invalid_bytes = [
            // There should be an error here due to the header having invalid zero bits.
            0b1100_0000, 1,
            0, 0, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // Transaction ID
        ];

        let message = StunDecoder::new(&invalid_bytes);
        assert!(matches!(
            message,
            Err(MessageDecodeError::NonZeroStartingBits)
        ));
    }
}
