/// This error occurs whenever an attempt to decode a message fails due to the message having an
/// invalid format.
#[derive(Debug, PartialEq, Eq)]
pub enum MessageDecodeError {
    /// Every STUN header must start with two zero bits. This error is raised if either of those
    /// two bits are set.
    NonZeroStartingBits,

    /// The magic cookie field did not have the fixed value of 0x2112A442.
    InvalidMagicCookie,

    /// An attempt was made to decode a value into a MessageClass type that didn't correspond to
    /// one of the valid message classes.
    InvalidMessageClass,

    /// An attempt was made to decode a value into a MessageMethod type that didn't correspond to
    /// a valid message method.
    InvalidMessageMethod,

    /// The data provided to the decoder was not large enough to perform the current operation
    /// (e.g., decoding the header, or if occurring while decoding an attribute, the data was not
    /// able to decode the entire attribute.
    UnexpectedEndOfData,
}
