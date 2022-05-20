use rand::prelude::*;

mod attributes;
mod header;

pub use attributes::StunAttributeIterator;
pub use header::StunHeader;

/// The class for a given STUN message.
#[derive(Debug)]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

static BINDING_REQUEST: [u8; 2] = [0x00, 0x01];

/// Magic data that must be included in all STUN messages to clarify that the STUN message
/// uses rfc5389, rather than the outdated rfc3489.
static MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

const STUN_HEADER_BYTES: usize = 20;
const MESSAGE_TYPE_BYTES: usize = 2;
const MESSAGE_LENGTH_BYTES: usize = 2;
const MAGIC_COOKIE_BYTES: usize = 4;
const TRANSACTION_ID_BYTES: usize = 12;

pub struct StunRequest {
    buf: [u8; 20],
}

impl StunRequest {
    pub fn new<T: RngCore>(rng: &mut T) -> Self {
        // Crreate the header
        let mut buf = [0u8; 20];
        buf[0..2].copy_from_slice(&BINDING_REQUEST);
        buf[4..8].copy_from_slice(&MAGIC_COOKIE);

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
