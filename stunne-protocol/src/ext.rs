use std::net::SocketAddr;

use crate::encodings::{MappedAddressEncoder, XorMappedAddressEncoder};
use crate::TransactionId;

pub trait SocketAddrExt {
    fn as_mapped_address(&self) -> MappedAddressEncoder;
    fn as_xor_mapped_address(&self, tx_id: TransactionId) -> XorMappedAddressEncoder;
}

impl SocketAddrExt for SocketAddr {
    fn as_mapped_address(&self) -> MappedAddressEncoder {
        MappedAddressEncoder::new(*self)
    }

    fn as_xor_mapped_address(&self, tx_id: TransactionId) -> XorMappedAddressEncoder {
        XorMappedAddressEncoder::new(*self, tx_id)
    }
}
