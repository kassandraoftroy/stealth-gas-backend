use alloy::primitives::{Bytes, FixedBytes};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct BlindedSignature {
    pub id: FixedBytes<32>,
    pub signature: Bytes,
}