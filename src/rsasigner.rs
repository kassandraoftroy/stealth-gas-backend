use alloy::primitives::Bytes;
use blind_rsa_signatures::{KeyPair, Options};
use rand::thread_rng;

pub struct BlindSigner {
    key_pair: KeyPair,
    options: Options,
}

impl BlindSigner {
    pub fn new(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            options: Options::default(),
        }
    }

    pub fn sign_blinded_message<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        blinded_message: Bytes,
    ) -> Result<Bytes, String> {
        let blind_msg_slice: &[u8] = blinded_message.as_ref();
        self.key_pair
            .sk
            .blind_sign(rng, blind_msg_slice, &self.options)
            .map(|sig| Bytes::from(sig.to_vec()))
            .map_err(|e| format!("Failed to sign blinded message: {}", e))
    }

    pub fn sign_blinded_messages_filtered(
        &self,
        blinded_messages: Vec<Bytes>,
    ) -> (Vec<Bytes>, Vec<Bytes>) {
        let mut rng = thread_rng();
        blinded_messages
            .into_iter()
            .filter_map(|msg| {
                self.sign_blinded_message(&mut rng, msg.clone())
                    .ok()
                    .map(|signature| (msg, signature))
            })
            .unzip()
    }
}
