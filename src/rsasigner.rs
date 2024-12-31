use blind_rsa_signatures::{KeyPair, Options, /*Signature, MessageRandomizer*/};
use alloy::primitives::Bytes;
use rand::thread_rng;
//use serde::{Deserialize, Serialize};

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

    pub fn sign_blinded_messages(&self, blinded_messages: Vec<Bytes>) -> Result<Vec<Bytes>, String> {
        let rng = &mut thread_rng();
        
        // Process all messages, fail fast on any error
        let signed_messages = blinded_messages.into_iter()
            .map(|blind_msg| {
                let blind_msg_slice: &[u8] = blind_msg.as_ref();
                self.key_pair
                    .sk
                    .blind_sign(rng, blind_msg_slice, &self.options)
                    .map(|sig| Bytes::from(sig.to_vec()))
                    .map_err(|e| format!("Failed to sign blinded message: {}", e))
            })
            .collect::<Result<Vec<Bytes>, String>>()?;
        
        Ok(signed_messages)
    }

    // pub fn verify_unblinded_signature(&self, msg_randomizer: &[u8], msg: &[u8], signature: Bytes) -> bool {
    //     let signature_vec: Vec<u8> = signature.to_vec();
    //     let sig = Signature(signature_vec);
        
    //     // Convert &[u8] to [u8; 32] and create MessageRandomizer
    //     let randomizer = if msg_randomizer.len() == 32 {
    //         let mut array = [0u8; 32];
    //         array.copy_from_slice(msg_randomizer);
    //         Some(MessageRandomizer(array))
    //     } else {
    //         None
    //     };
        
    //     sig.verify(&self.key_pair.pk, randomizer, msg, &self.options)
    //         .is_ok()
    // }
}
