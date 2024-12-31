use blind_rsa_signatures::{PublicKey, reexports::rsa::PublicKeyParts};
use hex;
use blind_rsa_signatures::reexports::rsa::RsaPublicKey as BlindRsaPublicKey;
use blind_rsa_signatures::reexports::rsa::BigUint;

/// Convert a `blind_rsa_signatures::PublicKey` to a hex representation
pub fn encode_public_key_to_hex(pubkey: &PublicKey) -> String {
    // Get the modulus (n) and exponent (e)
    let modulus = pubkey.n().to_bytes_be();
    let exponent = pubkey.e().to_bytes_be();

    // Convert modulus and exponent to hex
    let modulus_hex = hex::encode(modulus);
    let exponent_hex = hex::encode(exponent);

    // Concatenate exponent and modulus with a 0x prefix
    format!("0x{}00{}", exponent_hex, modulus_hex)
}

/// Convert a hex representation back into a `blind_rsa_signatures::PublicKey`
pub fn decode_hex_to_public_key(hex_key: &str) -> PublicKey {
    // Remove the "0x" prefix
    let hex = hex_key.trim_start_matches("0x");

    // Extract the exponent (first 6 hex characters) and modulus (rest)
    let exponent_hex = &hex[0..6]; // e is typically 0x010001
    let modulus_hex = &hex[8..];

    // Decode hex strings into bytes
    let exponent_bytes = hex::decode(exponent_hex).expect("Invalid exponent hex");
    let modulus_bytes = hex::decode(modulus_hex).expect("Invalid modulus hex");

    // Convert bytes to BigUint
    let exponent = BigUint::from_bytes_be(&exponent_bytes);
    let modulus = BigUint::from_bytes_be(&modulus_bytes);

    // Construct the DER representation for the public key
    let blind_key = BlindRsaPublicKey::new(
        modulus,
        exponent
    ).expect("Failed to convert key");
    
    PublicKey(blind_key)
}
