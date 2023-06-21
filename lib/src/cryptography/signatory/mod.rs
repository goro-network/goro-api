pub mod public;

use crate::errors::GoRoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type SignerAccount = public::SignerPublicKey;

#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SignerSecret {
    Sr25519(schnorrkel::MiniSecretKey),
    Ed25519(ed25519_dalek::SecretKey),
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignerKeypair {
    #[zeroize(skip)]
    public: SignerAccount,
    private: SignerSecret,
}

impl SignerKeypair {
    pub const LENGTH_SECRET: usize = 32;
    pub const LENGTH_PUBLIC: usize = SignerAccount::PUBKEY_LENGTH;
    pub const LENGTH_SIGNATURE: usize = 64;
    pub const SIGNING_CONTEXT: &[u8] = b"substrate";
    pub const SR25519_EXPANSION_MODE: schnorrkel::ExpansionMode = schnorrkel::MiniSecretKey::ED25519_MODE;

    pub fn generate_sr25519() -> Self {
        let mini_secret_key = schnorrkel::MiniSecretKey::generate();
        let keypair = mini_secret_key.expand_to_keypair(Self::SR25519_EXPANSION_MODE);
        let public = SignerAccount::from(keypair.public.to_bytes());
        let private = SignerSecret::Sr25519(mini_secret_key);

        Self { public, private }
    }

    pub fn generate_ed25519() -> Self {
        let schnorrkel_mini_secret_key = schnorrkel::MiniSecretKey::generate();
        let ed25519_secret = ed25519_dalek::SecretKey::from_bytes(schnorrkel_mini_secret_key.as_bytes()).unwrap();
        let ed25519_public = ed25519_dalek::PublicKey::from(&ed25519_secret);
        let public = SignerAccount::from(ed25519_public.to_bytes());
        let private = SignerSecret::Ed25519(ed25519_secret);

        Self { public, private }
    }

    pub fn try_from_sr25519_secret_bytes(secret_bytes: &[u8]) -> Result<Self, GoRoError> {
        if secret_bytes.len() != Self::LENGTH_SECRET {
            return Err(GoRoError::BadInputBufferLength {
                expected: Self::LENGTH_SECRET,
                given: secret_bytes.len(),
            });
        }

        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(secret_bytes).unwrap();
        let keypair = mini_secret_key.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
        let public = SignerAccount::from(keypair.public.to_bytes());
        let private = SignerSecret::Sr25519(mini_secret_key);

        Ok(Self { public, private })
    }

    pub fn try_from_ed25519_secret_bytes(secret_bytes: &[u8]) -> Result<Self, GoRoError> {
        if secret_bytes.len() != Self::LENGTH_SECRET {
            return Err(GoRoError::BadInputBufferLength {
                expected: Self::LENGTH_SECRET,
                given: secret_bytes.len(),
            });
        }

        let schnorrkel_mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(secret_bytes).unwrap();
        let ed25519_secret = ed25519_dalek::SecretKey::from_bytes(schnorrkel_mini_secret_key.as_bytes()).unwrap();
        let ed25519_public = ed25519_dalek::PublicKey::from(&ed25519_secret);
        let public = SignerAccount::from(ed25519_public.to_bytes());
        let private = SignerSecret::Ed25519(ed25519_secret);

        Ok(Self { public, private })
    }

    pub fn sign(&self, message: &[u8]) -> [u8; Self::LENGTH_SIGNATURE] {
        match &self.private {
            SignerSecret::Ed25519(inner) => {
                let expanded_secret_key = ed25519_dalek::ExpandedSecretKey::from(inner);
                let public_key = ed25519_dalek::PublicKey::from(inner);
                let signature = expanded_secret_key.sign(message, &public_key);

                signature.to_bytes()
            }
            SignerSecret::Sr25519(inner) => {
                let expanded_secret_key = inner.expand(Self::SR25519_EXPANSION_MODE);
                let public_key = expanded_secret_key.to_public();
                let signature = expanded_secret_key.sign_simple(Self::SIGNING_CONTEXT, message, &public_key);

                signature.to_bytes()
            }
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; Self::LENGTH_SIGNATURE]) -> bool {
        match &self.private {
            SignerSecret::Ed25519(_) => true,
            SignerSecret::Sr25519(inner) => {
                let keypair = inner.expand_to_keypair(Self::SR25519_EXPANSION_MODE);
                let signature_sr25519 = schnorrkel::Signature::from_bytes(&signature[..]).unwrap();
                let result = keypair.verify_simple(Self::SIGNING_CONTEXT, message, &signature_sr25519);

                result.is_ok()
            }
        }
    }
}

impl std::fmt::Display for SignerKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.public)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use hex::{decode, encode};
    use sp_core::crypto::Ss58Codec;
    use sp_core::ed25519::{Pair as Ed25519KeyPair, Public as Ed25519PublicKey, Signature as Ed25519Signature};
    use sp_core::sr25519::{Pair as Sr25519KeyPair, Public as Sr25519PublicKey, Signature as Sr25519Signature};
    use sp_core::Pair;

    const MESSAGE_HEX: &str = "deadbeef";
    const ALICE_MINISECRET_HEX: &str = "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
    const EXPECTED_SR25519_PUBKEY: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    const EXPECTED_SR25519_ADDRESS: &str = "gr5wupneKLGRBrA3hkcrXgbwXp1F26SV7L4LymGxCKs9QMXn1";
    const EXPECTED_ED25519_PUBKEY: &str = "34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a691";
    const EXPECTED_ED25519_ADDRESS: &str = "gr2LLpGt2rLUixu5YzrWNvbX9qJeavgZLh95UpwBpvZSq6xpA";

    #[test]
    fn alice_sr25519_signature_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_sr25519_secret_bytes(&minisecret_bytes).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.sign(&message_bytes);
        let signature = Sr25519Signature::from_slice(&signature).unwrap();
        let substrate_pubkey = Sr25519PublicKey::from_ss58check(EXPECTED_SR25519_ADDRESS).unwrap();

        assert!(Sr25519KeyPair::verify(&signature, &message_bytes, &substrate_pubkey));
    }

    #[test]
    fn alice_ed25519_signature_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_ed25519_secret_bytes(&minisecret_bytes).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.sign(&message_bytes);
        let signature = Ed25519Signature::from_slice(&signature).unwrap();
        let substrate_pubkey = Ed25519PublicKey::from_ss58check(EXPECTED_ED25519_ADDRESS).unwrap();

        assert!(Ed25519KeyPair::verify(&signature, &message_bytes, &substrate_pubkey));
    }

    #[test]
    fn alice_sr25519_pubkey_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_sr25519_secret_bytes(&minisecret_bytes).unwrap();
        let pubkey = encode::<&[u8]>(&signer.public);

        assert_eq!(pubkey, EXPECTED_SR25519_PUBKEY);
    }

    #[test]
    fn alice_sr25519_address_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_sr25519_secret_bytes(&minisecret_bytes).unwrap();
        let address = signer.to_string();

        assert_eq!(address, EXPECTED_SR25519_ADDRESS);
    }

    #[test]
    fn alice_ed25519_pubkey_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_ed25519_secret_bytes(&minisecret_bytes).unwrap();
        let pubkey = encode::<&[u8]>(&signer.public);

        assert_eq!(pubkey, EXPECTED_ED25519_PUBKEY);
    }

    #[test]
    fn alice_ed25519_address_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_ed25519_secret_bytes(&minisecret_bytes).unwrap();
        let address = signer.to_string();

        assert_eq!(address, EXPECTED_ED25519_ADDRESS);
    }
}
