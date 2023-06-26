pub mod private;
pub mod public;

use crate::errors::GoRoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type SignerAccount = public::SignerAccount;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignerKeypair {
    private: private::SignerSecret,
    #[zeroize(skip)]
    public: SignerAccount,
}

impl SignerKeypair {
    pub const LENGTH_SECRET: usize = private::SignerSecret::PRIKEY_LENGTH;
    pub const LENGTH_PUBLIC: usize = SignerAccount::PUBKEY_LENGTH;
    pub const LENGTH_SIGNATURE: usize = private::SignerSecret::SIGNATURE_LENGTH;

    pub fn generate(is_ed25519: bool) -> Self {
        let private = if is_ed25519 {
            private::SignerSecret::generate_sr25519()
        } else {
            private::SignerSecret::generate_ed25519()
        };
        let public = private.get_account();

        Self { public, private }
    }

    pub fn try_from_secret_bytes(is_ed25519: bool, secret_bytes: &[u8]) -> Result<Self, GoRoError> {
        let private = if is_ed25519 {
            private::SignerSecret::try_from_ed25519_secret_bytes(secret_bytes)?
        } else {
            private::SignerSecret::try_from_sr25519_secret_bytes(secret_bytes)?
        };
        let public = private.get_account();

        Ok(Self { private, public })
    }

    pub fn is_ed25519(&self) -> bool {
        self.private.is_ed25519
    }

    pub fn sign(&self, message: &[u8]) -> [u8; Self::LENGTH_SIGNATURE] {
        self.private.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; Self::LENGTH_SIGNATURE]) -> Result<bool, GoRoError> {
        if self.is_ed25519() {
            self.public.verify_ed25519_signature(signature, message)
        } else {
            self.public.verify_sr25519_signature(signature, message)
        }
    }

    pub fn verify_with_string_account(string_account: &str, signature: &[u8], message: &[u8]) -> Result<bool, GoRoError> {
        SignerAccount::verify_with_string_account(string_account, signature, message)
    }

    pub fn verify_with_bytes_account(bytes_account: &[u8], signature: &[u8], message: &[u8]) -> Result<bool, GoRoError> {
        SignerAccount::verify_with_bytes_account(bytes_account, signature, message)
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
    const ALICE_PUBKEY_SR25519: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    const ALICE_SS58_SR25519: &str = "gr5wupneKLGRBrA3hkcrXgbwXp1F26SV7L4LymGxCKs9QMXn1";
    const ALICE_PUBKEY_ED25519: &str = "34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a691";
    const ALICE_SS58_ED25519: &str = "gr2LLpGt2rLUixu5YzrWNvbX9qJeavgZLh95UpwBpvZSq6xpA";

    #[test]
    fn alice_sr25519_signature_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_secret_bytes(false, &minisecret_bytes).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.sign(&message_bytes);
        let signature = Sr25519Signature::from_slice(&signature).unwrap();
        let substrate_pubkey = Sr25519PublicKey::from_ss58check(ALICE_SS58_SR25519).unwrap();

        assert!(Sr25519KeyPair::verify(&signature, &message_bytes, &substrate_pubkey));
    }

    #[test]
    fn alice_ed25519_signature_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_secret_bytes(true, &minisecret_bytes).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.sign(&message_bytes);
        let signature = Ed25519Signature::from_slice(&signature).unwrap();
        let substrate_pubkey = Ed25519PublicKey::from_ss58check(ALICE_SS58_ED25519).unwrap();

        assert!(Ed25519KeyPair::verify(&signature, &message_bytes, &substrate_pubkey));
    }

    #[test]
    fn alice_sr25519_pubkey_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_secret_bytes(false, &minisecret_bytes).unwrap();
        let pubkey = encode::<&[u8]>(&signer.public);

        assert_eq!(pubkey, ALICE_PUBKEY_SR25519);
    }

    #[test]
    fn alice_sr25519_address_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_secret_bytes(false, &minisecret_bytes).unwrap();
        let address = signer.to_string();

        assert_eq!(address, ALICE_SS58_SR25519);
    }

    #[test]
    fn alice_ed25519_pubkey_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_secret_bytes(true, &minisecret_bytes).unwrap();
        let pubkey = encode::<&[u8]>(&signer.public);

        assert_eq!(pubkey, ALICE_PUBKEY_ED25519);
    }

    #[test]
    fn alice_ed25519_address_from_minisecret_is_correct() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let signer = SignerKeypair::try_from_secret_bytes(true, &minisecret_bytes).unwrap();
        let address = signer.to_string();

        assert_eq!(address, ALICE_SS58_ED25519);
    }

    #[test]
    fn alice_sr25519_substrate_signature_can_be_verified_correctly() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let pubkey_bytes = decode(ALICE_PUBKEY_SR25519).unwrap();
        let signer = Sr25519KeyPair::from_seed_slice(&minisecret_bytes).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.sign(&message_bytes);
        let verification_ss58 =
            SignerKeypair::verify_with_string_account(ALICE_SS58_SR25519, signature.as_ref(), &message_bytes);
        let verification_bytes = SignerKeypair::verify_with_bytes_account(&pubkey_bytes, signature.as_ref(), &message_bytes);

        assert!(verification_ss58.is_ok());
        assert!(verification_ss58.unwrap());
        assert!(verification_bytes.is_ok());
        assert!(verification_bytes.unwrap());
    }

    #[test]
    fn alice_ed25519_substrate_signature_can_be_verified_correctly() {
        let minisecret_bytes = decode(ALICE_MINISECRET_HEX).unwrap();
        let pubkey_bytes = decode(ALICE_PUBKEY_ED25519).unwrap();
        let signer = Ed25519KeyPair::from_seed_slice(&minisecret_bytes).unwrap();
        let message_bytes = decode(MESSAGE_HEX).unwrap();
        let signature = signer.sign(&message_bytes);
        let verification_ss58 =
            SignerKeypair::verify_with_string_account(ALICE_SS58_ED25519, signature.as_ref(), &message_bytes);
        let verification_bytes = SignerKeypair::verify_with_bytes_account(&pubkey_bytes, signature.as_ref(), &message_bytes);

        assert!(verification_ss58.is_ok());
        assert!(verification_ss58.unwrap());
        assert!(verification_bytes.is_ok());
        assert!(verification_bytes.unwrap());
    }
}
