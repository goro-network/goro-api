use crate::cryptography::signatory::private::SignerSecret;
use crate::errors::GoRoError;
use blake2::{Blake2b512, Digest};
use ss58_registry::Ss58AddressFormatRegistry;
use std::fmt::Display;
use std::ops::{Deref, DerefMut, Range, RangeInclusive};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignerAccount([u8; Self::PUBKEY_LENGTH]);

impl SignerAccount {
    pub const PREFIX_DEFAULT: u16 = Self::PREFIX_GORO;
    pub const PREFIX_GORO: u16 = Ss58AddressFormatRegistry::GoroAccount as u16;
    pub const PREFIX_KRIGAN: u16 = Ss58AddressFormatRegistry::KriganAccount as u16;
    pub const PREFIX_SS58: &[u8; 7] = b"SS58PRE";
    pub const PUBKEY_LENGTH: usize = 32;
    pub const SS58_BYTES_INFIX_RANGE: Range<usize> = Self::SS58_BYTES_PREFIX_LENGTH..Self::SS58_BYTES_SUFFIX_INDEX;
    pub const SS58_BYTES_LENGTH: usize = Self::PUBKEY_LENGTH + Self::SS58_BYTES_SUFFIX_PREFIX_LENGTH;
    pub const SS58_BYTES_PREFIX_LENGTH: usize = 2;
    pub const SS58_BYTES_SUFFIX_INDEX: usize = Self::SS58_BYTES_LENGTH - Self::SS58_BYTES_SUFFIX_LENGTH;
    pub const SS58_BYTES_SUFFIX_LENGTH: usize = 2;
    pub const SS58_BYTES_SUFFIX_RANGE: Range<usize> = Self::SS58_BYTES_SUFFIX_INDEX..Self::SS58_BYTES_LENGTH;
    pub const SS58_BYTES_SUFFIX_PREFIX_LENGTH: usize = Self::SS58_BYTES_PREFIX_LENGTH + Self::SS58_BYTES_SUFFIX_LENGTH;
    pub const SS58_STRING_LENGTH_RANGE: RangeInclusive<usize> = Self::SS58_STRING_MIN_LENGTH..=Self::SS58_STRING_MAX_LENGTH;
    pub const SS58_STRING_MAX_LENGTH: usize = 50;
    pub const SS58_STRING_MIN_LENGTH: usize = Self::SS58_BYTES_SUFFIX_PREFIX_LENGTH;
    pub const SIGNATURE_BYTES_LENGTH: usize = 64;

    pub fn try_from_slice(source: &[u8]) -> Result<Self, GoRoError> {
        if source.len() != Self::PUBKEY_LENGTH {
            return Err(GoRoError::BadInputBufferLength {
                expected: Self::PUBKEY_LENGTH,
                given: source.len(),
            });
        }

        let mut inner = [0; Self::PUBKEY_LENGTH];
        inner.copy_from_slice(source);

        Ok(Self(inner))
    }

    pub fn get_goro_address(&self) -> String {
        self.get_ss58_string(Self::PREFIX_GORO)
    }

    pub fn get_krigan_address(&self) -> String {
        self.get_ss58_string(Self::PREFIX_KRIGAN)
    }

    pub fn try_from_ss58(ss58_string: &str) -> Result<Self, GoRoError> {
        let character_count = ss58_string.len();

        if !Self::SS58_STRING_LENGTH_RANGE.contains(&character_count) {
            return Err(GoRoError::BadSs58Length {
                max: Self::SS58_STRING_MAX_LENGTH,
                min: Self::SS58_STRING_MIN_LENGTH,
                given: character_count,
            });
        }

        let mut decoded_buffer = [0u8; Self::SS58_BYTES_LENGTH];
        let _ = bs58::decode(ss58_string).into(&mut decoded_buffer); // infallible because above lines

        let mut result = Self::default();
        result.copy_from_slice(&decoded_buffer[Self::SS58_BYTES_INFIX_RANGE]);

        Ok(result)
    }

    pub fn try_from_hex_bytes(hex_bytes: &str) -> Result<Self, GoRoError> {
        let mut result = Self::default();
        hex::decode_to_slice(hex_bytes, &mut result[..]).map_err(|_| GoRoError::BadInputBufferLength {
            expected: Self::PUBKEY_LENGTH,
            given: hex_bytes.len() / 2,
        })?;

        Ok(result)
    }

    pub fn try_from_string(any_string: &str) -> Result<Self, GoRoError> {
        if any_string.starts_with("0x") {
            let sanitized_string = any_string.replace("0x", "");

            Self::try_from_hex_bytes(&sanitized_string)
        } else {
            Self::try_from_ss58(any_string)
        }
    }

    pub fn verify_sr25519_signature(&self, signature: &[u8], message: &[u8]) -> Result<bool, GoRoError> {
        if signature.len() != Self::SIGNATURE_BYTES_LENGTH {
            return Err(GoRoError::BadSignatureLength {
                expected: Self::SIGNATURE_BYTES_LENGTH,
                given: signature.len(),
            });
        }

        let signature_sr25519 = schnorrkel::Signature::from_bytes(signature).map_err(|_| GoRoError::BadSignatureFormat)?;
        let pubkey_sr25519 = schnorrkel::PublicKey::from_bytes(&self.0[..]).unwrap(); // infallible
        let verification_result = pubkey_sr25519.verify_simple(SignerSecret::SIGNING_CONTEXT, message, &signature_sr25519);

        Ok(verification_result.is_ok())
    }

    pub fn verify_ed25519_signature(&self, signature: &[u8], message: &[u8]) -> Result<bool, GoRoError> {
        if signature.len() != Self::SIGNATURE_BYTES_LENGTH {
            return Err(GoRoError::BadSignatureLength {
                expected: Self::SIGNATURE_BYTES_LENGTH,
                given: signature.len(),
            });
        }

        let signature_ed25519 = ed25519_zebra::Signature::try_from(signature).map_err(|_| GoRoError::BadSignatureFormat)?;
        let pubkey_ed25519_bytes =
            ed25519_zebra::VerificationKeyBytes::try_from(&self.0[..]).map_err(|_| GoRoError::BadPublicKeyFormat)?;
        let pubkey_ed25519 =
            ed25519_zebra::VerificationKey::try_from(pubkey_ed25519_bytes).map_err(|_| GoRoError::BadPublicKeyFormat)?;
        let verification_result = pubkey_ed25519.verify(&signature_ed25519, message);

        Ok(verification_result.is_ok())
    }

    pub fn verify_anyhow(&self, signature: &[u8], message: &[u8]) -> bool {
        let ed25519_verification = self.verify_ed25519_signature(signature, message);
        let sr25519_verification = self.verify_sr25519_signature(signature, message);

        match (ed25519_verification, sr25519_verification) {
            (Err(_), Err(_)) => panic!("Both failed!"),
            (Ok(is_verified), Err(_)) => is_verified,
            (Err(_), Ok(is_verified)) => is_verified,
            (Ok(is_verified_ed25519), Ok(is_verified_sr25519)) => is_verified_ed25519 | is_verified_sr25519,
        }
    }

    pub fn verify_with_string_account(string_account: &str, signature: &[u8], message: &[u8]) -> Result<bool, GoRoError> {
        Ok(Self::try_from_string(string_account)?.verify_anyhow(signature, message))
    }

    pub fn verify_with_bytes_account(bytes_account: &[u8], signature: &[u8], message: &[u8]) -> Result<bool, GoRoError> {
        Ok(Self::try_from_slice(bytes_account)?.verify_anyhow(signature, message))
    }

    fn get_ss58_string(&self, prefix: u16) -> String {
        let mut hash_buffer = [0u8; 64]; // 512-bit
        let mut ss58_string_buffer = [0u8; Self::SS58_STRING_MAX_LENGTH];
        let mut version_buffer = [0u8; Self::SS58_BYTES_LENGTH];
        let ident: u16 = prefix & 0b0011_1111_1111_1111; // 14-bit only

        match ident {
            0..=63 => version_buffer[0] = ident as u8,
            64..=16_383 => {
                let first = (((ident & 0b0000_0000_1111_1100) as u8) >> 2) | 0b01000000;
                let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;

                version_buffer[0] = first;
                version_buffer[1] = second;
            }
            _ => unreachable!("No way this will be executed"),
        }

        let version_buffer_infix = &mut version_buffer[Self::SS58_BYTES_INFIX_RANGE];
        version_buffer_infix.copy_from_slice(&self.0[..]);
        let mut hasher = Blake2b512::new();
        hasher.update(Self::PREFIX_SS58);
        hasher.update(&version_buffer[..Self::SS58_BYTES_SUFFIX_INDEX]);
        hasher.finalize_into((&mut hash_buffer).into());
        let version_buffer_without_prefix = &mut version_buffer[Self::SS58_BYTES_SUFFIX_RANGE];
        version_buffer_without_prefix.copy_from_slice(&hash_buffer[..Self::SS58_BYTES_SUFFIX_LENGTH]);
        let string_length = bs58::encode(&version_buffer[..]).into(&mut ss58_string_buffer[..]).unwrap(); // infallible

        std::str::from_utf8(&ss58_string_buffer[..string_length]).unwrap().to_owned()
    }
}

impl Deref for SignerAccount {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl DerefMut for SignerAccount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

impl Default for SignerAccount {
    fn default() -> Self {
        Self([0u8; Self::PUBKEY_LENGTH])
    }
}

impl Display for SignerAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_ss58_string(Self::PREFIX_DEFAULT))
    }
}

impl TryFrom<&str> for SignerAccount {
    type Error = GoRoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from_string(value)
    }
}

impl TryFrom<String> for SignerAccount {
    type Error = GoRoError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_string(&value)
    }
}

impl From<[u8; 32]> for SignerAccount {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use sp_core::crypto::{AccountId32, Ss58Codec};
    use sp_core::ed25519::Pair as Ed25519KeyPair;
    use sp_core::sr25519::Pair as Sr25519KeyPair;
    use sp_core::Pair;

    const ALICE_MINISECRET_HEX: &str = "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
    const ALICE_SR25519_HEX: &str = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    const ALICE_SR25519_GORO: &str = "gr5wupneKLGRBrA3hkcrXgbwXp1F26SV7L4LymGxCKs9QMXn1";
    const ALICE_SR25519_KRIGAN: &str = "kRvkvFKT8tJDBBRizPdK1Efug3j7XRC5JFJJUJ1aMnzj6aXuB";
    const ALICE_ED25519_HEX: &str = "0x34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a691";
    const ALICE_ED25519_GORO: &str = "gr2LLpGt2rLUixu5YzrWNvbX9qJeavgZLh95UpwBpvZSq6xpA";
    const ALICE_ED25519_KRIGAN: &str = "kRs9MEogrQNGiJAkqdrxrUfVJ52X6FS9XcP2yMfozPh2XKjFN";
    const ALICE_MESSAGE: &[u8] = b"Hello, this is Alice!";

    #[test]
    fn encode_alice_goro_is_correct() {
        let sr25519_pubkey = SignerAccount::try_from(ALICE_SR25519_HEX).unwrap();
        let ed25519_pubkey = SignerAccount::try_from(ALICE_ED25519_HEX).unwrap();
        let sr25519_goro = sr25519_pubkey.to_string();
        let ed25519_goro = ed25519_pubkey.to_string();
        let sr25519_substrate_account = AccountId32::from_ss58check(&sr25519_goro).unwrap();
        let ed25519_substrate_account = AccountId32::from_ss58check(&ed25519_goro).unwrap();
        let sr25519_substrate_hex = format!("0x{}", hex::encode(sr25519_substrate_account));
        let ed25519_substrate_hex = format!("0x{}", hex::encode(ed25519_substrate_account));

        assert_eq!(sr25519_goro, ALICE_SR25519_GORO);
        assert_eq!(ed25519_goro, ALICE_ED25519_GORO);
        assert_eq!(sr25519_substrate_hex, ALICE_SR25519_HEX);
        assert_eq!(ed25519_substrate_hex, ALICE_ED25519_HEX);
    }

    #[test]
    fn encode_alice_krigan_is_correct() {
        let sr25519_pubkey = SignerAccount::try_from(ALICE_SR25519_HEX).unwrap();
        let ed25519_pubkey = SignerAccount::try_from(ALICE_ED25519_HEX).unwrap();
        let sr25519_krigan = sr25519_pubkey.get_krigan_address();
        let ed25519_krigan = ed25519_pubkey.get_krigan_address();
        let sr25519_substrate_account = AccountId32::from_ss58check(&sr25519_krigan).unwrap();
        let ed25519_substrate_account = AccountId32::from_ss58check(&ed25519_krigan).unwrap();
        let sr25519_substrate_hex = format!("0x{}", hex::encode(sr25519_substrate_account));
        let ed25519_substrate_hex = format!("0x{}", hex::encode(ed25519_substrate_account));

        assert_eq!(sr25519_krigan, ALICE_SR25519_KRIGAN);
        assert_eq!(ed25519_krigan, ALICE_ED25519_KRIGAN);
        assert_eq!(sr25519_substrate_hex, ALICE_SR25519_HEX);
        assert_eq!(ed25519_substrate_hex, ALICE_ED25519_HEX);
    }

    #[test]
    fn decode_alice_goro_is_correct() {
        let sr25519_pubkey = SignerAccount::try_from(ALICE_SR25519_GORO).unwrap();
        let ed25519_pubkey = SignerAccount::try_from(ALICE_ED25519_GORO).unwrap();

        assert_eq!(sr25519_pubkey.to_string(), ALICE_SR25519_GORO);
        assert_eq!(ed25519_pubkey.to_string(), ALICE_ED25519_GORO);
        assert!(AccountId32::from_ss58check(ALICE_SR25519_GORO).is_ok());
        assert!(AccountId32::from_ss58check(ALICE_ED25519_GORO).is_ok());
    }

    #[test]
    fn decode_alice_krigan_is_correct() {
        let sr25519_pubkey = SignerAccount::try_from(ALICE_SR25519_KRIGAN).unwrap();
        let ed25519_pubkey = SignerAccount::try_from(ALICE_ED25519_KRIGAN).unwrap();

        assert_eq!(sr25519_pubkey.get_krigan_address(), ALICE_SR25519_KRIGAN);
        assert_eq!(ed25519_pubkey.get_krigan_address(), ALICE_ED25519_KRIGAN);
        assert!(AccountId32::from_ss58check(ALICE_SR25519_KRIGAN).is_ok());
        assert!(AccountId32::from_ss58check(ALICE_ED25519_KRIGAN).is_ok());
    }

    #[test]
    fn verify_alice_goro_signature_is_correct() {
        let sr25519_pubkey = SignerAccount::try_from(ALICE_SR25519_GORO).unwrap();
        let ed25519_pubkey = SignerAccount::try_from(ALICE_ED25519_GORO).unwrap();
        let substrate_sr25519_keypair = Sr25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let substrate_ed25519_keypair = Ed25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let signature_sr25519 = substrate_sr25519_keypair.sign(ALICE_MESSAGE);
        let signature_ed25519 = substrate_ed25519_keypair.sign(ALICE_MESSAGE);
        let signature_verification_sr25519 = sr25519_pubkey
            .verify_sr25519_signature(&signature_sr25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_ed25519 = ed25519_pubkey
            .verify_ed25519_signature(&signature_ed25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_anyhow_with_sr25519 =
            SignerAccount::verify_with_string_account(ALICE_SR25519_GORO, &signature_sr25519.0[..], ALICE_MESSAGE).unwrap();
        let signature_verification_anyhow_with_ed25519 =
            SignerAccount::verify_with_string_account(ALICE_ED25519_GORO, &signature_ed25519.0[..], ALICE_MESSAGE).unwrap();

        assert!(signature_verification_sr25519);
        assert!(signature_verification_ed25519);
        assert!(signature_verification_anyhow_with_sr25519);
        assert!(signature_verification_anyhow_with_ed25519);
    }

    #[test]
    fn verify_alice_krigan_signature_is_correct() {
        let sr25519_pubkey = SignerAccount::try_from(ALICE_SR25519_KRIGAN).unwrap();
        let ed25519_pubkey = SignerAccount::try_from(ALICE_ED25519_KRIGAN).unwrap();
        let substrate_sr25519_keypair = Sr25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let substrate_ed25519_keypair = Ed25519KeyPair::from_string(ALICE_MINISECRET_HEX, None).unwrap();
        let signature_sr25519 = substrate_sr25519_keypair.sign(ALICE_MESSAGE);
        let signature_ed25519 = substrate_ed25519_keypair.sign(ALICE_MESSAGE);
        let signature_verification_sr25519 = sr25519_pubkey
            .verify_sr25519_signature(&signature_sr25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_ed25519 = ed25519_pubkey
            .verify_ed25519_signature(&signature_ed25519.0[..], ALICE_MESSAGE)
            .unwrap();
        let signature_verification_anyhow_with_sr25519 =
            SignerAccount::verify_with_string_account(ALICE_SR25519_KRIGAN, &signature_sr25519.0[..], ALICE_MESSAGE).unwrap();
        let signature_verification_anyhow_with_ed25519 =
            SignerAccount::verify_with_string_account(ALICE_ED25519_KRIGAN, &signature_ed25519.0[..], ALICE_MESSAGE).unwrap();

        assert!(signature_verification_sr25519);
        assert!(signature_verification_ed25519);
        assert!(signature_verification_anyhow_with_sr25519);
        assert!(signature_verification_anyhow_with_ed25519);
    }
}
