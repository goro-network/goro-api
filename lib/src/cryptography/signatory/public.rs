use crate::errors::GoRoError;
use blake2::{Blake2b512, Digest};
use ss58_registry::Ss58AddressFormatRegistry;
use std::fmt::Display;
use std::ops::{Deref, DerefMut, Range};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignerPublicKey([u8; Self::LENGTH]);

impl SignerPublicKey {
    pub const LENGTH: usize = 32;
    pub const LENGTH_SS58_PREFIX: usize = 2;
    pub const LENGTH_SS58_SUFFIX: usize = 2;
    pub const LENGTH_SS58_OTHER: usize = Self::LENGTH_SS58_PREFIX + Self::LENGTH_SS58_SUFFIX;
    pub const LENGTH_SS58: usize = Self::LENGTH + Self::LENGTH_SS58_OTHER;
    pub const SS58_PUBKEY_REF_RANGE: Range<usize> = Self::LENGTH_SS58_PREFIX..(Self::LENGTH_SS58 - Self::LENGTH_SS58_SUFFIX);
    pub const PREFIX_SS58: &[u8; 7] = b"SS58PRE";
    pub const PREFIX_DEFAULT: u16 = Self::PREFIX_GORO;
    pub const PREFIX_GORO: u16 = Ss58AddressFormatRegistry::GoroAccount as u16;
    pub const PREFIX_KRIGAN: u16 = Ss58AddressFormatRegistry::KriganAccount as u16;

    pub fn from_slice(source: &[u8]) -> Result<Self, GoRoError> {
        if source.len() != Self::LENGTH {
            return Err(GoRoError::BadInputBufferLength {
                expected: Self::LENGTH,
                got: source.len(),
            });
        }

        let mut inner = [0; Self::LENGTH];
        inner.copy_from_slice(source);

        Ok(Self(inner))
    }

    pub fn get_goro_address(&self) -> String {
        self.get_string_with_prefix(Self::PREFIX_GORO)
    }

    pub fn get_krigan_address(&self) -> String {
        self.get_string_with_prefix(Self::PREFIX_KRIGAN)
    }

    pub fn from_ss58(ss58_string: &str) -> Result<Self, GoRoError> {
        let decoded_ss58 = bs58::decode(ss58_string).into_vec().map_err(|_| GoRoError::BadSs58Format)?;

        if decoded_ss58.len() != Self::LENGTH_SS58 {
            return Err(GoRoError::BadInputBufferLength {
                expected: Self::LENGTH,
                got: (decoded_ss58.len() - Self::LENGTH_SS58_OTHER),
            });
        }

        let mut result = Self::default();
        result.copy_from_slice(&decoded_ss58[Self::SS58_PUBKEY_REF_RANGE]);

        Ok(result)
    }

    pub fn from_hex_bytes(hex_bytes: &str) -> Result<Self, GoRoError> {
        let mut result = Self::default();
        hex::decode_to_slice(hex_bytes, &mut result[..]).map_err(|_| GoRoError::BadInputBufferLength {
            expected: Self::LENGTH,
            got: hex_bytes.len() / 2,
        })?;

        Ok(result)
    }

    pub fn try_from_string(any_string: &str) -> Result<Self, GoRoError> {
        if any_string.starts_with("0x") {
            let sanitized_string = any_string.replace("0x", "");

            Self::from_hex_bytes(&sanitized_string)
        } else {
            Self::from_ss58(any_string)
        }
    }

    fn get_string_with_prefix(&self, prefix: u16) -> String {
        let ident = prefix & 0b0011_1111_1111_1111; // 14-bit only
        let mut version = match ident {
            0..=63 => vec![ident as u8],
            64..=16_383 => {
                let first = (((ident & 0b0000_0000_1111_1100) as u8) >> 2) | 0b01000000;
                let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;

                vec![first, second]
            }
            _ => unreachable!("No way this will be executed"),
        };
        version.extend(self.0.as_ref());
        let mut version_hash = Blake2b512::new();
        version_hash.update(Self::PREFIX_SS58);
        version_hash.update(&version);
        let version_hash = version_hash.finalize().to_vec();
        version.extend(&version_hash[0..2]);

        bs58::encode(version).into_string()
    }
}

impl Deref for SignerPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl DerefMut for SignerPublicKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

impl Default for SignerPublicKey {
    fn default() -> Self {
        Self([0u8; Self::LENGTH])
    }
}

impl Display for SignerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_string_with_prefix(Self::PREFIX_DEFAULT))
    }
}

impl TryFrom<&str> for SignerPublicKey {
    type Error = GoRoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from_string(value)
    }
}

impl TryFrom<String> for SignerPublicKey {
    type Error = GoRoError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_string(&value)
    }
}

impl From<[u8; 32]> for SignerPublicKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const ALICE_SR25519_HEX: &str = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    const ALICE_SR25519_GORO: &str = "gr5wupneKLGRBrA3hkcrXgbwXp1F26SV7L4LymGxCKs9QMXn1";
    const ALICE_SR25519_KRIGAN: &str = "kRvkvFKT8tJDBBRizPdK1Efug3j7XRC5JFJJUJ1aMnzj6aXuB";
    const ALICE_ED25519_HEX: &str = "0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee";
    const ALICE_ED25519_GORO: &str = "gr4F7gcdZvHyi3JQrMmp6gumHXpQFJH9qttmFCinMoJFDu9bx";
    const ALICE_ED25519_KRIGAN: &str = "kRu4879SPUKmhNa68znGaEyjRmYGkd2k2p8ijjTQXGRpv8FWu";

    #[test]
    fn encode_alice_goro_is_correct() {
        let sr25519_pubkey = SignerPublicKey::try_from(ALICE_SR25519_HEX).unwrap();
        let ed25519_pubkey = SignerPublicKey::try_from(ALICE_ED25519_HEX).unwrap();

        let sr25519_goro = sr25519_pubkey.to_string();
        let ed25519_goro = ed25519_pubkey.to_string();

        assert_eq!(sr25519_goro, ALICE_SR25519_GORO);
        assert_eq!(ed25519_goro, ALICE_ED25519_GORO);
    }

    #[test]
    fn encode_alice_krigan_is_correct() {
        let sr25519_pubkey = SignerPublicKey::try_from(ALICE_SR25519_HEX).unwrap();
        let ed25519_pubkey = SignerPublicKey::try_from(ALICE_ED25519_HEX).unwrap();

        let sr25519_krigan = sr25519_pubkey.get_krigan_address();
        let ed25519_krigan = ed25519_pubkey.get_krigan_address();

        assert_eq!(sr25519_krigan, ALICE_SR25519_KRIGAN);
        assert_eq!(ed25519_krigan, ALICE_ED25519_KRIGAN);
    }

    #[test]
    fn decode_alice_goro_is_correct() {
        let sr25519_pubkey = SignerPublicKey::try_from(ALICE_SR25519_GORO).unwrap();
        let ed25519_pubkey = SignerPublicKey::try_from(ALICE_ED25519_GORO).unwrap();

        assert_eq!(sr25519_pubkey.to_string(), ALICE_SR25519_GORO);
        assert_eq!(ed25519_pubkey.to_string(), ALICE_ED25519_GORO);
    }

    #[test]
    fn decode_alice_krigan_is_correct() {
        let sr25519_pubkey = SignerPublicKey::try_from(ALICE_SR25519_KRIGAN).unwrap();
        let ed25519_pubkey = SignerPublicKey::try_from(ALICE_ED25519_KRIGAN).unwrap();

        assert_eq!(sr25519_pubkey.get_krigan_address(), ALICE_SR25519_KRIGAN);
        assert_eq!(ed25519_pubkey.get_krigan_address(), ALICE_ED25519_KRIGAN);
    }
}
