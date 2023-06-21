pub use std_mod::{decrypt, encrypt, DecryptedBytes, EncryptionResult};

pub const TAG_LENGTH: usize = 16;
pub const KEY_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 16;

mod std_mod {
    use crate::errors::GoRoError;
    use morus::{Key, Morus, Nonce, Tag};
    use std::ops::{Deref, DerefMut};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct EncryptionResult {
        pub result: Vec<u8>,
        pub tag: Tag,
    }

    impl EncryptionResult {
        pub fn into_single_buffer(self) -> Vec<u8> {
            let result_length = self.result.len();
            let tag_length = self.tag.len();
            let mut buffer = vec![0u8; tag_length + result_length];
            buffer[0..tag_length].copy_from_slice(&self.tag[..]);
            buffer[tag_length..result_length].copy_from_slice(&self.result[..]);

            buffer
        }
    }

    impl From<(Vec<u8>, Tag)> for EncryptionResult {
        fn from(value: (Vec<u8>, Tag)) -> Self {
            EncryptionResult {
                result: value.0,
                tag: value.1,
            }
        }
    }

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct DecryptedBytes {
        inner: Vec<u8>,
    }

    impl DecryptedBytes {
        pub fn into_vec(self) -> Vec<u8> {
            self.inner.clone()
        }
    }

    impl From<Vec<u8>> for DecryptedBytes {
        fn from(value: Vec<u8>) -> Self {
            DecryptedBytes { inner: value }
        }
    }

    impl Deref for DecryptedBytes {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl DerefMut for DecryptedBytes {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    pub fn encrypt(nonce: &Nonce, key: &Key, input: &[u8]) -> EncryptionResult {
        let mut encryption_result = EncryptionResult {
            result: vec![0u8; input.len()],
            tag: Default::default(),
        };
        encryption_result.result.copy_from_slice(input);
        encryption_result.tag = Morus::new(nonce, key).encrypt_in_place(&mut encryption_result.result[..], &[]);

        encryption_result
    }

    pub fn decrypt(nonce: &Nonce, key: &Key, tag: &Tag, encrypted_bytes: &[u8]) -> Result<DecryptedBytes, GoRoError> {
        let mut decrypted_result = DecryptedBytes {
            inner: vec![0u8; encrypted_bytes.len()],
        };
        decrypted_result.inner.copy_from_slice(encrypted_bytes);
        Morus::new(nonce, key).decrypt_in_place(&mut decrypted_result.inner, tag, &[])?;

        Ok(decrypted_result)
    }
}
