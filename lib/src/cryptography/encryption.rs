use crate::errors::GoRoError;
use morus::{Key, Morus, Nonce, Tag};
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const TAG_LENGTH: usize = 16;
pub const KEY_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 16;

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl From<(Vec<u8>, Tag)> for EncryptionResult {
    fn from(value: (Vec<u8>, Tag)) -> Self {
        EncryptionResult {
            result: value.0,
            tag: value.1,
        }
    }
}

#[cfg(feature = "std")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptedBytes {
    inner: Vec<u8>,
}

impl DecryptedBytes {
    pub fn into_vec(self) -> Vec<u8> {
        self.inner.clone()
    }
}

#[cfg(feature = "std")]
impl From<Vec<u8>> for DecryptedBytes {
    fn from(value: Vec<u8>) -> Self {
        DecryptedBytes { inner: value }
    }
}

#[cfg(feature = "std")]
impl Deref for DecryptedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(feature = "std")]
impl DerefMut for DecryptedBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(feature = "std")]
pub fn encrypt_alloc(nonce: &Nonce, key: &Key, input: &[u8]) -> EncryptionResult {
    let encryptor = Morus::new(nonce, key);

    encryptor.encrypt(input, &[]).into()
}

#[cfg(feature = "std")]
pub fn decrypt_alloc(
    nonce: &Nonce,
    key: &Key,
    tag: &Tag,
    encrypted_bytes: &[u8],
) -> Result<DecryptedBytes, GoRoError> {
    let decryptor = Morus::new(nonce, key);
    let decrypted_bytes = decryptor.decrypt(encrypted_bytes, tag, &[])?;

    Ok(decrypted_bytes.into())
}
