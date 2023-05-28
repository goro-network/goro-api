use crate::errors::GoRoError;
use blake3::{
    hash as blake3_hash, keyed_hash as blake3_keyed_hash, Hasher as Blake3Hasher, KEY_LEN, OUT_LEN,
};

pub struct Hasher {
    inner: Blake3Hasher,
}

impl Hasher {
    pub const OUTPUT_LENGTH: usize = OUT_LEN;
    pub const KEY_LENGTH: usize = KEY_LEN;

    pub fn new(key: Option<&[u8]>) -> Result<Self, GoRoError> {
        let inner;

        if let Some(hasher_key) = key {
            if hasher_key.len() != KEY_LEN {
                return Err(GoRoError::BadKeyLength {
                    expected: KEY_LEN,
                    given: hasher_key.len(),
                });
            }

            let key = hasher_key.try_into().unwrap();
            inner = Blake3Hasher::new_keyed(key);
        } else {
            inner = Blake3Hasher::new();
        }

        Ok(Self { inner })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize_into(self, hash_output: &mut [u8]) -> Result<(), GoRoError> {
        if hash_output.len() != OUT_LEN {
            return Err(GoRoError::BadDestinationLength {
                expected: OUT_LEN,
                given: hash_output.len(),
            });
        }

        let hash = self.inner.finalize();
        hash_output.copy_from_slice(&hash.as_bytes()[..]);

        Ok(())
    }

    pub fn hash_once(
        key: Option<&[u8]>,
        data: &[u8],
        hash_output: &mut [u8],
    ) -> Result<(), GoRoError> {
        let hash;

        if hash_output.len() != OUT_LEN {
            return Err(GoRoError::BadDestinationLength {
                expected: OUT_LEN,
                given: hash_output.len(),
            });
        }

        if let Some(hasher_key) = key {
            if hasher_key.len() != KEY_LEN {
                return Err(GoRoError::BadKeyLength {
                    expected: KEY_LEN,
                    given: hasher_key.len(),
                });
            }

            let key = hasher_key.try_into().unwrap();
            hash = blake3_keyed_hash(key, data);
        } else {
            hash = blake3_hash(data);
        }

        hash_output.copy_from_slice(&hash.as_bytes()[..]);

        Ok(())
    }
}
