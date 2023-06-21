use goro_api::cryptography::{encryption, hashing, mnemonic};
use goro_api::errors::GoRoError;
use safer_ffi::{derive_ReprC as ffi_repr_c, ffi_export, i32, u8, String as CString, Vec as CVec};

// region: results

#[ffi_repr_c]
#[repr(C)]
pub struct BytesResult {
    pub error_code: i32,
    pub bytes: CVec<u8>,
}

// endregion

// region: malloc release/free

#[ffi_export]
pub fn goro_release_any_bytes(rust_owned_bytes: CVec<u8>) {
    drop(rust_owned_bytes)
}

// endregion

// region: mnemonic

#[ffi_export]
pub fn goro_mnemonic_generate() -> CString {
    CString::from(mnemonic::generate())
}

#[ffi_export]
pub fn goro_mnemonic_length() -> usize {
    mnemonic::length()
}

// endregion

// region: hashing

#[ffi_export]
pub fn goro_hash_data(input_data: &CVec<u8>) -> BytesResult {
    let mut result = BytesResult {
        bytes: vec![0u8; hashing::Hasher::OUTPUT_LENGTH].into(),
        error_code: 0,
    };

    if input_data.is_empty() {
        result.error_code = GoRoError::EmptyInputBuffer.into();

        return result;
    }

    hashing::Hasher::hash_once(None, input_data, &mut result.bytes).unwrap();

    result
}

#[ffi_export]
pub fn goro_hash_data_with_salt(input_data: &CVec<u8>, salt: &CVec<u8>) -> BytesResult {
    let mut result = BytesResult {
        bytes: vec![0u8; hashing::Hasher::OUTPUT_LENGTH].into(),
        error_code: 0,
    };

    if input_data.is_empty() {
        result.error_code = GoRoError::EmptyInputBuffer.into();

        return result;
    }

    if salt.len() != hashing::Hasher::KEY_LENGTH {
        result.error_code = GoRoError::BadKeyLength {
            expected: hashing::Hasher::KEY_LENGTH,
            given: salt.len(),
        }
        .into();

        return result;
    }

    hashing::Hasher::hash_once(Some(salt), input_data, &mut result.bytes).unwrap();

    result
}

// endregion

// region: encrypt/decrypt

#[ffi_export]
pub fn goro_encrypt(nonce: &CVec<u8>, key: &CVec<u8>, input_data: &CVec<u8>) -> BytesResult {
    let mut result = BytesResult {
        bytes: Vec::new().into(),
        error_code: 0,
    };

    if nonce.len() != encryption::NONCE_LENGTH {
        result.error_code = GoRoError::BadNonce.into();

        return result;
    }

    if key.len() != encryption::KEY_LENGTH {
        result.error_code = GoRoError::BadKeyLength {
            expected: hashing::Hasher::KEY_LENGTH,
            given: key.len(),
        }
        .into();

        return result;
    }

    let mut nonce_array = [0u8; encryption::NONCE_LENGTH];
    let mut key_array = [0u8; encryption::KEY_LENGTH];
    nonce_array.copy_from_slice(&nonce[..]);
    key_array.copy_from_slice(&key[..]);
    result.bytes = encryption::encrypt(&nonce_array, &key_array, input_data)
        .into_single_buffer()
        .into();

    result
}

#[ffi_export]
pub fn goro_decrypt(nonce: &CVec<u8>, key: &CVec<u8>, tag: &CVec<u8>, input_data: &CVec<u8>) -> BytesResult {
    let mut result = BytesResult {
        bytes: Vec::new().into(),
        error_code: 0,
    };

    if nonce.len() != encryption::NONCE_LENGTH {
        result.error_code = GoRoError::BadNonce.into();

        return result;
    }

    if tag.len() != encryption::TAG_LENGTH {
        result.error_code = GoRoError::BadTagOnDecryption.into();

        return result;
    }

    if key.len() != encryption::KEY_LENGTH {
        result.error_code = GoRoError::BadKeyLength {
            expected: hashing::Hasher::KEY_LENGTH,
            given: key.len(),
        }
        .into();

        return result;
    }

    let mut nonce_array = [0u8; encryption::NONCE_LENGTH];
    let mut key_array = [0u8; encryption::KEY_LENGTH];
    let mut tag_array = [0u8; encryption::TAG_LENGTH];
    nonce_array.copy_from_slice(&nonce[..]);
    key_array.copy_from_slice(&key[..]);
    tag_array.copy_from_slice(&tag[..]);

    match encryption::decrypt(&nonce_array, &key_array, &tag_array, input_data) {
        Err(err) => {
            result.error_code = err.into();
        }
        Ok(decrypted_bytes) => {
            result.bytes = decrypted_bytes.into_vec().into();
        }
    }

    result
}

// endregion

// region: hacks

#[cfg(feature = "gen-headers")]
#[safer_ffi::cfg_headers]
#[test]
fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder().to_file("libgoroapi_unity.h")?.generate()
}

// endregion
