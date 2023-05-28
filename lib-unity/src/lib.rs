use goro_api::cryptography::{hashing, mnemonic};
use safer_ffi::{ffi_export, u8, String as CString, Vec as CVec};

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
pub fn goro_hash_data(input_data: &CVec<u8>) -> CVec<u8> {
    let mut hash_output = vec![0u8; hashing::Hasher::OUTPUT_LENGTH];

    if input_data.is_empty() {
        return hash_output.into();
    }

    hashing::Hasher::hash_once(None, input_data, &mut hash_output).unwrap();

    hash_output.into()
}

#[ffi_export]
pub fn goro_hash_data_with_salt(input_data: &CVec<u8>, salt: &CVec<u8>) -> CVec<u8> {
    let mut hash_output = vec![0u8; hashing::Hasher::OUTPUT_LENGTH];

    if salt.is_empty() | input_data.is_empty() {
        return hash_output.into();
    }

    if salt.len() != hashing::Hasher::KEY_LENGTH {
        return hash_output.into();
    }

    hashing::Hasher::hash_once(Some(salt), input_data, &mut hash_output).unwrap();

    hash_output.into()
}

// endregion

// region: hacks

#[cfg(feature = "gen-headers")]
#[safer_ffi::cfg_headers]
#[test]
fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("libgoroapi_unity.h")?
        .generate()
}

// endregion
