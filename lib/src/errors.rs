use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum GoRoError {
    #[error("Input buffer is empty!")]
    EmptyInputBuffer,
    #[error("Invalid key length (expected: {expected:?} | given: {given:?})!")]
    BadKeyLength { expected: usize, given: usize },
    #[error("Invalid destination length (expected: {expected:?} | given: {given:?})!")]
    BadDestinationLength { expected: usize, given: usize },
    #[error("Invalid Tag during decryption!")]
    BadTagOnDecryption,
    #[error("Invalid Nonce length during encryption/decryption!")]
    BadNonce,
    #[error("Bad input buffer length (expected {expected:?} | given {given:?}!")]
    BadInputBufferLength { expected: usize, given: usize },
    #[error("Bad SS58 format")]
    BadSs58Format,
    #[error("Critical failure, cannot generate random data!")]
    CryptoFailure,
    #[error("Bad SS58 character length (max {max:?} | min {min:?} | given {given:?}!")]
    BadSs58Length { max: usize, min: usize, given: usize },
    #[error("Bad signature length (expected: {expected:?} | given: {given:?})!")]
    BadSignatureLength { expected: usize, given: usize },
    #[error("Bad signature format!")]
    BadSignatureFormat,
    #[error("Bad public key format or Edward Decompression error!")]
    BadPublicKeyFormat,
}

impl From<GoRoError> for i32 {
    fn from(value: GoRoError) -> Self {
        match value {
            GoRoError::EmptyInputBuffer => -100,
            GoRoError::BadKeyLength { .. } => -101,
            GoRoError::BadDestinationLength { .. } => -102,
            GoRoError::BadTagOnDecryption => -103,
            GoRoError::BadNonce => -104,
            GoRoError::BadInputBufferLength { .. } => -105,
            GoRoError::BadSs58Format => -106,
            GoRoError::CryptoFailure => -107,
            GoRoError::BadSs58Length { .. } => -108,
            GoRoError::BadSignatureLength { .. } => -109,
            GoRoError::BadSignatureFormat => -110,
            GoRoError::BadPublicKeyFormat => -111,
        }
    }
}

impl From<morus::Error> for GoRoError {
    fn from(_: morus::Error) -> Self {
        GoRoError::BadTagOnDecryption
    }
}
