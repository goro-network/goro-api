use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum GoRoError {
    #[error("Input buffer is empty")]
    EmptyInputBuffer,
    #[error("Invalid key length (expected: {expected:?} | given: {given:?})")]
    BadKeyLength { expected: usize, given: usize },
    #[error("Invalid destination length (expected: {expected:?} | given: {given:?})")]
    BadDestinationLength { expected: usize, given: usize },
    #[error("Invalid Tag during decryption")]
    BadTagOnDecryption,
    #[error("Invalid Nonce length during encryption/decryption")]
    BadNonce,
    #[error("Bad input buffer length (expected {expected:?}, got {got:?}!")]
    BadInputBufferLength { expected: usize, got: usize },
    #[error("Bad SS58 format")]
    BadSs58Format,
    #[error("Critical failure, cannot generate random data!")]
    CryptoFailure,
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
        }
    }
}

impl From<morus::Error> for GoRoError {
    fn from(_: morus::Error) -> Self {
        GoRoError::BadTagOnDecryption
    }
}
