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
}

impl From<GoRoError> for i32 {
    fn from(value: GoRoError) -> Self {
        match value {
            GoRoError::EmptyInputBuffer => -100,
            GoRoError::BadKeyLength { .. } => -101,
            GoRoError::BadDestinationLength { .. } => -102,
            GoRoError::BadTagOnDecryption => -103,
            GoRoError::BadNonce => -104,
        }
    }
}

impl From<morus::Error> for GoRoError {
    fn from(_: morus::Error) -> Self {
        GoRoError::BadTagOnDecryption
    }
}
