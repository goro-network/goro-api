use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum GoRoError {
    #[error("Invalid key length (expected: {expected:?} | given: {given:?})")]
    BadKeyLength { expected: usize, given: usize },
    #[error("Invalid destination length (expected: {expected:?} | given: {given:?})")]
    BadDestinationLength { expected: usize, given: usize },
}

impl From<GoRoError> for i32 {
    fn from(value: GoRoError) -> Self {
        match value {
            GoRoError::BadKeyLength { .. } => -101,
            GoRoError::BadDestinationLength { .. } => -102,
        }
    }
}
