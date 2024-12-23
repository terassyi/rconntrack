use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("invalid value: {0}")]
    InvalidValue(String),
}
