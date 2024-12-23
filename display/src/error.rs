use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("json error: {0}")]
    Json(serde_json::Error),
    #[error("I/O error: {0}")]
    IO(std::io::Error),
}
