use thiserror::Error;

use crate::get::ValidationError;

#[derive(Debug, Error)]
pub(super) enum Error {
    #[error("conntrack error: {0}")]
    Conntrack(conntrack::error::Error),
    #[error("display error: {0}")]
    Display(display::error::Error),
    #[error("failed to parse IP address or CIDR: {0}")]
    FailedToParseAddrOrCIDR(String),
    #[error("validation error: {0}")]
    Validation(ValidationError),
}
