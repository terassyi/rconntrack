use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum Error {
    #[error("conntrack error: {0}")]
    Conntrack(conntrack::error::Error),
    #[error("display error: {0}")]
    Display(display::error::Error),
    #[error("failed to parse IP address or CIDR: {0}")]
    FailedToParseAddrOrCIDR(String),
}
