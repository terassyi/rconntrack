use std::io;

use netlink_packet_utils::DecodeError;
use thiserror::Error;

use crate::flow::FlowError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to create socket: {0}")]
    Socket(io::Error),
    #[error("invalid family: {0}")]
    InvalidFamily(String),
    #[error("invalid l4 protocol: {0}")]
    InvalidL4Protocol(String),
    #[error("invalid table: {0}")]
    InvalidTable(String),
    #[error("invalid tcp state: {0}")]
    InvalidTcpState(String),
    #[error("invalid ct state: {0}")]
    InvalidCtState(String),
    #[error("failed to send ctnetlink message: {0}")]
    Send(io::Error),
    #[error("failed to receive ctnetlink messages: {0}")]
    Recv(io::Error),
    #[error("failed to poll ctnetlink messages: {0}")]
    Poll(io::Error),
    #[error("netlink error: {0}")]
    Netfilter(DecodeError),
    #[error("netlink error message: {0}")]
    NetlinkMessage(NetlinkError),
    #[error("flow error: {0}")]
    Flow(FlowError),
    #[error("message error: {0}")]
    Message(String),
    #[error("dummy")]
    Dummy,
}

#[derive(Debug, Error)]
pub enum NetlinkError {
    #[error("operation not permitted")]
    OperationNotPermitted,
    #[error("no entry")]
    NoEntry,
    #[error("I/O")]
    IO,
    #[error("already exists")]
    AlreadyExists,
    #[error("invalid argument")]
    InvalidArgument,
    #[error("other: {0}")]
    Other(i32),
}

impl From<i32> for NetlinkError {
    fn from(e: i32) -> Self {
        match e {
            -1 => Self::OperationNotPermitted,
            -2 => Self::NoEntry,
            -5 => Self::IO,
            -17 => Self::AlreadyExists,
            -22 => Self::InvalidArgument,
            _ => Self::Other(e),
        }
    }
}
