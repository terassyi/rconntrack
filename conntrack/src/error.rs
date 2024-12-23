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
    NetlinkMessage(i32), // TODO: implement detailed netlink error message kind.
    #[error("flow error: {0}")]
    Flow(FlowError),
    #[error("dummy")]
    Dummy,
}
