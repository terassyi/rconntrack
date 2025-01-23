use std::{net::IpAddr, str::FromStr};

use error::Error;

pub(crate) mod error;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Output {
    #[default]
    Table,
    Json,
}

impl FromStr for Output {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Output::Json),
            "table" => Ok(Output::Table),
            _ => Err(Error::InvalidValue(s.to_string())),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) enum Table {
    #[default]
    Conntrack,
    // Expect, // not implemented
    Dying,
    Unconfirmed,
}

impl FromStr for Table {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "conntrack" => Ok(Table::Conntrack),
            "dying" => Ok(Table::Dying),
            "unconfirmed" => Ok(Table::Unconfirmed),
            _ => Err(Error::InvalidValue(s.to_string())),
        }
    }
}

impl From<Table> for conntrack::Table {
    fn from(t: Table) -> Self {
        match t {
            Table::Conntrack => conntrack::Table::Conntrack,
            Table::Dying => conntrack::Table::Dying,
            Table::Unconfirmed => conntrack::Table::Unconfirmed,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) enum Family {
    #[default]
    Ipv4,
    Ipv6,
    Any,
}

impl FromStr for Family {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ipv4" => Ok(Family::Ipv4),
            "ipv6" => Ok(Family::Ipv6),
            "any" => Ok(Family::Any),
            _ => Err(Error::InvalidValue(s.to_string())),
        }
    }
}

impl From<Family> for conntrack::Family {
    fn from(f: Family) -> Self {
        match f {
            Family::Ipv4 => conntrack::Family::Ipv4,
            Family::Ipv6 => conntrack::Family::Ipv6,
            Family::Any => conntrack::Family::Unspec,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Protocol::Any),
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            _ => Err(Error::InvalidValue(s.to_string())),
        }
    }
}

impl From<Protocol> for conntrack::flow::Protocol {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Any | Protocol::Tcp => conntrack::flow::Protocol::Tcp,
            Protocol::Udp => conntrack::flow::Protocol::Udp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Assured,
    SeenReply,
    FixedTimeout,
    Expected,
    Detailed(u16),
}

impl FromStr for Status {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "assured" => Ok(Status::Assured),
            "seen_reply" => Ok(Status::SeenReply),
            "fixed_timeout" => Ok(Status::FixedTimeout),
            "expected" => Ok(Status::Expected),
            _ => s
                .parse::<u16>()
                .map(Status::Detailed)
                .map_err(|_| Error::InvalidValue(s.to_string())),
        }
    }
}

impl From<Status> for conntrack::flow::Status {
    fn from(s: Status) -> Self {
        match s {
            Status::Assured => conntrack::flow::Status::assured(),
            Status::SeenReply => conntrack::flow::Status::seen_reply(),
            Status::FixedTimeout => conntrack::flow::Status::fixed_timeout(),
            Status::Expected => conntrack::flow::Status::expected(),
            Status::Detailed(v) => conntrack::flow::Status::from(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tuple {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl From<&Tuple> for conntrack::flow::Tuple {
    fn from(t: &Tuple) -> Self {
        conntrack::flow::Tuple {
            src_addr: t.src_addr,
            dst_addr: t.dst_addr,
            src_port: t.src_port,
            dst_port: t.dst_port,
        }
    }
}
