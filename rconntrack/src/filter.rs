use std::{net::IpAddr, str::FromStr};

use conntrack::flow::TcpState;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::{
    config::{Family, Protocol, Status, Table},
    error::Error,
};

#[derive(Debug, Default, Clone)]
pub(super) struct Filter {
    pub(super) table: Table,
    pub(super) family: Family,
    pub(super) zero: bool,
    pub(super) protocol: Protocol,
    pub(super) orig_src_addr: Option<String>,
    pub(super) orig_dst_addr: Option<String>,
    pub(super) reply_src_addr: Option<String>,
    pub(super) reply_dst_addr: Option<String>,
    pub(super) orig_src_port: Option<u16>,
    pub(super) orig_dst_port: Option<u16>,
    pub(super) reply_src_port: Option<u16>,
    pub(super) reply_dst_port: Option<u16>,
    pub(super) mark: Option<u32>,
    pub(super) r#use: Option<u32>,
    pub(super) tcp_state: Option<TcpState>,
    pub(super) status: Option<Status>,
}

impl Filter {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        table: Table,
        family: Family,
        zero: bool,
        protocol: Protocol,
        orig_src_addr: Option<String>,
        orig_dst_addr: Option<String>,
        reply_src_addr: Option<String>,
        reply_dst_addr: Option<String>,
        orig_src_port: Option<u16>,
        orig_dst_port: Option<u16>,
        reply_src_port: Option<u16>,
        reply_dst_port: Option<u16>,
        mark: Option<u32>,
        r#use: Option<u32>,
        tcp_state: Option<TcpState>,
        status: Option<Status>,
    ) -> Filter {
        Filter {
            table,
            family,
            zero,
            protocol,
            orig_src_addr,
            orig_dst_addr,
            reply_src_addr,
            reply_dst_addr,
            orig_src_port,
            orig_dst_port,
            reply_src_port,
            reply_dst_port,
            mark,
            r#use,
            tcp_state,
            status,
        }
    }
}

impl TryFrom<&Filter> for conntrack::request::Filter {
    type Error = Error;

    fn try_from(f: &Filter) -> Result<Self, Self::Error> {
        let mut filter = conntrack::request::Filter::default().family(f.family.into());
        if f.protocol.ne(&Protocol::Any) {
            filter = filter.protocol(f.protocol.into());
        }
        if let Some(addr) = &f.orig_src_addr {
            let cidr = parse_addr_or_cidr(addr)?;
            filter = filter.orig_src_addr(cidr);
        }
        if let Some(addr) = &f.orig_dst_addr {
            let cidr = parse_addr_or_cidr(addr)?;
            filter = filter.orig_dst_addr(cidr);
        }
        if let Some(addr) = &f.reply_src_addr {
            let cidr = parse_addr_or_cidr(addr)?;
            filter = filter.reply_src_addr(cidr);
        }
        if let Some(addr) = &f.reply_dst_addr {
            let cidr = parse_addr_or_cidr(addr)?;
            filter = filter.reply_dst_addr(cidr);
        }
        if let Some(port) = f.orig_src_port {
            filter = filter.orig_src_port(port);
        }
        if let Some(port) = f.orig_dst_port {
            filter = filter.orig_dst_port(port);
        }
        if let Some(port) = f.reply_src_port {
            filter = filter.reply_src_port(port);
        }
        if let Some(port) = f.reply_dst_port {
            filter = filter.reply_dst_port(port);
        }
        if let Some(m) = f.mark {
            filter = filter.mark(m);
        }
        if let Some(u) = f.r#use {
            filter = filter.r#use(u);
        }
        if let Some(s) = f.tcp_state {
            filter = filter.tcp_state(s);
        }
        if let Some(status) = f.status {
            filter = filter.status(status.into())
        }

        Ok(filter)
    }
}

fn parse_addr_or_cidr(s: &str) -> Result<IpNet, Error> {
    match IpNet::from_str(s) {
        Ok(cidr) => Ok(cidr),
        Err(_e) => {
            let addr = match IpAddr::from_str(s) {
                Ok(addr) => addr,
                Err(_e) => return Err(Error::FailedToParseAddrOrCIDR(s.to_string())),
            };
            match addr {
                IpAddr::V4(addr) => {
                    Ok(IpNet::V4(Ipv4Net::new(addr, 32).map_err(|_| {
                        Error::FailedToParseAddrOrCIDR(s.to_string())
                    })?))
                }
                IpAddr::V6(addr) => {
                    Ok(IpNet::V6(Ipv6Net::new(addr, 128).map_err(|_| {
                        Error::FailedToParseAddrOrCIDR(s.to_string())
                    })?))
                }
            }
        }
    }
}
