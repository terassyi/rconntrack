use std::{net::IpAddr, str::FromStr};

use async_trait::async_trait;
use clap::Parser;
use conntrack::{
    flow::TcpState,
    request::{Request, RequestMeta, RequestOperation},
};
use display::{json::JsonDisplay, table::TableDisplay, Display};
use futures::TryStreamExt;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::{
    cmd::Runner,
    config::{Family, Output, Protocol, Status, Table},
    error::Error,
    executor::{Executor, Operation},
};

#[derive(Debug, Parser)]
#[command(about = "List connection tracking entries")]
pub struct ListCmd {
    #[arg(
        short,
        long,
        default_value = "table",
        help = "Output format (\"table\", \"json\")"
    )]
    output: Output,
    #[arg(
        short,
        long,
        default_value = "conntrack",
        help = "Tables (\"conntrack\", \"dying\", \"unconfirmed\")"
    )]
    table: Table,
    #[arg(
        short,
        long,
        default_value = "ipv4",
        help = "L3 layer protocol (\"ipv4\", \"ipv6\", \"any\")"
    )]
    family: Family,
    #[arg(
        short,
        long,
        default_value = "any",
        help = "L4 layer protocol (\"any\", \"tcp\", \"udp\")"
    )]
    protocol: Protocol,
    #[arg(
        short,
        long,
        default_value = "false",
        help = "Zero counters while listing"
    )]
    zero: bool,
    #[arg(
        long,
        help = "Filter for source address from original direction. Accept IP address format or with prefix. e.g. \"192.168.0.1\" or \"192.168.0.0/24\""
    )]
    orig_src_addr: Option<String>,
    #[arg(
        long,
        help = "Filter for destination address from original direction. Accept IP address format or with prefix. e.g. \"192.168.0.1\" or \"192.168.0.0/24\""
    )]
    orig_dst_addr: Option<String>,
    #[arg(
        long,
        help = "Filter for source address from reply direction. Accept IP address format or with prefix. e.g. \"192.168.0.1\" or \"192.168.0.0/24\""
    )]
    reply_src_addr: Option<String>,
    #[arg(
        long,
        help = "Filter for destination address from reply direction. Accept IP address format or with prefix. e.g. \"192.168.0.1\" or \"192.168.0.0/24\""
    )]
    reply_dst_addr: Option<String>,
    #[arg(long, help = "Filter for source port from original direction.")]
    orig_src_port: Option<u16>,
    #[arg(long, help = "Filter for source port from original direction.")]
    orig_dst_port: Option<u16>,
    #[arg(long, help = "Filter for source port from reply direction.")]
    reply_src_port: Option<u16>,
    #[arg(long, help = "Filter for source port from reply direction.")]
    reply_dst_port: Option<u16>,
    #[arg(long, help = "Filter for mark")]
    mark: Option<u32>,
    #[arg(long, help = "Filter for use")]
    r#use: Option<u32>,
    #[arg(
        long,
        help = "Filter for tcp state. (\"none\", \"syn_sent\", \"syn_recv\", \"established\", \"fin_wait\", \"close_wait\", \"last_ack\", \"time_wait\", \"close\", \"listen\")"
    )]
    tcp_state: Option<TcpState>,
    #[arg(
        long,
        help = "Filter for status flags. (\"assured\", \"seen_reply\", \"fixed_timeout\", \"expected\" or u16 integer (When specifying the integer value, you should use with --detailed-status flag.))"
    )]
    status: Option<Status>,
    #[arg(
        long,
        help = "Show detailed status flags. Flags are shown binary format."
    )]
    detailed_status: bool,
    #[arg(long, help = "Don't print the header")]
    no_header: bool,
}

#[async_trait]
impl Runner for ListCmd {
    async fn run(&self) -> Result<(), Error> {
        let filter = Filter::new(
            self.table,
            self.family,
            self.zero,
            self.protocol,
            self.orig_src_addr.clone(),
            self.orig_dst_addr.clone(),
            self.reply_src_addr.clone(),
            self.reply_dst_addr.clone(),
            self.orig_src_port,
            self.orig_dst_port,
            self.reply_src_port,
            self.reply_dst_port,
            self.mark,
            self.r#use,
            self.tcp_state,
            self.status,
        );
        let op = ListOperation::new(filter);
        let executor = Executor::new(op);
        let mut ct = executor.exec().await?;

        match self.output {
            Output::Table => {
                let mut table_display = TableDisplay::new(
                    std::io::stdout(),
                    self.detailed_status,
                    self.family.into(),
                    self.protocol.into(),
                );
                if !self.no_header {
                    table_display.header().map_err(Error::Display)?;
                }
                while let Some(flows) = ct.try_next().await.map_err(Error::Conntrack)? {
                    for flow in flows.iter() {
                        table_display.consume(flow).map_err(Error::Display)?;
                    }
                }
            }
            Output::Json => {
                let mut json_display = JsonDisplay::new(std::io::stdout());
                while let Some(flows) = ct.try_next().await.map_err(Error::Conntrack)? {
                    for flow in flows.iter() {
                        json_display.consume(flow).map_err(Error::Display)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ListOperation {
    filter: Filter,
}

impl Operation for ListOperation {
    fn request(&self) -> Result<Request, Error> {
        let mut meta = RequestMeta::default()
            .table(self.filter.table.into())
            .family(self.filter.family.into());
        if self.filter.zero {
            meta = meta.zero()
        }
        Ok(Request::new(
            meta,
            RequestOperation::List(Some(conntrack::request::Filter::try_from(&self.filter)?)),
        ))
    }
}

impl ListOperation {
    fn new(filter: Filter) -> ListOperation {
        ListOperation { filter }
    }
}

#[derive(Debug, Default, Clone)]
struct Filter {
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
}

impl Filter {
    #[allow(clippy::too_many_arguments)]
    fn new(
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
        let mut filter = conntrack::request::Filter::default();
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
