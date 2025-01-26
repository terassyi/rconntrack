use std::net::IpAddr;

use async_trait::async_trait;
use clap::Parser;
use conntrack::{
    event::Event,
    flow::Tuple,
    request::{Direction, GetParams, Request, RequestMeta, RequestOperation},
    socket::NfConntrackSocket,
    Conntrack,
};
use display::{json::JsonDisplay, table::TableDisplay, Display};
use thiserror::Error;

use crate::{
    cmd::{DisplayRunner, Runner},
    config::{Family, Output, Protocol, Table},
    error::Error,
    executor::{Executor, Operation, OperationType},
};

const PARAMS_FOR_BOTH_MSG: &str = r"When acceptable parameters for the either direction is given, parameters for the another directions are ignored.
When both of directions are acceptable, the original direction is preferred.";

#[derive(Debug, Parser)]
#[command(about = "Get a connection tracking entry")]
pub struct GetCmd {
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
    #[arg(long, help = "Source address from original direction")]
    orig_src_addr: Option<IpAddr>,
    #[arg(long, help = "Destination address from original direction")]
    orig_dst_addr: Option<IpAddr>,
    #[arg(long, help = "Source address from reply direction")]
    reply_src_addr: Option<IpAddr>,
    #[arg(long, help = "Destination address from reply direction")]
    reply_dst_addr: Option<IpAddr>,
    #[arg(long, help = "Source port from original direction.")]
    orig_src_port: Option<u16>,
    #[arg(long, help = "Destination port from original direction.")]
    orig_dst_port: Option<u16>,
    #[arg(long, help = "Source port from reply direction.")]
    reply_src_port: Option<u16>,
    #[arg(long, help = "Destination port from reply direction.")]
    reply_dst_port: Option<u16>,
    #[arg(
        long,
        help = "Show detailed status flags. Flags are shown binary format."
    )]
    detailed_status: bool,
    #[arg(long, help = "Don't print the header")]
    no_header: bool,
}

impl GetCmd {
    fn validate(&self) -> Result<(bool, bool), Error> {
        // 1. When any of orig-xxx flags are specified, all of orig-xxx flags must be specified.
        // 2. When any of reply-xxx flags are specified, all of reply-xxx flags must be specified.
        // 3. When all of orig-xxx flags are set and any of reply-xxx are set, reply-xxx is ignored, and vice versa.
        // 4. When all of orig-xxx and reply-xxx flags are set, orig-xxx is preferred.
        let orig_and = self.orig_src_addr.is_some()
            && self.orig_dst_addr.is_some()
            && self.orig_src_port.is_some()
            && self.orig_dst_port.is_some();
        let reply_and = self.reply_src_addr.is_some()
            && self.reply_dst_addr.is_some()
            && self.reply_src_port.is_some()
            && self.reply_dst_port.is_some();
        let orig_or = self.orig_src_addr.is_some()
            || self.orig_dst_addr.is_some()
            || self.orig_src_port.is_some()
            || self.orig_dst_port.is_some();
        let reply_or = self.reply_src_addr.is_some()
            || self.reply_dst_addr.is_some()
            || self.reply_src_port.is_some()
            || self.reply_dst_port.is_some();
        let orig_accepted = orig_and && orig_or;
        let reply_accepted = reply_and && reply_or;
        if (!orig_accepted && !reply_accepted) && (!orig_or && !reply_or) {
            return Err(Error::Validation(ValidationError::Missing));
        }
        if orig_or && reply_or {
            eprintln!(
                "You set some parameters for both directions.\n{}\n\n",
                PARAMS_FOR_BOTH_MSG
            );
            if !orig_accepted && !reply_accepted {
                return Err(Error::Validation(ValidationError::Missing));
            }
        }
        if !orig_accepted && orig_or {
            return Err(Error::Validation(ValidationError::Orig));
        }
        if !reply_accepted && reply_or {
            return Err(Error::Validation(ValidationError::Reply));
        }
        Ok((orig_accepted, reply_accepted))
    }

    fn get_tuples(&self) -> Result<Direction, Error> {
        let (orig_accepted, reply_accepted) = self.validate()?;
        // After a validation, all needed field are confirmed not to be None.
        // So, unwrappable.
        if orig_accepted {
            Ok(Direction::Orig(Tuple {
                src_addr: self.orig_src_addr.unwrap(),
                dst_addr: self.orig_dst_addr.unwrap(),
                src_port: self.orig_src_port.unwrap(),
                dst_port: self.orig_dst_port.unwrap(),
            }))
        } else if reply_accepted {
            Ok(Direction::Reply(Tuple {
                src_addr: self.reply_src_addr.unwrap(),
                dst_addr: self.reply_dst_addr.unwrap(),
                src_port: self.reply_src_port.unwrap(),
                dst_port: self.reply_dst_port.unwrap(),
            }))
        } else {
            Err(Error::Validation(ValidationError::Missing))
        }
    }
}

#[async_trait]
impl Runner for GetCmd {
    async fn run(&self) -> Result<(), Error> {
        let directed_tuple = self.get_tuples()?;
        let op = GetOperation::new(self.table, self.family, self.protocol, directed_tuple);

        let executor = Executor::new(op);
        let ct = executor.exec().await?;
        match self.output {
            Output::Table => {
                let table_display = TableDisplay::new(
                    tokio::io::stdout(),
                    self.detailed_status,
                    self.family.into(),
                    self.protocol.into(),
                    false,
                );

                self.process(ct, table_display).await
            }
            Output::Json => {
                let json_display = JsonDisplay::new(tokio::io::stdout());
                self.process(ct, json_display).await
            }
        }
    }
}

#[async_trait]
impl DisplayRunner for GetCmd {
    async fn process<D: Display + Send + Sync>(
        &self,
        mut ct: Conntrack<NfConntrackSocket>,
        mut display: D,
    ) -> Result<(), Error> {
        if self.output.ne(&Output::Json) && !self.no_header() {
            display.header().await.map_err(Error::Display)?;
        }
        for event in ct.recv_once().await.map_err(Error::Conntrack)?.iter() {
            if let Event::Flow(flow) = event {
                display.consume(flow).await.map_err(Error::Display)?;
            }
        }
        Ok(())
    }

    fn output(&self) -> Output {
        self.output
    }

    fn detailed_status(&self) -> bool {
        self.detailed_status
    }

    fn family(&self) -> Family {
        self.family
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn no_header(&self) -> bool {
        self.no_header
    }

    fn event(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct GetOperation {
    table: Table,
    family: Family,
    protocol: Protocol,
    tuple: Direction,
}

impl GetOperation {
    fn new(
        table: Table,
        family: Family,
        protocol: Protocol,
        directed_tuple: Direction,
    ) -> GetOperation {
        GetOperation {
            table,
            family,
            protocol,
            tuple: directed_tuple,
        }
    }
}

impl Operation for GetOperation {
    fn request(&self) -> Result<Request, Error> {
        let meta = RequestMeta::default()
            .table(self.table.into())
            .family(self.family.into());

        Ok(Request::new(
            meta,
            RequestOperation::Get(GetParams::new(self.protocol.into(), self.tuple.clone())),
        ))
    }

    fn typ(&self) -> OperationType {
        OperationType::Get
    }
}

#[derive(Debug, Error)]
pub(crate) enum ValidationError {
    #[error(
        r"incompleted parameters.
You must set one of following parameter groups.
  --orig-src-addr
  --orig-dst-addr
  --orig-src-port
  --orig-dst-port
or
  --reply-src-addr
  --reply-dst-addr
  --reply-src-port
  --reply-dst-port"
    )]
    Missing,
    #[error(
        r"incompleted parameters for the original direction.
You must set all of following parameters.
  --orig-src-addr
  --orig-dst-addr
  --orig-src-port
  --orig-dst-port"
    )]
    Orig,
    #[error(
        r"incompleted parameters for the reply direction.
You must set all of following parameters.
  --reply-src-addr
  --reply-dst-addr
  --reply-src-port
  --reply-dst-port"
    )]
    Reply,
}
