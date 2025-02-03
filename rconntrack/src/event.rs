use async_trait::async_trait;
use clap::Parser;
use conntrack::{
    event::Event,
    flow::{Flow, TcpState},
    request::{Request, RequestMeta, RequestOperation},
    socket::NfConntrackSocket,
    Conntrack,
};
use display::{
    flow::{EventFlowRow, FlowColumn},
    json::JsonDisplay,
    table::TableDisplay,
    Display,
};
use futures::TryStreamExt;

use crate::{
    cmd::{DisplayRunner, Runner},
    config::{Family, Output, Protocol, Status, Table},
    error::Error,
    executor::{Executor, Operation, OperationType},
    filter::Filter,
};

#[derive(Debug, Parser)]
#[command(about = "Poll and show connection tracking events")]
pub struct EventCmd {
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
    #[arg(long, help = "Filter for destination port from original direction.")]
    orig_dst_port: Option<u16>,
    #[arg(long, help = "Filter for source port from reply direction.")]
    reply_src_port: Option<u16>,
    #[arg(long, help = "Filter for destination port from reply direction.")]
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
impl Runner for EventCmd {
    async fn run(&self) -> Result<(), Error> {
        let filter = Filter::new(
            self.table,
            self.family,
            false, // --zero flag is not allowed for Event command.
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
        let op = EventOperation::new(filter);
        let executor = Executor::new(op);
        let ct = executor.exec().await?;

        match self.output() {
            Output::Table => {
                let event_flow_row = EventFlowRow::new(
                    self.detailed_status,
                    self.family.into(),
                    self.protocol.into(),
                );
                let table_display = TableDisplay::new(tokio::io::stdout(), event_flow_row);
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
impl DisplayRunner for EventCmd {
    async fn process<D: Display + Send + Sync>(
        &self,
        mut ct: Conntrack<NfConntrackSocket>,
        mut display: D,
    ) -> Result<(), Error> {
        if self.output().ne(&Output::Json) && !self.no_header() {
            display.header().await.map_err(Error::Display)?;
        }
        loop {
            tokio::select! {
                e = tokio::signal::ctrl_c() => {
                    if let Err(e) = e {
                        eprintln!("failed to receive ctrl-c: {}", e);
                    }
                    break;
                },
                res = async {
                    while let Some(events) = ct.try_next().await.map_err(Error::Conntrack)? {
                        for event in events.iter() {
                            if let Event::Flow(flow) = event {
                                display.consume::<FlowColumn, Flow>(flow).await.map_err(Error::Display)?;
                            }
                        }
                    }
                    Ok::<(), Error>(())
                } => {
                    res?
                },
            }
        }
        Ok(())
    }

    fn output(&self) -> Output {
        self.output
    }

    fn no_header(&self) -> bool {
        self.no_header
    }
}

#[derive(Debug)]
struct EventOperation {
    filter: Filter,
}

impl EventOperation {
    fn new(filter: Filter) -> EventOperation {
        EventOperation { filter }
    }
}

impl Operation for EventOperation {
    fn request(&self) -> Result<conntrack::request::Request, Error> {
        let meta = RequestMeta::default()
            .table(self.filter.table.into())
            .family(self.filter.family.into());
        Ok(Request::new(
            meta,
            RequestOperation::Event(Some(conntrack::request::Filter::try_from(&self.filter)?)),
        ))
    }

    fn typ(&self) -> OperationType {
        OperationType::Event
    }
}
