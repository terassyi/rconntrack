use async_trait::async_trait;
use clap::{Parser, Subcommand};
use conntrack::{socket::NfConntrackSocket, Conntrack};
use display::{json::JsonDisplay, table::TableDisplay, Display};
use futures::TryStreamExt;
use tokio::io::AsyncWriteExt;

use crate::{
    config::{Family, Output, Protocol},
    error::Error,
    get::GetCmd,
    list::ListCmd,
    version::VersionCmd,
};

#[derive(Debug, Parser)]
#[command(about = "Rconntrack is command line interface for the connection tracking in Linux.")]
pub(super) struct Cmd {
    #[clap(subcommand)]
    sub: SubCmd,
}

// All subcommands(except version command) must satisfy Runner traits.
#[async_trait]
pub(super) trait Runner {
    async fn run(&self) -> Result<(), Error>;
}

#[derive(Debug, Subcommand)]
pub(super) enum SubCmd {
    Version(VersionCmd),
    List(ListCmd),
    Get(GetCmd),
}

impl Cmd {
    pub(super) async fn run(&self) -> Result<(), Error> {
        match &self.sub {
            SubCmd::Version(version) => version.run().await,
            SubCmd::List(list) => list.run().await,
            SubCmd::Get(get) => get.run().await,
        }
    }
}

#[async_trait]
pub(super) trait DisplayRunner {
    fn output(&self) -> Output;
    fn detailed_status(&self) -> bool;
    fn family(&self) -> Family;
    fn protocol(&self) -> Protocol;
    fn no_header(&self) -> bool;
    async fn display<W: AsyncWriteExt + Unpin + Send + Sync>(
        &self,
        mut ct: Conntrack<NfConntrackSocket>,
        writer: W,
    ) -> Result<(), Error> {
        match self.output() {
            Output::Table => {
                let mut table_display = TableDisplay::new(
                    writer,
                    self.detailed_status(),
                    self.family().into(),
                    self.protocol().into(),
                );
                if !self.no_header() {
                    table_display.header().await.map_err(Error::Display)?;
                }
                while let Some(flows) = ct.try_next().await.map_err(Error::Conntrack)? {
                    for flow in flows.iter() {
                        table_display.consume(flow).await.map_err(Error::Display)?;
                    }
                }
            }
            Output::Json => {
                let mut json_display = JsonDisplay::new(writer);
                while let Some(flows) = ct.try_next().await.map_err(Error::Conntrack)? {
                    for flow in flows.iter() {
                        json_display.consume(flow).await.map_err(Error::Display)?;
                    }
                }
            }
        }
        Ok(())
    }
}
