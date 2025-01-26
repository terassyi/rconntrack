use async_trait::async_trait;
use clap::{Parser, Subcommand};
use conntrack::{socket::NfConntrackSocket, Conntrack};
use display::Display;

use crate::{
    config::{Family, Output, Protocol},
    count::CountCmd,
    error::Error,
    event::EventCmd,
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
    Event(EventCmd),
    Count(CountCmd),
}

impl Cmd {
    pub(super) async fn run(&self) -> Result<(), Error> {
        match &self.sub {
            SubCmd::Version(version) => version.run().await,
            SubCmd::List(list) => list.run().await,
            SubCmd::Get(get) => get.run().await,
            SubCmd::Event(event) => event.run().await,
            SubCmd::Count(count) => count.run().await,
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
    fn event(&self) -> bool;
    async fn process<D: Display + Send + Sync>(
        &self,
        mut ct: Conntrack<NfConntrackSocket>,
        mut display: D,
    ) -> Result<(), Error>;
}
