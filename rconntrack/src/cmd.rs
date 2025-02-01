use async_trait::async_trait;
use clap::{Parser, Subcommand};
use conntrack::{socket::NfConntrackSocket, Conntrack};
use display::Display;

use crate::{
    config::Output, count::CountCmd, error::Error, event::EventCmd, get::GetCmd, list::ListCmd,
    stats::StatsCmd, version::VersionCmd,
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
    Stats(StatsCmd),
}

impl Cmd {
    pub(super) async fn run(&self) -> Result<(), Error> {
        match &self.sub {
            SubCmd::Version(version) => version.run().await,
            SubCmd::List(list) => list.run().await,
            SubCmd::Get(get) => get.run().await,
            SubCmd::Event(event) => event.run().await,
            SubCmd::Count(count) => count.run().await,
            SubCmd::Stats(stat) => stat.run().await,
        }
    }
}

#[async_trait]
pub(super) trait DisplayRunner {
    fn output(&self) -> Output;
    fn no_header(&self) -> bool;
    async fn process<D: Display + Send + Sync>(
        &self,
        mut ct: Conntrack<NfConntrackSocket>,
        mut display: D,
    ) -> Result<(), Error>;
}
