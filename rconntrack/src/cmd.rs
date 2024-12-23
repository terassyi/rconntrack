use async_trait::async_trait;
use clap::{Parser, Subcommand};

use crate::{error::Error, list::ListCmd, version::VersionCmd};

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
}

impl Cmd {
    pub(super) async fn run(&self) -> Result<(), Error> {
        match &self.sub {
            SubCmd::Version(version) => version.run().await,
            SubCmd::List(list) => list.run().await,
        }
    }
}
