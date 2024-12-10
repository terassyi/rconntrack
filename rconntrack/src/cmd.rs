use clap::{Parser, Subcommand};

use crate::{list::ListCmd, version::VersionCmd};

#[derive(Debug, Parser)]
pub(super) struct Cmd {
    #[clap(subcommand)]
    sub: SubCmd,
}

#[derive(Debug, Subcommand)]
pub(super) enum SubCmd {
    Version(VersionCmd),
    List(ListCmd),
}

impl Cmd {
    pub(super) fn run(&self) {
        match &self.sub {
            SubCmd::Version(version) => {
                version.run();
            }
            SubCmd::List(list) => {
                list.run();
            }
        }
    }
}
