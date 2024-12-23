use async_trait::async_trait;
use clap::Parser;

use crate::{cmd::Runner, error::Error};

build_info::build_info!(fn build_info);

#[derive(Debug, Parser)]
#[command(about = "Show version information")]
pub(super) struct VersionCmd {
    #[arg(
        short = 'd',
        long,
        required = false,
        help = "Show detailed version information"
    )]
    detail: bool,
}

#[async_trait]
impl Runner for VersionCmd {
    async fn run(&self) -> Result<(), Error> {
        if self.detail {
            println!("{:#?}", build_info());
        } else {
            println!(
                "{}",
                build_info::format!("{{{} v{} built with {} at {}}}", $.crate_info.name, $.crate_info.version, $.compiler, $.timestamp)
            );
        }
        Ok(())
    }
}
