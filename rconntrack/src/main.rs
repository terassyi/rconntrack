use std::process::exit;

use clap::Parser;
use cmd::Cmd;

mod cmd;
mod config;
mod count;
mod error;
mod event;
mod executor;
mod filter;
mod get;
mod list;
mod stats;
mod version;

#[tokio::main]
async fn main() {
    let cmd = Cmd::parse();

    if let Err(e) = cmd.run().await {
        eprintln!("{e}");
        exit(-1);
    }
}
