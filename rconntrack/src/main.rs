use clap::Parser;
use cmd::Cmd;

mod cmd;
mod list;
mod version;

fn main() {
    let cmd = Cmd::parse();

    cmd.run();
}
