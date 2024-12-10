use clap::Parser;

build_info::build_info!(fn build_info);

#[derive(Debug, Parser)]
pub(super) struct VersionCmd {
    #[arg(
        short = 'd',
        long,
        required = false,
        help = "Show detailed version information"
    )]
    detail: bool,
}

impl VersionCmd {
    pub(super) fn run(&self) {
        if self.detail {
            println!("{:#?}", build_info());
        } else {
            println!(
                "{}",
                build_info::format!("{{{} v{} built with {} at {}}}", $.crate_info.name, $.crate_info.version, $.compiler, $.timestamp)
            );
        }
    }
}
