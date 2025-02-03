use async_trait::async_trait;
use clap::Parser;
use conntrack::{
    event::Event,
    request::{Request, RequestMeta, RequestOperation},
    socket::NfConntrackSocket,
    Conntrack,
};
use display::{json::JsonDisplay, stats::StatsRow, table::TableDisplay, Display};
use futures::TryStreamExt;

use crate::{
    cmd::{DisplayRunner, Runner},
    config::{Family, Output},
    error::Error,
    executor::{Executor, Operation, OperationType},
};

#[derive(Debug, Parser)]
#[command(about = "Show statistics")]
pub struct StatsCmd {
    #[arg(
        short,
        long,
        default_value = "table",
        help = "Output format (\"table\", \"json\")"
    )]
    output: Output,
    #[arg(long, help = "Don't print the header")]
    no_header: bool,
}

#[async_trait]
impl Runner for StatsCmd {
    async fn run(&self) -> Result<(), Error> {
        let op = StatsOperation::new();
        let executor = Executor::new(op);
        let ct = executor.exec().await?;

        match self.output() {
            Output::Table => {
                let stats_row = StatsRow::new();
                let table_display = TableDisplay::new(tokio::io::stdout(), stats_row);
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
impl DisplayRunner for StatsCmd {
    fn output(&self) -> Output {
        self.output
    }

    fn no_header(&self) -> bool {
        self.no_header
    }

    async fn process<D: Display + Send + Sync>(
        &self,
        mut ct: Conntrack<NfConntrackSocket>,
        mut display: D,
    ) -> Result<(), Error> {
        if self.output().ne(&Output::Json) && !self.no_header() {
            display.header().await.map_err(Error::Display)?;
        }
        while let Some(events) = ct.try_next().await.map_err(Error::Conntrack)? {
            for event in events.iter() {
                if let Event::Stats(stats) = event {
                    display.consume(stats).await.map_err(Error::Display)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct StatsOperation {}

impl Operation for StatsOperation {
    fn request(&self) -> Result<Request, Error> {
        let meta = RequestMeta::default().family(Family::Any.into());

        Ok(Request::new(meta, RequestOperation::Stat))
    }

    fn typ(&self) -> OperationType {
        OperationType::Stats
    }
}

impl StatsOperation {
    fn new() -> StatsOperation {
        StatsOperation {}
    }
}
