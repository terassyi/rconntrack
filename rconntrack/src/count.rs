use async_trait::async_trait;
use clap::Parser;
use conntrack::{
    event::Event,
    request::{Request, RequestMeta, RequestOperation},
};

use crate::{
    cmd::Runner,
    config::{Family, Table},
    error::Error,
    executor::{Executor, Operation, OperationType},
};

#[derive(Debug, Parser)]
#[command(about = "Show active tracked entries")]
pub struct CountCmd {
    #[arg(
        short,
        long,
        default_value = "conntrack",
        help = "Tables (\"conntrack\")"
    )]
    table: Table,
}

#[async_trait]
impl Runner for CountCmd {
    async fn run(&self) -> Result<(), Error> {
        let op = CountOperation::new(self.table);
        let executor = Executor::new(op);
        let mut ct = executor.exec().await?;

        for event in ct.recv_once().await.map_err(Error::Conntrack)?.iter() {
            if let Event::Count(c) = event {
                println!("{c}")
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct CountOperation {
    table: Table,
}

impl Operation for CountOperation {
    fn request(&self) -> Result<Request, Error> {
        let meta = RequestMeta::default()
            .family(Family::Any.into())
            .table(self.table.into());
        Ok(Request::new(meta, RequestOperation::Count))
    }

    fn typ(&self) -> OperationType {
        OperationType::Counter
    }
}

impl CountOperation {
    fn new(table: Table) -> CountOperation {
        CountOperation { table }
    }
}
