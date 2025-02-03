use async_trait::async_trait;
use conntrack::Family;
use error::Error;
use serde::Serialize;

pub mod error;
pub mod flow;
pub mod json;
pub mod stats;
pub mod table;

#[async_trait]
pub trait Display {
    async fn consume<C: Column, E: Serialize + ToColumns<C> + Send + Sync>(
        &mut self,
        entry: &E,
    ) -> Result<(), Error>;
    async fn header(&mut self) -> Result<(), Error>;
}

pub trait Row {
    fn row<C: Column, E: Serialize + ToColumns<C> + Send + Sync>(&self, entry: &E) -> String;
    fn header(&self) -> String;
}

pub trait Column {
    fn header(&self) -> String;
    fn column(&self, header: bool) -> String;
}

pub trait ToColumns<C: Column> {
    fn to_columns(&self, opt: ToColumnOptions) -> Vec<C>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ToColumnOptions {
    pub event: bool,
    pub detailed_status: bool,
    pub omit_tcp_state: bool,
    pub family: Family,
}
