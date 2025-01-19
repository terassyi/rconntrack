use async_trait::async_trait;
use conntrack::flow::Flow;
use error::Error;

pub mod error;
pub mod json;
pub mod table;

#[async_trait]
pub trait Display {
    async fn consume(&mut self, flow: &Flow) -> Result<(), Error>;
    async fn header(&mut self) -> Result<(), Error>;
}
