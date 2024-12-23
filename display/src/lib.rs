use conntrack::flow::Flow;
use error::Error;

pub mod error;
pub mod json;
pub mod table;

pub trait Display {
    fn consume(&mut self, flow: &Flow) -> Result<(), Error>;
    fn header(&mut self) -> Result<(), Error>;
}
