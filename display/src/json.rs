use std::io;

use conntrack::flow::Flow;

use crate::{error::Error, Display};

pub struct JsonDisplay<W: io::Write> {
    writer: W,
}

impl<W> JsonDisplay<W>
where
    W: io::Write,
{
    pub fn new(writer: W) -> JsonDisplay<W> {
        JsonDisplay { writer }
    }
}

impl<W> Display for JsonDisplay<W>
where
    W: io::Write,
{
    fn consume(&mut self, flow: &Flow) -> Result<(), Error> {
        let str = serde_json::to_string(flow).map_err(Error::Json)?;
        self.writer.write(str.as_bytes()).map_err(Error::IO)?;
        Ok(())
    }

    fn header(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
