use async_trait::async_trait;
use conntrack::flow::Flow;
use tokio::io::AsyncWriteExt;

use crate::{error::Error, Display};

pub struct JsonDisplay<W: AsyncWriteExt + Unpin + Send + Sync> {
    writer: W,
}

unsafe impl<W> Send for JsonDisplay<W> where W: AsyncWriteExt + Unpin + Send + Sync {}
unsafe impl<W> Sync for JsonDisplay<W> where W: AsyncWriteExt + Unpin + Send + Sync {}

impl<W> JsonDisplay<W>
where
    W: AsyncWriteExt + Unpin + Send + Sync,
{
    pub fn new(writer: W) -> JsonDisplay<W> {
        JsonDisplay { writer }
    }
}

#[async_trait]
impl<W> Display for JsonDisplay<W>
where
    W: AsyncWriteExt + Unpin + Send + Sync,
{
    async fn consume(&mut self, flow: &Flow) -> Result<(), Error> {
        let str = serde_json::to_string(flow).map_err(Error::Json)?;
        self.writer.write(str.as_bytes()).await.map_err(Error::IO)?;
        Ok(())
    }

    async fn header(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
