use async_trait::async_trait;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use crate::{error::Error, Column, Display, Row, ToColumns};

/*
* ipv6 or unspec and detailed flags
PROTOCOL PROTONUM    TIMEOUT   TCP_STATE                           ORIG_SRC_ADDR                           ORIG_DST_ADDR ORIG_SRC_PORT ORIG_DST_PORT                          REPLY_SRC_ADDR                          REPLY_DST_ADDR REPLY_SRC_PORT REPLY_DST_PORT           FLAGS  MARK   USE
     tcp        6 4294967295 ESTABLISHED xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx         65535         65535 xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx          65535          65535 111111111111111 65535 65535

* ipv6 or unspec
PROTOCOL PROTONUM    TIMEOUT   TCP_STATE                           ORIG_SRC_ADDR                           ORIG_DST_ADDR ORIG_SRC_PORT ORIG_DST_PORT                          REPLY_SRC_ADDR                          REPLY_DST_ADDR REPLY_SRC_PORT REPLY_DST_PORT         FLAGS  MARK   USE
     tcp        6 4294967295 ESTABLISHED xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx         65535         65535 xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx          65535          65535 FIXED_TIMEOUT 65535 65535

* ipv4 and detailed flags
PROTOCOL PROTONUM    TIMEOUT   TCP_STATE   ORIG_SRC_ADDR   ORIG_DST_ADDR ORIG_SRC_PORT ORIG_DST_PORT  REPLY_SRC_ADDR  REPLY_DST_ADDR REPLY_SRC_PORT REPLY_DST_PORT           FLAGS  MARK   USE
     tcp        6 4294967295 ESTABLISHED xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx         65535         65535 xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx          65535          65535 111111111111111 65535 65535

* ipv4
PROTOCOL PROTONUM    TIMEOUT   TCP_STATE   ORIG_SRC_ADDR   ORIG_DST_ADDR ORIG_SRC_PORT ORIG_DST_PORT  REPLY_SRC_ADDR  REPLY_DST_ADDR REPLY_SRC_PORT REPLY_DST_PORT          FLAGS  MARK   USE
     tcp        6 4294967295 ESTABLISHED xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx         65535         65535 xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx          65535          65535  FIXED_TIMEOUT 65535 65535
 */

pub struct TableDisplay<W: AsyncWriteExt + Unpin + Send + Sync, R: Row> {
    writer: W,
    row: R,
}

unsafe impl<W, R> Send for TableDisplay<W, R>
where
    W: AsyncWriteExt + Unpin + Send + Sync,
    R: Row,
{
}
unsafe impl<W, R> Sync for TableDisplay<W, R>
where
    W: AsyncWriteExt + Unpin + Send + Sync,
    R: Row,
{
}

impl<W, R> TableDisplay<W, R>
where
    W: AsyncWriteExt + Unpin + Send + Sync,
    R: Row,
{
    pub fn new(writer: W, row: R) -> TableDisplay<W, R> {
        TableDisplay { writer, row }
    }
}

#[async_trait]
impl<W, R> Display for TableDisplay<W, R>
where
    W: tokio::io::AsyncWriteExt + Unpin + Send + Sync,
    R: Row,
{
    async fn consume<C: Column, E: Serialize + ToColumns<C> + Send + Sync>(
        &mut self,
        entry: &E,
    ) -> Result<(), Error> {
        let r = self.row.row(entry);
        self.writer.write(r.as_bytes()).await.map_err(Error::IO)?;
        Ok(())
    }

    async fn header(&mut self) -> Result<(), Error> {
        self.writer
            .write(self.row.header().as_bytes())
            .await
            .map_err(Error::IO)?;
        Ok(())
    }
}
