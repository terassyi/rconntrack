use async_trait::async_trait;
use conntrack::{
    flow::{Flow, Protocol, Status},
    Family,
};
use tokio::io::AsyncWriteExt;

use crate::{error::Error, Display};

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

pub struct TableDisplay<W: AsyncWriteExt + Unpin + Send + Sync> {
    writer: W,
    detailed_status: bool,
    family: Family,
    protocol: Protocol, // default is Tcp, Tcp shows TCP_STATE(when showing Udp flows TCP_STATE is empty.).
    event: bool,
}

unsafe impl<W> Send for TableDisplay<W> where W: AsyncWriteExt + Unpin + Send + Sync {}
unsafe impl<W> Sync for TableDisplay<W> where W: AsyncWriteExt + Unpin + Send + Sync {}

impl<W> TableDisplay<W>
where
    W: AsyncWriteExt + Unpin + Send + Sync,
{
    const HEADER: [Column; 15] = [
        Column::Protocol(String::new()),
        Column::ProtocolNumber(0),
        Column::Timeout(0),
        Column::TcpState(None),
        Column::OrigSrcAddr(String::new()),
        Column::OrigDstAddr(String::new()),
        Column::OrigSrcPort(0),
        Column::OrigDstPort(0),
        Column::ReplySrcAddr(String::new()),
        Column::ReplyDstAddr(String::new()),
        Column::ReplySrcPort(0),
        Column::ReplyDstPort(0),
        Column::Flags(String::new()),
        Column::Mark(None),
        Column::Use(None),
    ];
    const EVENT_HEADER: [Column; 14] = [
        Column::Event(String::new()),
        Column::Protocol(String::new()),
        Column::ProtocolNumber(0),
        Column::Timeout(0),
        Column::TcpState(None),
        Column::OrigSrcAddr(String::new()),
        Column::OrigDstAddr(String::new()),
        Column::OrigSrcPort(0),
        Column::OrigDstPort(0),
        Column::ReplySrcAddr(String::new()),
        Column::ReplyDstAddr(String::new()),
        Column::ReplySrcPort(0),
        Column::ReplyDstPort(0),
        Column::Flags(String::new()),
    ];

    pub fn new(
        writer: W,
        detailed_status: bool,
        family: Family,
        protocol: Protocol,
        event: bool,
    ) -> TableDisplay<W> {
        TableDisplay {
            writer,
            detailed_status,
            family,
            protocol,
            event,
        }
    }

    fn row(&self, columns: &[Column], header: bool) -> String {
        let mut row_str = String::new();

        let format_addr = |s: &str| -> String {
            if self.family.eq(&Family::Ipv4) {
                format!("{:>15}", s)
            } else {
                format!("{:>39}", s)
            }
        };

        for (i, c) in columns.iter().enumerate() {
            match c {
                Column::Event(e) => {
                    if header {
                        row_str += &format!("{:>7}", c.header());
                    } else {
                        row_str += &format!("{:>7}", e);
                    }
                }
                Column::Protocol(p) => {
                    if header {
                        row_str += &format!("{:>8}", c.header());
                    } else {
                        row_str += &format!("{:>8}", p);
                    }
                }
                Column::ProtocolNumber(n) => {
                    if header {
                        row_str += &format!("{:>8}", c.header());
                    } else {
                        row_str += &format!("{:>8}", n);
                    }
                }
                Column::Timeout(t) => {
                    if header {
                        row_str += &format!("{:>10}", c.header());
                    } else {
                        row_str += &format!("{:>10}", t);
                    }
                }
                Column::TcpState(s) => {
                    if self.protocol.eq(&Protocol::Tcp) {
                        if header {
                            row_str += &format!("{:>11}", c.header());
                        } else {
                            match s {
                                Some(s) => {
                                    row_str += &format!("{:>11}", s);
                                }
                                None => {
                                    row_str += &format!("{:>11}", "");
                                }
                            }
                        }
                    }
                }
                Column::OrigSrcAddr(s) => {
                    if header {
                        row_str += &format_addr(&c.header());
                    } else {
                        row_str += &format_addr(s);
                    }
                }
                Column::OrigDstAddr(s) => {
                    if header {
                        row_str += &format_addr(&c.header());
                    } else {
                        row_str += &format_addr(s);
                    }
                }
                Column::OrigSrcPort(n) => {
                    if header {
                        row_str += &format!("{:>13}", c.header());
                    } else {
                        row_str += &format!("{:>13}", n);
                    }
                }
                Column::OrigDstPort(n) => {
                    if header {
                        row_str += &format!("{:>13}", c.header());
                    } else {
                        row_str += &format!("{:>13}", n);
                    }
                }
                Column::ReplySrcAddr(s) => {
                    if header {
                        row_str += &format_addr(&c.header());
                    } else {
                        row_str += &format_addr(s);
                    }
                }
                Column::ReplyDstAddr(s) => {
                    if header {
                        row_str += &format_addr(&c.header());
                    } else {
                        row_str += &format_addr(s);
                    }
                }
                Column::ReplySrcPort(n) => {
                    if header {
                        row_str += &format!("{:>14}", c.header());
                    } else {
                        row_str += &format!("{:>14}", n);
                    }
                }
                Column::ReplyDstPort(n) => {
                    if header {
                        row_str += &format!("{:>14}", c.header());
                    } else {
                        row_str += &format!("{:>14}", n);
                    }
                }
                Column::Flags(f) =>
                {
                    #[allow(clippy::collapsible_else_if)]
                    if self.detailed_status {
                        if header {
                            row_str += &format!("{:>15}", c.header());
                        } else {
                            row_str += &format!("{:>15}", f);
                        }
                    } else {
                        if header {
                            row_str += &format!("{:>13}", c.header());
                        } else {
                            row_str += &format!("{:>13}", f);
                        }
                    }
                }
                Column::Mark(m) => {
                    if header {
                        row_str += &format!("{:>5}", c.header());
                    } else {
                        match m {
                            Some(m) => {
                                row_str += &format!("{:>5}", m);
                            }
                            None => {
                                row_str += &format!("{:>5}", "");
                            }
                        }
                    }
                }
                Column::Use(u) => {
                    if header {
                        row_str += &format!("{:>5}", c.header());
                    } else {
                        match u {
                            Some(u) => {
                                row_str += &format!("{:>5}", u);
                            }
                            None => {
                                row_str += &format!("{:>5}", "");
                            }
                        }
                    }
                }
            }

            if i != columns.len() - 1 {
                row_str += " ";
            }
        }
        row_str += "\n";

        row_str
    }

    fn columns(&self, flow: &Flow) -> [Column; 15] {
        [
            Column::Protocol(String::from(flow.protocol).to_lowercase()),
            Column::ProtocolNumber(u8::from(flow.protocol)),
            Column::Timeout(flow.timeout),
            Column::TcpState(flow.tcp_state.map(|s| String::from(s).to_uppercase())),
            Column::OrigSrcAddr(flow.original.src_addr.to_string()),
            Column::OrigDstAddr(flow.original.dst_addr.to_string()),
            Column::OrigSrcPort(flow.original.src_port),
            Column::OrigDstPort(flow.original.dst_port),
            Column::ReplySrcAddr(flow.reply.src_addr.to_string()),
            Column::ReplyDstAddr(flow.reply.dst_addr.to_string()),
            Column::ReplySrcPort(flow.reply.src_port),
            Column::ReplyDstPort(flow.reply.dst_port),
            Column::Flags(self.ct_status_to_string(&flow.status)),
            Column::Mark(flow.mark),
            Column::Use(flow.r#use),
        ]
    }

    fn event_columns(&self, flow: &Flow) -> [Column; 14] {
        [
            Column::Event(String::from(flow.event_type).to_uppercase()),
            Column::Protocol(String::from(flow.protocol).to_lowercase()),
            Column::ProtocolNumber(u8::from(flow.protocol)),
            Column::Timeout(flow.timeout),
            Column::TcpState(flow.tcp_state.map(|s| String::from(s).to_uppercase())),
            Column::OrigSrcAddr(flow.original.src_addr.to_string()),
            Column::OrigDstAddr(flow.original.dst_addr.to_string()),
            Column::OrigSrcPort(flow.original.src_port),
            Column::OrigDstPort(flow.original.dst_port),
            Column::ReplySrcAddr(flow.reply.src_addr.to_string()),
            Column::ReplyDstAddr(flow.reply.dst_addr.to_string()),
            Column::ReplySrcPort(flow.reply.src_port),
            Column::ReplyDstPort(flow.reply.dst_port),
            Column::Flags(self.ct_status_to_string(&flow.status)),
        ]
    }

    fn ct_status_to_string(&self, status: &Status) -> String {
        if self.detailed_status {
            let n = u16::from(status);
            format!("{:0>15b}", n)
        } else {
            status.preferred_one()
        }
    }
}

#[async_trait]
impl<W> Display for TableDisplay<W>
where
    W: tokio::io::AsyncWriteExt + Unpin + Send + Sync,
{
    async fn consume(&mut self, flow: &Flow) -> Result<(), Error> {
        let row = if self.event {
            let c = self.event_columns(flow);
            self.row(&c, false)
        } else {
            let c = self.columns(flow);
            self.row(&c, false)
        };
        self.writer.write(row.as_bytes()).await.map_err(Error::IO)?;
        Ok(())
    }

    async fn header(&mut self) -> Result<(), Error> {
        let row = if self.event {
            self.row(&Self::EVENT_HEADER, true)
        } else {
            self.row(&Self::HEADER, true)
        };
        self.writer.write(row.as_bytes()).await.map_err(Error::IO)?;
        Ok(())
    }
}

#[derive(Debug)]
enum Column {
    Event(String),
    Protocol(String),
    ProtocolNumber(u8),
    Timeout(u32),
    TcpState(Option<String>),
    OrigSrcAddr(String),
    OrigDstAddr(String),
    OrigSrcPort(u16),
    OrigDstPort(u16),
    ReplySrcAddr(String),
    ReplyDstAddr(String),
    ReplySrcPort(u16),
    ReplyDstPort(u16),
    Flags(String),
    Mark(Option<u32>),
    Use(Option<u32>),
}

impl Column {
    fn header(&self) -> String {
        match self {
            Column::Event(_) => String::from("EVENT"),
            Column::Protocol(_) => String::from("PROTOCOL"),
            Column::ProtocolNumber(_) => String::from("PROTONUM"),
            Column::Timeout(_) => String::from("TIMEOUT"),
            Column::TcpState(_) => String::from("TCP_STATE"),
            Column::OrigSrcAddr(_) => String::from("ORIG_SRC_ADDR"),
            Column::OrigDstAddr(_) => String::from("ORIG_DST_ADDR"),
            Column::OrigSrcPort(_) => String::from("ORIG_SRC_PORT"),
            Column::OrigDstPort(_) => String::from("ORIG_DST_PORT"),
            Column::ReplySrcAddr(_) => String::from("REPLY_SRC_ADDR"),
            Column::ReplyDstAddr(_) => String::from("REPLY_DST_ADDR"),
            Column::ReplySrcPort(_) => String::from("REPLY_SRC_PORT"),
            Column::ReplyDstPort(_) => String::from("REPLY_DST_PORT"),
            Column::Flags(_) => String::from("FLAGS"),
            Column::Mark(_) => String::from("MARK"),
            Column::Use(_) => String::from("USE"),
        }
    }
}
