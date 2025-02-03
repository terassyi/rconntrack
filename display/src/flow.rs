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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use conntrack::{
    flow::{Flow, Protocol, Status},
    Family,
};
use serde::Serialize;

use crate::{Column, Row, ToColumnOptions, ToColumns};

pub struct FlowRow {
    detailed_status: bool,
    family: Family,
    protocol: Protocol, // default is Tcp, Tcp shows TCP_STATE(when showing Udp flows, TCP_STATE is empty.).
}

impl FlowRow {
    pub fn new(detailed_status: bool, family: Family, protocol: Protocol) -> FlowRow {
        FlowRow {
            detailed_status,
            family,
            protocol,
        }
    }
}

impl Row for FlowRow {
    fn row<C: Column, E: Serialize + ToColumns<C> + Send + Sync>(&self, entry: &E) -> String {
        let mut row_str = String::new();

        let columns = entry.to_columns(ToColumnOptions {
            event: false,
            detailed_status: self.detailed_status,
            omit_tcp_state: self.protocol.eq(&Protocol::Udp),
            family: self.family,
        });

        for (i, c) in columns.iter().enumerate() {
            row_str += &c.column(false);
            if i != columns.len() - 1 {
                row_str += " ";
            }
        }
        row_str += "\n";

        row_str
    }

    fn header(&self) -> String {
        let dummy_addr = match self.family {
            Family::Ipv4 => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            Family::Ipv6 | Family::Unspec => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        };
        let dummy_flag = if self.detailed_status {
            (String::new(), true)
        } else {
            (String::new(), false)
        };
        let header_columns: Vec<FlowColumn> = if self.protocol.eq(&Protocol::Tcp) {
            vec![
                FlowColumn::Protocol(String::new()),
                FlowColumn::ProtocolNumber(0),
                FlowColumn::Timeout(0),
                FlowColumn::TcpState(None),
                FlowColumn::OrigSrcAddr((dummy_addr, self.family)),
                FlowColumn::OrigDstAddr((dummy_addr, self.family)),
                FlowColumn::OrigSrcPort(0),
                FlowColumn::OrigDstPort(0),
                FlowColumn::ReplySrcAddr((dummy_addr, self.family)),
                FlowColumn::ReplyDstAddr((dummy_addr, self.family)),
                FlowColumn::ReplySrcPort(0),
                FlowColumn::ReplyDstPort(0),
                FlowColumn::Flags(dummy_flag),
                FlowColumn::Mark(None),
                FlowColumn::Use(None),
            ]
        } else {
            vec![
                FlowColumn::Protocol(String::new()),
                FlowColumn::ProtocolNumber(0),
                FlowColumn::Timeout(0),
                FlowColumn::OrigSrcAddr((dummy_addr, self.family)),
                FlowColumn::OrigDstAddr((dummy_addr, self.family)),
                FlowColumn::OrigSrcPort(0),
                FlowColumn::OrigDstPort(0),
                FlowColumn::ReplySrcAddr((dummy_addr, self.family)),
                FlowColumn::ReplyDstAddr((dummy_addr, self.family)),
                FlowColumn::ReplySrcPort(0),
                FlowColumn::ReplyDstPort(0),
                FlowColumn::Flags(dummy_flag),
                FlowColumn::Mark(None),
                FlowColumn::Use(None),
            ]
        };
        let mut row_str = String::new();

        for (i, c) in header_columns.iter().enumerate() {
            row_str += &c.column(true);
            if i != header_columns.len() - 1 {
                row_str += " ";
            }
        }
        row_str += "\n";

        row_str
    }
}

#[derive(Debug)]
pub enum FlowColumn {
    Event(String),
    Protocol(String),
    ProtocolNumber(u8),
    Timeout(u32),
    TcpState(Option<String>),
    OrigSrcAddr((IpAddr, Family)),
    OrigDstAddr((IpAddr, Family)),
    OrigSrcPort(u16),
    OrigDstPort(u16),
    ReplySrcAddr((IpAddr, Family)),
    ReplyDstAddr((IpAddr, Family)),
    ReplySrcPort(u16),
    ReplyDstPort(u16),
    Flags((String, bool)),
    Mark(Option<u32>),
    Use(Option<u32>),
}

impl Column for FlowColumn {
    fn header(&self) -> String {
        match self {
            FlowColumn::Event(_) => String::from("EVENT"),
            FlowColumn::Protocol(_) => String::from("PROTOCOL"),
            FlowColumn::ProtocolNumber(_) => String::from("PROTONUM"),
            FlowColumn::Timeout(_) => String::from("TIMEOUT"),
            FlowColumn::TcpState(_) => String::from("TCP_STATE"),
            FlowColumn::OrigSrcAddr(_) => String::from("ORIG_SRC_ADDR"),
            FlowColumn::OrigDstAddr(_) => String::from("ORIG_DST_ADDR"),
            FlowColumn::OrigSrcPort(_) => String::from("ORIG_SRC_PORT"),
            FlowColumn::OrigDstPort(_) => String::from("ORIG_DST_PORT"),
            FlowColumn::ReplySrcAddr(_) => String::from("REPLY_SRC_ADDR"),
            FlowColumn::ReplyDstAddr(_) => String::from("REPLY_DST_ADDR"),
            FlowColumn::ReplySrcPort(_) => String::from("REPLY_SRC_PORT"),
            FlowColumn::ReplyDstPort(_) => String::from("REPLY_DST_PORT"),
            FlowColumn::Flags(_) => String::from("FLAGS"),
            FlowColumn::Mark(_) => String::from("MARK"),
            FlowColumn::Use(_) => String::from("USE"),
        }
    }

    fn column(&self, header: bool) -> String {
        let format_addr = |addr: &IpAddr, family: Family| -> String {
            match family {
                Family::Ipv4 => format!("{:>15}", addr),
                Family::Ipv6 | Family::Unspec => format!("{:>39}", addr),
            }
        };
        let format_addr_header = |h: &str, addr: &IpAddr| -> String {
            match addr {
                IpAddr::V4(_addr) => format!("{:>15}", h),
                IpAddr::V6(_addr) => format!("{:>39}", h),
            }
        };

        match self {
            FlowColumn::Event(e) => {
                if header {
                    format!("{:>7}", self.header())
                } else {
                    format!("{:>7}", e)
                }
            }
            FlowColumn::Protocol(p) => {
                if header {
                    format!("{:>8}", self.header())
                } else {
                    format!("{:>8}", p)
                }
            }
            FlowColumn::ProtocolNumber(n) => {
                if header {
                    format!("{:>8}", self.header())
                } else {
                    format!("{:>8}", n)
                }
            }
            FlowColumn::Timeout(t) => {
                if header {
                    format!("{:>10}", self.header())
                } else {
                    format!("{:>10}", t)
                }
            }
            FlowColumn::TcpState(s) => {
                if header {
                    format!("{:>11}", self.header())
                } else {
                    match s {
                        Some(s) => {
                            format!("{:>11}", s)
                        }
                        None => {
                            format!("{:>11}", "")
                        }
                    }
                }
            }
            FlowColumn::OrigSrcAddr(a) => {
                if header {
                    format_addr_header(&self.header(), &a.0)
                } else {
                    format_addr(&a.0, a.1)
                }
            }
            FlowColumn::OrigDstAddr(a) => {
                if header {
                    format_addr_header(&self.header(), &a.0)
                } else {
                    format_addr(&a.0, a.1)
                }
            }
            FlowColumn::OrigSrcPort(n) => {
                if header {
                    format!("{:>13}", self.header())
                } else {
                    format!("{:>13}", n)
                }
            }
            FlowColumn::OrigDstPort(n) => {
                if header {
                    format!("{:>13}", self.header())
                } else {
                    format!("{:>13}", n)
                }
            }
            FlowColumn::ReplySrcAddr(a) => {
                if header {
                    format_addr_header(&self.header(), &a.0)
                } else {
                    format_addr(&a.0, a.1)
                }
            }
            FlowColumn::ReplyDstAddr(a) => {
                if header {
                    format_addr_header(&self.header(), &a.0)
                } else {
                    format_addr(&a.0, a.1)
                }
            }
            FlowColumn::ReplySrcPort(n) => {
                if header {
                    format!("{:>14}", self.header())
                } else {
                    format!("{:>14}", n)
                }
            }
            FlowColumn::ReplyDstPort(n) => {
                if header {
                    format!("{:>14}", self.header())
                } else {
                    format!("{:>14}", n)
                }
            }
            FlowColumn::Flags((f, detail)) =>
            {
                #[allow(clippy::collapsible_else_if)]
                if *detail {
                    if header {
                        format!("{:>15}", self.header())
                    } else {
                        format!("{:>15}", f)
                    }
                } else {
                    if header {
                        format!("{:>13}", self.header())
                    } else {
                        format!("{:>13}", f)
                    }
                }
            }
            FlowColumn::Mark(m) => {
                if header {
                    format!("{:>5}", self.header())
                } else {
                    match m {
                        Some(m) => {
                            format!("{:>5}", m)
                        }
                        None => {
                            format!("{:>5}", "")
                        }
                    }
                }
            }
            FlowColumn::Use(u) => {
                if header {
                    format!("{:>5}", self.header())
                } else {
                    match u {
                        Some(u) => {
                            format!("{:>5}", u)
                        }
                        None => {
                            format!("{:>5}", "")
                        }
                    }
                }
            }
        }
    }
}

impl ToColumns<FlowColumn> for Flow {
    fn to_columns(&self, opt: ToColumnOptions) -> Vec<FlowColumn> {
        // Make sure the order is correct.
        let mut columns = Vec::new();

        if opt.event {
            columns.push(FlowColumn::Event(
                String::from(self.event_type).to_uppercase(),
            ));
        }

        columns.push(FlowColumn::Protocol(String::from(self.protocol)));
        columns.push(FlowColumn::ProtocolNumber(u8::from(self.protocol)));
        columns.push(FlowColumn::Timeout(self.timeout));
        if !opt.omit_tcp_state {
            columns.push(FlowColumn::TcpState(self.tcp_state.map(String::from)));
        }
        columns.push(FlowColumn::OrigSrcAddr((
            self.original.src_addr,
            opt.family,
        )));
        columns.push(FlowColumn::OrigDstAddr((
            self.original.dst_addr,
            opt.family,
        )));
        columns.push(FlowColumn::OrigSrcPort(self.original.src_port));
        columns.push(FlowColumn::OrigDstPort(self.original.dst_port));
        columns.push(FlowColumn::ReplySrcAddr((self.reply.src_addr, opt.family)));
        columns.push(FlowColumn::ReplyDstAddr((self.reply.dst_addr, opt.family)));
        columns.push(FlowColumn::ReplySrcPort(self.reply.src_port));
        columns.push(FlowColumn::ReplyDstPort(self.reply.dst_port));
        if opt.detailed_status {
            columns.push(FlowColumn::Flags((
                ct_status_to_string(&self.status, true),
                true,
            )));
        } else {
            columns.push(FlowColumn::Flags((
                ct_status_to_string(&self.status, false),
                false,
            )));
        }
        columns.push(FlowColumn::Mark(self.mark));
        columns.push(FlowColumn::Use(self.r#use));

        columns
    }
}

fn ct_status_to_string(status: &Status, detail: bool) -> String {
    if detail {
        let n = u16::from(status);
        format!("{:0>15b}", n)
    } else {
        status.preferred_one()
    }
}

pub struct EventFlowRow {
    detailed_status: bool,
    family: Family,
    protocol: Protocol, // default is Tcp, Tcp shows TCP_STATE(when showing Udp flows, TCP_STATE is empty.).
}

impl EventFlowRow {
    pub fn new(detailed_status: bool, family: Family, protocol: Protocol) -> EventFlowRow {
        EventFlowRow {
            detailed_status,
            family,
            protocol,
        }
    }
}

impl Row for EventFlowRow {
    fn row<C: Column, E: Serialize + ToColumns<C> + Send + Sync>(&self, entry: &E) -> String {
        let mut row_str = String::new();

        let columns = entry.to_columns(ToColumnOptions {
            event: true,
            detailed_status: self.detailed_status,
            omit_tcp_state: self.protocol.eq(&Protocol::Udp),
            family: self.family,
        });

        for (i, c) in columns.iter().enumerate() {
            row_str += &c.column(false);
            if i != columns.len() - 1 {
                row_str += " ";
            }
        }
        row_str += "\n";

        row_str
    }

    fn header(&self) -> String {
        let dummy_addr = match self.family {
            Family::Ipv4 => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            Family::Ipv6 | Family::Unspec => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        };
        let dummy_flag = if self.detailed_status {
            (String::new(), true)
        } else {
            (String::new(), false)
        };
        let header_columns: Vec<FlowColumn> = if self.protocol.eq(&Protocol::Tcp) {
            vec![
                FlowColumn::Event(String::new()),
                FlowColumn::Protocol(String::new()),
                FlowColumn::ProtocolNumber(0),
                FlowColumn::Timeout(0),
                FlowColumn::TcpState(None),
                FlowColumn::OrigSrcAddr((dummy_addr, self.family)),
                FlowColumn::OrigDstAddr((dummy_addr, self.family)),
                FlowColumn::OrigSrcPort(0),
                FlowColumn::OrigDstPort(0),
                FlowColumn::ReplySrcAddr((dummy_addr, self.family)),
                FlowColumn::ReplyDstAddr((dummy_addr, self.family)),
                FlowColumn::ReplySrcPort(0),
                FlowColumn::ReplyDstPort(0),
                FlowColumn::Flags(dummy_flag),
            ]
        } else {
            vec![
                FlowColumn::Event(String::new()),
                FlowColumn::Protocol(String::new()),
                FlowColumn::ProtocolNumber(0),
                FlowColumn::Timeout(0),
                FlowColumn::OrigSrcAddr((dummy_addr, self.family)),
                FlowColumn::OrigDstAddr((dummy_addr, self.family)),
                FlowColumn::OrigSrcPort(0),
                FlowColumn::OrigDstPort(0),
                FlowColumn::ReplySrcAddr((dummy_addr, self.family)),
                FlowColumn::ReplyDstAddr((dummy_addr, self.family)),
                FlowColumn::ReplySrcPort(0),
                FlowColumn::ReplyDstPort(0),
                FlowColumn::Flags(dummy_flag),
            ]
        };
        let mut row_str = String::new();

        for (i, c) in header_columns.iter().enumerate() {
            row_str += &c.column(true);
            if i != header_columns.len() - 1 {
                row_str += " ";
            }
        }
        row_str += "\n";

        row_str
    }
}
