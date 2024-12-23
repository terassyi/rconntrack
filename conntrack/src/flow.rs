use std::{collections::HashSet, net::IpAddr, str::FromStr};

use netlink_packet_netfilter::ctnetlink::{
    message::CtNetlinkMessage,
    nlas::{
        ct_attr::CtAttr,
        flow::{
            ip_tuple::{IpTupleBuilder, ProtocolTupleBuilder, TupleNla},
            nla::FlowNla,
            protocol_info::{ProtocolInfo, ProtocolInfoTcp},
            status::{ConnectionStatus, ConnectionStatusFlag},
        },
    },
};
use netlink_packet_utils::DecodeError;
use serde::{ser::SerializeSeq, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("invalid tcp state: {0}")]
    InvalidTcpState(String),
    #[error("invalid L4 protocol: {0}")]
    InvalidL4Protocol(String),
    #[error("invalid ct state: {0}")]
    InvalidCtState(String),
    #[error("netlink error: {0}")]
    Netlink(DecodeError),
}

#[derive(Debug, Clone, Serialize)]
pub struct Flow {
    pub original: Tuple,
    pub reply: Tuple,
    pub protocol: Protocol,
    pub mark: u32,
    pub r#use: u32,
    pub tcp_state: Option<TcpState>,
    pub status: Status,
    pub timeout: u32,
}

impl TryFrom<&CtNetlinkMessage> for Flow {
    type Error = FlowError;

    fn try_from(msg: &CtNetlinkMessage) -> Result<Self, Self::Error> {
        // We can parse the complete flow only from CtNetlinkMessage::New().
        if let CtNetlinkMessage::New(nlas) = msg {
            let mut flow_builder = FlowBuilder::default();
            for nla in nlas.iter() {
                match nla {
                    FlowNla::Orig(orig) => {
                        let mut tuple_builder = TupleBuilder::default();
                        for nla in orig.iter() {
                            match nla {
                                TupleNla::Ip(t) => {
                                    tuple_builder =
                                        tuple_builder.src_addr(t.src_addr).dst_addr(t.dst_addr)
                                }
                                TupleNla::Protocol(t) => {
                                    tuple_builder =
                                        tuple_builder.src_port(t.src_port).dst_port(t.dst_port);
                                }
                            }
                        }
                        flow_builder = flow_builder.original(tuple_builder.build()?);
                    }
                    FlowNla::Reply(rep) => {
                        let mut tuple_builder = TupleBuilder::default();
                        for nla in rep.iter() {
                            match nla {
                                TupleNla::Ip(t) => {
                                    tuple_builder =
                                        tuple_builder.src_addr(t.src_addr).dst_addr(t.dst_addr)
                                }
                                TupleNla::Protocol(t) => {
                                    tuple_builder =
                                        tuple_builder.src_port(t.src_port).dst_port(t.dst_port);
                                    flow_builder =
                                        flow_builder.protocol(Protocol::from(t.protocol));
                                }
                            }
                        }
                        flow_builder = flow_builder.reply(tuple_builder.build()?);
                    }
                    FlowNla::ProtocolInfo(info) => {
                        if let ProtocolInfo::Tcp(info) = info {
                            flow_builder = flow_builder.tcp_state(TcpState::try_from(info.state)?);
                        }
                    }
                    FlowNla::Mark(v) => flow_builder = flow_builder.mark(*v),
                    FlowNla::Use(v) => flow_builder = flow_builder.r#use(*v),
                    FlowNla::Timeout(t) => flow_builder = flow_builder.timeout(*t),
                    FlowNla::Status(s) => {
                        flow_builder = flow_builder.status(Status::from(s));
                    }
                    FlowNla::Id(_v) => { /* do nothing */ }
                    FlowNla::Other(_v) => { /* do nothing */ }
                }
            }
            Ok(flow_builder.build()?)
        } else {
            Err(FlowError::InvalidMessageType(msg.message_type()))
        }
    }
}

impl TryFrom<&Flow> for CtNetlinkMessage {
    type Error = FlowError;

    // This method must be called only from tests.
    // Some information cannot be fulfilled.
    fn try_from(flow: &Flow) -> Result<Self, Self::Error> {
        let mut nlas = Vec::new();
        // original
        let ip_tuple = IpTupleBuilder::default()
            .src_addr(flow.original.src_addr)
            .dst_addr(flow.original.dst_addr)
            .build()
            .map_err(FlowError::Netlink)?;
        let protocol_tuple = ProtocolTupleBuilder::default()
            .src_port(flow.original.src_port)
            .dst_port(flow.original.dst_port)
            .protocol(flow.protocol.into())
            .build()
            .map_err(FlowError::Netlink)?;
        nlas.push(FlowNla::Orig(vec![
            TupleNla::Ip(ip_tuple),
            TupleNla::Protocol(protocol_tuple),
        ]));
        // reply
        let ip_tuple = IpTupleBuilder::default()
            .src_addr(flow.reply.src_addr)
            .dst_addr(flow.reply.dst_addr)
            .build()
            .map_err(FlowError::Netlink)?;
        let protocol_tuple = ProtocolTupleBuilder::default()
            .src_port(flow.reply.src_port)
            .dst_port(flow.reply.dst_port)
            .protocol(flow.protocol.into())
            .build()
            .map_err(FlowError::Netlink)?;
        nlas.push(FlowNla::Reply(vec![
            TupleNla::Ip(ip_tuple),
            TupleNla::Protocol(protocol_tuple),
        ]));
        // protocol info
        let protocol_info = match flow.protocol {
            Protocol::Tcp => ProtocolInfo::Tcp(ProtocolInfoTcp {
                state: flow.tcp_state.unwrap().into(),
                wscale_original: 0,
                wscale_reply: 0,
                flgas_original: 0,
                flags_reply: 0,
            }),
            _ => ProtocolInfo::Other(CtAttr {
                nested: None,
                attr_type: 0,
                length: 0,
                value: Some(vec![0]),
            }),
        };
        nlas.push(FlowNla::ProtocolInfo(protocol_info));
        // mark
        nlas.push(FlowNla::Mark(flow.mark));
        // use
        nlas.push(FlowNla::Use(flow.r#use));
        // timeout
        nlas.push(FlowNla::Timeout(flow.timeout));
        // status
        let v = u16::from(&flow.status) as u32;
        nlas.push(FlowNla::Status(ConnectionStatus::from(v)));
        // id
        nlas.push(FlowNla::Id(0));
        Ok(CtNetlinkMessage::New(nlas))
    }
}

#[derive(Debug, Default)]
pub(super) struct FlowBuilder {
    original: Option<Tuple>,
    reply: Option<Tuple>,
    protocol: Option<Protocol>,
    mark: Option<u32>,
    r#use: Option<u32>,
    tcp_state: Option<TcpState>,
    status: Option<Status>,
    timeout: Option<u32>,
}

impl FlowBuilder {
    pub(super) fn original(mut self, tuple: Tuple) -> Self {
        self.original = Some(tuple);
        self
    }

    pub(super) fn reply(mut self, tuple: Tuple) -> Self {
        self.reply = Some(tuple);
        self
    }

    pub(super) fn protocol(mut self, proto: Protocol) -> Self {
        self.protocol = Some(proto);
        self
    }

    pub(super) fn mark(mut self, v: u32) -> Self {
        self.mark = Some(v);
        self
    }

    pub(super) fn r#use(mut self, v: u32) -> Self {
        self.r#use = Some(v);
        self
    }

    pub(super) fn tcp_state(mut self, state: TcpState) -> Self {
        self.tcp_state = Some(state);
        self
    }

    pub(super) fn status(mut self, s: Status) -> Self {
        self.status = Some(s);
        self
    }

    pub(super) fn timeout(mut self, t: u32) -> Self {
        self.timeout = Some(t);
        self
    }

    pub(super) fn build(&self) -> Result<Flow, FlowError> {
        Ok(Flow {
            original: self
                .original
                .clone()
                .ok_or(FlowError::MissingField("original".to_string()))?,
            reply: self
                .reply
                .clone()
                .ok_or(FlowError::MissingField("reply".to_string()))?,
            protocol: self
                .protocol
                .ok_or(FlowError::MissingField("protocol".to_string()))?,
            mark: self
                .mark
                .ok_or(FlowError::MissingField("mark".to_string()))?,
            r#use: self
                .r#use
                .ok_or(FlowError::MissingField("use".to_string()))?,
            tcp_state: self.tcp_state,
            status: self
                .status
                .clone()
                .ok_or(FlowError::MissingField("status".to_string()))?,
            timeout: self
                .timeout
                .ok_or(FlowError::MissingField("timeout".to_string()))?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Tuple {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Default)]
pub(super) struct TupleBuilder {
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

impl TupleBuilder {
    pub(super) fn src_addr(mut self, addr: IpAddr) -> Self {
        self.src_addr = Some(addr);
        self
    }

    pub(super) fn dst_addr(mut self, addr: IpAddr) -> Self {
        self.dst_addr = Some(addr);
        self
    }

    pub(super) fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    pub(super) fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    pub(super) fn build(&self) -> Result<Tuple, FlowError> {
        Ok(Tuple {
            src_addr: self
                .src_addr
                .ok_or(FlowError::MissingField("src_addr".to_string()))?,
            dst_addr: self
                .dst_addr
                .ok_or(FlowError::MissingField("dst_addr".to_string()))?,
            src_port: self
                .src_port
                .ok_or(FlowError::MissingField("src_port".to_string()))?,
            dst_port: self
                .dst_port
                .ok_or(FlowError::MissingField("dst_port".to_string()))?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Protocol {
    Tcp, // 6
    Udp, // 17
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        match v {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Other(v),
        }
    }
}

impl TryFrom<&str> for Protocol {
    type Error = FlowError;
    // only support tcp and udp
    fn try_from(p: &str) -> Result<Self, Self::Error> {
        match p.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            _ => Err(FlowError::InvalidL4Protocol(p.to_string())),
        }
    }
}

impl From<Protocol> for String {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Tcp => String::from("tcp"),
            Protocol::Udp => String::from("udp"),
            Protocol::Other(v) => format!("other({v})"),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum TcpState {
    None,
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    Listen,
}

impl TryFrom<&str> for TcpState {
    type Error = FlowError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().replace("_", "").as_str() {
            "none" => Ok(TcpState::None),
            "synsent" => Ok(TcpState::SynSent),
            "synrecv" => Ok(TcpState::SynRecv),
            "established" => Ok(TcpState::Established),
            "finwait" => Ok(TcpState::FinWait),
            "closewait" => Ok(TcpState::CloseWait),
            "lastack" => Ok(TcpState::LastAck),
            "timewait" => Ok(TcpState::TimeWait),
            "close" => Ok(TcpState::Close),
            "listen" => Ok(TcpState::Listen),
            _ => Err(FlowError::InvalidTcpState(s.to_string())),
        }
    }
}

impl TryFrom<u8> for TcpState {
    type Error = FlowError;
    fn try_from(s: u8) -> Result<Self, Self::Error> {
        match s {
            0 => Ok(TcpState::None),
            1 => Ok(TcpState::SynSent),
            2 => Ok(TcpState::SynRecv),
            3 => Ok(TcpState::Established),
            4 => Ok(TcpState::FinWait),
            5 => Ok(TcpState::CloseWait),
            6 => Ok(TcpState::LastAck),
            7 => Ok(TcpState::TimeWait),
            8 => Ok(TcpState::Close),
            9 => Ok(TcpState::Listen),
            _ => Err(FlowError::InvalidTcpState(format!("{s}"))),
        }
    }
}

impl From<TcpState> for u8 {
    fn from(s: TcpState) -> Self {
        match s {
            TcpState::None => 0,
            TcpState::SynSent => 1,
            TcpState::SynRecv => 2,
            TcpState::Established => 3,
            TcpState::FinWait => 4,
            TcpState::CloseWait => 5,
            TcpState::LastAck => 6,
            TcpState::TimeWait => 7,
            TcpState::Close => 8,
            TcpState::Listen => 9,
        }
    }
}

impl From<TcpState> for String {
    fn from(s: TcpState) -> Self {
        match s {
            TcpState::None => String::from("NONE"),
            TcpState::SynSent => String::from("SYN_SENT"),
            TcpState::SynRecv => String::from("SYN_RECV"),
            TcpState::Established => String::from("ESTABLISHED"),
            TcpState::FinWait => String::from("FIN_WAIT"),
            TcpState::CloseWait => String::from("CLOSE_WAIT"),
            TcpState::LastAck => String::from("LAST_ACK"),
            TcpState::TimeWait => String::from("TIME_WAIT"),
            TcpState::Close => String::from("CLOSE"),
            TcpState::Listen => String::from("LISTEN"),
        }
    }
}

impl FromStr for TcpState {
    type Err = FlowError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TcpState::try_from(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    inner: HashSet<ConnectionStatusFlag>,
}

impl Status {
    const PREFERRED: [ConnectionStatusFlag; 4] = [
        ConnectionStatusFlag::Assured,
        ConnectionStatusFlag::SeenReply,
        ConnectionStatusFlag::FixedTimeout,
        ConnectionStatusFlag::Expected,
    ];

    pub fn preferred_one(&self) -> String {
        if self.inner.is_empty() {
            return String::new();
        }

        for p in Self::PREFERRED.iter() {
            if self.inner.contains(p) {
                return ct_status_flag_to_string(p);
            }
        }

        ct_status_flag_to_string(
            self.inner
                .iter()
                .collect::<Vec<&ConnectionStatusFlag>>()
                .first()
                .unwrap(),
        )
    }

    pub fn assured() -> Status {
        Status {
            inner: HashSet::from([ConnectionStatusFlag::Assured]),
        }
    }

    pub fn seen_reply() -> Status {
        Status {
            inner: HashSet::from([ConnectionStatusFlag::SeenReply]),
        }
    }

    pub fn fixed_timeout() -> Status {
        Status {
            inner: HashSet::from([ConnectionStatusFlag::FixedTimeout]),
        }
    }

    pub fn expected() -> Status {
        Status {
            inner: HashSet::from([ConnectionStatusFlag::Expected]),
        }
    }
}

const FLAGS: [ConnectionStatusFlag; 15] = [
    ConnectionStatusFlag::Expected,
    ConnectionStatusFlag::SeenReply,
    ConnectionStatusFlag::Assured,
    ConnectionStatusFlag::Confirmed,
    ConnectionStatusFlag::SourceNAT,
    ConnectionStatusFlag::DestinationNAT,
    ConnectionStatusFlag::SequenceAdjust,
    ConnectionStatusFlag::SourceNATDone,
    ConnectionStatusFlag::DestinationNATDone,
    ConnectionStatusFlag::Dying,
    ConnectionStatusFlag::FixedTimeout,
    ConnectionStatusFlag::Template,
    ConnectionStatusFlag::Untracked,
    ConnectionStatusFlag::Helper,
    ConnectionStatusFlag::Offload,
];

impl From<&ConnectionStatus> for Status {
    fn from(s: &ConnectionStatus) -> Self {
        let mut flags = Vec::new();
        for flag in FLAGS.iter() {
            if (s.get() & (*flag as u32)) != 0 {
                flags.push(*flag);
            }
        }
        Status {
            inner: flags.into_iter().collect(),
        }
    }
}

impl From<&Status> for u16 {
    fn from(status: &Status) -> Self {
        let mut v = 0;
        for s in status.inner.iter() {
            v |= *s as u16;
        }
        v
    }
}

impl From<u16> for Status {
    fn from(value: u16) -> Self {
        let mut flags = Vec::new();
        for flag in FLAGS.iter() {
            if value & (*flag as u16) != 0 {
                flags.push(*flag);
            }
        }
        Status {
            inner: flags.into_iter().collect(),
        }
    }
}

impl Serialize for Status {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.inner.len()))?;
        for s in self.inner.iter() {
            seq.serialize_element(&ct_status_flag_to_string(s))?;
        }
        seq.end()
    }
}

fn ct_status_flag_to_string(f: &ConnectionStatusFlag) -> String {
    match f {
        ConnectionStatusFlag::Offload => String::from("OFFLOAD"),
        ConnectionStatusFlag::Helper => String::from("HELPER"),
        ConnectionStatusFlag::Untracked => String::from("UNTRACKED"),
        ConnectionStatusFlag::Template => String::from("TEMPLATE"),
        ConnectionStatusFlag::FixedTimeout => String::from("FIXED_TIMEOUT"),
        ConnectionStatusFlag::Dying => String::from("DYING"),
        ConnectionStatusFlag::DestinationNATDone => String::from("DNAT_DONE"),
        ConnectionStatusFlag::SourceNATDone => String::from("SNAT_DONE"),
        ConnectionStatusFlag::SequenceAdjust => String::from("SEQ_ADJ"),
        ConnectionStatusFlag::DestinationNAT => String::from("DNAT"),
        ConnectionStatusFlag::SourceNAT => String::from("SNAT"),
        ConnectionStatusFlag::Confirmed => String::from("CONFIRMED"),
        ConnectionStatusFlag::Assured => String::from("ASSURED"),
        ConnectionStatusFlag::SeenReply => String::from("SEEN_REPLY"),
        ConnectionStatusFlag::Expected => String::from("EXPECTED"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use netlink_packet_netfilter::ctnetlink::nlas::flow::status::ConnectionStatusFlag;
    use rstest::rstest;

    use super::Status;

    use super::TcpState;

    #[rstest(
        tcp_state,
        expected,
        case("syn_sent", TcpState::SynSent),
        case("synsent", TcpState::SynSent),
        case("SynSent", TcpState::SynSent),
        case("Syn_Sent", TcpState::SynSent),
        case("SYN_SENT", TcpState::SynSent),
        case("SYNSENT", TcpState::SynSent)
    )]
    fn test_tcp_state_try_from(tcp_state: &str, expected: TcpState) {
        let s = TcpState::try_from(tcp_state).unwrap();
        assert_eq!(s, expected)
    }

    #[rstest(
        val,
        expected,
        case(1 << 2, Status::assured()),
        case(1 << 1, Status::seen_reply()),
        case((1 << 1) + (1 << 2) + (1 << 7), Status{ inner: HashSet::from([ConnectionStatusFlag::Assured, ConnectionStatusFlag::SeenReply, ConnectionStatusFlag::SourceNATDone])}),
    )]
    fn test_status_from_u16(val: u16, expected: Status) {
        let status = Status::from(val);
        assert_eq!(status, expected);
    }
}
