use ipnet::IpNet;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_netfilter::{
    ctnetlink::nlas::flow::{
        ip_tuple::{IpTuple, ProtocolTuple, TupleNla},
        nla::FlowNla,
    },
    NetfilterMessage,
};

use crate::{
    error::Error,
    flow::{Flow, Protocol, Status, TcpState, Tuple},
    message::MessageBuilder,
    Family, Table,
};

#[derive(Debug)]
pub struct Request {
    meta: RequestMeta,
    op: RequestOperation,
}

impl Request {
    pub fn new(meta: RequestMeta, op: RequestOperation) -> Request {
        Request { meta, op }
    }

    pub fn message(&self) -> Result<Option<NetlinkMessage<NetfilterMessage>>, Error> {
        let builder = MessageBuilder::from(&self.meta);

        match &self.op {
            RequestOperation::List(_) => Ok(Some(builder.list())),
            RequestOperation::Get(param) => Ok(Some(builder.get(param))),
            RequestOperation::Event(_) => Ok(None),
            RequestOperation::Count => Ok(Some(builder.count())),
            RequestOperation::Stat => Ok(Some(builder.stat())),
        }
    }

    pub fn filter(&self) -> Option<Filter> {
        self.op.filter()
    }
}

#[derive(Debug)]
pub enum RequestOperation {
    List(Option<Filter>),
    Get(GetParams),
    Event(Option<Filter>),
    Count,
    Stat,
}

impl RequestOperation {
    pub(super) fn filter(&self) -> Option<Filter> {
        match self {
            RequestOperation::List(f) => f.clone(),
            RequestOperation::Get(_) => None,
            RequestOperation::Event(f) => f.clone(),
            RequestOperation::Count => None,
            RequestOperation::Stat => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RequestMeta {
    family: Family,
    table: Table,
    res_id: u16,
    // flags: u16,
    zero: bool,
}

impl RequestMeta {
    pub fn family(mut self, f: Family) -> RequestMeta {
        self.family = f;
        self
    }

    pub fn table(mut self, t: Table) -> RequestMeta {
        self.table = t;
        self
    }

    pub fn res_id(mut self, id: u16) -> RequestMeta {
        self.res_id = id;
        self
    }

    pub fn zero(mut self) -> RequestMeta {
        self.zero = true;
        self
    }
}

impl From<&RequestMeta> for MessageBuilder {
    fn from(r: &RequestMeta) -> Self {
        if r.zero {
            MessageBuilder::new(r.family, r.table)
                .res_id(r.res_id)
                .zero()
        } else {
            MessageBuilder::new(r.family, r.table).res_id(r.res_id)
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Filter {
    family: Option<Family>,
    protocol: Option<Protocol>,
    orig_src_addr: Option<IpNet>,
    orig_dst_addr: Option<IpNet>,
    reply_src_addr: Option<IpNet>,
    reply_dst_addr: Option<IpNet>,
    orig_src_port: Option<u16>,
    orig_dst_port: Option<u16>,
    reply_src_port: Option<u16>,
    reply_dst_port: Option<u16>,
    mark: Option<u32>,
    r#use: Option<u32>,
    tcp_state: Option<TcpState>,
    status: Option<Status>,
}

impl Filter {
    pub fn family(mut self, f: Family) -> Self {
        self.family = Some(f);
        self
    }

    pub fn protocol(mut self, p: Protocol) -> Self {
        self.protocol = Some(p);
        self
    }

    pub fn orig_src_addr(mut self, n: IpNet) -> Self {
        self.orig_src_addr = Some(n);
        self
    }

    pub fn orig_dst_addr(mut self, n: IpNet) -> Self {
        self.orig_dst_addr = Some(n);
        self
    }

    pub fn reply_src_addr(mut self, n: IpNet) -> Self {
        self.reply_src_addr = Some(n);
        self
    }

    pub fn reply_dst_addr(mut self, n: IpNet) -> Self {
        self.reply_dst_addr = Some(n);
        self
    }

    pub fn orig_src_port(mut self, p: u16) -> Self {
        self.orig_src_port = Some(p);
        self
    }

    pub fn orig_dst_port(mut self, p: u16) -> Self {
        self.orig_dst_port = Some(p);
        self
    }

    pub fn reply_src_port(mut self, p: u16) -> Self {
        self.reply_src_port = Some(p);
        self
    }

    pub fn reply_dst_port(mut self, p: u16) -> Self {
        self.reply_dst_port = Some(p);
        self
    }

    pub fn mark(mut self, m: u32) -> Self {
        self.mark = Some(m);
        self
    }

    pub fn r#use(mut self, u: u32) -> Self {
        self.r#use = Some(u);
        self
    }

    pub fn tcp_state(mut self, s: TcpState) -> Self {
        self.tcp_state = Some(s);
        self
    }

    pub fn status(mut self, s: Status) -> Self {
        self.status = Some(s);
        self
    }

    pub(super) fn apply(&self, flow: &Flow) -> bool {
        if let Some(f) = self.family {
            // Is it enough to check that flow.original.src_addr is matched?
            if !f.is_matched(flow.original.src_addr) {
                return false;
            }
        }
        if let Some(p) = self.protocol {
            if p.ne(&flow.protocol) {
                return false;
            }
        }
        if let Some(s) = self.tcp_state {
            match flow.tcp_state {
                Some(flow_s) => {
                    if s.ne(&flow_s) {
                        return false;
                    }
                }
                // When flow.tcp_state is None, its flow must not be TCP.
                // So, if tcp-state filter is set, this flow should be filtered out.
                None => return false,
            }
        }
        if let Some(cidr) = self.orig_src_addr {
            if !cidr.contains(&flow.original.src_addr) {
                return false;
            }
        }
        if let Some(cidr) = self.orig_dst_addr {
            if !cidr.contains(&flow.original.dst_addr) {
                return false;
            }
        }
        if let Some(cidr) = self.reply_src_addr {
            if !cidr.contains(&flow.reply.src_addr) {
                return false;
            }
        }
        if let Some(cidr) = self.reply_dst_addr {
            if !cidr.contains(&flow.reply.dst_addr) {
                return false;
            }
        }
        if let Some(port) = self.orig_src_port {
            if port.ne(&flow.original.src_port) {
                return false;
            }
        }
        if let Some(port) = self.orig_dst_port {
            if port.ne(&flow.original.dst_port) {
                return false;
            }
        }
        if let Some(port) = self.reply_src_port {
            if port.ne(&flow.reply.src_port) {
                return false;
            }
        }
        if let Some(port) = self.reply_dst_port {
            if port.ne(&flow.reply.dst_port) {
                return false;
            }
        }
        if let Some(mark) = self.mark {
            match flow.mark {
                Some(m) => {
                    if mark != m {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if let Some(us) = self.r#use {
            match flow.r#use {
                Some(u) => {
                    if us != u {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if let Some(s) = &self.status {
            let flow_status = u16::from(&flow.status);
            let filter_status = u16::from(s);
            if flow_status & filter_status == 0 {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
pub enum Direction {
    Orig(Tuple),
    Reply(Tuple),
}

#[derive(Debug, Clone)]
pub struct GetParams {
    protocol: Protocol,
    directed_tuple: Direction,
}

impl GetParams {
    pub fn new(protocol: Protocol, directed_tuple: Direction) -> GetParams {
        GetParams {
            protocol,
            directed_tuple,
        }
    }
}

impl From<&GetParams> for Vec<FlowNla> {
    fn from(param: &GetParams) -> Self {
        let mut nlas = Vec::new();
        let t = match &param.directed_tuple {
            Direction::Orig(tuple) => {
                let protocol = TupleNla::Protocol(ProtocolTuple {
                    src_port: tuple.src_port,
                    dst_port: tuple.dst_port,
                    protocol: u8::from(param.protocol),
                });
                let addrs = TupleNla::Ip(IpTuple {
                    src_addr: tuple.src_addr,
                    dst_addr: tuple.dst_addr,
                });
                FlowNla::Orig(vec![addrs, protocol])
            }
            Direction::Reply(tuple) => {
                let protocol = TupleNla::Protocol(ProtocolTuple {
                    src_port: tuple.src_port,
                    dst_port: tuple.dst_port,
                    protocol: u8::from(param.protocol),
                });
                let addrs = TupleNla::Ip(IpTuple {
                    src_addr: tuple.src_addr,
                    dst_addr: tuple.dst_addr,
                });
                FlowNla::Reply(vec![addrs, protocol])
            }
        };
        nlas.push(t);
        nlas
    }
}

#[cfg(test)]
mod tests {

    use ipnet::IpNet;
    use rstest::rstest;

    use crate::{
        flow::{Flow, FlowBuilder, Protocol, Status, TcpState, TupleBuilder},
        message::MessageType,
    };

    use super::Filter;

    fn ipv4_tcp_flow() -> Flow {
        FlowBuilder::default()
            .event_type(MessageType::Update)
            .original(
                TupleBuilder::default()
                    .src_addr("1.1.1.1".parse().unwrap())
                    .dst_addr("2.2.2.2".parse().unwrap())
                    .src_port(1234)
                    .dst_port(2345)
                    .build()
                    .unwrap(),
            )
            .reply(
                TupleBuilder::default()
                    .src_addr("3.3.3.3".parse().unwrap())
                    .dst_addr("4.4.4.4".parse().unwrap())
                    .src_port(3456)
                    .dst_port(4567)
                    .build()
                    .unwrap(),
            )
            .protocol(Protocol::Tcp)
            .mark(1)
            .r#use(1)
            .tcp_state(TcpState::Established)
            .timeout(1000)
            .status(Status::assured())
            .build()
            .unwrap()
    }

    fn ipv6_udp_flow() -> Flow {
        FlowBuilder::default()
            .event_type(MessageType::Update)
            .original(
                TupleBuilder::default()
                    .src_addr("fd00::1".parse().unwrap())
                    .dst_addr("fd00::2".parse().unwrap())
                    .src_port(1234)
                    .dst_port(2345)
                    .build()
                    .unwrap(),
            )
            .reply(
                TupleBuilder::default()
                    .src_addr("fd00::3".parse().unwrap())
                    .dst_addr("fd00::4".parse().unwrap())
                    .src_port(3456)
                    .dst_port(4567)
                    .build()
                    .unwrap(),
            )
            .protocol(Protocol::Udp)
            .mark(1)
            .r#use(1)
            .timeout(1000)
            .status(Status::assured())
            .build()
            .unwrap()
    }

    #[rstest(
        filter,
        flow,
        expected,
        case(
            Filter::default(),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .protocol(Protocol::Tcp),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .protocol(Protocol::Udp),
            ipv4_tcp_flow(),
            false),
        case(
            Filter::default()
                .orig_src_addr("1.1.1.1/32".parse::<IpNet>().unwrap())
                .orig_dst_addr("2.2.2.2/32".parse::<IpNet>().unwrap())
                .reply_src_addr("3.3.3.3/32".parse::<IpNet>().unwrap())
                .reply_dst_addr("4.4.4.4/32".parse::<IpNet>().unwrap()),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .orig_src_addr("1.1.1.1/32".parse::<IpNet>().unwrap())
                .orig_dst_addr("2.2.2.2/32".parse::<IpNet>().unwrap())
                .reply_src_addr("3.3.3.0/32".parse::<IpNet>().unwrap()) // Here doesn't match
                .reply_dst_addr("4.4.4.4/32".parse::<IpNet>().unwrap()),
            ipv4_tcp_flow(),
            false),
        case(
            Filter::default()
                .protocol(Protocol::Tcp)
                .reply_dst_port(4567),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .protocol(Protocol::Tcp)
                .tcp_state(TcpState::Established),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .protocol(Protocol::Tcp)
                .tcp_state(TcpState::TimeWait),
            ipv4_tcp_flow(),
            false),
        case(
            Filter::default()
                .protocol(Protocol::Tcp)
                .tcp_state(TcpState::TimeWait),
            ipv4_tcp_flow(),
            false),
        case(
            Filter::default()
                .mark(1),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .r#use(1),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .status(Status::assured()),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .status(Status::seen_reply()),
            ipv4_tcp_flow(),
            false),
        case(
            Filter::default()
                .status(Status::from((1<<1) + (1<<2))),
            ipv4_tcp_flow(),
            true),
        case(
            Filter::default()
                .orig_src_addr("fd00::1/128".parse::<IpNet>().unwrap()),
            ipv6_udp_flow(),
            true),
        case(
            Filter::default()
                .tcp_state(TcpState::Established),
            ipv6_udp_flow(),
            false),
    )]
    fn test_filter_apply(filter: Filter, flow: Flow, expected: bool) {
        let res = filter.apply(&flow);
        assert_eq!(res, expected);
    }
}
