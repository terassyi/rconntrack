use std::{net::IpAddr, task::Poll};

use error::Error;
use event::Event;
use futures::Stream;
use message::{Message, MessageGroup};
use netlink_packet_netfilter::constants::{AF_INET, AF_INET6, AF_UNSPEC};
use pin_project_lite::pin_project;
use request::{Filter, Request};
use socket::{ConntrackSocket, NfConntrackSocket};

pub mod error;
pub mod event;
pub mod flow;
pub mod message;
pub mod request;
pub mod socket;
pub mod stats;

#[derive(Debug, Clone, Copy, Default)]
pub struct ConntrackOption {
    flow_event_group: MessageGroup,
}

impl ConntrackOption {
    pub fn flow_event_group(&self) -> MessageGroup {
        self.flow_event_group
    }

    pub fn set_flow_event_group(mut self, group: MessageGroup) -> ConntrackOption {
        self.flow_event_group = group;
        self
    }
}

pin_project! {
    pub struct Conntrack<S> {
        #[pin]
        socket: S,
        filter: Option<Filter>,
    }
}

impl Conntrack<NfConntrackSocket> {
    pub fn new(opt: ConntrackOption) -> Result<Conntrack<NfConntrackSocket>, Error> {
        let socket = NfConntrackSocket::new(opt.flow_event_group())?;
        Ok(Conntrack {
            socket,
            filter: None,
        })
    }
}

impl<S> Conntrack<S>
where
    S: ConntrackSocket,
{
    pub fn with_socket(socket: S) -> Conntrack<S> {
        Conntrack {
            socket,
            filter: None,
        }
    }

    pub async fn request(&mut self, req: Request) -> Result<(), Error> {
        self.filter = req.filter();
        if let Some(msg) = req.message()? {
            self.socket.send(msg).await?;
        }

        Ok(())
    }

    pub async fn recv_once(&mut self) -> Result<Vec<Event>, Error> {
        self.socket
            .recv_once()
            .await?
            .iter()
            .map(Event::try_from)
            .collect()
    }
}

impl<S> Stream for Conntrack<S>
where
    S: ConntrackSocket + Stream<Item = Result<Vec<Message>, Error>>,
{
    type Item = Result<Vec<Event>, Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // clone the filter object to use each flow.
        let filter_opt = self.filter.clone();
        match self.project().socket.poll_next(cx) {
            Poll::Ready(msgs) => match msgs {
                Some(msgs) => match msgs {
                    Ok(msgs) => {
                        let events: Result<Vec<Event>, Error> =
                            msgs.iter().map(Event::try_from).collect();
                        let events = match events {
                            Ok(f) => f
                                .into_iter()
                                .filter(|e| match &filter_opt {
                                    Some(filter) => match e {
                                        Event::Flow(f) => filter.apply(f),
                                        _ => false,
                                    },
                                    None => true,
                                })
                                .collect(),
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        };
                        Poll::Ready(Some(Ok(events)))
                    }
                    Err(e) => Poll::Ready(Some(Err(e))),
                },
                None => Poll::Ready(None),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Family {
    Unspec,
    #[default]
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn is_matched(&self, addr: IpAddr) -> bool {
        match self {
            Family::Unspec => true,
            Family::Ipv4 => addr.is_ipv4(),
            Family::Ipv6 => addr.is_ipv6(),
        }
    }
}

impl From<Family> for u8 {
    fn from(family: Family) -> Self {
        match family {
            Family::Ipv4 => AF_INET,
            Family::Ipv6 => AF_INET6,
            Family::Unspec => AF_UNSPEC,
        }
    }
}

impl TryFrom<u8> for Family {
    type Error = Error;
    fn try_from(family: u8) -> Result<Self, Self::Error> {
        match family {
            AF_INET => Ok(Family::Ipv4),
            AF_INET6 => Ok(Family::Ipv6),
            AF_UNSPEC => Ok(Family::Unspec),
            _ => Err(Error::InvalidFamily(family.to_string())),
        }
    }
}

impl TryFrom<&str> for Family {
    type Error = Error;
    fn try_from(family: &str) -> Result<Self, Self::Error> {
        match family.to_lowercase().as_str() {
            "ipv4" => Ok(Family::Ipv4),
            "ipv6" => Ok(Family::Ipv6),
            "unspec" => Ok(Family::Unspec),
            _ => Err(Error::InvalidFamily(family.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Table {
    #[default]
    Conntrack,
    Dying,
    Unconfirmed,
    // Expect, // unimplemented
}

impl TryFrom<&str> for Table {
    type Error = Error;
    fn try_from(table: &str) -> Result<Self, Self::Error> {
        match table.to_lowercase().as_str() {
            "conntrack" => Ok(Table::Conntrack),
            "dying" => Ok(Table::Dying),
            "unconfirmed" => Ok(Table::Unconfirmed),
            _ => Err(Error::InvalidTable(table.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;

    use crate::{
        flow::{Flow, FlowBuilder, Protocol, Status, TcpState, TupleBuilder},
        message::MessageType,
        request::{Filter, Request, RequestMeta, RequestOperation},
        socket::MockConntrackSocket,
        Conntrack, ConntrackOption, Family,
    };

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

    #[tokio::test]
    async fn test_conntrack_poll_by_poll() {
        let base_ipv4_tcp_flow = ipv4_tcp_flow();
        let base_ipv6_udp_flow = ipv6_udp_flow();
        let mut ipv4_tcp_time_wait = base_ipv4_tcp_flow.clone();
        ipv4_tcp_time_wait.tcp_state = Some(TcpState::TimeWait);
        let mut ipv4_tcp_seen_reply = base_ipv4_tcp_flow.clone();
        ipv4_tcp_seen_reply.status = Status::seen_reply();
        let mut ipv4_tcp_another_addr = base_ipv4_tcp_flow.clone();
        ipv4_tcp_another_addr.original.src_addr = "1.1.1.2".parse().unwrap();

        let ipv4_flows = vec![
            base_ipv4_tcp_flow,
            ipv4_tcp_time_wait,
            ipv4_tcp_seen_reply,
            ipv4_tcp_another_addr,
        ];

        let ipv6_flows = vec![base_ipv6_udp_flow];
        let mock_socket = MockConntrackSocket::with_flow(ipv4_flows, ipv6_flows);
        let mut ct = Conntrack::with_socket(mock_socket);
        ct.request(Request::new(
            RequestMeta::default().family(Family::Unspec),
            RequestOperation::List(None),
        ))
        .await
        .unwrap();
        let mut received = 0;
        while let Some(flows) = ct.try_next().await.unwrap() {
            received += flows.len();
        }
        assert_eq!(received, 5);

        // filter family
        ct.request(Request::new(
            RequestMeta::default(),
            RequestOperation::List(None),
        ))
        .await
        .unwrap();
        let mut received = 0;
        while let Some(flows) = ct.try_next().await.unwrap() {
            received += flows.len();
        }
        assert_eq!(received, 4);

        // filter l4 protocol
        ct.request(Request::new(
            RequestMeta::default().family(Family::Unspec),
            RequestOperation::List(Some(Filter::default().protocol(Protocol::Udp))),
        ))
        .await
        .unwrap();
        let mut received = 0;
        while let Some(flows) = ct.try_next().await.unwrap() {
            received += flows.len();
        }
        assert_eq!(received, 1);

        // filter orig_src_addr
        ct.request(Request::new(
            RequestMeta::default().family(Family::Unspec),
            RequestOperation::List(Some(
                Filter::default().orig_src_addr("1.1.1.2/32".parse().unwrap()),
            )),
        ))
        .await
        .unwrap();
        let mut received = 0;
        while let Some(flows) = ct.try_next().await.unwrap() {
            received += flows.len();
        }
        assert_eq!(received, 1);

        // filter tcp_state and status
        ct.request(Request::new(
            RequestMeta::default().family(Family::Unspec),
            RequestOperation::List(Some(
                Filter::default()
                    .tcp_state(TcpState::TimeWait)
                    .status(Status::assured()),
            )),
        ))
        .await
        .unwrap();
        let mut received = 0;
        while let Some(flows) = ct.try_next().await.unwrap() {
            received += flows.len();
        }
        assert_eq!(received, 1);

        // no matched flows
        ct.request(Request::new(
            RequestMeta::default().family(Family::Ipv6),
            RequestOperation::List(Some(Filter::default().protocol(Protocol::Tcp))),
        ))
        .await
        .unwrap();
        let mut received = 0;
        while let Some(flows) = ct.try_next().await.unwrap() {
            received += flows.len();
        }
        assert_eq!(received, 0);
    }

    #[ignore = "With privilege"]
    #[tokio::test]
    async fn test_conntrack_poll_with_privilege() {
        let mut ct = Conntrack::new(ConntrackOption::default()).unwrap();
        ct.request(Request::new(
            RequestMeta::default(),
            RequestOperation::List(None),
        ))
        .await
        .unwrap();

        while let Some(_flows) = ct
            .try_next()
            .await
            .expect("Failed to parse Flow from CtNetlink message")
        {}
    }
}
