use std::{pin::Pin, task::Poll};

use async_trait::async_trait;
use futures::Stream;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    constants::{AF_INET, AF_INET6, AF_UNSPEC},
    ctnetlink::message::CtNetlinkMessage,
    NetfilterMessage, NetfilterMessageInner,
};
use netlink_sys::{
    protocols::NETLINK_NETFILTER, AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket,
};

use crate::{
    error::{Error, NetlinkError},
    flow::Flow,
    message::{Message, MessageGroup},
};

#[async_trait]
pub trait ConntrackSocket: Stream {
    async fn send(&mut self, msg: NetlinkMessage<NetfilterMessage>) -> Result<(), Error>;
    async fn recv(&mut self) -> Result<Vec<Message>, Error>;
    async fn recv_once(&mut self) -> Result<Vec<Message>, Error>;
}

pub struct NfConntrackSocket {
    inner: TokioSocket,
}

impl NfConntrackSocket {
    const SOCKET_AUTOPID: u32 = 0;
    pub(super) fn new(group: MessageGroup) -> Result<NfConntrackSocket, Error> {
        let mut socket = TokioSocket::new(NETLINK_NETFILTER).map_err(Error::Socket)?;
        let socket_ref_mut = socket.socket_mut();
        socket_ref_mut
            .bind(&SocketAddr::new(Self::SOCKET_AUTOPID, group.into()))
            .map_err(Error::Socket)?;
        Ok(NfConntrackSocket { inner: socket })
    }
}

#[async_trait]
impl ConntrackSocket for NfConntrackSocket {
    async fn send(&mut self, msg: NetlinkMessage<NetfilterMessage>) -> Result<(), Error> {
        let mut buf = vec![0u8; msg.header.length as usize];
        msg.serialize(&mut buf[..]);
        self.inner.send(&buf).await.map_err(Error::Send)?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<Message>, Error> {
        let mut events = Vec::new();
        let mut done = false;
        loop {
            let (data, _) = self.inner.recv_from_full().await.map_err(Error::Recv)?;
            let data_l = data.len();
            let mut read = 0;
            while data_l > read {
                let msg = <NetlinkMessage<NetfilterMessage>>::deserialize(&data[read..])
                    .map_err(Error::Netfilter)?;
                read += msg.buffer_len();
                let flag = msg.header.flags;
                match msg.payload {
                    NetlinkPayload::Done(_) => {
                        done = true;
                        break;
                    }
                    NetlinkPayload::Error(e) => {
                        return Err(Error::NetlinkMessage(NetlinkError::from(e.raw_code())))
                    }
                    NetlinkPayload::InnerMessage(msg) => {
                        let res_id = msg.header.res_id;
                        if let NetfilterMessageInner::CtNetlink(msg) = msg.inner {
                            events.push(Message::new(msg, flag, res_id));
                        }
                    }
                    _ => {}
                }
            }
            if done {
                break;
            }
        }

        Ok(events)
    }

    async fn recv_once(&mut self) -> Result<Vec<Message>, Error> {
        let mut events = Vec::new();
        let (data, _) = self.inner.recv_from_full().await.map_err(Error::Recv)?;
        let data_l = data.len();
        let mut read = 0;
        while data_l > read {
            let msg = <NetlinkMessage<NetfilterMessage>>::deserialize(&data[read..])
                .map_err(Error::Netfilter)?;
            read += msg.buffer_len();
            let flag = msg.header.flags;
            match msg.payload {
                NetlinkPayload::Done(_) => {
                    break;
                }
                NetlinkPayload::Error(e) => {
                    return Err(Error::NetlinkMessage(NetlinkError::from(e.raw_code())))
                }
                NetlinkPayload::InnerMessage(msg) => {
                    let res_id = msg.header.res_id;
                    if let NetfilterMessageInner::CtNetlink(msg) = msg.inner {
                        events.push(Message::new(msg, flag, res_id));
                    }
                }
                _ => {}
            }
        }

        Ok(events)
    }
}

impl Stream for NfConntrackSocket {
    type Item = Result<Vec<Message>, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.inner.poll_recv_from_full(cx) {
            Poll::Ready(res) => match res {
                Ok((buf, _)) => {
                    let mut events = Vec::new();
                    let l = buf.len();
                    let mut read = 0;
                    while l > read {
                        let msg =
                            match <NetlinkMessage<NetfilterMessage>>::deserialize(&buf[read..]) {
                                Ok(msg) => msg,
                                Err(e) => return Poll::Ready(Some(Err(Error::Netfilter(e)))),
                            };
                        read += msg.buffer_len();
                        let flag = msg.header.flags;
                        match msg.payload {
                            NetlinkPayload::Done(_) => {
                                // When receiving a done message, msgs must be empty.
                                // Even if msgs is not empty, ignore it.
                                return Poll::Ready(None);
                            }
                            NetlinkPayload::Error(e) => {
                                return Poll::Ready(Some(Err(Error::NetlinkMessage(
                                    NetlinkError::from(e.raw_code()),
                                ))));
                            }
                            NetlinkPayload::InnerMessage(msg) => {
                                let res_id = msg.header.res_id;
                                if let NetfilterMessageInner::CtNetlink(msg) = msg.inner {
                                    events.push(Message::new(msg, flag, res_id));
                                }
                            }
                            _ => {}
                        }
                    }
                    Poll::Ready(Some(Ok(events)))
                }
                Err(e) => Poll::Ready(Some(Err(Error::Poll(e)))),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct MockConntrackSocket {
    request: Option<NetfilterMessage>,
    ipv4_data: Vec<Message>,
    ipv6_data: Vec<Message>,
    ipv4_index: usize,
    ipv6_index: usize,
}

impl MockConntrackSocket {
    #[allow(dead_code)]
    pub(super) fn new() -> MockConntrackSocket {
        MockConntrackSocket {
            request: None,
            ipv4_data: Vec::new(),
            ipv6_data: Vec::new(),
            ipv4_index: 0,
            ipv6_index: 0,
        }
    }

    #[allow(dead_code)]
    pub(super) fn with_flow(ipv4_flows: Vec<Flow>, ipv6_flows: Vec<Flow>) -> MockConntrackSocket {
        let ipv4_msgs = ipv4_flows
            .iter()
            .map(|f| Message::new(CtNetlinkMessage::try_from(f).unwrap(), 0, 0))
            .collect();
        let ipv6_msgs = ipv6_flows
            .iter()
            .map(|f| Message::new(CtNetlinkMessage::try_from(f).unwrap(), 0, 0))
            .collect();

        MockConntrackSocket {
            request: None,
            ipv4_data: ipv4_msgs,
            ipv6_data: ipv6_msgs,
            ipv4_index: 0,
            ipv6_index: 0,
        }
    }

    #[allow(dead_code)]
    pub(super) fn with_event(
        ipv4_event: Vec<Message>,
        ipv6_event: Vec<Message>,
    ) -> MockConntrackSocket {
        MockConntrackSocket {
            request: None,
            ipv4_data: ipv4_event,
            ipv6_data: ipv6_event,
            ipv4_index: 0,
            ipv6_index: 0,
        }
    }

    fn clear(&mut self) {
        self.request = None;
        self.ipv4_index = 0;
        self.ipv6_index = 0;
    }
}

#[async_trait]
impl ConntrackSocket for MockConntrackSocket {
    async fn send(&mut self, msg: NetlinkMessage<NetfilterMessage>) -> Result<(), Error> {
        if self.request.is_some() {
            return Err(Error::Recv(std::io::Error::new(
                std::io::ErrorKind::Other,
                "request is already received",
            )));
        }
        if let NetlinkPayload::InnerMessage(nf) = msg.payload {
            self.request = Some(nf);
            Ok(())
        } else {
            Err(Error::Recv(std::io::Error::new(
                std::io::ErrorKind::Other,
                "netfilter message is expected",
            )))
        }
    }

    async fn recv(&mut self) -> Result<Vec<Message>, Error> {
        Ok(vec![])
    }

    async fn recv_once(&mut self) -> Result<Vec<Message>, Error> {
        Ok(vec![])
    }
}

impl Stream for MockConntrackSocket {
    type Item = Result<Vec<Message>, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.request.is_none() {
            return Poll::Ready(Some(Err(Error::Recv(std::io::Error::new(
                std::io::ErrorKind::Other,
                "request is not received yet",
            )))));
        }

        let family = self.request.as_ref().unwrap().header.family;

        match family {
            AF_INET => {
                if self.ipv4_data.is_empty() {
                    return Poll::Ready(Some(Err(Error::Poll(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "empty",
                    )))));
                }
                if self.ipv4_data.len() > self.ipv4_index {
                    if self.ipv4_index + 1 > self.ipv4_data.len() {
                        let data = self.ipv4_data[self.ipv4_index..(self.ipv4_index + 1)].to_vec();
                        self.ipv4_index += 2;
                        Poll::Ready(Some(Ok(data)))
                    } else {
                        let data = vec![self.ipv4_data[self.ipv4_index].clone()];
                        self.ipv4_index += 1;
                        Poll::Ready(Some(Ok(data)))
                    }
                } else {
                    self.clear();
                    Poll::Ready(None)
                }
            }
            AF_INET6 => {
                if self.ipv6_data.is_empty() {
                    return Poll::Ready(Some(Err(Error::Poll(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "empty",
                    )))));
                }
                if self.ipv6_data.len() > self.ipv6_index {
                    if self.ipv6_index + 1 > self.ipv6_data.len() {
                        let data = self.ipv6_data[self.ipv6_index..(self.ipv6_index + 1)].to_vec();
                        self.ipv6_index += 2;
                        Poll::Ready(Some(Ok(data)))
                    } else {
                        let data = vec![self.ipv6_data[self.ipv6_index].clone()];
                        self.ipv6_index += 1;
                        Poll::Ready(Some(Ok(data)))
                    }
                } else {
                    self.clear();
                    Poll::Ready(None)
                }
            }
            AF_UNSPEC => {
                if self.ipv4_data.is_empty() && self.ipv6_data.is_empty() {
                    return Poll::Ready(Some(Err(Error::Poll(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "empty",
                    )))));
                }
                if self.ipv4_data.len() > self.ipv4_index {
                    if self.ipv4_index + 1 > self.ipv4_data.len() {
                        let data = self.ipv4_data[self.ipv4_index..(self.ipv4_index + 1)].to_vec();
                        self.ipv4_index += 2;
                        return Poll::Ready(Some(Ok(data)));
                    } else {
                        let data = vec![self.ipv4_data[self.ipv4_index].clone()];
                        self.ipv4_index += 1;
                        return Poll::Ready(Some(Ok(data)));
                    }
                }
                if self.ipv6_data.len() > self.ipv6_index {
                    if self.ipv6_index + 1 > self.ipv6_data.len() {
                        let data = self.ipv6_data[self.ipv6_index..(self.ipv6_index + 1)].to_vec();
                        self.ipv6_index += 2;
                        Poll::Ready(Some(Ok(data)))
                    } else {
                        let data = vec![self.ipv6_data[self.ipv6_index].clone()];
                        self.ipv6_index += 1;
                        Poll::Ready(Some(Ok(data)))
                    }
                } else {
                    self.clear();
                    Poll::Ready(None)
                }
            }
            _ => {
                self.clear();
                Poll::Ready(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use netlink_packet_netfilter::ctnetlink::message::CtNetlinkMessage;

    use crate::{
        message::{Message, MessageBuilder},
        socket::{ConntrackSocket, MockConntrackSocket},
        Family, Table,
    };

    const IPV4_MSGS: [Message; 5] = [
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
    ];

    const IPV6_MSGS: [Message; 3] = [
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
        Message {
            flag: 0,
            res_id: 0,
            msg: CtNetlinkMessage::New(vec![]),
        },
    ];

    #[tokio::test]
    async fn test_mock_conntrack_socket_poll() {
        let mut mock_socket =
            MockConntrackSocket::with_event(IPV4_MSGS.to_vec(), IPV6_MSGS.to_vec());
        let mut read = 0;
        mock_socket
            .send(MessageBuilder::new(Family::Unspec, Table::Conntrack).list())
            .await
            .unwrap();
        while let Some(_msg) = mock_socket.try_next().await.unwrap() {
            read += 1;
        }
        assert_eq!(8, read);
    }
}
