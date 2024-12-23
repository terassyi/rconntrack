use std::{pin::Pin, task::Poll};

use async_trait::async_trait;
use futures::Stream;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    constants::{AF_INET, AF_INET6, AF_UNSPEC, NFNETLINK_V0},
    ctnetlink::message::CtNetlinkMessage,
    NetfilterHeader, NetfilterMessage,
};
use netlink_sys::{protocols::NETLINK_NETFILTER, AsyncSocket, AsyncSocketExt, TokioSocket};

use crate::{error::Error, flow::Flow};

#[async_trait]
pub trait ConntrackSocket: Stream {
    async fn send(&mut self, msg: NetlinkMessage<NetfilterMessage>) -> Result<(), Error>;
    async fn recv(&mut self) -> Result<Vec<NetfilterMessage>, Error>;
    async fn recv_once(&mut self) -> Result<Vec<NetfilterMessage>, Error>;
}

pub struct NfConntrackSocket {
    inner: TokioSocket,
}

impl NfConntrackSocket {
    pub(super) fn new() -> Result<NfConntrackSocket, Error> {
        let socket = TokioSocket::new(NETLINK_NETFILTER).map_err(Error::Socket)?;
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

    async fn recv(&mut self) -> Result<Vec<NetfilterMessage>, Error> {
        let mut msgs = Vec::new();
        let mut done = false;
        loop {
            let (data, _) = self.inner.recv_from_full().await.map_err(Error::Recv)?;
            let data_l = data.len();
            let mut read = 0;
            while data_l > read {
                let msg = <NetlinkMessage<NetfilterMessage>>::deserialize(&data[read..])
                    .map_err(Error::Netfilter)?;
                read += msg.buffer_len();
                match msg.payload {
                    NetlinkPayload::Done(_) => {
                        done = true;
                        break;
                    }
                    NetlinkPayload::Error(e) => return Err(Error::NetlinkMessage(e.raw_code())),
                    NetlinkPayload::InnerMessage(msg) => {
                        msgs.push(msg);
                    }
                    _ => {}
                }
            }
            if done {
                break;
            }
        }

        Ok(msgs)
    }

    async fn recv_once(&mut self) -> Result<Vec<NetfilterMessage>, Error> {
        let mut msgs = Vec::new();
        let (data, _) = self.inner.recv_from_full().await.map_err(Error::Recv)?;
        let data_l = data.len();
        let mut read = 0;
        while data_l > read {
            let msg = <NetlinkMessage<NetfilterMessage>>::deserialize(&data[read..])
                .map_err(Error::Netfilter)?;
            read += msg.buffer_len();
            match msg.payload {
                NetlinkPayload::Done(_) => {
                    break;
                }
                NetlinkPayload::Error(e) => return Err(Error::NetlinkMessage(e.raw_code())),
                NetlinkPayload::InnerMessage(msg) => {
                    msgs.push(msg);
                }
                _ => {}
            }
        }

        Ok(msgs)
    }
}

impl Stream for NfConntrackSocket {
    type Item = Result<Vec<NetfilterMessage>, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.inner.poll_recv_from_full(cx) {
            Poll::Ready(res) => match res {
                Ok((buf, _)) => {
                    let mut msgs = Vec::new();
                    let l = buf.len();
                    let mut read = 0;
                    while l > read {
                        let msg =
                            match <NetlinkMessage<NetfilterMessage>>::deserialize(&buf[read..]) {
                                Ok(msg) => msg,
                                Err(e) => return Poll::Ready(Some(Err(Error::Netfilter(e)))),
                            };
                        read += msg.buffer_len();
                        match msg.payload {
                            NetlinkPayload::Done(_) => {
                                // When receiving a done message, msgs must be empty.
                                // Even if msgs is not empty, ignore it.
                                return Poll::Ready(None);
                            }
                            NetlinkPayload::Error(e) => {
                                return Poll::Ready(Some(Err(Error::NetlinkMessage(e.raw_code()))));
                            }
                            NetlinkPayload::InnerMessage(msg) => {
                                msgs.push(msg);
                            }
                            _ => {}
                        }
                    }
                    Poll::Ready(Some(Ok(msgs)))
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
    ipv4_data: Vec<NetfilterMessage>,
    ipv6_data: Vec<NetfilterMessage>,
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
        let ipv4_header = NetfilterHeader::new(AF_INET, NFNETLINK_V0, 0);
        let ipv6_header = NetfilterHeader::new(AF_INET6, NFNETLINK_V0, 0);
        let ipv4_msgs = ipv4_flows
            .iter()
            .map(|f| {
                NetfilterMessage::new(ipv4_header.clone(), CtNetlinkMessage::try_from(f).unwrap())
            })
            .collect();
        let ipv6_msgs = ipv6_flows
            .iter()
            .map(|f| {
                NetfilterMessage::new(ipv6_header.clone(), CtNetlinkMessage::try_from(f).unwrap())
            })
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
    pub(super) fn with_msg(
        ipv4_msg: Vec<NetfilterMessage>,
        ipv6_msg: Vec<NetfilterMessage>,
    ) -> MockConntrackSocket {
        MockConntrackSocket {
            request: None,
            ipv4_data: ipv4_msg,
            ipv6_data: ipv6_msg,
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

    async fn recv(&mut self) -> Result<Vec<NetfilterMessage>, Error> {
        Ok(vec![])
    }

    async fn recv_once(&mut self) -> Result<Vec<NetfilterMessage>, Error> {
        Ok(vec![])
    }
}

impl Stream for MockConntrackSocket {
    type Item = Result<Vec<NetfilterMessage>, Error>;

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
    use netlink_packet_netfilter::{
        constants::{AF_INET, AF_INET6, NFNETLINK_V0},
        ctnetlink::message::CtNetlinkMessage,
        NetfilterHeader, NetfilterMessage, NetfilterMessageInner,
    };

    use crate::{
        message::MessageBuilder,
        socket::{ConntrackSocket, MockConntrackSocket},
        Family, Table,
    };

    const IPV4_NF_HDR: NetfilterHeader = NetfilterHeader {
        family: AF_INET,
        version: NFNETLINK_V0,
        res_id: 0,
    };

    const IPV4_MSGS: [NetfilterMessage; 5] = [
        NetfilterMessage {
            header: IPV4_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
        NetfilterMessage {
            header: IPV4_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
        NetfilterMessage {
            header: IPV4_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
        NetfilterMessage {
            header: IPV4_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
        NetfilterMessage {
            header: IPV4_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
    ];

    const IPV6_NF_HDR: NetfilterHeader = NetfilterHeader {
        family: AF_INET6,
        version: NFNETLINK_V0,
        res_id: 0,
    };

    const IPV6_MSGS: [NetfilterMessage; 3] = [
        NetfilterMessage {
            header: IPV6_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
        NetfilterMessage {
            header: IPV6_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
        NetfilterMessage {
            header: IPV6_NF_HDR,
            inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::New(vec![])),
        },
    ];

    #[tokio::test]
    async fn test_mock_conntrack_socket_poll() {
        let mut mock_socket = MockConntrackSocket::with_msg(IPV4_MSGS.to_vec(), IPV6_MSGS.to_vec());
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
