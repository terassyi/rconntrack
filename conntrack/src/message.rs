use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_MATCH, NLM_F_ROOT,
};
use netlink_packet_netfilter::{
    constants::{NFNETLINK_V0, NLM_F_REQUEST},
    ctnetlink::{message::CtNetlinkMessage, nlas::flow::nla::FlowNla},
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner,
};
use serde::Serialize;

use crate::{request::GetParams, Family, Table};

#[derive(Debug, Clone)]
pub struct Message {
    pub flag: u16,
    pub res_id: u16,
    pub msg: CtNetlinkMessage,
}

impl Message {
    pub fn new(msg: CtNetlinkMessage, flag: u16, res_id: u16) -> Message {
        Message { flag, msg, res_id }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MessageType {
    New = 1,
    Update = 2,
    Destroy = 4,
}

impl From<MessageType> for String {
    fn from(e: MessageType) -> Self {
        match e {
            MessageType::New => String::from("New"),
            MessageType::Update => String::from("Update"),
            MessageType::Destroy => String::from("Destroy"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageGroup {
    inner: u32,
}

impl MessageGroup {
    pub fn set(mut self, t: MessageType) -> Self {
        self.inner |= t as u32;
        self
    }
}

impl Default for MessageGroup {
    fn default() -> Self {
        MessageGroup {
            inner: MessageType::New as u32,
        }
    }
}

impl From<MessageGroup> for u32 {
    fn from(g: MessageGroup) -> Self {
        g.inner
    }
}

impl From<u32> for MessageGroup {
    fn from(g: u32) -> Self {
        MessageGroup { inner: g }
    }
}

#[derive(Debug, Default)]
pub(super) struct MessageBuilder {
    family: Family,
    table: Table,
    res_id: u16,
    flag: u16,
    zero: bool,
}

impl MessageBuilder {
    pub(super) fn new(family: Family, table: Table) -> MessageBuilder {
        MessageBuilder {
            family,
            table,
            res_id: 0,
            flag: NLM_F_REQUEST, // MessageBuilder will be used for building a request message.
            zero: false,
        }
    }

    #[allow(dead_code)]
    pub(super) fn flags(mut self, flag: u16) -> MessageBuilder {
        self.flag |= flag;
        self
    }

    pub(super) fn zero(mut self) -> MessageBuilder {
        self.zero = true;
        self
    }

    pub(super) fn res_id(mut self, id: u16) -> MessageBuilder {
        self.res_id = id;
        self
    }

    pub(super) fn list(&self) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = self.flag | NLM_F_DUMP;
        // Should we set sequence number?

        let mut msg = if self.zero {
            NetlinkMessage::new(
                hdr,
                NetlinkPayload::from(NetfilterMessage::new(
                    NetfilterHeader::new(self.family.into(), NFNETLINK_V0, self.res_id),
                    CtNetlinkMessage::GetCrtZero(None),
                )),
            )
        } else {
            match self.table {
                Table::Conntrack => NetlinkMessage::new(
                    hdr,
                    NetlinkPayload::from(NetfilterMessage::new(
                        NetfilterHeader::new(self.family.into(), NFNETLINK_V0, self.res_id),
                        CtNetlinkMessage::Get(None),
                    )),
                ),
                Table::Dying => NetlinkMessage::new(
                    hdr,
                    NetlinkPayload::from(NetfilterMessage::new(
                        NetfilterHeader::new(self.family.into(), NFNETLINK_V0, self.res_id),
                        CtNetlinkMessage::GetDying(None),
                    )),
                ),
                Table::Unconfirmed => NetlinkMessage::new(
                    hdr,
                    NetlinkPayload::from(NetfilterMessage::new(
                        NetfilterHeader::new(self.family.into(), NFNETLINK_V0, self.res_id),
                        CtNetlinkMessage::GetUnconfirmed(None),
                    )),
                ),
            }
        };
        msg.finalize();
        msg
    }

    pub(super) fn get(&self, param: &GetParams) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = self.flag;
        // Should we set sequence number?
        let nlas = Vec::<FlowNla>::from(param);
        let mut msg = match self.table {
            Table::Conntrack => NetlinkMessage::new(
                hdr,
                NetlinkPayload::from(NetfilterMessage::new(
                    NetfilterHeader::new(self.family.into(), NFNETLINK_V0, self.res_id),
                    CtNetlinkMessage::Get(Some(nlas)),
                )),
            ),
            Table::Dying => NetlinkMessage::from(NetfilterMessage::new(
                NetfilterHeader::new(self.family.into(), NFNETLINK_V0, self.res_id),
                CtNetlinkMessage::GetDying(Some(nlas)),
            )),
            Table::Unconfirmed => NetlinkMessage::from(NetfilterMessage::new(
                NetfilterHeader::new(self.family.into(), NFNETLINK_V0, self.res_id),
                CtNetlinkMessage::GetUnconfirmed(Some(nlas)),
            )),
        };
        msg.finalize();
        msg
    }

    pub(super) fn count(&self) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = self.flag;
        let mut msg = NetlinkMessage::new(
            hdr,
            NetlinkPayload::from(NetfilterMessage::new(
                NetfilterHeader::new(self.family.into(), NFNETLINK_V0, 0),
                NetfilterMessageInner::CtNetlink(CtNetlinkMessage::GetStats(None)),
            )),
        );
        msg.finalize();
        msg
    }

    pub(super) fn stat(&self) -> NetlinkMessage<NetfilterMessage> {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = self.flag | NLM_F_ROOT | NLM_F_MATCH;

        let mut msg = NetlinkMessage::new(
            hdr,
            NetlinkPayload::from(NetfilterMessage::new(
                NetfilterHeader::new(self.family.into(), NFNETLINK_V0, 0),
                NetfilterMessageInner::CtNetlink(CtNetlinkMessage::GetStatsCPU(None)),
            )),
        );
        msg.finalize();
        msg
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_netfilter::{
        constants::{AF_INET, AF_INET6, NFNETLINK_V0},
        ctnetlink::message::CtNetlinkMessage,
        NetfilterHeader, NetfilterMessage, NetfilterMessageInner,
    };
    use rstest::rstest;

    use crate::{Family, Table};

    use super::MessageBuilder;

    const NF_HDR_IPV4: NetfilterHeader = NetfilterHeader {
        family: AF_INET,
        version: NFNETLINK_V0,
        res_id: 0,
    };

    const NF_HDR_IPV6: NetfilterHeader = NetfilterHeader {
        family: AF_INET6,
        version: NFNETLINK_V0,
        res_id: 0,
    };

    const BASE_LIST: NetfilterMessage = NetfilterMessage {
        header: NF_HDR_IPV4,
        inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::Get(None)),
    };

    const BASE_LIST_IPV6: NetfilterMessage = NetfilterMessage {
        header: NF_HDR_IPV6,
        inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::Get(None)),
    };

    const LIST_ZERO: NetfilterMessage = NetfilterMessage {
        header: NF_HDR_IPV4,
        inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::GetCrtZero(None)),
    };

    const LIST_DYING: NetfilterMessage = NetfilterMessage {
        header: NF_HDR_IPV4,
        inner: NetfilterMessageInner::CtNetlink(CtNetlinkMessage::GetDying(None)),
    };

    #[rstest(
        builder,
        expected,
        case(MessageBuilder::default(), BASE_LIST),
        case(MessageBuilder::new(Family::Ipv6, Table::Conntrack), BASE_LIST_IPV6),
        case(MessageBuilder::default().zero(), LIST_ZERO),
        case(MessageBuilder::new(Family::Ipv4, Table::Dying), LIST_DYING),
    )]
    fn test_message_builder_list(builder: MessageBuilder, expected: NetfilterMessage) {
        let payload = builder.list().payload;
        let payload_type = payload.message_type();
        if let NetlinkPayload::InnerMessage(msg) = payload {
            assert_eq!(msg, expected);
        } else {
            panic!("NetlinkPayload::InnerMessage(msg) is expected, but got {payload_type}")
        }
    }
}
