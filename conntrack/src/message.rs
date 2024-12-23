use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP};
use netlink_packet_netfilter::{
    constants::{NFNETLINK_V0, NLM_F_REQUEST},
    ctnetlink::message::CtNetlinkMessage,
    NetfilterHeader, NetfilterMessage,
};

use crate::{Family, Table};

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
