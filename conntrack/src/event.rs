use netlink_packet_netfilter::ctnetlink::{message::CtNetlinkMessage, nlas::stat::nla::StatNla};

use crate::{
    error::Error,
    flow::{Flow, FlowBuilder},
    message::{Message, MessageType},
    stats::Stats,
};

pub enum Event {
    Flow(Flow),
    Count(u32),
    Stats(Stats),
}

impl TryFrom<&Message> for Event {
    type Error = Error;

    fn try_from(msg: &Message) -> Result<Self, Self::Error> {
        // This constant is defined in Linux kernel (linux/netlink.h)
        const NLM_F_CREATE: u16 = 0x400;
        match &msg.msg {
            CtNetlinkMessage::New(nlas) => {
                let mut builder = FlowBuilder::try_from(nlas).map_err(Error::Flow)?;
                builder = if msg.flag & NLM_F_CREATE != 0 {
                    builder.event_type(MessageType::New)
                } else {
                    builder.event_type(MessageType::Update)
                };
                let flow = builder.build().map_err(Error::Flow)?;
                Ok(Event::Flow(flow))
            }
            CtNetlinkMessage::Delete(nlas) => {
                let flow = FlowBuilder::try_from(nlas)
                    .map_err(Error::Flow)?
                    .event_type(MessageType::Destroy)
                    .build()
                    .map_err(Error::Flow)?;
                Ok(Event::Flow(flow))
            }
            CtNetlinkMessage::GetStats(Some(nlas)) => {
                let counter = nlas
                    .iter()
                    .find_map(|nla| match nla {
                        StatNla::Searched(c) => Some(*c),
                        _ => None,
                    })
                    .ok_or(Error::Message("failed to get the counter".to_string()))?;
                Ok(Event::Count(counter))
            }
            CtNetlinkMessage::GetStatsCPU(Some(nlas)) => {
                Ok(Event::Stats(Stats::from_nlas(msg.res_id, nlas)))
            }
            _ => Err(Error::Message(format!(
                "unknown message type: {}",
                msg.msg.message_type()
            ))),
        }
    }
}
