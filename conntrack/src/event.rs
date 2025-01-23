use netlink_packet_netfilter::ctnetlink::message::CtNetlinkMessage;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Event {
    pub flag: u16,
    pub msg: CtNetlinkMessage,
}

impl Event {
    pub fn new(msg: CtNetlinkMessage, flag: u16) -> Event {
        Event { flag, msg }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EventType {
    New = 1,
    Update = 2,
    Destroy = 4,
}

impl From<EventType> for String {
    fn from(e: EventType) -> Self {
        match e {
            EventType::New => String::from("New"),
            EventType::Update => String::from("Update"),
            EventType::Destroy => String::from("Destroy"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventGroup {
    inner: u32,
}

impl EventGroup {
    pub fn set(mut self, t: EventType) -> Self {
        self.inner |= t as u32;
        self
    }
}

impl Default for EventGroup {
    fn default() -> Self {
        EventGroup {
            inner: EventType::New as u32,
        }
    }
}

impl From<EventGroup> for u32 {
    fn from(g: EventGroup) -> Self {
        g.inner
    }
}

impl From<u32> for EventGroup {
    fn from(g: u32) -> Self {
        EventGroup { inner: g }
    }
}
