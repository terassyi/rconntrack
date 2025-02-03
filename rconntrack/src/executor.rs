use conntrack::{
    message::{MessageGroup, MessageType},
    request::Request,
    socket::NfConntrackSocket,
    Conntrack, ConntrackOption,
};

use crate::error::Error;

pub(crate) trait Operation {
    fn request(&self) -> Result<Request, Error>;
    fn typ(&self) -> OperationType;
}

pub(super) struct Executor<O: Operation> {
    op: O,
}

impl<O> Executor<O>
where
    O: Operation,
{
    pub(super) fn new(op: O) -> Executor<O> {
        Executor { op }
    }

    pub(super) async fn exec(&self) -> Result<Conntrack<NfConntrackSocket>, Error> {
        let mut ct = if self.op.typ().eq(&OperationType::Event) {
            Conntrack::new(
                ConntrackOption::default().set_flow_event_group(
                    MessageGroup::default()
                        .set(MessageType::Update)
                        .set(MessageType::Destroy),
                ),
            )
            .map_err(Error::Conntrack)?
        } else {
            Conntrack::new(ConntrackOption::default()).map_err(Error::Conntrack)?
        };
        let req = self.op.request()?;
        ct.request(req).await.map_err(Error::Conntrack)?;
        Ok(ct)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationType {
    Get,
    List,
    Event,
    Counter,
    Stats,
}
