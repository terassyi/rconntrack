use conntrack::{
    event::{EventGroup, EventType},
    request::Request,
    socket::NfConntrackSocket,
    Conntrack,
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
                EventGroup::default()
                    .set(EventType::Update)
                    .set(EventType::Destroy),
            )
            .map_err(Error::Conntrack)?
        } else {
            Conntrack::new(EventGroup::default()).map_err(Error::Conntrack)?
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
}
