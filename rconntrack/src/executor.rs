use conntrack::{request::Request, socket::NfConntrackSocket, Conntrack};

use crate::error::Error;

pub(crate) trait Operation {
    fn request(&self) -> Result<Request, Error>;
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
        let mut ct = Conntrack::new().map_err(Error::Conntrack)?;
        let req = self.op.request()?;
        ct.request(req).await.map_err(Error::Conntrack)?;
        Ok(ct)
    }
}
