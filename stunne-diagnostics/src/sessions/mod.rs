use std::time::Instant;

mod determine_mapping;

pub(crate) use determine_mapping::DetermineMappingSession;

#[derive(Debug)]
pub(crate) enum StunEvent<'a> {
    Idle { now: Instant },
    DatagramReceived { bytes: &'a [u8] },
}

pub(crate) trait StunSessionState: Sized + Copy + std::fmt::Debug {
    type Outgoing: std::fmt::Debug;
    type Output;

    fn process(self, event: &StunEvent) -> (Self, Self::Outgoing);
    fn status(&self) -> StunSessionStatus<Self::Output>;
}

#[derive(Debug)]
pub(crate) struct StunSession<T> {
    state: T,
}

impl<T> StunSession<T>
where
    T: StunSessionState,
{
    pub(crate) fn new(state: T) -> Self {
        Self { state }
    }

    pub(crate) fn process(&mut self, event: &StunEvent) -> T::Outgoing {
        let (new_state, outgoing) = self.state.process(event);
        self.state = new_state;
        outgoing
    }

    pub(crate) fn status(&self) -> StunSessionStatus<T::Output> {
        self.state.status()
    }
}

#[derive(Debug)]
pub(crate) enum StunSessionStatus<T> {
    Waiting { timeout: Instant },
    Complete { result: T },
}
