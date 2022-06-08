use std::time::Instant;

mod determine_mapping;

pub(crate) use determine_mapping::DetermineMappingSession;

#[derive(Clone, Copy, Debug)]
pub(crate) enum StunEvent {
    Idle { now: Instant },
    DatagramReceived,
}

pub(crate) trait StunSession: Sized + Copy + std::fmt::Debug {
    type Outgoing: std::fmt::Debug;
    type Messages: std::fmt::Debug;

    fn process(self, event: StunEvent) -> (Self, Self::Outgoing, Self::Messages);
    fn timeout(&self) -> Option<Instant>;
}
