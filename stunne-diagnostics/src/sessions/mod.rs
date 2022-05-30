use std::time::{Duration, Instant};

mod determine_mapping;

pub(crate) use determine_mapping::DetermineMappingSession;

pub(crate) enum Instructions {
    Done,
    Continue(Duration),
}

pub(crate) trait StunSession {
    type Error;

    fn process(&mut self, now: Instant) -> Result<Instructions, Self::Error>;

    /// Process events (e.g., incoming bytes, possibly a way to signal we want the thing to exit)?
    fn recv(&mut self);
}
