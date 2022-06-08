use crate::sessions::{StunEvent, StunSession};
use std::time::{Duration, Instant};

const TIMEOUT_SECS: Duration = Duration::from_secs(3);

/*
pub(crate) enum DetermineMappingResult {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}
*/

#[derive(Clone, Copy, Debug)]
pub(crate) enum DetermineMappingSession {
    Initial,
    FirstPacketSent { timeout_at: Instant },
    Done,
}

impl DetermineMappingSession {
    pub(crate) fn new() -> Self {
        Self::Initial
    }
}

impl DetermineMappingSession {
    fn no_change(self) -> (Self, OutgoingDatagrams, Messages) {
        (self, OutgoingDatagrams::None, Messages::None)
    }
}

impl StunSession for DetermineMappingSession {
    type Outgoing = OutgoingDatagrams;
    type Messages = Messages;

    fn process(self, event: StunEvent) -> (Self, Self::Outgoing, Self::Messages) {
        match (self, event) {
            (Self::Initial, StunEvent::Idle { now }) => (
                Self::FirstPacketSent {
                    timeout_at: now + TIMEOUT_SECS,
                },
                OutgoingDatagrams::FirstAttempt,
                Messages::None,
            ),
            (Self::Initial, StunEvent::DatagramReceived) => self.no_change(),
            (Self::FirstPacketSent { timeout_at }, StunEvent::Idle { now }) if timeout_at < now => {
                (
                    Self::Done,
                    OutgoingDatagrams::None,
                    Messages::UnexpectedTimeoutError,
                )
            }
            (Self::FirstPacketSent { .. }, StunEvent::Idle { .. }) => self.no_change(),
            (Self::FirstPacketSent { .. }, StunEvent::DatagramReceived { .. }) => {
                (Self::Done, OutgoingDatagrams::None, Messages::Finished)
            }
            (Self::Done, _) => self.no_change(),
        }
    }

    fn timeout(&self) -> Option<Instant> {
        match self {
            Self::Initial => None,
            Self::FirstPacketSent { timeout_at } => Some(*timeout_at),
            Self::Done => None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum OutgoingDatagrams {
    None,
    FirstAttempt,
}

#[derive(Debug)]
pub(crate) enum Messages {
    None,
    UnexpectedTimeoutError,
    Finished,
}
