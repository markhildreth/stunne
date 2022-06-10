use crate::sessions::{StunEvent, StunSessionState, StunSessionStatus};
use std::time::{Duration, Instant};

const TIMEOUT_SECS: Duration = Duration::from_secs(3);

type DetermineMappingResult = Result<AddressPortMapping, DetermineMappingError>;

#[derive(Debug, Clone, Copy)]
pub(crate) enum AddressPortMapping {
    EndpointIndependent,
    // AddressDependent,
    // AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DetermineMappingError {
    UnexpectedTimeout,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DetermineMappingSession {
    Initial,
    FirstPacketSent {
        timeout_at: Instant,
    },
    Complete {
        result: Result<AddressPortMapping, DetermineMappingError>,
    },
}

impl Default for DetermineMappingSession {
    fn default() -> Self {
        Self::Initial
    }
}

impl DetermineMappingSession {
    fn no_change(self) -> (Self, OutgoingDatagrams) {
        (self, OutgoingDatagrams::None)
    }
}

impl StunSessionState for DetermineMappingSession {
    type Outgoing = OutgoingDatagrams;
    type Output = DetermineMappingResult;

    fn process(self, event: &StunEvent) -> (Self, Self::Outgoing) {
        match (self, event) {
            (Self::Initial, StunEvent::Idle { now }) => (
                Self::FirstPacketSent {
                    timeout_at: *now + TIMEOUT_SECS,
                },
                OutgoingDatagrams::FirstAttempt,
            ),
            (Self::Initial, StunEvent::DatagramReceived { .. }) => self.no_change(),
            (Self::FirstPacketSent { timeout_at }, StunEvent::Idle { now })
                if timeout_at < *now =>
            {
                (
                    Self::Complete {
                        result: Err(DetermineMappingError::UnexpectedTimeout),
                    },
                    OutgoingDatagrams::None,
                )
            }
            (Self::FirstPacketSent { .. }, StunEvent::Idle { .. }) => self.no_change(),
            (Self::FirstPacketSent { .. }, StunEvent::DatagramReceived { .. }) => (
                Self::Complete {
                    result: Ok(AddressPortMapping::EndpointIndependent),
                },
                OutgoingDatagrams::None,
            ),
            (Self::Complete { .. }, _) => self.no_change(),
        }
    }

    fn status(&self) -> StunSessionStatus<Self::Output> {
        match self {
            // TODO: The initial state needs a listing here, even though theoretically the first thing
            // a session runner should do it give the state the ability to process the initial state
            // and send initial datagram packets before needing to ask if it needs to sleep. This
            // makes me think that the types need to be changed here. Perhaps a session should have a
            // function like "initial_process" with a similar siganture to "process" which then returns
            // the session state? That eliminates needing to do this bogus timeout.
            Self::Initial => StunSessionStatus::Waiting {
                timeout: Instant::now() + Duration::from_secs(10),
            },
            Self::FirstPacketSent { timeout_at } => StunSessionStatus::Waiting {
                timeout: *timeout_at,
            },
            Self::Complete { result } => StunSessionStatus::Complete { result: *result },
        }
    }
}

#[derive(Debug)]
pub(crate) enum OutgoingDatagrams {
    None,
    FirstAttempt,
}
