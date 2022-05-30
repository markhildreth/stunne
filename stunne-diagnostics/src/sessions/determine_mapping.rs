use crate::sessions::{Instructions, StunSession};
use std::time::{Duration, Instant};

const TIMEOUT_SECS: Duration = Duration::from_secs(3);

/*
pub(crate) enum DetermineMappingResult {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}
*/

#[derive(Debug)]
pub(crate) enum DetermineMappingError {
    InvalidTimeout,
}

#[derive(Debug)]
pub(crate) struct DetermineMappingSession {
    timeout: Option<Instant>,
    received: bool,
}

impl DetermineMappingSession {
    pub(crate) fn new() -> Self {
        Self {
            timeout: None,
            received: false,
        }
    }
}

impl StunSession for DetermineMappingSession {
    type Error = DetermineMappingError;

    fn process(&mut self, now: Instant) -> Result<Instructions, Self::Error> {
        if self.received {
            return Ok(Instructions::Done);
        }

        match self.timeout {
            Some(t) if t <= now => Err(DetermineMappingError::InvalidTimeout),
            Some(t) => Ok(Instructions::Continue(t - now)),
            None => {
                self.timeout = Some(now + TIMEOUT_SECS);
                Ok(Instructions::Continue(TIMEOUT_SECS))
            }
        }
    }

    fn recv(&mut self) {
        self.received = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_response() {
        let session = DetermineMappingSession::new();
    }
}
