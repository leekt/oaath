//! Injected clock. Expiry is never read from the system clock directly, so
//! tests and deployments own time.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{RelayErrorCode, RelayResult};
use crate::records::MAX_TIMESTAMP;

pub trait RelayClock: Send + Sync {
    /// Milliseconds since the Unix epoch, or `None` when the clock is unreadable.
    fn now(&self) -> Option<u64>;
}

/// An unreadable or out-of-range clock is an internal failure.
pub fn relay_now(clock: &dyn RelayClock) -> RelayResult<u64> {
    match clock.now() {
        Some(now) if now <= MAX_TIMESTAMP => Ok(now),
        _ => Err(RelayErrorCode::Internal),
    }
}

/// The deployment's wall clock.
pub struct SystemClock;

impl RelayClock for SystemClock {
    fn now(&self) -> Option<u64> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        u64::try_from(elapsed.as_millis()).ok()
    }
}
