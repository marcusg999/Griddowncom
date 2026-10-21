//! Simulation time and the injected clock.
//!
//! Nothing in this crate reads a wall clock. Every timestamp a stack or a
//! metric ever sees comes from here, so a run is reproducible from its seed and
//! a test can pin behaviour to an exact microsecond.

use serde::{Deserialize, Serialize};

/// Microseconds since the start of the run.
pub type Micros = u64;

/// A point in simulated time, microsecond resolution.
///
/// Microseconds rather than nanoseconds because the shortest thing we model is
/// a BLE packet (hundreds of microseconds) and the longest is a two-hour
/// deadline; u64 microseconds covers 580 000 years, so no run can overflow it.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Serialize, Deserialize,
)]
pub struct SimTime(Micros);

impl SimTime {
    pub const ZERO: SimTime = SimTime(0);

    pub const fn from_micros(us: Micros) -> Self {
        SimTime(us)
    }

    /// Lossy by construction: negative, NaN and overflowing inputs clamp to a
    /// representable value rather than panicking, because scenario files are
    /// untrusted input.
    pub fn from_millis_f64(ms: f64) -> Self {
        SimTime(saturating_us(ms * 1_000.0))
    }

    pub fn from_secs_f64(s: f64) -> Self {
        SimTime(saturating_us(s * 1_000_000.0))
    }

    pub const fn from_secs(s: u64) -> Self {
        SimTime(s.saturating_mul(1_000_000))
    }

    pub const fn as_micros(self) -> Micros {
        self.0
    }

    pub fn as_secs_f64(self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }

    pub fn as_millis_f64(self) -> f64 {
        self.0 as f64 / 1_000.0
    }

    pub const fn saturating_add(self, other: SimTime) -> Self {
        SimTime(self.0.saturating_add(other.0))
    }

    pub const fn saturating_sub(self, other: SimTime) -> Self {
        SimTime(self.0.saturating_sub(other.0))
    }

    pub const fn saturating_mul(self, k: u64) -> Self {
        SimTime(self.0.saturating_mul(k))
    }
}

fn saturating_us(v: f64) -> Micros {
    // `as` on f64 -> u64 in Rust is a saturating cast and maps NaN to 0, so this
    // cannot panic and cannot wrap. Stated explicitly because the whole
    // no-panic property of scenario loading rests on it.
    if v.is_nan() {
        0
    } else {
        v as u64
    }
}

/// Anything that can report the current simulated time.
///
/// The engine owns the only implementation that advances; stacks receive the
/// time as a value so they cannot reach for a real clock.
pub trait Clock {
    fn now(&self) -> SimTime;
}

/// A clock the engine advances by hand as it pops events.
#[derive(Clone, Copy, Default, Debug)]
pub struct ManualClock {
    now: SimTime,
}

impl ManualClock {
    pub fn new(start: SimTime) -> Self {
        ManualClock { now: start }
    }

    /// Monotonic by construction: time never moves backwards even if an event
    /// is somehow scheduled in the past.
    pub fn advance_to(&mut self, t: SimTime) {
        if t > self.now {
            self.now = t;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SimTime {
        self.now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_floats_clamp_instead_of_panicking() {
        assert_eq!(SimTime::from_secs_f64(f64::NAN), SimTime::ZERO);
        assert_eq!(SimTime::from_secs_f64(-5.0), SimTime::ZERO);
        assert_eq!(SimTime::from_secs_f64(f64::INFINITY).as_micros(), u64::MAX);
    }

    #[test]
    fn clock_is_monotonic() {
        let mut c = ManualClock::new(SimTime::from_secs(10));
        c.advance_to(SimTime::from_secs(5));
        assert_eq!(c.now(), SimTime::from_secs(10));
        c.advance_to(SimTime::from_secs(11));
        assert_eq!(c.now(), SimTime::from_secs(11));
    }
}
