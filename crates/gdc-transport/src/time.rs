//! Monotonic time, injected.
//!
//! Nothing in this crate reads a wall clock. Every function that needs "now"
//! takes it as an argument or reads it from an injected [`Clock`], so a test can
//! pin link-loss detection, reassembly timeouts and reconnect backoff to exact
//! millisecond boundaries without hardware and without sleeping.

use core::cell::Cell;

/// Milliseconds on a monotonic clock. The epoch is arbitrary and per-process;
/// only differences are meaningful.
///
/// `u64` milliseconds is ~584 million years, so every arithmetic helper here
/// saturates rather than wraps and no code path can produce a negative duration
/// that later underflows.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct Millis(pub u64);

impl Millis {
    pub const ZERO: Millis = Millis(0);

    #[must_use]
    pub const fn secs(s: u64) -> Millis {
        Millis(s.saturating_mul(1000))
    }

    #[must_use]
    pub const fn saturating_add(self, other: Millis) -> Millis {
        Millis(self.0.saturating_add(other.0))
    }

    /// Elapsed time from `earlier` to `self`, clamped at zero.
    ///
    /// A host can hand us an out-of-order timestamp (two radio callbacks racing
    /// on different threads in the Swift or Kotlin shell). Clamping means that
    /// turns into "no time passed" rather than a gigantic duration that would
    /// instantly expire every timer.
    #[must_use]
    pub const fn since(self, earlier: Millis) -> Millis {
        Millis(self.0.saturating_sub(earlier.0))
    }

    #[must_use]
    pub fn as_secs_f32(self) -> f32 {
        self.0 as f32 / 1000.0
    }

    /// Build from seconds, refusing NaN and negatives instead of wrapping.
    #[must_use]
    pub fn from_secs_f32(s: f32) -> Millis {
        if !s.is_finite() || s <= 0.0 {
            return Millis::ZERO;
        }
        Millis((s * 1000.0).min(u64::MAX as f32) as u64)
    }
}

/// A monotonic clock source.
///
/// Implemented by the native shell (`SystemClock` over `CLOCK_MONOTONIC` /
/// `DispatchTime`), by `gdc-sim` over its own virtual time, and by
/// [`TestClock`] in tests.
pub trait Clock {
    /// Monotonic now. Must never go backwards; if the underlying source can,
    /// the implementation is responsible for clamping.
    fn now(&self) -> Millis;
}

/// A hand-cranked clock for tests and for the simulator's first cut.
#[derive(Debug, Default)]
pub struct TestClock {
    now: Cell<u64>,
}

impl TestClock {
    #[must_use]
    pub fn new(start: Millis) -> Self {
        TestClock {
            now: Cell::new(start.0),
        }
    }

    pub fn advance(&self, by: Millis) {
        self.now.set(self.now.get().saturating_add(by.0));
    }

    pub fn set(&self, to: Millis) {
        self.now.set(to.0);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Millis {
        Millis(self.now.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_timestamps_clamp_to_zero() {
        // Two radio callbacks racing in the native shell must not be able to
        // produce a duration that instantly expires every timer in the crate.
        assert_eq!(Millis(5).since(Millis(500)), Millis::ZERO);
    }

    #[test]
    fn durations_saturate_rather_than_wrap() {
        assert_eq!(Millis(u64::MAX).saturating_add(Millis(10)), Millis(u64::MAX));
    }

    #[test]
    fn seconds_conversion_refuses_nonsense() {
        assert_eq!(Millis::from_secs_f32(f32::NAN), Millis::ZERO);
        assert_eq!(Millis::from_secs_f32(-3.0), Millis::ZERO);
        assert_eq!(Millis::from_secs_f32(1.5), Millis(1500));
    }

    #[test]
    fn test_clock_advances_monotonically() {
        let c = TestClock::new(Millis(100));
        c.advance(Millis(50));
        assert_eq!(c.now(), Millis(150));
    }
}
