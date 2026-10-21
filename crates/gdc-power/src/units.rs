//! Charge arithmetic and the injected clock.
//!
//! Charge is held as an integer count of picocoulombs, which is the same thing
//! as one microamp flowing for one microsecond. Every current in the cost table
//! is in microamps and every duration in microseconds, so an event cost is a
//! single multiply with no rounding at all. That matters more than it looks: a
//! float accumulator over a 24-hour relay simulation at thousands of events per
//! second drifts, and a drifting battery number is exactly the kind of figure
//! this project is not allowed to publish.

/// Picocoulombs in one milliamp-hour. 1 mAh = 3.6 C.
pub const PC_PER_MAH: u64 = 3_600_000_000_000;

/// Microseconds in one hour. Used wherever a per-hour rate is integrated.
pub const US_PER_HOUR: u64 = 3_600_000_000;

/// Milliseconds in one hour.
pub const MS_PER_HOUR: u64 = 3_600_000;

/// An amount of electric charge, in picocoulombs (equivalently microamp-microseconds).
///
/// Saturating throughout. A saturated charge is a bug, but a panic on an
/// arithmetic edge in the energy accountant would take down a node, and the
/// house rule is that nothing driven by remote input panics.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Charge(u64);

impl Charge {
    pub const ZERO: Charge = Charge(0);

    pub const fn from_pc(pc: u64) -> Self {
        Charge(pc)
    }

    /// A constant current for a duration. The only primitive the cost table needs.
    pub const fn from_ua_us(current_ua: u64, dur_us: u64) -> Self {
        Charge(current_ua.saturating_mul(dur_us))
    }

    /// Microcoulombs, for event costs that are quoted as a lump rather than as
    /// a current times a time.
    pub const fn from_uc(uc: u64) -> Self {
        Charge(uc.saturating_mul(1_000_000))
    }

    /// Milliamp-hours, for budgets and for recalibration against a field
    /// measurement. Lossy at the picocoulomb, which is 2.8e-13 mAh and
    /// therefore irrelevant.
    pub fn from_mah(mah: f64) -> Self {
        if !mah.is_finite() || mah <= 0.0 {
            return Charge::ZERO;
        }
        Charge((mah * PC_PER_MAH as f64) as u64)
    }

    pub const fn as_pc(self) -> u64 {
        self.0
    }

    pub fn as_mah(self) -> f64 {
        self.0 as f64 / PC_PER_MAH as f64
    }

    /// Average current, in microamps, if this charge is spent over `dur_us`.
    pub fn as_mean_ua(self, dur_us: u64) -> u64 {
        if dur_us == 0 {
            return 0;
        }
        self.0 / dur_us
    }

    pub const fn saturating_add(self, other: Charge) -> Charge {
        Charge(self.0.saturating_add(other.0))
    }

    pub const fn saturating_sub(self, other: Charge) -> Charge {
        Charge(self.0.saturating_sub(other.0))
    }

    pub const fn saturating_mul(self, n: u64) -> Charge {
        Charge(self.0.saturating_mul(n))
    }

    /// Scale by the rational `num/den`. Used for duty cycles and for the
    /// per-priority slices of the budget, both of which must stay in integers
    /// so that two runs of the simulator agree bit for bit.
    pub const fn scaled(self, num: u64, den: u64) -> Charge {
        if den == 0 {
            return Charge::ZERO;
        }
        // Reassociate to keep the product in range for charges up to ~1 Ah.
        match self.0.checked_mul(num) {
            Some(p) => Charge(p / den),
            None => Charge((self.0 / den).saturating_mul(num)),
        }
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Debug for Charge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:.6}mAh", self.as_mah())
    }
}

impl core::ops::Add for Charge {
    type Output = Charge;
    fn add(self, rhs: Charge) -> Charge {
        self.saturating_add(rhs)
    }
}

impl core::iter::Sum for Charge {
    fn sum<I: Iterator<Item = Charge>>(iter: I) -> Charge {
        iter.fold(Charge::ZERO, |a, b| a.saturating_add(b))
    }
}

/// A monotonic millisecond clock, injected.
///
/// There is no call to `std::time` anywhere in this crate. The budget enforcer
/// decides whether a radio may transmit; a test that cannot pin the clock
/// cannot pin that decision, and an energy figure that depends on wall-clock
/// time is not reproducible.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// The clock used by every test and by the simulator.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_ms: core::cell::Cell<u64>,
}

impl ManualClock {
    pub fn new(start_ms: u64) -> Self {
        ManualClock {
            now_ms: core::cell::Cell::new(start_ms),
        }
    }

    pub fn advance_ms(&self, by: u64) {
        self.now_ms.set(self.now_ms.get().saturating_add(by));
    }

    pub fn set_ms(&self, to: u64) {
        self.now_ms.set(to);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.get()
    }
}

impl<T: Clock + ?Sized> Clock for &T {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mah_is_one_milliamp_for_one_hour() {
        let c = Charge::from_ua_us(1_000, US_PER_HOUR);
        assert_eq!(c.as_pc(), PC_PER_MAH);
        assert!((c.as_mah() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn mean_current_round_trips() {
        let c = Charge::from_ua_us(11_000, 1_024_000);
        assert_eq!(c.as_mean_ua(1_024_000), 11_000);
    }

    #[test]
    fn scaling_stays_exact_for_clean_ratios() {
        let c = Charge::from_mah(200.0);
        assert_eq!(c.scaled(1, 4).as_pc(), c.as_pc() / 4);
        assert_eq!(c.scaled(7, 10).as_pc(), c.as_pc() / 10 * 7);
    }

    #[test]
    fn scaling_does_not_overflow_on_huge_charges() {
        let c = Charge::from_pc(u64::MAX / 2);
        // Would overflow a naive multiply-then-divide.
        assert!(c.scaled(3, 4).as_pc() > c.as_pc() / 2);
    }

    #[test]
    fn arithmetic_saturates_instead_of_panicking() {
        assert_eq!(Charge::ZERO.saturating_sub(Charge::from_uc(1)), Charge::ZERO);
        assert_eq!(Charge::from_pc(u64::MAX).saturating_mul(2).as_pc(), u64::MAX);
        assert_eq!(Charge::from_mah(f64::NAN), Charge::ZERO);
        assert_eq!(Charge::from_mah(-1.0), Charge::ZERO);
    }

    #[test]
    fn manual_clock_is_the_only_time_source() {
        let c = ManualClock::new(1_000);
        assert_eq!(c.now_ms(), 1_000);
        c.advance_ms(500);
        assert_eq!(c.now_ms(), 1_500);
    }
}
