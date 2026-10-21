//! The narrowest interface this crate needs from `gdc-power`.
//!
//! `gdc-power` owns the energy model, the duty-cycle policy and the radio
//! scheduling budget. None of that is transport's business, but transport is
//! where the decisions land: how long to scan, how often to advertise, how much
//! a joule is worth against a second of delivery latency.
//!
//! Per the brief's crate-ownership rule, the traits below are defined here, in
//! the crate that needs them, with a default implementation good enough to test
//! and simulate against. When `gdc-power` lands, it implements these and the
//! defaults are deleted. The orchestrator reconciles.
//!
//! Nothing here is a duty cycle constant. The point of this module is that
//! **no duty cycle is hard-coded in `gdc-transport`** — a reviewer who finds
//! one has found a bug.

use crate::caps::{AppState, Platform};
use crate::link::{BlePhy, CostEstimate};
use crate::time::Millis;

/// How aggressively to run the discovery radios right now.
///
/// A plan, not a constant: produced by [`DutyCyclePolicy`], applied by the
/// native shell through [`crate::native::BleHost::apply`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DutyCycle {
    /// How long a scan runs each period.
    pub scan_window: Millis,
    /// Period between the start of one scan and the start of the next.
    /// `scan_window == scan_period` means continuous scanning.
    pub scan_period: Millis,
    /// BLE advertising interval. The controller's own units are 0.625 ms steps;
    /// the shell converts and clamps.
    pub advertise_interval: Millis,
    /// Whether to advertise at all this period. On a platform that cannot
    /// advertise and scan at once — a backgrounded iPhone — the duty-cycle
    /// policy alternates this instead of trying to do both, and that
    /// alternation is the only correct way to use that row of the matrix.
    pub advertise: bool,
    /// Whether to scan at all this period.
    pub scan: bool,
}

impl DutyCycle {
    /// Fraction of wall time the scanner is on. Used by the energy model and
    /// by the acquisition-time metric.
    #[must_use]
    pub fn scan_ratio(&self) -> f32 {
        if !self.scan || self.scan_period == Millis::ZERO {
            return 0.0;
        }
        (self.scan_window.0 as f32 / self.scan_period.0 as f32).clamp(0.0, 1.0)
    }

    /// Continuous scan and fast advertising. Correct for the foreground, far
    /// too expensive for a day of relay duty.
    #[must_use]
    pub fn aggressive() -> DutyCycle {
        DutyCycle {
            scan_window: Millis(1_000),
            scan_period: Millis(1_000),
            advertise_interval: Millis(152),
            advertise: true,
            scan: true,
        }
    }

    /// A placeholder balanced plan, used only until `gdc-power` supplies one.
    ///
    /// The brief's budget is ~5 %/hr on a 4000 mAh-class phone while relaying
    /// with the screen off. Picking the window/period pair that hits that is
    /// `gdc-power`'s job, which is exactly why this is behind a trait.
    #[must_use]
    pub fn placeholder_balanced() -> DutyCycle {
        DutyCycle {
            scan_window: Millis(2_000),
            scan_period: Millis(8_000),
            advertise_interval: Millis(400),
            advertise: true,
            scan: true,
        }
    }
}

/// Produces the current duty cycle.
///
/// **Needed from `gdc-power`.** Transport calls this on every scheduling tick
/// and applies whatever it says. The arguments are the only context transport
/// has that the power model does not: which platform and app state we are in,
/// and how many usable neighbours we already have (there is no point scanning
/// hard when surrounded, and every point when alone).
pub trait DutyCyclePolicy {
    fn duty_cycle(
        &self,
        platform: Platform,
        state: AppState,
        usable_neighbours: usize,
        now: Millis,
    ) -> DutyCycle;
}

/// Stand-in policy so this crate is testable and simulatable alone.
///
/// Deliberately simple and deliberately not tuned: tuning it here would be
/// taking a decision that belongs in `gdc-power`.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultDutyCyclePolicy;

impl DutyCyclePolicy for DefaultDutyCyclePolicy {
    fn duty_cycle(
        &self,
        platform: Platform,
        state: AppState,
        usable_neighbours: usize,
        now: Millis,
    ) -> DutyCycle {
        let mut dc = if state.is_foreground() {
            DutyCycle::aggressive()
        } else {
            DutyCycle::placeholder_balanced()
        };

        // Alone and backgrounded: scan harder, because the cost of not finding
        // anyone is a message that never moves.
        if usable_neighbours == 0 && !state.is_foreground() {
            dc.scan_window = Millis(3_000);
            dc.scan_period = Millis(6_000);
        }

        // The one place the capability matrix changes the *shape* of the plan
        // rather than its numbers: a row that cannot advertise and scan at once
        // must alternate. We alternate on the scan period so that both halves
        // get a full duty cycle instead of two starved ones.
        let c = crate::caps::caps(platform, state);
        if !c.can_advertise_and_scan {
            let phase = if dc.scan_period == Millis::ZERO {
                0
            } else {
                (now.0 / dc.scan_period.0.max(1)) % 2
            };
            dc.scan = phase == 0;
            dc.advertise = phase == 1;
        }
        dc
    }
}

/// Measured energy figures, replacing the priors in [`crate::link::prior`].
///
/// **Needed from `gdc-power`.** Everything transport does with energy goes
/// through this trait, so there is exactly one place where a measured radio
/// event table displaces a datasheet guess.
pub trait EnergyModel {
    /// Cost of an already-established BLE link on the given PHY.
    fn ble_cost(&self, phy: BlePhy, platform: Platform, state: AppState) -> CostEstimate;

    /// Cost of bringing up and running a Wi-Fi burst.
    fn wifi_cost(&self, flavour: crate::caps::WifiFlavour) -> CostEstimate;

    /// The exchange rate between energy and delivery latency, in millijoules
    /// per second of latency avoided.
    ///
    /// This single scalar is what makes "the most efficient available network"
    /// a computable question rather than a slogan: it is the only thing that
    /// lets a joule be compared with a second. See
    /// [`crate::select::break_even_bytes`] for how it enters the arithmetic,
    /// and why the answer ranges over more than an order of magnitude as this
    /// value sweeps from 0 to infinity.
    ///
    /// The brief's battery stance — "biased toward delivery" within a fixed
    /// balanced profile — says this should be a middling value rather than
    /// either extreme.
    fn latency_value_mj_per_s(&self) -> f32;
}

/// Stand-in energy model built from the priors in [`crate::link::prior`].
#[derive(Clone, Copy, Debug)]
pub struct PriorEnergyModel {
    pub latency_value_mj_per_s: f32,
}

impl Default for PriorEnergyModel {
    fn default() -> Self {
        PriorEnergyModel {
            // Default λ. Derivation of the choice, not of the formula:
            //
            // A 4000 mAh phone at 3.85 V holds about 55 kJ. The brief's budget
            // spends 5 %/hr while relaying, i.e. ~2.8 kJ/hr, i.e. ~0.77 J/s of
            // sustained draw for the whole radio subsystem. Paying 50 mJ to
            // avoid one second of delivery latency is therefore about 6 % of
            // one second's whole energy budget — a visible but not reckless
            // price, which is what "biased toward delivery" buys.
            //
            // Sweeping this is the first thing `gdc-sim` should do with the
            // break-even calculation.
            latency_value_mj_per_s: 50.0,
        }
    }
}

impl EnergyModel for PriorEnergyModel {
    fn ble_cost(&self, _phy: BlePhy, _platform: Platform, _state: AppState) -> CostEstimate {
        crate::link::prior::ble_cost()
    }

    fn wifi_cost(&self, flavour: crate::caps::WifiFlavour) -> CostEstimate {
        crate::link::prior::wifi_cost(flavour)
    }

    fn latency_value_mj_per_s(&self) -> f32 {
        self.latency_value_mj_per_s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_ratio_is_total() {
        let mut dc = DutyCycle::placeholder_balanced();
        assert!((dc.scan_ratio() - 0.25).abs() < 1e-6);
        dc.scan_period = Millis::ZERO;
        assert_eq!(dc.scan_ratio(), 0.0);
        dc.scan = false;
        assert_eq!(dc.scan_ratio(), 0.0);
        // A nonsense plan with a window longer than its period clamps instead
        // of claiming a ratio above 1.
        let silly = DutyCycle {
            scan_window: Millis(10_000),
            scan_period: Millis(100),
            ..DutyCycle::aggressive()
        };
        assert_eq!(silly.scan_ratio(), 1.0);
    }

    #[test]
    fn a_row_that_cannot_do_both_alternates_instead() {
        let p = DefaultDutyCyclePolicy;
        // Backgrounded iOS: the plan must never ask for both at once.
        let mut saw_scan = false;
        let mut saw_adv = false;
        for t in 0..8 {
            let dc = p.duty_cycle(
                Platform::Ios,
                AppState::Background,
                0,
                Millis(t * 6_000),
            );
            assert!(
                !(dc.scan && dc.advertise),
                "backgrounded iOS was asked to scan and advertise at once"
            );
            saw_scan |= dc.scan;
            saw_adv |= dc.advertise;
        }
        assert!(saw_scan && saw_adv, "both halves must get a turn");

        // Backgrounded Android: both, always.
        let dc = p.duty_cycle(Platform::Android, AppState::Background, 0, Millis(0));
        assert!(dc.scan && dc.advertise);
    }
}
