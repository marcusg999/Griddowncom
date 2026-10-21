//! Energy hooks.
//!
//! `gdc-power` owns the real cost table and the duty-cycle policy. This module
//! defines the narrowest interface the simulator needs to charge a node for a
//! radio event, plus a placeholder table so `gdc-sim` runs standalone.
//!
//! The placeholder numbers are deliberately crude and labelled as such. Do not
//! quote them. They exist so the harness can emit an mAh column that becomes
//! real the moment `gdc-power` lands.

use crate::clock::SimTime;
use crate::phy::PhyMode;
use crate::platform::Regime;
use crate::provenance::{ParamDoc, ParamSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A billable radio event.
///
/// Deliberately coarse: these are the events a scheduler can actually decide
/// about. Anything finer belongs inside `gdc-power`'s table, not in the
/// simulator's event stream.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RadioEvent {
    /// One advertising event, on air for `airtime`.
    Advertise { mode: PhyMode, airtime: SimTime },
    /// One scan window held open for `duration`.
    Scan { duration: SimTime },
    /// Establishing a connection, including discovery.
    ConnectionSetup { duration: SimTime },
    /// One connection event on an established link, whether or not data flowed.
    ConnectionEvent { duration: SimTime },
    /// Transmitting a frame over a link.
    Transmit {
        mode: PhyMode,
        bytes: usize,
        airtime: SimTime,
    },
    /// Receiving and decoding a frame.
    Receive {
        mode: PhyMode,
        bytes: usize,
        airtime: SimTime,
    },
    /// Host wake-up to process something, radio idle. Charged because the
    /// application processor is the dominant cost of a chatty protocol.
    HostWake { duration: SimTime },
}

/// The energy interface. One trait, two jobs: price an event, and report what a
/// node has spent.
///
/// `gdc-power` is expected to provide the real implementation. Kept to three
/// methods so that it can, without having to know anything about the
/// simulator's internals.
pub trait EnergyModel {
    /// Cost of one radio event in mAh, independent of who performed it beyond
    /// the platform regime it was performed in.
    fn event_cost_mah(&self, regime: Regime, event: &RadioEvent) -> f64;

    /// Charge a node for an event.
    fn charge(&mut self, node: u32, regime: Regime, event: &RadioEvent);

    /// Total charge drawn by a node since the run started, in mAh.
    fn accumulated_mah(&self, node: u32) -> f64;
}

/// Crude placeholder table so the simulator runs without `gdc-power`.
///
/// Derived from nothing but plausible BLE current draws: a radio on at ~12 mA,
/// a host wake at ~25 mA, and a connection setup costing a fixed lump. Every
/// value is `ParamSource::Assumed` and the harness labels the mAh column as a
/// placeholder in its JSON output.
#[derive(Clone, Debug)]
pub struct PlaceholderEnergyModel {
    pub radio_tx_ma: f64,
    pub radio_rx_ma: f64,
    pub scan_ma: f64,
    pub host_wake_ma: f64,
    pub connection_setup_mah: f64,
    totals: HashMap<u32, f64>,
}

impl Default for PlaceholderEnergyModel {
    fn default() -> Self {
        PlaceholderEnergyModel {
            radio_tx_ma: 15.0,
            radio_rx_ma: 12.0,
            scan_ma: 12.0,
            host_wake_ma: 25.0,
            connection_setup_mah: 0.0008,
            totals: HashMap::new(),
        }
    }
}

impl PlaceholderEnergyModel {
    pub fn provenance() -> Vec<ParamDoc> {
        let d = PlaceholderEnergyModel::default();
        let why = "PLACEHOLDER. gdc-sim does not own the energy table; gdc-power \
                   does. These are order-of-magnitude BLE current draws and exist \
                   only so the harness can emit an mAh column before gdc-power \
                   lands. Do not quote.";
        vec![
            ParamDoc::new("placeholder_radio_tx_ma", d.radio_tx_ma, "mA", ParamSource::assumed(why)),
            ParamDoc::new("placeholder_radio_rx_ma", d.radio_rx_ma, "mA", ParamSource::assumed(why)),
            ParamDoc::new("placeholder_scan_ma", d.scan_ma, "mA", ParamSource::assumed(why)),
            ParamDoc::new("placeholder_host_wake_ma", d.host_wake_ma, "mA", ParamSource::assumed(why)),
        ]
    }

    fn mah(ma: f64, d: SimTime) -> f64 {
        ma * d.as_secs_f64() / 3600.0
    }
}

impl EnergyModel for PlaceholderEnergyModel {
    fn event_cost_mah(&self, _regime: Regime, event: &RadioEvent) -> f64 {
        match event {
            RadioEvent::Advertise { airtime, .. } => Self::mah(self.radio_tx_ma, *airtime),
            RadioEvent::Scan { duration } => Self::mah(self.scan_ma, *duration),
            RadioEvent::ConnectionSetup { duration } => {
                self.connection_setup_mah + Self::mah(self.radio_rx_ma, *duration)
            }
            RadioEvent::ConnectionEvent { duration } => Self::mah(self.radio_rx_ma, *duration),
            RadioEvent::Transmit { airtime, .. } => Self::mah(self.radio_tx_ma, *airtime),
            RadioEvent::Receive { airtime, .. } => Self::mah(self.radio_rx_ma, *airtime),
            RadioEvent::HostWake { duration } => Self::mah(self.host_wake_ma, *duration),
        }
    }

    fn charge(&mut self, node: u32, regime: Regime, event: &RadioEvent) {
        let c = self.event_cost_mah(regime, event);
        if c.is_finite() && c >= 0.0 {
            *self.totals.entry(node).or_insert(0.0) += c;
        }
    }

    fn accumulated_mah(&self, node: u32) -> f64 {
        self.totals.get(&node).copied().unwrap_or(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{AppState, Platform};

    fn regime() -> Regime {
        Regime {
            platform: Platform::Android,
            state: AppState::Background,
        }
    }

    #[test]
    fn charging_accumulates_and_is_monotonic() {
        let mut m = PlaceholderEnergyModel::default();
        assert_eq!(m.accumulated_mah(0), 0.0);
        for _ in 0..10 {
            m.charge(
                0,
                regime(),
                &RadioEvent::Scan {
                    duration: SimTime::from_secs(1),
                },
            );
        }
        let after = m.accumulated_mah(0);
        assert!(after > 0.0);
        assert_eq!(m.accumulated_mah(1), 0.0);
        m.charge(
            0,
            regime(),
            &RadioEvent::Scan {
                duration: SimTime::ZERO,
            },
        );
        assert!((m.accumulated_mah(0) - after).abs() < 1e-12);
    }

    #[test]
    fn transmitting_costs_more_than_receiving_the_same_airtime() {
        let m = PlaceholderEnergyModel::default();
        let air = SimTime::from_micros(1000);
        let tx = m.event_cost_mah(
            regime(),
            &RadioEvent::Transmit {
                mode: PhyMode::Ble1M,
                bytes: 96,
                airtime: air,
            },
        );
        let rx = m.event_cost_mah(
            regime(),
            &RadioEvent::Receive {
                mode: PhyMode::Ble1M,
                bytes: 96,
                airtime: air,
            },
        );
        assert!(tx > rx);
    }
}
