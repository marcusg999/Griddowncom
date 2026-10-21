//! The radio energy cost table.
//!
//! # EVERY NUMBER IN THIS FILE IS MODELLED. NONE OF IT IS MEASURED.
//!
//! This container has no radios and no phones. Nobody here has put a current
//! probe on a handset. The defaults below are built from three kinds of input,
//! and each entry says which kind it is:
//!
//! * `Datasheet` — a figure published by a silicon vendor for a discrete part.
//! * `DerivedFromSpec` — arithmetic over the Bluetooth Core specification, e.g.
//!   bits per symbol on a given PHY. These are the only entries that are not
//!   really estimates; airtime per byte on LE 1M is 8 us because the symbol
//!   rate says so.
//! * `Reasoned` — my own reasoning from the above, usually a scaling argument
//!   from discrete silicon to a phone's combo chip. No citation exists. These
//!   are guesses with a stated derivation, which is different from a guess, but
//!   not by as much as a reader might hope.
//!
//! There is deliberately no `Measured` variant. One cannot be constructed
//! without a field measurement, and when one arrives it enters through
//! [`crate::calibrate`], which rewrites the uncertain entries and stamps the
//! table [`TableOrigin::Calibrated`]. Until that happens every figure this
//! crate emits is labelled `modelled, uncalibrated` by
//! [`crate::account::BatteryReport`], and there is no code path that produces
//! an unlabelled one.
//!
//! The two entries that dominate the answer are `ap_awake_penalty_ua` and
//! `ap_sleep`. See [`ApSleep`]; between them they move the headline battery
//! figure by roughly a factor of seven, which is more than everything else in
//! this file put together.

use crate::units::{Charge, US_PER_HOUR};

/// Where a single figure came from. There is no `Measured` variant on purpose.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Provenance {
    /// A silicon vendor's published electrical characteristics.
    Datasheet {
        part: &'static str,
        figure: &'static str,
    },
    /// A third-party published measurement or source listing.
    Published {
        source: &'static str,
        figure: &'static str,
    },
    /// Arithmetic over a specification. Not an estimate.
    DerivedFromSpec { note: &'static str },
    /// My own reasoning. No citation. State it as such wherever it is used.
    Reasoned { note: &'static str },
    /// Refitted against a field measurement by [`crate::calibrate`].
    Calibrated { round: u32, note: &'static str },
}

impl Provenance {
    /// A short tag for reports. Deliberately blunt.
    pub fn tag(&self) -> &'static str {
        match self {
            Provenance::Datasheet { .. } => "datasheet",
            Provenance::Published { .. } => "published",
            Provenance::DerivedFromSpec { .. } => "derived-from-spec",
            Provenance::Reasoned { .. } => "REASONED (my own guess)",
            Provenance::Calibrated { .. } => "calibrated",
        }
    }

    /// True when the figure rests on nothing but this crate's own reasoning.
    pub fn is_unsourced_guess(&self) -> bool {
        matches!(self, Provenance::Reasoned { .. })
    }

    pub fn note(&self) -> &'static str {
        match self {
            Provenance::Datasheet { figure, .. } => figure,
            Provenance::Published { figure, .. } => figure,
            Provenance::DerivedFromSpec { note } => note,
            Provenance::Reasoned { note } => note,
            Provenance::Calibrated { note, .. } => note,
        }
    }
}

/// One row of the published cost table, for reporting.
#[derive(Clone, Copy, Debug)]
pub struct CostFact {
    pub field: &'static str,
    pub unit: &'static str,
    pub default: &'static str,
    pub provenance: Provenance,
}

/// Whether the whole table is still pure model or has been refitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TableOrigin {
    /// No measurement has ever touched this table.
    Modelled,
    /// Refitted against a field measurement. `device` is free text from the
    /// person who took the measurement.
    Calibrated {
        round: u32,
        device: &'static str,
        /// What the refit multiplied the uncertain terms by, in parts per
        /// thousand, so a reader can see how wrong the model was.
        scale_ppt: u32,
    },
}

impl TableOrigin {
    /// The provenance string every published figure must carry.
    pub fn label(&self) -> &'static str {
        match self {
            TableOrigin::Modelled => "modelled, uncalibrated",
            TableOrigin::Calibrated { .. } => "modelled, calibrated against a field round",
        }
    }
}

/// Whether the application processor gets to suspend while a radio session is
/// up, or is pinned awake by it.
///
/// This is the single largest uncertainty in the model and it is a *binary*
/// one, not a tolerance band.
///
/// * `Offloaded` — the controller runs filtered scanning and autonomous
///   advertising by itself and the AP suspends between matching reports. The
///   relay then costs about what the radio costs.
/// * `Pinned` — holding a scan session open keeps the AP out of its deepest
///   sleep state for the duration. The relay then costs about what *not
///   suspending* costs, which on a phone is an order of magnitude more than
///   the radio.
///
/// `Pinned` is the default, because reporting the optimistic branch as the
/// expected number is the specific failure this project is most exposed to.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ApSleep {
    /// AP suspends between wakes; only `ap_wake_hold_us` per wake is charged.
    Offloaded,
    /// AP is held awake for the whole time any scan session is open.
    #[default]
    Pinned,
}

/// A Bluetooth LE PHY. Airtime per byte follows from the symbol rate.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Phy {
    #[default]
    Le1M,
    Le2M,
    /// Coded PHY, S=2 coding, 500 kbit/s.
    LeCodedS2,
    /// Coded PHY, S=8 coding, 125 kbit/s.
    LeCodedS8,
}

impl Phy {
    /// Airtime for one byte, in microseconds.
    ///
    /// Derived, not estimated: 1 Msym/s with 1 bit/symbol is 8 us/byte, 2 Msym/s
    /// is 4 us/byte, and the coded PHY spends S symbols per bit on the payload.
    /// Packet framing overhead is not in here; it is charged by the per-event
    /// entries that know the packet shape.
    pub const fn us_per_byte(self) -> u64 {
        match self {
            Phy::Le1M => 8,
            Phy::Le2M => 4,
            Phy::LeCodedS2 => 16,
            Phy::LeCodedS8 => 64,
        }
    }

    /// Whether this PHY is normally run at raised transmit power. Coded PHY
    /// exists to buy range, and in practice it is paired with the highest
    /// transmit power the platform will give, so the two are conflated here
    /// rather than modelled as independent axes. That conflation is itself an
    /// assumption and is listed in the provenance table.
    pub const fn uses_boosted_tx(self) -> bool {
        matches!(self, Phy::LeCodedS2 | Phy::LeCodedS8)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Phy::Le1M => "LE 1M",
            Phy::Le2M => "LE 2M",
            Phy::LeCodedS2 => "LE Coded S=2",
            Phy::LeCodedS8 => "LE Coded S=8",
        }
    }

    pub const ALL: [Phy; 4] = [Phy::Le1M, Phy::Le2M, Phy::LeCodedS2, Phy::LeCodedS8];
}

/// The modelled per-event radio energy cost table.
///
/// Fields are public so that a calibration round, a sensitivity sweep or a
/// critic can poke at individual entries. Every field is listed in
/// [`CostTable::provenance`] and a test fails if one is added without a row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CostTable {
    pub origin: TableOrigin,
    pub ap_sleep: ApSleep,

    // ---- device-level states -------------------------------------------------
    /// Battery current of a 4000 mAh-class phone, screen off, suspended, with
    /// this app not running. Not charged to us, but part of the 5 %/hr target.
    pub suspended_floor_ua: u32,
    /// *Additional* battery current while the application processor is held out
    /// of suspend. The dominant term in the whole model.
    pub ap_awake_penalty_ua: u32,
    /// How long the AP stays out of suspend per wake event, covering the
    /// interrupt, the scheduler, the callback across the UniFFI boundary and
    /// the idle-governor hysteresis before it will re-enter a deep state.
    pub ap_wake_hold_us: u32,

    // ---- BLE scanning --------------------------------------------------------
    /// Receiver-on current during a scan window.
    pub ble_rx_current_ua: u32,
    /// Current attributable to having a scan session registered at all, charged
    /// across the whole session whether or not a window is open.
    pub scan_session_idle_ua: u32,
    /// Radio ramp-up and settle per scan window, charged at rx + session current.
    pub scan_ramp_us: u32,
    /// Cost of one advertisement report crossing from controller to host.
    pub adv_report_charge: Charge,

    // ---- BLE advertising -----------------------------------------------------
    /// One advertising event: the primary-channel set plus the scan-response
    /// listen windows.
    pub adv_event_charge: Charge,

    // ---- BLE connections -----------------------------------------------------
    /// One connection event carrying an empty or single small packet.
    pub conn_event_charge: Charge,
    /// Connection establishment end to end: initiating scan, connect request,
    /// feature and length exchange, PHY update, first data.
    pub conn_setup_charge: Charge,

    // ---- BLE payload ---------------------------------------------------------
    pub ble_tx_current_ua: u32,
    /// Transmit current at the raised power the coded PHYs are run at.
    pub ble_tx_boosted_current_ua: u32,
    pub ble_link_rx_current_ua: u32,
    /// CPU to verify, decrypt and re-encode one frame, charged per frame
    /// processed including duplicates that are dropped after verification.
    pub cpu_per_frame_charge: Charge,

    // ---- Wi-Fi ---------------------------------------------------------------
    /// Bringing an infrastructure-free peer-to-peer Wi-Fi group up to the point
    /// where bytes can move.
    pub wifi_bringup_charge: Charge,
    pub wifi_teardown_charge: Charge,
    pub wifi_active_current_ua: u32,
    /// Application-level goodput used to convert bytes into radio-on time.
    pub wifi_goodput_kbps: u32,
}

impl Default for CostTable {
    fn default() -> Self {
        CostTable::modelled()
    }
}

impl CostTable {
    /// The project default. Modelled, uncalibrated, pessimistic on AP sleep.
    pub const fn modelled() -> Self {
        CostTable {
            origin: TableOrigin::Modelled,
            ap_sleep: ApSleep::Pinned,

            suspended_floor_ua: 12_000,
            ap_awake_penalty_ua: 128_000,
            ap_wake_hold_us: 8_000,

            ble_rx_current_ua: 11_000,
            scan_session_idle_ua: 2_500,
            scan_ramp_us: 2_000,
            adv_report_charge: Charge::from_uc(1),

            adv_event_charge: Charge::from_uc(40),

            conn_event_charge: Charge::from_uc(2),
            conn_setup_charge: Charge::from_uc(13_000),

            ble_tx_current_ua: 10_500,
            ble_tx_boosted_current_ua: 24_000,
            ble_link_rx_current_ua: 10_000,
            cpu_per_frame_charge: Charge::from_uc(90),

            wifi_bringup_charge: Charge::from_uc(450_000),
            wifi_teardown_charge: Charge::from_uc(60_000),
            wifi_active_current_ua: 200_000,
            wifi_goodput_kbps: 6_000,
        }
    }

    /// The optimistic branch of the single biggest unknown: the AP suspends
    /// between filtered advertisement reports. Reported alongside the default
    /// so that the size of the unknown is visible rather than buried.
    pub const fn modelled_with_offload() -> Self {
        let mut t = CostTable::modelled();
        t.ap_sleep = ApSleep::Offloaded;
        t
    }

    pub const fn tx_current_ua(&self, phy: Phy) -> u32 {
        if phy.uses_boosted_tx() {
            self.ble_tx_boosted_current_ua
        } else {
            self.ble_tx_current_ua
        }
    }

    /// Charge to transmit `bytes` of frame on `phy`.
    pub fn tx_charge(&self, bytes: u64, phy: Phy) -> Charge {
        Charge::from_ua_us(
            self.tx_current_ua(phy) as u64,
            bytes.saturating_mul(phy.us_per_byte()),
        )
    }

    /// Charge to receive `bytes` of frame on `phy`.
    pub fn rx_charge(&self, bytes: u64, phy: Phy) -> Charge {
        Charge::from_ua_us(
            self.ble_link_rx_current_ua as u64,
            bytes.saturating_mul(phy.us_per_byte()),
        )
    }

    /// Per-byte transmit cost at a PHY, for the published table.
    pub fn tx_per_byte(&self, phy: Phy) -> Charge {
        self.tx_charge(1, phy)
    }

    /// Per-byte receive cost at a PHY, for the published table.
    pub fn rx_per_byte(&self, phy: Phy) -> Charge {
        self.rx_charge(1, phy)
    }

    /// Charge for one scan window of `window_us`, radio only.
    pub fn scan_window_charge(&self, window_us: u64) -> Charge {
        let on = Charge::from_ua_us(self.ble_rx_current_ua as u64, window_us);
        let ramp = Charge::from_ua_us(
            self.ble_rx_current_ua as u64 + self.scan_session_idle_ua as u64,
            self.scan_ramp_us as u64,
        );
        on.saturating_add(ramp)
    }

    /// Charge for `bytes` over an already-up Wi-Fi link.
    pub fn wifi_transfer_charge(&self, bytes: u64) -> Charge {
        if self.wifi_goodput_kbps == 0 {
            return Charge::ZERO;
        }
        // bytes -> bits -> microseconds at the stated goodput.
        let us = bytes.saturating_mul(8_000) / self.wifi_goodput_kbps as u64;
        Charge::from_ua_us(self.wifi_active_current_ua as u64, us)
    }

    /// The whole-device floor for one hour. Reported, never charged to the app.
    pub fn hourly_floor(&self) -> Charge {
        Charge::from_ua_us(self.suspended_floor_ua as u64, US_PER_HOUR)
    }

    /// Every entry with its provenance, in report order.
    ///
    /// A test destructures [`CostTable`] exhaustively against this list, so a
    /// field cannot be added without a row here. That is the whole point: an
    /// unlabelled entry in this table would silently corrupt every battery
    /// number the project reports.
    pub fn provenance(&self) -> &'static [CostFact] {
        PROVENANCE
    }

    /// Count of entries whose only support is this crate's own reasoning.
    pub fn unsourced_entry_count(&self) -> usize {
        PROVENANCE
            .iter()
            .filter(|f| f.provenance.is_unsourced_guess())
            .count()
    }
}

/// Field names of [`CostTable`], excluding `origin`, in provenance order.
pub(crate) const COST_FIELDS: [&str; 18] = [
    "ap_sleep",
    "suspended_floor_ua",
    "ap_awake_penalty_ua",
    "ap_wake_hold_us",
    "ble_rx_current_ua",
    "scan_session_idle_ua",
    "scan_ramp_us",
    "adv_report_charge",
    "adv_event_charge",
    "conn_event_charge",
    "conn_setup_charge",
    "ble_tx_current_ua",
    "ble_tx_boosted_current_ua",
    "ble_link_rx_current_ua",
    "cpu_per_frame_charge",
    "wifi_bringup_charge",
    "wifi_teardown_charge",
    "wifi_active_current_ua",
];

const PROVENANCE: &[CostFact] = &[
    CostFact {
        field: "ap_sleep",
        unit: "enum",
        default: "Pinned",
        provenance: Provenance::Reasoned {
            note: "Binary unknown, not a tolerance. Both platforms document hardware \
                   offload for filtered scanning and autonomous advertising, which would \
                   let the AP suspend; but an app that is also relaying runs a foreground \
                   service, holds a partial wakelock on Android, and services callbacks \
                   across UniFFI, all of which keep the AP out of its deepest state. I \
                   default to Pinned because publishing the optimistic branch as the \
                   expected figure is the specific dishonesty this project is exposed to. \
                   Moves the headline number by ~7x on its own.",
        },
    },
    CostFact {
        field: "suspended_floor_ua",
        unit: "uA",
        default: "12000",
        provenance: Provenance::Reasoned {
            note: "A 4000 mAh-class phone, screen off, suspended, cellular attached, our \
                   app not running. Published idle-drain figures for this class of device \
                   cluster around 0.2-0.4 %/hr; 12 mA is 0.3 %/hr. Not charged to the app \
                   but it is inside the 5 %/hr target, so it is reported separately.",
        },
    },
    CostFact {
        field: "ap_awake_penalty_ua",
        unit: "uA",
        default: "128000",
        provenance: Provenance::Reasoned {
            note: "The additional battery current while the AP is out of suspend with the \
                   screen off. Derived as the gap between a suspended phone (~12 mA) and \
                   the same phone awake-but-idle with the screen off, which for this class \
                   of silicon I take to be 120-150 mA. I use 128 mA. This is a guess with \
                   a derivation and it is the largest single term in the model. One real \
                   Android measurement replaces it outright.",
        },
    },
    CostFact {
        field: "ap_wake_hold_us",
        unit: "us",
        default: "8000",
        provenance: Provenance::Reasoned {
            note: "Time the AP stays out of suspend per wake: interrupt, kernel path, \
                   scheduler, the Kotlin/Swift callback, the UniFFI hop into Rust, and the \
                   cpuidle governor's hysteresis before it will re-enter a deep state. \
                   8 ms is my estimate of that whole path; I have no citation for it. Only \
                   matters in the Offloaded branch.",
        },
    },
    CostFact {
        field: "ble_rx_current_ua",
        unit: "uA",
        default: "11000",
        provenance: Provenance::Reasoned {
            note: "Scaled from datasheet silicon: the Nordic nRF52840 product spec lists \
                   RX at 1 Mbps around 4.6 mA with the DC/DC converter at 3 V. A phone's \
                   BLE lives on a Wi-Fi/BT combo chip sharing a PMIC rail with worse \
                   conversion efficiency and more host-interface traffic. I apply a 2.4x \
                   scaling factor. The 4.6 mA is a datasheet figure; the 2.4x is mine.",
        },
    },
    CostFact {
        field: "scan_session_idle_ua",
        unit: "uA",
        default: "2500",
        provenance: Provenance::Reasoned {
            note: "Current attributable to a scan session being registered at all, between \
                   windows: the combo chip cannot reach its deepest state while it owes the \
                   host a scan. Chosen as roughly a quarter of receiver-on current. No \
                   citation.",
        },
    },
    CostFact {
        field: "scan_ramp_us",
        unit: "us",
        default: "2000",
        provenance: Provenance::Reasoned {
            note: "Per-window radio ramp-up, PLL lock and settle, plus controller \
                   bookkeeping. Discrete BLE parts settle in tens of microseconds; I use \
                   2 ms to cover the controller-side scheduling around it on a combo chip. \
                   Negligible at the window lengths the policy picks (<0.2 % of the total), \
                   so its imprecision does not matter much.",
        },
    },
    CostFact {
        field: "adv_report_charge",
        unit: "uC",
        default: "1",
        provenance: Provenance::Reasoned {
            note: "One advertisement report crossing controller to host: HCI event, driver \
                   path, and the host-side filter check. 1 uC. This is the entry that makes \
                   density expensive in a crowd, and it is a guess. In the Offloaded branch \
                   it also sets how often the AP is woken, so it matters more there.",
        },
    },
    CostFact {
        field: "adv_event_charge",
        unit: "uC",
        default: "40",
        provenance: Provenance::Reasoned {
            note: "Computed then scaled. A 31-byte ADV_IND is ~376 us of airtime on LE 1M \
                   per primary channel (derived from spec); three channels plus a short \
                   listen window each, at nRF52840 datasheet TX 4.8 mA / RX 4.6 mA at 0 dBm, \
                   gives ~9 uC on discrete silicon. I scale by ~2.4x for a phone and round \
                   up to 40 uC for controller scheduling overhead. The airtime is derived, \
                   the currents are datasheet, the scaling and the round-up are mine. \
                   Second-least constrained entry in the table.",
        },
    },
    CostFact {
        field: "conn_event_charge",
        unit: "uC",
        default: "2",
        provenance: Provenance::Reasoned {
            note: "One connection event with an empty or single small packet: ~80 us TX plus \
                   ~80 us RX plus ramp, at the same datasheet currents, phone-scaled. Does \
                   NOT include waking the AP; that is charged separately, which is why a \
                   fast connection interval is expensive in this model for a reason that has \
                   nothing to do with the radio.",
        },
    },
    CostFact {
        field: "conn_setup_charge",
        unit: "uC",
        default: "13000",
        provenance: Provenance::Reasoned {
            note: "Connection establishment end to end, modelled as ~1.2 s of receiver-on \
                   equivalent (initiating scan, connect request, feature exchange, length \
                   extension, PHY update, first data) at this table's RX current, plus the \
                   connection events inside it. 13 mC is 3.6e-3 mAh, so ~280 establishments \
                   cost 1 mAh. Churn is therefore cheap in this model and link thrash is not \
                   the thing to optimise against.",
        },
    },
    CostFact {
        field: "ble_tx_current_ua",
        unit: "uA",
        default: "10500",
        provenance: Provenance::Reasoned {
            note: "nRF52840 product spec TX at 0 dBm is about 4.8 mA with DC/DC at 3 V; \
                   scaled 2.2x for a phone combo chip. Datasheet base, my scaling.",
        },
    },
    CostFact {
        field: "ble_tx_boosted_current_ua",
        unit: "uA",
        default: "24000",
        provenance: Provenance::Reasoned {
            note: "The same part at +8 dBm is about 14.8 mA; scaled ~1.6x rather than 2.2x \
                   because at raised power the PA dominates and the combo-chip overhead is \
                   proportionally smaller. Used for the coded PHYs, which conflates PHY with \
                   transmit power. That conflation is an assumption, not a measurement.",
        },
    },
    CostFact {
        field: "ble_link_rx_current_ua",
        unit: "uA",
        default: "10000",
        provenance: Provenance::Reasoned {
            note: "Receiver-on during connected-mode payload reception. Slightly below the \
                   scan figure because a connection event is a scheduled wake with no \
                   filtering work, where a scan window is open-ended. The difference is my \
                   judgement, not a measurement.",
        },
    },
    CostFact {
        field: "cpu_per_frame_charge",
        unit: "uC",
        default: "90",
        provenance: Provenance::Reasoned {
            note: "Verify, AEAD-open and re-encode one frame of gdc-wire's 256-byte bucket: \
                   ~1.5 ms of a single core at ~60 mA of incremental SoC current. Charged per \
                   frame processed including duplicates dropped after verification, because \
                   rule 4 of the Bridgefy findings requires verifying before forwarding, so \
                   a duplicate costs real work. 2.5e-5 mAh per frame, i.e. negligible, which \
                   is itself a useful result: authenticate-before-relay is not expensive.",
        },
    },
    CostFact {
        field: "wifi_bringup_charge",
        unit: "uC",
        default: "450000",
        provenance: Provenance::Reasoned {
            note: "Bringing an infra-free peer-to-peer group up to first byte: Wi-Fi Aware \
                   or Wi-Fi Direct discovery, group negotiation, association, link setup. \
                   Modelled as ~2.5 s at ~180 mA. 0.45 C is 0.125 mAh, i.e. about 34 BLE \
                   connection establishments or 0.5 s of AP-awake time. This is what makes \
                   a Wi-Fi burst something to be earned by backlog rather than used by \
                   default. No citation; the 2.5 s and the 180 mA are both mine.",
        },
    },
    CostFact {
        field: "wifi_teardown_charge",
        unit: "uC",
        default: "60000",
        provenance: Provenance::Reasoned {
            note: "Group teardown and return of the chip to its idle state. Modelled as \
                   ~0.33 s at the same current. Mine.",
        },
    },
    CostFact {
        field: "wifi_active_current_ua",
        unit: "uA",
        default: "200000",
        provenance: Provenance::Reasoned {
            note: "Active transfer current on a phone's Wi-Fi, paired with \
                   wifi_goodput_kbps = 6000 to give a per-byte figure. At 6 Mbit/s goodput \
                   this is ~0.27 uC per byte, so the whole of gdc-wire's largest bucket costs \
                   less than a third of a microcoulomb to move. Wi-Fi in this project is \
                   essentially all fixed cost, which is the conclusion that matters, and it \
                   is robust to both figures being wrong by 2x.",
        },
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cost_field_has_a_provenance_row() {
        // Exhaustive destructure with no `..`: adding a field to CostTable
        // without adding a provenance row is a compile error here, and adding
        // one without updating COST_FIELDS fails the assertions below.
        let CostTable {
            origin: _,
            ap_sleep: _,
            suspended_floor_ua: _,
            ap_awake_penalty_ua: _,
            ap_wake_hold_us: _,
            ble_rx_current_ua: _,
            scan_session_idle_ua: _,
            scan_ramp_us: _,
            adv_report_charge: _,
            adv_event_charge: _,
            conn_event_charge: _,
            conn_setup_charge: _,
            ble_tx_current_ua: _,
            ble_tx_boosted_current_ua: _,
            ble_link_rx_current_ua: _,
            cpu_per_frame_charge: _,
            wifi_bringup_charge: _,
            wifi_teardown_charge: _,
            wifi_active_current_ua: _,
            wifi_goodput_kbps: _,
        } = CostTable::modelled();

        // wifi_goodput_kbps is documented inside the wifi_active_current_ua row
        // because the pair only means anything together.
        assert_eq!(PROVENANCE.len(), COST_FIELDS.len());
        for (fact, name) in PROVENANCE.iter().zip(COST_FIELDS.iter()) {
            assert_eq!(&fact.field, name, "provenance order must match COST_FIELDS");
            assert!(!fact.provenance.note().is_empty());
        }
    }

    #[test]
    fn no_entry_can_claim_to_be_measured() {
        // There is no Measured variant; the strongest claim available without a
        // field round is Datasheet. Assert the default table makes no stronger
        // claim than that, and that it is honest about how much is guesswork.
        for fact in PROVENANCE {
            assert!(
                !matches!(fact.provenance, Provenance::Calibrated { .. }),
                "{} claims calibration on an uncalibrated table",
                fact.field
            );
        }
        assert_eq!(
            CostTable::modelled().origin.label(),
            "modelled, uncalibrated"
        );
        assert!(
            CostTable::modelled().unsourced_entry_count() >= 10,
            "the table is mostly my own reasoning and must say so"
        );
    }

    #[test]
    fn phy_airtime_follows_the_symbol_rate() {
        assert_eq!(Phy::Le1M.us_per_byte(), 8);
        assert_eq!(Phy::Le2M.us_per_byte(), 4);
        assert_eq!(Phy::LeCodedS2.us_per_byte(), 16);
        assert_eq!(Phy::LeCodedS8.us_per_byte(), 64);
        // 2M is strictly cheaper per byte than 1M despite identical current.
        let t = CostTable::modelled();
        assert!(t.tx_per_byte(Phy::Le2M) < t.tx_per_byte(Phy::Le1M));
        // Coded S=8 is the most expensive per byte by a wide margin: 8x the
        // airtime of 1M at more than twice the current.
        assert!(
            t.tx_per_byte(Phy::LeCodedS8).as_pc() > t.tx_per_byte(Phy::Le1M).as_pc() * 15
        );
    }

    #[test]
    fn hand_computed_tx_charge() {
        let t = CostTable::modelled();
        // 288 bytes (gdc-wire 256-byte bucket + 32-byte header) on LE 1M:
        // 288 * 8 us = 2304 us at 10500 uA = 24_192_000 pC.
        assert_eq!(t.tx_charge(288, Phy::Le1M).as_pc(), 24_192_000);
    }

    #[test]
    fn hand_computed_scan_window_charge() {
        let t = CostTable::modelled();
        // 512 ms window: 512_000 us * 11_000 uA = 5_632_000_000 pC,
        // plus 2000 us ramp at 13_500 uA = 27_000_000 pC.
        assert_eq!(t.scan_window_charge(512_000).as_pc(), 5_659_000_000);
    }

    #[test]
    fn wifi_is_almost_entirely_fixed_cost() {
        let t = CostTable::modelled();
        let bringup = t.wifi_bringup_charge.saturating_add(t.wifi_teardown_charge);
        // Moving a hundred of gdc-wire's largest frames costs far less than
        // bringing the radio up once. This is the whole justification for
        // gating Wi-Fi on backlog depth.
        let payload = t.wifi_transfer_charge(100 * 1056);
        assert!(payload.as_pc() * 10 < bringup.as_pc());
    }
}
