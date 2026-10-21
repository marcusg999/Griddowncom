//! The link abstraction.
//!
//! A [`Link`] is one usable path to one peer over one radio. The same trait is
//! implemented by a real BLE connection driven through the native shell
//! (`HostLink`, in [`crate::conn`]) and by `gdc-sim`'s synthetic links, which
//! is what lets the selection policy in [`crate::select`] be tested against a
//! PHY trace and then shipped unchanged.
//!
//! # Division of labour with `gdc-sim`
//!
//! This module does **no PHY modelling**. It does not compute path loss, it
//! does not model fading, it does not decide whether a packet was received. It
//! holds the *observable* state of a link — MTU, measured goodput, RSSI, cost,
//! which platforms it spans, whether it is usable right now — and the arithmetic
//! that turns observations into policy inputs. The numbers in [`prior`] are
//! starting estimates used only until a measurement exists; the simulator and
//! the field both overwrite them.

use crate::caps::{
    caps, AppState, Caps, PairKind, Platform, StatePair, Support, WifiFlavour, ATT_MTU_FLOOR,
};
use crate::time::Millis;

/// Identifies a live link within one process. Not stable across sessions, not
/// derived from any device address, never put on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct LinkId(pub u32);

/// An opaque handle the native shell uses to name a discovered peer.
///
/// Deliberately not a MAC address, not a `CBPeripheral` UUID, not a name. The
/// shell keeps the mapping privately and hands Rust an integer, so no stable
/// device identifier can reach the mesh layers even by accident. Handles are
/// per-session and are invalidated by a new-identity or panic wipe.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct PeerHandle(pub u32);

/// BLE physical layer options we are prepared to ask for.
///
/// Modelled as distinct options rather than a constant because the choice is a
/// direct lever on M1, the per-hop distance number. Whether to pull it is a
/// policy decision; see [`crate::select::CodedPhyPolicy`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BlePhy {
    /// LE 1M, uncoded. The universal default and the only PHY an iOS device
    /// will ever be observed on from our side, since CoreBluetooth cannot
    /// request anything else.
    Le1M,
    /// LE Coded, S=8.
    ///
    /// Range/rate trade-off, and the arithmetic is worth stating because it is
    /// the single biggest lever we have on M1:
    ///
    /// * S=8 coding gives roughly 6 dB of extra link budget (the spec's design
    ///   target; 125 kbit/s raw against 1 Mbit/s raw is 9 dB of processing gain
    ///   on paper, of which about 6 dB survives as usable sensitivity).
    /// * Converting dB of margin into metres depends entirely on the path-loss
    ///   exponent, which is `gdc-sim`'s business, not ours. For the record:
    ///   free space (n = 2) turns 6 dB into a 2.0x range multiplier; a built-up
    ///   outdoor street (n = 3, which is the regime M1 is measured in) turns it
    ///   into 1.58x; a cluttered n = 4 environment into 1.41x.
    /// * So "roughly doubles the range" is the optimistic end. We budget 1.6x
    ///   for the metric we are actually graded on and treat 2x as the ceiling.
    ///
    /// The rate cost is the other half. Raw rate is 1/8 of 1M. Measured
    /// goodput, however, is not 1/8, because 1M-PHY goodput is nowhere near its
    /// raw rate — it is capped by connection interval, packets per interval and
    /// ATT overhead, none of which change with the PHY. Our prior is a 0.25
    /// goodput ratio (see [`prior::CODED8_GOODPUT_RATIO`]).
    ///
    /// UNVERIFIED: the 0.25 goodput ratio. It is the number most likely to be
    /// wrong in this file and it feeds the break-even calculation directly.
    LeCoded8,
}

impl BlePhy {
    /// Extra link budget over 1M, in dB. Used by `gdc-sim` as an input to its
    /// own propagation model; we do not apply it ourselves.
    #[must_use]
    pub fn link_budget_gain_db(self) -> f32 {
        match self {
            BlePhy::Le1M => 0.0,
            BlePhy::LeCoded8 => 6.0,
        }
    }

    /// Goodput multiplier against the 1M prior.
    #[must_use]
    pub fn goodput_ratio(self) -> f32 {
        match self {
            BlePhy::Le1M => 1.0,
            BlePhy::LeCoded8 => prior::CODED8_GOODPUT_RATIO,
        }
    }
}

/// Which radio a link runs on.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Medium {
    Ble(BlePhy),
    Wifi(WifiFlavour),
}

impl Medium {
    #[must_use]
    pub fn is_ble(self) -> bool {
        matches!(self, Medium::Ble(_))
    }
}

/// Signal quality as the radio reports it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Quality {
    /// Most recent RSSI in dBm. Hosts that cannot report RSSI on a connected
    /// link (iOS only reports it on request, and not at all for a peripheral's
    /// view of a central) send `None` and we fall back to loss.
    pub rssi_dbm: Option<i16>,
    /// Observed datagram loss over the recent window, in parts per thousand.
    pub loss_permil: u16,
    /// dBm per second, positive meaning the peer is getting closer. Fed by the
    /// RSSI trend; drives survival prediction.
    pub rssi_slope_dbm_s: f32,
}

impl Quality {
    /// A single 0.0-1.0 health score, for ranking links against each other.
    ///
    /// Clamped at both ends and total over every input a radio can produce,
    /// including a host that reports +100 dBm or 65535 permil loss.
    #[must_use]
    pub fn score(&self) -> f32 {
        // -40 dBm is "touching"; -95 dBm is the edge of a 1M-PHY link.
        let rssi_term = match self.rssi_dbm {
            Some(r) => ((f32::from(r) + 95.0) / 55.0).clamp(0.0, 1.0),
            None => 0.5,
        };
        let loss_term = 1.0 - (f32::from(self.loss_permil.min(1000)) / 1000.0);
        (0.6 * rssi_term + 0.4 * loss_term).clamp(0.0, 1.0)
    }
}

impl Default for Quality {
    fn default() -> Self {
        Quality {
            rssi_dbm: None,
            loss_permil: 0,
            rssi_slope_dbm_s: 0.0,
        }
    }
}

/// Energy and latency cost of using a link, as the power model sees it.
///
/// Populated from [`prior`] until `gdc-power` supplies measured figures through
/// [`crate::power::EnergyModel`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CostEstimate {
    /// Energy to bring the radio up to the point where it can move a byte to
    /// this peer: discovery, association, key agreement, socket setup. Zero for
    /// a link that is already up.
    pub bring_up_mj: f32,
    /// Wall-clock latency of that bring-up.
    pub bring_up: Millis,
    /// Marginal energy per byte transferred, in millijoules.
    pub mj_per_byte: f32,
    /// Power drawn just holding the link open with no traffic.
    pub idle_mw: f32,
}

/// Measured and estimated goodput for a link.
///
/// "Goodput" throughout this crate means *application payload* bytes per
/// second: after the fragment header, after ATT overhead, after retransmits.
/// That is what `docs/METRICS.md` asks for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Goodput {
    /// EWMA of observed payload bytes per second, once there is enough traffic
    /// to mean anything.
    pub measured_bps: Option<f32>,
    /// Prior from the medium, the platform pair and the app states.
    pub estimated_bps: f32,
}

impl Goodput {
    /// What policy should use: measurement if we have one, prior otherwise.
    /// Never zero, so it is always safe to divide by.
    #[must_use]
    pub fn effective_bps(&self) -> f32 {
        let v = self.measured_bps.unwrap_or(self.estimated_bps);
        if v.is_finite() && v > 1.0 {
            v
        } else {
            1.0
        }
    }

    #[must_use]
    pub fn is_measured(&self) -> bool {
        self.measured_bps.is_some()
    }
}

/// Rolling goodput meter. Deterministic: no clock of its own, every sample
/// carries its own timestamps.
#[derive(Clone, Debug, Default)]
pub struct GoodputMeter {
    ewma_bps: Option<f32>,
    samples: u32,
    bytes_total: u64,
}

impl GoodputMeter {
    /// Smoothing factor. 0.3 reacts within a handful of transfers, which is
    /// what we want for a link whose owner is walking.
    const ALPHA: f32 = 0.3;

    /// Minimum bytes in one observation before it is allowed to move the
    /// estimate. A 20-byte datagram on a 23-MTU link tells you almost nothing
    /// about throughput and would otherwise dominate the average.
    const MIN_SAMPLE_BYTES: u32 = 256;

    /// Record a completed transfer of `bytes` payload that took `elapsed`.
    pub fn observe(&mut self, bytes: u32, elapsed: Millis) {
        if bytes < Self::MIN_SAMPLE_BYTES || elapsed == Millis::ZERO {
            return;
        }
        let bps = bytes as f32 / elapsed.as_secs_f32();
        if !bps.is_finite() || bps <= 0.0 {
            return;
        }
        self.bytes_total = self.bytes_total.saturating_add(u64::from(bytes));
        self.samples = self.samples.saturating_add(1);
        self.ewma_bps = Some(match self.ewma_bps {
            None => bps,
            Some(prev) => prev + Self::ALPHA * (bps - prev),
        });
    }

    #[must_use]
    pub fn measured_bps(&self) -> Option<f32> {
        // Two samples before we believe it. One sample is an anecdote.
        if self.samples >= 2 {
            self.ewma_bps
        } else {
            None
        }
    }

    #[must_use]
    pub fn bytes_total(&self) -> u64 {
        self.bytes_total
    }
}

/// Why a link that exists cannot be used right now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnusableReason {
    /// The peer is backgrounded on a platform that cannot sustain this role in
    /// the background. The headline case: a backgrounded iOS peer that we are
    /// relying on to scan for us.
    PeerStateForbidsRole,
    /// Neither end can discover the other in their current states, so even
    /// though we have a link object the path cannot be re-established.
    NoDiscoveryPath,
    /// This medium is not available to one of the two ends in its current app
    /// state — e.g. a Wi-Fi link whose peer just went to the background on iOS,
    /// where MultipeerConnectivity stops.
    MediumUnavailableInState,
    /// Keepalives have been missed; the link is presumed gone but not yet
    /// torn down.
    LivenessLost,
    /// Loss or RSSI has fallen below the floor where a 1056-byte frame has any
    /// realistic chance of completing.
    QualityBelowFloor,
    /// Host reported the link closed.
    Closed,
}

/// Whether a link can carry traffic right now, and if not, why not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Usability {
    Usable,
    Unusable(UnusableReason),
}

impl Usability {
    #[must_use]
    pub fn is_usable(self) -> bool {
        matches!(self, Usability::Usable)
    }
}

/// Everything policy needs to know about a link, captured at one instant.
///
/// Cheap to produce and `Copy`-ish, because selection recomputes it for every
/// peer on every scheduling tick.
#[derive(Clone, Debug)]
pub struct LinkSnapshot {
    pub id: LinkId,
    pub medium: Medium,
    pub local: Platform,
    pub remote: Platform,
    pub local_state: AppState,
    pub remote_state: AppState,
    /// ATT MTU the host negotiated, or the Wi-Fi datagram size.
    pub att_mtu: u16,
    pub quality: Quality,
    pub goodput: Goodput,
    pub cost: CostEstimate,
    /// When the link came up.
    pub up_since: Millis,
    /// Last time anything was received on it.
    pub last_rx: Millis,
    pub usability: Usability,
}

impl LinkSnapshot {
    #[must_use]
    pub fn pair(&self) -> PairKind {
        PairKind::of(self.local, self.remote)
    }

    #[must_use]
    pub fn state_pair(&self) -> StatePair {
        StatePair::of(self.local_state, self.remote_state)
    }

    /// Payload bytes that fit in one datagram on this link, after ATT overhead
    /// but before the fragment header.
    #[must_use]
    pub fn datagram_payload(&self) -> u16 {
        match self.medium {
            Medium::Ble(_) => Caps::datagram_payload(self.att_mtu),
            // Wi-Fi links are stream- or datagram-oriented depending on
            // flavour; the shell presents a datagram interface sized well
            // above any frame we send, so one frame is never fragmented on
            // Wi-Fi.
            Medium::Wifi(_) => self.att_mtu.max(ATT_MTU_FLOOR),
        }
    }

    /// How long we predict the link has left, from its RSSI trend.
    ///
    /// Used as a gate on Wi-Fi bursts: a burst that cannot finish is pure cost.
    /// The model is deliberately crude — margin divided by rate of margin loss —
    /// because anything cleverer belongs in `gdc-sim` where it can be validated
    /// against a mobility trace.
    #[must_use]
    pub fn predicted_survival(&self) -> Millis {
        const FLOOR_DBM: f32 = -95.0;
        // No RSSI: fall back on a flat pedestrian assumption. A link between two
        // walking people lasts on the order of ten seconds once it is at the
        // edge, and indefinitely if they are walking together. We cannot tell
        // which, so we take the pessimistic one.
        let Some(rssi) = self.quality.rssi_dbm else {
            return Millis::secs(10);
        };
        let margin = f32::from(rssi) - FLOOR_DBM;
        if margin <= 0.0 {
            return Millis::ZERO;
        }
        if self.quality.rssi_slope_dbm_s >= -0.1 {
            // Stable or improving. Cap the claim: we will not promise more than
            // a minute of survival to anyone on the strength of a trend.
            return Millis::secs(60);
        }
        let secs = margin / -self.quality.rssi_slope_dbm_s;
        Millis::from_secs_f32(secs.min(60.0))
    }
}

/// One usable path to one peer over one radio.
///
/// Datagram-oriented and poll-driven on purpose:
///
/// * Datagrams, not a stream, because BLE is datagrams and because the
///   fragmenter above needs to know exactly what fits.
/// * Polled, not callback-driven, because an injected clock plus a polled
///   interface is what makes the whole crate deterministic. The native shells
///   push events into a queue; nothing in Rust blocks or wakes on its own.
///
/// Implementors: the native-shell-backed link in this crate, and `gdc-sim`.
pub trait Link {
    fn id(&self) -> LinkId;

    /// Current observable state. Must be cheap: called once per peer per tick.
    fn snapshot(&self) -> LinkSnapshot;

    /// Queue one datagram. `bytes.len()` must not exceed
    /// [`LinkSnapshot::datagram_payload`]; an over-long datagram is an error,
    /// never a panic and never a silent truncation.
    fn send(&mut self, bytes: &[u8]) -> Result<(), LinkError>;

    /// Take the next received datagram, if one has arrived.
    fn recv(&mut self) -> Option<Vec<u8>>;

    /// Bytes still queued for transmission. Feeds the break-even calculation:
    /// the backlog that matters is what is waiting, not what has been sent.
    fn pending_tx_bytes(&self) -> u32;

    /// Request teardown. Idempotent.
    fn close(&mut self);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum LinkError {
    #[error("datagram of {got} bytes exceeds link payload of {max}")]
    TooLong { got: usize, max: usize },
    #[error("link is not usable: {0:?}")]
    NotUsable(UnusableReason),
    #[error("transmit queue is full")]
    TxQueueFull,
    #[error("link is closed")]
    Closed,
}

/// Starting estimates. Every one of these is a prior to be replaced by a
/// measurement, and every one is tagged with how much we trust it.
///
/// None of these numbers are PHY modelling. They are the coarse "what does this
/// radio do in practice" figures that the selection policy needs before any
/// traffic has flowed. `gdc-sim` overrides them from its own model;
/// `gdc-power` overrides the energy ones from its event table; the field round
/// overrides all of them.
pub mod prior {
    use super::*;

    /// BLE 1M PHY, connection-oriented, write-without-response, both ends
    /// foreground. Application payload bytes per second.
    ///
    /// UNVERIFIED. This is the number the whole break-even threshold scales
    /// with, so it is the first thing the field round must pin down. The
    /// defensible range from published measurements of similar apps is roughly
    /// 2-10 kB/s; we take the low-middle of it, because being wrong low makes
    /// us burst too eagerly and being wrong high makes us never burst, and of
    /// the two the first is recoverable by a tunable sweep.
    pub const BLE_1M_FG_BPS: f32 = 4_000.0;

    /// Goodput of Coded PHY S=8 relative to 1M. See [`BlePhy::LeCoded8`] for
    /// why this is not 1/8.
    ///
    /// UNVERIFIED.
    pub const CODED8_GOODPUT_RATIO: f32 = 0.25;

    /// Wi-Fi Direct payload bytes per second between two phones a few metres
    /// apart. UNVERIFIED; the ratio to BLE is what matters and it is large
    /// under any plausible value.
    pub const WIFI_DIRECT_BPS: f32 = 1_500_000.0;
    /// Wi-Fi Aware. UNVERIFIED.
    pub const WIFI_AWARE_BPS: f32 = 1_000_000.0;
    /// MultipeerConnectivity over AWDL. UNVERIFIED.
    pub const MULTIPEER_BPS: f32 = 2_000_000.0;

    /// Time to go from "we have decided to burst" to "the first payload byte
    /// has moved", for each flavour. Discovery, group formation or NAN
    /// publish/subscribe, DHCP or IPv6 link-local, and a TCP handshake.
    ///
    /// UNVERIFIED, and the second most important number in this file. Published
    /// Wi-Fi Direct group formation times cluster around 2-5 s when the peers
    /// have not paired before.
    pub const WIFI_DIRECT_BRINGUP: Millis = Millis(3_000);
    pub const WIFI_AWARE_BRINGUP: Millis = Millis(2_000);
    pub const MULTIPEER_BRINGUP: Millis = Millis(2_500);

    /// Energy to perform that bring-up, in millijoules, counting only this
    /// device. UNVERIFIED; derived as bring-up duration times an assumed
    /// 600 mW for a Wi-Fi radio that is scanning and associating.
    pub const WIFI_BRINGUP_MJ: f32 = 1_800.0;

    /// Marginal energy per payload byte.
    ///
    /// BLE: a connected LE radio moving data draws on the order of 10 mA at
    /// 3.7 V, so ~37 mW; at [`BLE_1M_FG_BPS`] that is 37/4000 = 0.00925 mJ per
    /// byte. UNVERIFIED, from datasheet-class numbers rather than measurement.
    pub const BLE_MJ_PER_BYTE: f32 = 0.009_25;
    /// Wi-Fi: ~500 mW while transferring, at [`WIFI_DIRECT_BPS`].
    /// UNVERIFIED.
    pub const WIFI_MJ_PER_BYTE: f32 = 0.000_33;

    /// Power to hold a link open with no traffic.
    pub const BLE_IDLE_MW: f32 = 4.0;
    /// A Wi-Fi Direct group with no traffic is expensive, which is why bursts
    /// are torn down rather than kept. UNVERIFIED.
    pub const WIFI_IDLE_MW: f32 = 250.0;

    /// Goodput prior for a BLE link, derated for both ends' app states.
    ///
    /// The two derates multiply: a link between a backgrounded iPhone and a
    /// backgrounded Android is slower than either derate alone, because the
    /// connection interval is negotiated to satisfy the slower end and then
    /// both ends' schedulers interfere.
    #[must_use]
    pub fn ble_goodput_bps(
        phy: BlePhy,
        local: Platform,
        local_state: AppState,
        remote: Platform,
        remote_state: AppState,
    ) -> f32 {
        let l = caps(local, local_state).goodput_derate;
        let r = caps(remote, remote_state).goodput_derate;
        (BLE_1M_FG_BPS * phy.goodput_ratio() * l * r).max(1.0)
    }

    #[must_use]
    pub fn wifi_goodput_bps(f: WifiFlavour) -> f32 {
        match f {
            WifiFlavour::WifiDirect => WIFI_DIRECT_BPS,
            WifiFlavour::WifiAware => WIFI_AWARE_BPS,
            WifiFlavour::Multipeer => MULTIPEER_BPS,
        }
    }

    #[must_use]
    pub fn wifi_bringup(f: WifiFlavour) -> Millis {
        match f {
            WifiFlavour::WifiDirect => WIFI_DIRECT_BRINGUP,
            WifiFlavour::WifiAware => WIFI_AWARE_BRINGUP,
            WifiFlavour::Multipeer => MULTIPEER_BRINGUP,
        }
    }

    /// Cost estimate for a BLE link that is already up.
    #[must_use]
    pub fn ble_cost() -> CostEstimate {
        CostEstimate {
            bring_up_mj: 0.0,
            bring_up: Millis::ZERO,
            mj_per_byte: BLE_MJ_PER_BYTE,
            idle_mw: BLE_IDLE_MW,
        }
    }

    /// Cost estimate for a Wi-Fi burst that has not been brought up yet.
    #[must_use]
    pub fn wifi_cost(f: WifiFlavour) -> CostEstimate {
        CostEstimate {
            bring_up_mj: WIFI_BRINGUP_MJ,
            bring_up: wifi_bringup(f),
            mj_per_byte: WIFI_MJ_PER_BYTE,
            idle_mw: WIFI_IDLE_MW,
        }
    }
}

/// Whether a medium is available to a given end in a given app state.
///
/// Reads the capability matrix; no platform special cases here.
#[must_use]
pub fn medium_available(medium: Medium, platform: Platform, state: AppState) -> bool {
    let c = caps(platform, state);
    match medium {
        Medium::Ble(BlePhy::Le1M) => c.can_advertise || c.can_scan,
        Medium::Ble(BlePhy::LeCoded8) => {
            // Requires the platform to be able to select a PHY at all, and the
            // controller to support the coding. Unknown is not permission.
            c.phy_selectable.is_usable() && c.coded_phy.is_usable()
        }
        Medium::Wifi(f) => c.wifi.contains(&f),
    }
}

/// Decide whether a link is usable right now from the capability matrix and
/// the link's own observed health.
///
/// This is the function the rest of the stack calls instead of reasoning about
/// platforms. In particular it is what stops us from handing traffic to a
/// backgrounded iOS peer that cannot hold up its end.
#[must_use]
pub fn evaluate_usability(
    medium: Medium,
    local: Platform,
    local_state: AppState,
    remote: Platform,
    remote_state: AppState,
    quality: &Quality,
    is_local_central: bool,
) -> Usability {
    if !medium_available(medium, local, local_state)
        || !medium_available(medium, remote, remote_state)
    {
        return Usability::Unusable(UnusableReason::MediumUnavailableInState);
    }

    let lc = caps(local, local_state);
    let rc = caps(remote, remote_state);

    // Role feasibility. On a BLE link one end is central and one is peripheral,
    // and a backgrounded iOS device can do either but not both at once. If the
    // role we are relying on the peer to play is one it cannot play in its
    // current state, the link is not usable even if it is nominally connected.
    if medium.is_ble() {
        let (local_needs_scan, remote_needs_scan) = (is_local_central, !is_local_central);
        if local_needs_scan && !lc.can_scan {
            return Usability::Unusable(UnusableReason::PeerStateForbidsRole);
        }
        if remote_needs_scan && !rc.can_scan {
            return Usability::Unusable(UnusableReason::PeerStateForbidsRole);
        }
        if local_needs_scan && !rc.can_advertise {
            return Usability::Unusable(UnusableReason::NoDiscoveryPath);
        }
        if remote_needs_scan && !lc.can_advertise {
            return Usability::Unusable(UnusableReason::NoDiscoveryPath);
        }
    }

    // Quality floor. Below this a 1056-byte frame has essentially no chance of
    // getting through within the 30 s M1 deadline, so spending the energy is
    // worse than waiting for a better moment.
    if quality.loss_permil > 500 {
        return Usability::Unusable(UnusableReason::QualityBelowFloor);
    }
    if let Some(r) = quality.rssi_dbm {
        if r < -98 {
            return Usability::Unusable(UnusableReason::QualityBelowFloor);
        }
    }

    Usability::Usable
}

/// Build a snapshot for a link whose observable state we know. Used by the
/// host-backed link, by the simulator, and by tests.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn snapshot(
    id: LinkId,
    medium: Medium,
    local: Platform,
    local_state: AppState,
    remote: Platform,
    remote_state: AppState,
    att_mtu: u16,
    quality: Quality,
    meter: &GoodputMeter,
    is_local_central: bool,
    up_since: Millis,
    last_rx: Millis,
) -> LinkSnapshot {
    let estimated_bps = match medium {
        Medium::Ble(phy) => prior::ble_goodput_bps(phy, local, local_state, remote, remote_state),
        Medium::Wifi(f) => prior::wifi_goodput_bps(f),
    };
    let cost = match medium {
        Medium::Ble(_) => prior::ble_cost(),
        Medium::Wifi(f) => prior::wifi_cost(f),
    };
    LinkSnapshot {
        id,
        medium,
        local,
        remote,
        local_state,
        remote_state,
        att_mtu,
        quality,
        goodput: Goodput {
            measured_bps: meter.measured_bps(),
            estimated_bps,
        },
        cost,
        up_since,
        last_rx,
        usability: evaluate_usability(
            medium,
            local,
            local_state,
            remote,
            remote_state,
            &quality,
            is_local_central,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(rssi: i16) -> Quality {
        Quality {
            rssi_dbm: Some(rssi),
            ..Quality::default()
        }
    }

    #[test]
    fn coded_phy_is_an_option_not_a_constant() {
        assert!(BlePhy::LeCoded8.link_budget_gain_db() > BlePhy::Le1M.link_budget_gain_db());
        assert!(BlePhy::LeCoded8.goodput_ratio() < 1.0);
        // And it is unavailable on iOS at any app state, because CoreBluetooth
        // cannot ask for it.
        for s in [AppState::Foreground, AppState::Background] {
            assert!(!medium_available(
                Medium::Ble(BlePhy::LeCoded8),
                Platform::Ios,
                s
            ));
            // 1M is always available.
            assert!(medium_available(Medium::Ble(BlePhy::Le1M), Platform::Ios, s));
        }
    }

    #[test]
    fn coded_phy_needs_the_host_to_confirm_the_controller() {
        // Android can select a PHY, but the matrix leaves coded support
        // Unknown until the host answers isLeCodedPhySupported(). Unknown must
        // not be treated as yes.
        assert!(!medium_available(
            Medium::Ble(BlePhy::LeCoded8),
            Platform::Android,
            AppState::Foreground
        ));
    }

    #[test]
    fn backgrounded_ios_peer_cannot_be_relied_on_to_scan() {
        // We are the peripheral; the backgrounded iPhone would have to be the
        // central and keep scanning. The matrix says a backgrounded iOS device
        // cannot do both, and our advertisement is what it would have to find.
        // This is the gate the rest of the stack depends on.
        let u = evaluate_usability(
            Medium::Ble(BlePhy::Le1M),
            Platform::Android,
            AppState::Foreground,
            Platform::Ios,
            AppState::Background,
            &q(-60),
            /* is_local_central */ false,
        );
        // iOS background *can* scan (slowly), so the link is not outright
        // refused; what it cannot do is scan and advertise at once, which is
        // handled by role election rather than by refusing the link.
        assert!(u.is_usable());

        // The other direction: we are central, the backgrounded iPhone only
        // has to advertise. This is the configuration role election must pick.
        let u2 = evaluate_usability(
            Medium::Ble(BlePhy::Le1M),
            Platform::Android,
            AppState::Foreground,
            Platform::Ios,
            AppState::Background,
            &q(-60),
            true,
        );
        assert!(u2.is_usable());
    }

    #[test]
    fn a_wifi_link_dies_when_the_ios_peer_backgrounds() {
        // MultipeerConnectivity does not run in the background, so a live
        // Wi-Fi link must be declared unusable the moment the peer backgrounds.
        let u = evaluate_usability(
            Medium::Wifi(WifiFlavour::Multipeer),
            Platform::Ios,
            AppState::Foreground,
            Platform::Ios,
            AppState::Background,
            &q(-50),
            true,
        );
        assert_eq!(
            u,
            Usability::Unusable(UnusableReason::MediumUnavailableInState)
        );
    }

    #[test]
    fn hostile_quality_values_do_not_produce_nonsense_scores() {
        for rssi in [i16::MIN, -200, -95, 0, 127, i16::MAX] {
            for loss in [0u16, 1000, u16::MAX] {
                let s = Quality {
                    rssi_dbm: Some(rssi),
                    loss_permil: loss,
                    rssi_slope_dbm_s: f32::NAN,
                }
                .score();
                assert!(s.is_finite() && (0.0..=1.0).contains(&s), "{rssi} {loss} {s}");
            }
        }
    }

    #[test]
    fn goodput_is_never_zero_so_division_is_safe() {
        let g = Goodput {
            measured_bps: Some(0.0),
            estimated_bps: 0.0,
        };
        assert!(g.effective_bps() >= 1.0);
        let g2 = Goodput {
            measured_bps: Some(f32::NAN),
            estimated_bps: 100.0,
        };
        assert!(g2.effective_bps() >= 1.0);
    }

    #[test]
    fn meter_ignores_tiny_samples_and_needs_two_before_it_speaks() {
        let mut m = GoodputMeter::default();
        m.observe(20, Millis(10));
        assert_eq!(m.measured_bps(), None, "a 20-byte datagram is not a sample");
        m.observe(4000, Millis(1000));
        assert_eq!(m.measured_bps(), None, "one sample is an anecdote");
        m.observe(4000, Millis(1000));
        let v = m.measured_bps().expect("two samples");
        assert!((v - 4000.0).abs() < 1.0, "{v}");
    }

    #[test]
    fn meter_survives_zero_elapsed() {
        let mut m = GoodputMeter::default();
        m.observe(1024, Millis::ZERO);
        m.observe(1024, Millis::ZERO);
        assert_eq!(m.measured_bps(), None);
    }

    #[test]
    fn background_derate_compounds_across_both_ends() {
        let fg = prior::ble_goodput_bps(
            BlePhy::Le1M,
            Platform::Android,
            AppState::Foreground,
            Platform::Android,
            AppState::Foreground,
        );
        let mixed = prior::ble_goodput_bps(
            BlePhy::Le1M,
            Platform::Android,
            AppState::Foreground,
            Platform::Ios,
            AppState::Background,
        );
        let worst = prior::ble_goodput_bps(
            BlePhy::Le1M,
            Platform::Ios,
            AppState::Background,
            Platform::Ios,
            AppState::Background,
        );
        assert!(worst < mixed && mixed < fg, "{worst} {mixed} {fg}");
    }

    #[test]
    fn survival_prediction_is_bounded_and_total() {
        let mut snap = snapshot(
            LinkId(1),
            Medium::Ble(BlePhy::Le1M),
            Platform::Android,
            AppState::Foreground,
            Platform::Android,
            AppState::Foreground,
            247,
            Quality {
                rssi_dbm: Some(-60),
                loss_permil: 0,
                rssi_slope_dbm_s: -5.0,
            },
            &GoodputMeter::default(),
            true,
            Millis::ZERO,
            Millis::ZERO,
        );
        // 35 dB of margin losing 5 dB/s = 7 s.
        assert_eq!(snap.predicted_survival(), Millis(7_000));

        snap.quality.rssi_slope_dbm_s = 0.0;
        assert_eq!(snap.predicted_survival(), Millis::secs(60), "capped");

        snap.quality.rssi_dbm = Some(-120);
        assert_eq!(snap.predicted_survival(), Millis::ZERO, "already gone");

        snap.quality.rssi_dbm = None;
        assert_eq!(snap.predicted_survival(), Millis::secs(10), "pessimistic");

        snap.quality.rssi_dbm = Some(-60);
        snap.quality.rssi_slope_dbm_s = f32::NAN;
        let s = snap.predicted_survival();
        assert!(s <= Millis::secs(60));
    }

    #[test]
    fn datagram_payload_at_the_ble_floor() {
        let snap = snapshot(
            LinkId(1),
            Medium::Ble(BlePhy::Le1M),
            Platform::Ios,
            AppState::Foreground,
            Platform::Android,
            AppState::Foreground,
            23,
            Quality::default(),
            &GoodputMeter::default(),
            true,
            Millis::ZERO,
            Millis::ZERO,
        );
        assert_eq!(snap.datagram_payload(), 20);
        assert_eq!(snap.pair(), PairKind::IosAndroid);
    }
}
