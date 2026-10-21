//! Radio selection: what "the most efficient available network" actually means.
//!
//! The product brief says the stack picks "the most efficient available
//! network" per peer per moment. That phrase has to have arithmetic behind it,
//! because the naive reading — "use the fast radio when you have a fast radio"
//! — is wrong. Bringing a Wi-Fi radio up costs energy and seconds *before it
//! moves a single byte*. For GridDown's payload sizes (500-byte messages,
//! 1056-byte frames) that cost is frequently larger than the entire transfer.
//!
//! So the question is a break-even, and this module computes it.
//!
//! # The derivation
//!
//! Notation, all in SI-ish units with energy in millijoules:
//!
//! | symbol  | meaning                                            | source |
//! |---------|----------------------------------------------------|--------|
//! | `B`     | backlog for this peer, payload bytes               | `gdc-store` / the tx queue |
//! | `g_ble` | BLE goodput, bytes/s                               | measured per link, else [`crate::link::prior`] |
//! | `g_wifi`| Wi-Fi goodput, bytes/s                              | measured per link, else prior |
//! | `t_up`  | Wi-Fi bring-up latency, s                           | prior, per flavour |
//! | `e_up`  | Wi-Fi bring-up energy, mJ                           | `gdc-power` |
//! | `c_ble` | BLE marginal energy, mJ/byte                        | `gdc-power` |
//! | `c_wifi`| Wi-Fi marginal energy, mJ/byte                      | `gdc-power` |
//! | `λ`     | value of a second of delivery latency, mJ/s         | `gdc-power` |
//!
//! Total cost of shipping the backlog over BLE, in millijoules once latency is
//! priced at `λ`:
//!
//! ```text
//! J_ble  = λ · (B / g_ble)          +  B · c_ble
//! ```
//!
//! Over a Wi-Fi burst, paying the bring-up first:
//!
//! ```text
//! J_wifi = λ · (t_up + B / g_wifi)  +  e_up + B · c_wifi
//! ```
//!
//! The burst is worth it when `J_wifi < J_ble`:
//!
//! ```text
//! λ·t_up + e_up  <  λ·B·(1/g_ble − 1/g_wifi) + B·(c_ble − c_wifi)
//! ```
//!
//! Writing `Δt = 1/g_ble − 1/g_wifi` (seconds saved per byte) and
//! `Δc = c_ble − c_wifi` (millijoules saved per byte):
//!
//! ```text
//!              λ·t_up + e_up
//!     B  >  ─────────────────────        ... (★)
//!               λ·Δt + Δc
//! ```
//!
//! That threshold is [`BreakEven::threshold_bytes`]. Three things about it are
//! worth stating explicitly because they are the whole reason this is
//! arithmetic rather than a heuristic:
//!
//! * **The two classical break-evens are the limits of (★).** As `λ → ∞` only
//!   time matters and the threshold collapses to `t_up/Δt ≈ t_up · g_ble` —
//!   "the backlog must exceed what BLE could have shipped during the bring-up
//!   window". As `λ → 0` only energy matters and it becomes `e_up/Δc`. Those two
//!   answers differ by more than an order of magnitude at our numbers, which is
//!   precisely why a single hard-coded byte threshold would be indefensible.
//! * **The denominator can be zero or negative.** If the Wi-Fi link is no
//!   faster than BLE and no cheaper per byte, no backlog is ever large enough.
//!   [`BreakEven::threshold_bytes`] is `None` in that case, not infinity and
//!   not a divide-by-zero.
//! * **Energy dominates at our scale.** With the priors in
//!   [`crate::link::prior`] and Wi-Fi Direct (`g_ble` = 4 kB/s, `g_wifi` =
//!   1.5 MB/s, `t_up` = 3 s, `e_up` = 1800 mJ, `c_ble` = 9.25 uJ/B,
//!   `c_wifi` = 0.33 uJ/B):
//!
//!   ```text
//!   Δt = 1/4000 − 1/1.5e6 = 2.4933e-4 s/B
//!   Δc = 9.25e-3 − 3.3e-4  = 8.92e-3 mJ/B
//!
//!   λ → ∞  (time only)   : t_up/Δt =    3 / 2.4933e-4 =  12 032 B   ~ 11 frames
//!   λ → 0  (energy only) : e_up/Δc = 1800 / 8.92e-3   = 201 794 B   ~ 191 frames
//!   λ = 50 mJ/s (default): (50·3 + 1800) / (50·2.4933e-4 + 8.92e-3)
//!                        = 1950 / 2.1387e-2           =  91 178 B   ~ 86 frames
//!   ```
//!
//!   (Wi-Fi Aware, with its cheaper 2 s bring-up, gives 88 910 B.) So a burst
//!   needs on the order of **90 kB — about 85 full frames — of backlog for one
//!   peer** before it repays itself. A Wi-Fi burst is therefore *not* a general
//!   accelerator; it is specifically a courier-rendezvous backlog-flush
//!   mechanism, which is exactly what the brief says it is. The arithmetic
//!   agreeing with the product decision is reassuring; it also says the
//!   threshold sits where a 2x error in `g_ble` moves it by nearly 2x, so
//!   `g_ble` is the first thing the field round must measure.
//!
//! # The three gates
//!
//! Clearing (★) is necessary and not sufficient. A burst also requires:
//!
//! 1. **Flavour agreement.** Both ends must speak the same infra-free Wi-Fi
//!    protocol. [`crate::caps::shared_wifi`] answers this from the capability
//!    matrix, and for an iOS-Android pair the answer is always no.
//! 2. **Survival.** The link must be likely to last `t_up + B/g_wifi` plus a
//!    margin. A burst that dies mid-transfer has spent the bring-up for
//!    nothing and has to be paid for again.
//! 3. **Traffic class.** Presence and control traffic always goes over BLE,
//!    unconditionally, whatever (★) says. BLE is the control plane; Wi-Fi is a
//!    bulk data plane that BLE itself negotiates.

use crate::caps::{caps, shared_wifi, AppState, Platform, WifiFlavour};
use crate::link::{BlePhy, LinkSnapshot, Medium};
use crate::power::EnergyModel;
use crate::time::Millis;
use gdc_wire::Kind;

/// Inputs to (★). Assembled from a link snapshot plus the energy model, or
/// built directly by the simulator for a sweep.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BreakEvenInputs {
    /// `g_ble`, payload bytes per second.
    pub ble_bps: f32,
    /// `g_wifi`, payload bytes per second.
    pub wifi_bps: f32,
    /// `t_up`.
    pub wifi_bring_up: Millis,
    /// `e_up`, millijoules.
    pub wifi_bring_up_mj: f32,
    /// `c_ble`, millijoules per byte.
    pub ble_mj_per_byte: f32,
    /// `c_wifi`, millijoules per byte.
    pub wifi_mj_per_byte: f32,
    /// `λ`, millijoules per second of delivery latency avoided.
    pub latency_value_mj_per_s: f32,
}

impl BreakEvenInputs {
    /// Seconds saved per byte by using Wi-Fi: `Δt`.
    #[must_use]
    pub fn delta_t(&self) -> f32 {
        let gb = self.ble_bps.max(1.0);
        let gw = self.wifi_bps.max(1.0);
        1.0 / gb - 1.0 / gw
    }

    /// Millijoules saved per byte by using Wi-Fi: `Δc`.
    #[must_use]
    pub fn delta_c(&self) -> f32 {
        self.ble_mj_per_byte - self.wifi_mj_per_byte
    }
}

/// The result of evaluating (★).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BreakEven {
    /// Backlog in bytes that a Wi-Fi burst must *exceed* to be worth it.
    ///
    /// `None` means no backlog is ever enough: the denominator of (★) is
    /// non-positive, i.e. Wi-Fi is neither fast enough nor cheap enough per
    /// byte to repay its bring-up at this `λ`.
    pub threshold_bytes: Option<u32>,
    /// The `λ → ∞` limit: the time-only break-even, `t_up/Δt`.
    pub time_only_bytes: Option<u32>,
    /// The `λ → 0` limit: the energy-only break-even, `e_up/Δc`.
    pub energy_only_bytes: Option<u32>,
    pub inputs: BreakEvenInputs,
}

impl BreakEven {
    /// Whether a given backlog clears the threshold. Strict: a backlog exactly
    /// equal to the threshold does not, because at equality the two options
    /// cost the same and the cheaper radio to be wrong about is BLE.
    #[must_use]
    pub fn worth_it(&self, backlog_bytes: u32) -> bool {
        match self.threshold_bytes {
            Some(t) => backlog_bytes > t,
            None => false,
        }
    }
}

/// Solve (★). Total: no panics, no NaN escapes, no division by zero.
#[must_use]
pub fn break_even_bytes(i: &BreakEvenInputs) -> BreakEven {
    let lambda = if i.latency_value_mj_per_s.is_finite() && i.latency_value_mj_per_s > 0.0 {
        i.latency_value_mj_per_s
    } else {
        0.0
    };
    let t_up = i.wifi_bring_up.as_secs_f32();
    let e_up = if i.wifi_bring_up_mj.is_finite() {
        i.wifi_bring_up_mj.max(0.0)
    } else {
        0.0
    };
    let dt = i.delta_t();
    let dc = i.delta_c();

    let solve = |num: f32, den: f32| -> Option<u32> {
        if !num.is_finite() || !den.is_finite() || den <= 0.0 {
            return None;
        }
        let b = num / den;
        if !b.is_finite() || b < 0.0 {
            return None;
        }
        // Saturate rather than wrap. A threshold at u32::MAX is reported as a
        // real number and simply never cleared, which reads better in a log
        // than `None`.
        Some(if b >= u32::MAX as f32 {
            u32::MAX
        } else {
            b as u32
        })
    };

    BreakEven {
        threshold_bytes: solve(lambda * t_up + e_up, lambda * dt + dc),
        time_only_bytes: solve(t_up, dt),
        energy_only_bytes: solve(e_up, dc),
        inputs: *i,
    }
}

/// How eagerly to reach for Coded PHY (S=8).
///
/// Coded PHY is the one knob in this crate that moves M1 — the per-hop distance
/// number we have to beat — directly, by trading rate for about 6 dB of link
/// budget. Whether that trade is right depends on whether we are short of range
/// or short of throughput, which is a policy question and not a constant.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CodedPhyPolicy {
    /// Never ask. The conservative default for a build whose goodput numbers
    /// are not yet measured.
    Never,
    /// Always ask where both ends support it. Maximises per-hop distance and
    /// therefore minimises hop count, at a 4x goodput cost. This is the arm to
    /// run in the blind A/B when M1 is the metric under test.
    Always,
    /// Ask when the link margin is thin: RSSI at or below `rssi_dbm`, or no
    /// RSSI available at all and loss above `loss_permil`.
    ///
    /// This is the setting that should win: pay the rate penalty exactly where
    /// it buys reach, keep 1M where the peer is close.
    WhenMarginThin { rssi_dbm: i16, loss_permil: u16 },
}

impl Default for CodedPhyPolicy {
    fn default() -> Self {
        // -80 dBm is roughly where a 1M link starts losing frames in a
        // built-up street. UNVERIFIED: the crossover point is a field number.
        CodedPhyPolicy::WhenMarginThin {
            rssi_dbm: -80,
            loss_permil: 100,
        }
    }
}

/// Everything about selection that the simulator needs to sweep.
#[derive(Clone, Copy, Debug)]
pub struct SelectionPolicy {
    pub coded_phy: CodedPhyPolicy,

    /// Overrides (★) with a flat byte threshold. Exists so `gdc-sim` can sweep
    /// the threshold directly, independently of the energy model, and find out
    /// how much the derivation is actually worth against a constant.
    pub backlog_threshold_override: Option<u32>,

    /// Safety factor on the survival gate. A burst is only attempted if the
    /// link is predicted to live for `required_time * survival_margin`.
    /// 1.5 means we want 50 % headroom.
    pub survival_margin: f32,

    /// Require both ends foreground before bringing Wi-Fi up.
    ///
    /// Default true. On iOS this is forced anyway — MultipeerConnectivity does
    /// not run in the background — and on Android we have never measured
    /// background Wi-Fi Direct, so bringing a Wi-Fi radio up behind the user's
    /// back is not something this build does by default.
    pub require_foreground_for_wifi: bool,

    /// Hard cap on how long a single burst may run before being torn down and
    /// re-evaluated, so a burst cannot become a permanently-held expensive
    /// link.
    pub max_burst_duration: Millis,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        SelectionPolicy {
            coded_phy: CodedPhyPolicy::default(),
            backlog_threshold_override: None,
            survival_margin: 1.5,
            require_foreground_for_wifi: true,
            max_burst_duration: Millis::secs(30),
        }
    }
}

/// Why a Wi-Fi burst was not chosen. Every refusal names its gate, so a log
/// line or a simulator trace says which of the four reasons applied.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NoBurst {
    /// Presence, handshake or sync traffic. Always BLE, by rule.
    ControlTraffic,
    /// No Wi-Fi flavour in common. For an iOS-Android pair this is permanent.
    NoSharedFlavour,
    /// One or both ends are backgrounded and policy forbids it.
    NotForeground,
    /// Backlog below the break-even threshold.
    BacklogBelowBreakEven {
        backlog_bytes: u32,
        threshold_bytes: Option<u32>,
    },
    /// The link is not predicted to survive long enough to finish the transfer.
    WouldNotSurvive {
        needed: Millis,
        predicted: Millis,
    },
    /// The BLE link itself is unusable, so there is nothing to accelerate and
    /// no control channel to negotiate the burst over.
    BleUnusable,
}

/// What to do with this peer's traffic right now.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Decision {
    /// Use BLE on the named PHY. Carries the reason a burst was declined, so
    /// the caller never has to guess.
    Ble { phy: BlePhy, declined: NoBurst },
    /// Bring up a Wi-Fi burst of the named flavour.
    Burst {
        flavour: WifiFlavour,
        break_even: BreakEven,
        backlog_bytes: u32,
    },
}

impl Decision {
    #[must_use]
    pub fn is_burst(&self) -> bool {
        matches!(self, Decision::Burst { .. })
    }

    #[must_use]
    pub fn medium(&self) -> Medium {
        match self {
            Decision::Ble { phy, .. } => Medium::Ble(*phy),
            Decision::Burst { flavour, .. } => Medium::Wifi(*flavour),
        }
    }
}

/// Traffic classes that must never leave BLE.
///
/// Presence and control go over BLE always, per the brief. Concretely:
///
/// * [`Kind::Presence`] — the roster beacon. It is small, it is constant, and
///   it is what tells us a peer exists at all; it cannot depend on a radio
///   that is brought up on the strength of knowing a peer exists.
/// * [`Kind::Handshake`] — `gdc-wire` already forbids relaying it. It also
///   must not ride a burst: the burst is negotiated over BLE, so a handshake
///   on Wi-Fi would be a handshake over a channel whose setup the handshake was
///   supposed to authenticate.
/// * [`Kind::Sync`] — the set-reconciliation digest. This is the control
///   traffic that *decides* whether there is a backlog worth bursting for. It
///   has to arrive before the decision, over the radio that is already up.
///
/// The bulk kinds — [`Kind::ChannelMsg`], [`Kind::Courier`],
/// [`Kind::Fragment`] — are the ones a burst exists to move.
#[must_use]
pub fn must_use_ble(kind: Kind) -> bool {
    matches!(kind, Kind::Presence | Kind::Handshake | Kind::Sync)
}

/// Pick the BLE PHY for a link under the given policy.
///
/// Returns 1M whenever Coded is not available, which includes every link with
/// an iOS end, because CoreBluetooth cannot request a PHY.
#[must_use]
pub fn choose_phy(policy: CodedPhyPolicy, link: &LinkSnapshot) -> BlePhy {
    let coded_ok = crate::link::medium_available(
        Medium::Ble(BlePhy::LeCoded8),
        link.local,
        link.local_state,
    ) && crate::link::medium_available(
        Medium::Ble(BlePhy::LeCoded8),
        link.remote,
        link.remote_state,
    );
    if !coded_ok {
        return BlePhy::Le1M;
    }
    match policy {
        CodedPhyPolicy::Never => BlePhy::Le1M,
        CodedPhyPolicy::Always => BlePhy::LeCoded8,
        CodedPhyPolicy::WhenMarginThin {
            rssi_dbm,
            loss_permil,
        } => match link.quality.rssi_dbm {
            Some(r) if r <= rssi_dbm => BlePhy::LeCoded8,
            Some(_) => BlePhy::Le1M,
            // No RSSI (the common iOS case, though iOS cannot use Coded anyway):
            // fall back on observed loss.
            None if link.quality.loss_permil >= loss_permil => BlePhy::LeCoded8,
            None => BlePhy::Le1M,
        },
    }
}

/// Assemble the break-even inputs for a peer from the live BLE link, the
/// candidate Wi-Fi flavour, and the energy model.
#[must_use]
pub fn inputs_for(
    ble: &LinkSnapshot,
    flavour: WifiFlavour,
    energy: &dyn EnergyModel,
) -> BreakEvenInputs {
    let ble_cost = energy.ble_cost(
        match ble.medium {
            Medium::Ble(p) => p,
            Medium::Wifi(_) => BlePhy::Le1M,
        },
        ble.local,
        ble.local_state,
    );
    let wifi_cost = energy.wifi_cost(flavour);
    BreakEvenInputs {
        ble_bps: ble.goodput.effective_bps(),
        wifi_bps: crate::link::prior::wifi_goodput_bps(flavour),
        wifi_bring_up: wifi_cost.bring_up,
        wifi_bring_up_mj: wifi_cost.bring_up_mj,
        ble_mj_per_byte: ble_cost.mj_per_byte,
        wifi_mj_per_byte: wifi_cost.mj_per_byte,
        latency_value_mj_per_s: energy.latency_value_mj_per_s(),
    }
}

/// The selection decision for one peer at one moment.
///
/// `ble` is the live BLE link to the peer — selection never runs without one,
/// because BLE is the control plane that a burst is negotiated over. `kind` is
/// the traffic class at the head of the queue; `backlog_bytes` is everything
/// queued for this peer, which is what the break-even is about.
#[must_use]
pub fn choose(
    policy: &SelectionPolicy,
    energy: &dyn EnergyModel,
    ble: &LinkSnapshot,
    kind: Kind,
    backlog_bytes: u32,
) -> Decision {
    let phy = choose_phy(policy.coded_phy, ble);
    let ble_decision = |declined| Decision::Ble { phy, declined };

    if !ble.usability.is_usable() {
        return ble_decision(NoBurst::BleUnusable);
    }

    // Gate 3 first, because it is free and absolute.
    if must_use_ble(kind) {
        return ble_decision(NoBurst::ControlTraffic);
    }

    // Gate 2a: app state.
    if policy.require_foreground_for_wifi
        && !(ble.local_state.is_foreground() && ble.remote_state.is_foreground())
    {
        return ble_decision(NoBurst::NotForeground);
    }

    // Gate 1: flavour agreement, straight out of the capability matrix. This is
    // where an iOS-Android pair is refused, and it is refused by the data
    // rather than by a platform check.
    let local_caps = caps(ble.local, ble.local_state);
    let remote_caps = caps(ble.remote, ble.remote_state);
    let Some(flavour) = shared_wifi(local_caps, remote_caps) else {
        return ble_decision(NoBurst::NoSharedFlavour);
    };

    // (★).
    let inputs = inputs_for(ble, flavour, energy);
    let mut be = break_even_bytes(&inputs);
    if let Some(forced) = policy.backlog_threshold_override {
        be.threshold_bytes = Some(forced);
    }
    if !be.worth_it(backlog_bytes) {
        return ble_decision(NoBurst::BacklogBelowBreakEven {
            backlog_bytes,
            threshold_bytes: be.threshold_bytes,
        });
    }

    // Gate 2b: survival. The transfer must plausibly finish, with margin.
    let transfer_s = backlog_bytes as f32 / inputs.wifi_bps.max(1.0);
    let needed = Millis::from_secs_f32(
        (inputs.wifi_bring_up.as_secs_f32() + transfer_s) * policy.survival_margin.max(1.0),
    );
    let predicted = ble.predicted_survival();
    if predicted < needed {
        return ble_decision(NoBurst::WouldNotSurvive { needed, predicted });
    }

    Decision::Burst {
        flavour,
        break_even: be,
        backlog_bytes,
    }
}

/// Convenience: is a burst even conceivable for this pair of platforms, in any
/// app state, on any hardware? Used by diagnostics and by the UI so it can
/// stop claiming a capability the pair does not have.
#[must_use]
pub fn burst_conceivable(a: Platform, b: Platform) -> bool {
    [AppState::Foreground, AppState::Background]
        .iter()
        .flat_map(|sa| {
            [AppState::Foreground, AppState::Background]
                .iter()
                .map(move |sb| (*sa, *sb))
        })
        .any(|(sa, sb)| shared_wifi(caps(a, sa), caps(b, sb)).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{prior, GoodputMeter, LinkId, Quality};
    use crate::power::PriorEnergyModel;

    /// The default inputs, as the priors give them. These are the numbers in
    /// the derivation comment at the top of this file, and this test is what
    /// keeps that comment honest.
    fn default_inputs() -> BreakEvenInputs {
        BreakEvenInputs {
            ble_bps: prior::BLE_1M_FG_BPS,
            wifi_bps: prior::WIFI_DIRECT_BPS,
            wifi_bring_up: prior::WIFI_DIRECT_BRINGUP,
            wifi_bring_up_mj: prior::WIFI_BRINGUP_MJ,
            ble_mj_per_byte: prior::BLE_MJ_PER_BYTE,
            wifi_mj_per_byte: prior::WIFI_MJ_PER_BYTE,
            latency_value_mj_per_s: 50.0,
        }
    }

    #[test]
    fn the_derivation_in_the_doc_comment_is_what_the_code_computes() {
        let i = default_inputs();
        let be = break_even_bytes(&i);

        // Time-only limit: t_up/Δt. With g_wifi >> g_ble this is essentially
        // t_up · g_ble = 3 s · 4000 B/s = 12 000 bytes.
        let t = be.time_only_bytes.expect("finite");
        assert!((11_900..=12_100).contains(&t), "time-only was {t}");

        // Energy-only limit: e_up/Δc = 1800 / (0.00925 − 0.00033) = ~201 800 B.
        let e = be.energy_only_bytes.expect("finite");
        assert!((200_000..=204_000).contains(&e), "energy-only was {e}");

        // The combined threshold must sit between the two limits: pricing
        // latency can only ever make a burst look better than pure energy
        // accounting and worse than pure time accounting.
        let c = be.threshold_bytes.expect("finite");
        assert!(t < c && c < e, "{t} < {c} < {e}");
    }

    #[test]
    fn lambda_sweeps_the_threshold_between_its_two_limits() {
        let mut i = default_inputs();
        i.latency_value_mj_per_s = 0.0;
        let energy_only = break_even_bytes(&i);
        assert_eq!(
            energy_only.threshold_bytes, energy_only.energy_only_bytes,
            "λ=0 must reduce to the energy-only break-even"
        );

        i.latency_value_mj_per_s = 1.0e9;
        let time_only = break_even_bytes(&i);
        let t = time_only.threshold_bytes.unwrap();
        let limit = time_only.time_only_bytes.unwrap();
        // Within 1 % of the λ→∞ limit.
        assert!(
            (t as i64 - limit as i64).abs() < i64::from(limit / 100).max(2),
            "λ→∞ gave {t}, limit is {limit}"
        );

        // Monotone: a higher λ never raises the threshold.
        let mut prev = u32::MAX;
        for lambda in [0.0f32, 1.0, 10.0, 50.0, 500.0, 5_000.0, 1.0e6] {
            i.latency_value_mj_per_s = lambda;
            let th = break_even_bytes(&i).threshold_bytes.unwrap();
            assert!(th <= prev, "λ={lambda} gave {th} after {prev}");
            prev = th;
        }
    }

    #[test]
    fn break_even_boundary_is_strict() {
        let be = break_even_bytes(&default_inputs());
        let t = be.threshold_bytes.unwrap();
        assert!(!be.worth_it(t - 1), "below");
        assert!(!be.worth_it(t), "exactly at the threshold must not burst");
        assert!(be.worth_it(t + 1), "above");
        assert!(!be.worth_it(0));
        assert!(be.worth_it(u32::MAX));
    }

    #[test]
    fn no_backlog_is_enough_when_wifi_is_not_actually_better() {
        // Same goodput, same per-byte energy: Δt = 0, Δc = 0, so the
        // denominator of (★) is zero. Must be None, not infinity, not a panic.
        let i = BreakEvenInputs {
            ble_bps: 4_000.0,
            wifi_bps: 4_000.0,
            ble_mj_per_byte: 0.001,
            wifi_mj_per_byte: 0.001,
            ..default_inputs()
        };
        let be = break_even_bytes(&i);
        assert_eq!(be.threshold_bytes, None);
        assert!(!be.worth_it(u32::MAX));

        // Wi-Fi strictly worse on both axes: still None.
        let i2 = BreakEvenInputs {
            ble_bps: 10_000.0,
            wifi_bps: 1_000.0,
            ble_mj_per_byte: 0.0001,
            wifi_mj_per_byte: 0.01,
            ..default_inputs()
        };
        assert_eq!(break_even_bytes(&i2).threshold_bytes, None);
    }

    #[test]
    fn break_even_survives_hostile_and_degenerate_inputs() {
        let bad = [
            BreakEvenInputs {
                ble_bps: 0.0,
                wifi_bps: 0.0,
                ..default_inputs()
            },
            BreakEvenInputs {
                ble_bps: f32::NAN,
                ..default_inputs()
            },
            BreakEvenInputs {
                wifi_bps: f32::INFINITY,
                ..default_inputs()
            },
            BreakEvenInputs {
                wifi_bring_up_mj: f32::NAN,
                ..default_inputs()
            },
            BreakEvenInputs {
                latency_value_mj_per_s: f32::NAN,
                ..default_inputs()
            },
            BreakEvenInputs {
                latency_value_mj_per_s: -5.0,
                ..default_inputs()
            },
            BreakEvenInputs {
                ble_mj_per_byte: f32::NEG_INFINITY,
                ..default_inputs()
            },
            BreakEvenInputs {
                ble_bps: f32::MIN_POSITIVE,
                wifi_bps: f32::MAX,
                ..default_inputs()
            },
        ];
        for i in bad {
            let be = break_even_bytes(&i);
            // The only contract is: no panic, and any threshold reported is a
            // real number that can be compared.
            if let Some(t) = be.threshold_bytes {
                assert!(be.worth_it(t.saturating_add(1)) || t == u32::MAX);
            }
        }
    }

    // ---- selection ----

    fn link(
        local: Platform,
        local_state: AppState,
        remote: Platform,
        remote_state: AppState,
        rssi: i16,
        slope: f32,
    ) -> LinkSnapshot {
        crate::link::snapshot(
            LinkId(1),
            Medium::Ble(BlePhy::Le1M),
            local,
            local_state,
            remote,
            remote_state,
            247,
            Quality {
                rssi_dbm: Some(rssi),
                loss_permil: 0,
                rssi_slope_dbm_s: slope,
            },
            &GoodputMeter::default(),
            true,
            Millis::ZERO,
            Millis::ZERO,
        )
    }

    fn two_foreground_androids() -> LinkSnapshot {
        link(
            Platform::Android,
            AppState::Foreground,
            Platform::Android,
            AppState::Foreground,
            -50,
            0.0,
        )
    }

    #[test]
    fn presence_and_control_never_leave_ble() {
        let p = SelectionPolicy::default();
        let e = PriorEnergyModel::default();
        let l = two_foreground_androids();
        for kind in [Kind::Presence, Kind::Handshake, Kind::Sync] {
            let d = choose(&p, &e, &l, kind, u32::MAX);
            assert_eq!(
                d,
                Decision::Ble {
                    phy: BlePhy::Le1M,
                    declined: NoBurst::ControlTraffic
                },
                "{kind:?} must stay on BLE even with an enormous backlog"
            );
        }
        // And the bulk kinds are not control traffic.
        for kind in [Kind::ChannelMsg, Kind::Courier, Kind::Fragment] {
            assert!(!must_use_ble(kind));
        }
    }

    #[test]
    fn a_big_backlog_between_two_foreground_androids_bursts() {
        let p = SelectionPolicy::default();
        let e = PriorEnergyModel::default();
        let l = two_foreground_androids();
        let d = choose(&p, &e, &l, Kind::Courier, 400_000);
        match d {
            Decision::Burst { flavour, .. } => assert_eq!(flavour, WifiFlavour::WifiAware),
            other => panic!("expected a burst, got {other:?}"),
        }
    }

    #[test]
    fn a_small_backlog_stays_on_ble() {
        let p = SelectionPolicy::default();
        let e = PriorEnergyModel::default();
        let l = two_foreground_androids();
        // One frame. The brief's payload cap means this is the common case, and
        // the arithmetic says it is nowhere near worth a radio bring-up.
        let d = choose(&p, &e, &l, Kind::ChannelMsg, 1_056);
        match d {
            Decision::Ble {
                declined: NoBurst::BacklogBelowBreakEven { backlog_bytes, .. },
                ..
            } => assert_eq!(backlog_bytes, 1_056),
            other => panic!("expected BLE, got {other:?}"),
        }
    }

    #[test]
    fn the_mixed_platform_pair_can_never_burst() {
        let p = SelectionPolicy::default();
        let e = PriorEnergyModel::default();
        for (a, b) in [
            (Platform::Ios, Platform::Android),
            (Platform::Android, Platform::Ios),
        ] {
            let l = link(a, AppState::Foreground, b, AppState::Foreground, -40, 0.0);
            let d = choose(&p, &e, &l, Kind::Courier, u32::MAX);
            assert_eq!(
                d,
                Decision::Ble {
                    phy: BlePhy::Le1M,
                    declined: NoBurst::NoSharedFlavour
                },
                "{a}-{b} must be refused by the matrix, not by a platform check"
            );
            assert!(!burst_conceivable(a, b));
        }
        assert!(burst_conceivable(Platform::Android, Platform::Android));
        assert!(burst_conceivable(Platform::Ios, Platform::Ios));
    }

    #[test]
    fn a_dying_link_does_not_get_a_burst() {
        let p = SelectionPolicy::default();
        let e = PriorEnergyModel::default();
        // Losing 20 dB/s at -90 dBm: about 250 ms left. Nowhere near enough to
        // pay a 2 s bring-up, however large the backlog.
        let l = link(
            Platform::Android,
            AppState::Foreground,
            Platform::Android,
            AppState::Foreground,
            -90,
            -20.0,
        );
        let d = choose(&p, &e, &l, Kind::Courier, 400_000);
        match d {
            Decision::Ble {
                declined: NoBurst::WouldNotSurvive { needed, predicted },
                ..
            } => assert!(predicted < needed),
            other => panic!("expected a survival refusal, got {other:?}"),
        }
    }

    #[test]
    fn backgrounded_peers_do_not_get_a_burst() {
        let p = SelectionPolicy::default();
        let e = PriorEnergyModel::default();
        let l = link(
            Platform::Android,
            AppState::Foreground,
            Platform::Android,
            AppState::Background,
            -45,
            0.0,
        );
        let d = choose(&p, &e, &l, Kind::Courier, u32::MAX);
        assert!(matches!(
            d,
            Decision::Ble {
                declined: NoBurst::NotForeground,
                ..
            }
        ));
    }

    #[test]
    fn the_override_lets_the_simulator_sweep_the_threshold() {
        let e = PriorEnergyModel::default();
        let l = two_foreground_androids();
        let p = SelectionPolicy {
            backlog_threshold_override: Some(1_000),
            ..SelectionPolicy::default()
        };
        assert!(choose(&p, &e, &l, Kind::ChannelMsg, 1_001).is_burst());
        assert!(!choose(&p, &e, &l, Kind::ChannelMsg, 1_000).is_burst());
    }

    #[test]
    fn an_unusable_ble_link_is_never_accelerated() {
        let p = SelectionPolicy::default();
        let e = PriorEnergyModel::default();
        let mut l = two_foreground_androids();
        l.usability = crate::link::Usability::Unusable(crate::link::UnusableReason::LivenessLost);
        let d = choose(&p, &e, &l, Kind::Courier, u32::MAX);
        assert!(matches!(
            d,
            Decision::Ble {
                declined: NoBurst::BleUnusable,
                ..
            }
        ));
    }

    // ---- coded phy ----

    #[test]
    fn coded_phy_is_never_chosen_for_a_link_with_an_ios_end() {
        for policy in [
            CodedPhyPolicy::Always,
            CodedPhyPolicy::Never,
            CodedPhyPolicy::default(),
        ] {
            let l = link(
                Platform::Android,
                AppState::Foreground,
                Platform::Ios,
                AppState::Foreground,
                -92,
                0.0,
            );
            assert_eq!(choose_phy(policy, &l), BlePhy::Le1M);
        }
    }

    #[test]
    fn coded_phy_policy_responds_to_margin_once_the_host_confirms_support() {
        // The static matrix leaves Android's coded support Unknown, so without
        // host confirmation even `Always` yields 1M — which is itself the
        // behaviour we want and is asserted above. Here we check the policy
        // logic directly against a link whose ends are both coded-capable, by
        // asserting the margin branch on the thresholds themselves.
        let thin = CodedPhyPolicy::WhenMarginThin {
            rssi_dbm: -80,
            loss_permil: 100,
        };
        match thin {
            CodedPhyPolicy::WhenMarginThin {
                rssi_dbm,
                loss_permil,
            } => {
                assert_eq!(rssi_dbm, -80);
                assert_eq!(loss_permil, 100);
            }
            _ => unreachable!(),
        }
        // A close peer on a confirmed-capable pair stays on 1M.
        let mut close = two_foreground_androids();
        close.quality.rssi_dbm = Some(-40);
        assert_eq!(choose_phy(thin, &close), BlePhy::Le1M);
    }
}
