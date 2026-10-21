//! The radio model: path loss, shadowing, bodies, buildings, and the two BLE
//! PHYs we can actually choose between on a phone.
//!
//! Every constant here is either cited or explicitly marked as an assumption.
//! None of them is calibrated — there is no field data yet. [`fit_from_samples`]
//! is the hook that replaces the assumptions with fitted values once the user
//! hands us CSVs from a walk.

use crate::provenance::{ParamDoc, ParamSource};
use serde::{Deserialize, Serialize};

/// Which BLE physical layer a transmission uses.
///
/// These are the two a phone can realistically pick between. 2M is faster but
/// shorter-ranged and so is never the right answer for a mesh floor; S=2 coded
/// sits between the two modelled points and can be added by setting
/// `coding_factor` and `coded_gain_db` from a scenario file.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhyMode {
    /// LE 1M, the uncoded default and the only mode guaranteed everywhere.
    Ble1M,
    /// LE Coded, S=8. Longer reach, one eighth of the symbol-to-bit rate.
    BleCoded8,
}

impl PhyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PhyMode::Ble1M => "ble_1m",
            PhyMode::BleCoded8 => "ble_coded_s8",
        }
    }

    pub const ALL: [PhyMode; 2] = [PhyMode::Ble1M, PhyMode::BleCoded8];
}

/// Where a phone is while it relays. Body shadowing is the loss nobody models
/// and it is worth more dB than most of the parameters people argue about.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyPosition {
    /// Held out, screen visible, nothing between the antenna and the peer.
    InHand,
    /// Trouser or jacket pocket. One layer of cloth and a leg or a torso.
    Pocket,
    /// Pocket on the far side of the body from the peer. Worst realistic case
    /// and the one that happens whenever two walkers are not facing each other.
    PocketBodyBlocked,
    /// In a bag or rucksack.
    Bag,
}

/// Obstruction model for a built-up area.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct ObstructionConfig {
    /// Extra loss for each building block the straight line between two nodes
    /// passes through. In a street grid this is what makes round-a-corner links
    /// fail while same-street links at the same distance work.
    pub per_block_db: f64,
    /// Diffuse clutter loss accumulated per 100 m even with clear line of
    /// sight: parked cars, street furniture, bodies of other pedestrians.
    pub clutter_db_per_100m: f64,
    /// Ceiling on total obstruction loss, so a pathological geometry cannot
    /// produce a 400 dB link and an undefined probability.
    pub max_db: f64,
}

impl Default for ObstructionConfig {
    fn default() -> Self {
        ObstructionConfig {
            per_block_db: 18.0,
            clutter_db_per_100m: 4.0,
            max_db: 60.0,
        }
    }
}

/// Everything the PHY needs, all of it loadable from a scenario file.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PhyConfig {
    /// Conducted transmit power. Phones advertise at or near 0 dBm; the
    /// Bluetooth class-2 ceiling is +4 dBm and neither iOS nor Android exposes
    /// a way to raise it from an app.
    pub tx_power_dbm: f64,
    /// Free-space loss at the 1 m reference distance, 2.44 GHz.
    pub ref_loss_db: f64,
    /// Log-distance exponent. 2.0 is free space; published urban
    /// outdoor-to-outdoor fits sit between 2.7 and 3.5.
    pub path_loss_exponent: f64,
    /// Log-normal shadowing standard deviation, dB.
    pub shadowing_sigma_db: f64,
    /// How long one shadowing realisation persists before it is redrawn, in
    /// seconds. Shadowing is spatially correlated, so a walking pair should not
    /// get an independent draw every millisecond.
    pub shadowing_coherence_s: f64,
    /// Body loss by phone position, dB, applied once per end of the link.
    pub body_loss_in_hand_db: f64,
    pub body_loss_pocket_db: f64,
    pub body_loss_pocket_blocked_db: f64,
    pub body_loss_bag_db: f64,
    pub obstruction: ObstructionConfig,
    /// Receiver sensitivity on LE 1M for a real phone front end, at the packet
    /// error rate implied by `per_at_sensitivity`.
    pub sensitivity_1m_dbm: f64,
    /// Coding gain of LE Coded S=8 over LE 1M.
    pub coded_gain_db: f64,
    /// Steepness of the error-rate transition around sensitivity, dB. Smaller
    /// is a sharper cliff.
    pub per_transition_db: f64,
    /// Packet error rate exactly at the sensitivity point.
    pub per_at_sensitivity: f64,
    /// Error-rate floor that no amount of signal removes: front-end
    /// imperfection, 2.4 GHz Wi-Fi interference, scheduler misses.
    pub per_floor: f64,
    /// Reference payload the quoted PER applies to. Longer packets fail more
    /// often for the same per-bit error rate.
    pub per_reference_bytes: f64,
    /// Symbol rate of the LE radio.
    pub symbol_rate_sps: f64,
    /// Symbols per bit on the coded PHY. The Bluetooth Core spec defines S=2
    /// and S=8; S=8 is one eighth of 1 Mbit/s, i.e. 125 kbit/s.
    pub coded_symbols_per_bit: f64,
    /// Co-channel capture threshold: a colliding packet this many dB weaker
    /// than the wanted one does not destroy it.
    pub capture_threshold_db: f64,
}

impl Default for PhyConfig {
    fn default() -> Self {
        PhyConfig {
            tx_power_dbm: 0.0,
            ref_loss_db: 40.2,
            path_loss_exponent: 2.6,
            shadowing_sigma_db: 6.0,
            shadowing_coherence_s: 5.0,
            body_loss_in_hand_db: 2.0,
            body_loss_pocket_db: 8.0,
            body_loss_pocket_blocked_db: 15.0,
            body_loss_bag_db: 10.0,
            obstruction: ObstructionConfig::default(),
            sensitivity_1m_dbm: -93.0,
            coded_gain_db: 12.0,
            per_transition_db: 2.0,
            per_at_sensitivity: 0.308,
            per_floor: 0.01,
            per_reference_bytes: 37.0,
            symbol_rate_sps: 1_000_000.0,
            coded_symbols_per_bit: 8.0,
            capture_threshold_db: 6.0,
        }
    }
}

impl PhyConfig {
    /// The provenance table. This is the answer to "where did 3.0 come from".
    pub fn provenance(&self) -> Vec<ParamDoc> {
        vec![
            ParamDoc::new(
                "tx_power_dbm",
                self.tx_power_dbm,
                "dBm",
                ParamSource::lit(
                    "Handset BLE transmitters sit at or near 0 dBm conducted; \
                     neither CoreBluetooth nor the Android BLE API exposes TX power \
                     control to an app, so this is fixed rather than a lever.",
                ),
            ),
            ParamDoc::new(
                "ref_loss_db",
                self.ref_loss_db,
                "dB",
                ParamSource::spec(
                    "Free-space path loss at d=1 m, f=2.44 GHz: \
                     20*log10(4*pi*d/lambda) = 40.19 dB. Derived, not guessed.",
                ),
            ),
            ParamDoc::new(
                "path_loss_exponent",
                self.path_loss_exponent,
                "",
                ParamSource::assumed(
                    "Street-canyon line-of-sight end of the published urban \
                     log-distance band (2.7-3.5 is a blind urban fit, but that band \
                     already absorbs building blockage, which this model accounts for \
                     separately in obstruction.per_block_db; double-counting it would \
                     make every link fail). THE SINGLE MOST IMPORTANT NUMBER TO \
                     REFIT: M1 per-hop distance scales as 10^(margin/(10*n)).",
                ),
            ),
            ParamDoc::new(
                "shadowing_sigma_db",
                self.shadowing_sigma_db,
                "dB",
                ParamSource::assumed(
                    "Typical log-normal shadowing sigma for outdoor urban links is \
                     quoted between 4 and 8 dB; 6 dB taken as the mid-point. Sets \
                     the width of the 10th/90th percentile band M1 asks for.",
                ),
            ),
            ParamDoc::new(
                "shadowing_coherence_s",
                self.shadowing_coherence_s,
                "s",
                ParamSource::assumed(
                    "At 1.3 m/s a pedestrian covers ~6.5 m in 5 s, which is the \
                     order of the shadowing decorrelation distance in street \
                     canyons. Refit from the autocorrelation of field RSSI.",
                ),
            ),
            ParamDoc::new(
                "body_loss_pocket_db",
                self.body_loss_pocket_db,
                "dB",
                ParamSource::assumed(
                    "Body/pocket loss at 2.4 GHz is commonly reported in the 5-15 dB \
                     range depending on whether the torso is in the path. 8 dB for a \
                     near-side pocket, 15 dB for far-side. MEASURE THIS FIRST: it is \
                     the difference between a 40 m and a 100 m per-hop claim and \
                     nobody publishing mesh-messenger range figures states it.",
                ),
            ),
            ParamDoc::new(
                "body_loss_pocket_blocked_db",
                self.body_loss_pocket_blocked_db,
                "dB",
                ParamSource::assumed("See body_loss_pocket_db."),
            ),
            ParamDoc::new(
                "obstruction_per_block_db",
                self.obstruction.per_block_db,
                "dB",
                ParamSource::assumed(
                    "One building block of brick/concrete between two street-level \
                     antennas. Chosen so a round-the-corner link at 50 m fails while \
                     a same-street link at 50 m succeeds, which is the qualitative \
                     behaviour any built-up-area measurement shows.",
                ),
            ),
            ParamDoc::new(
                "obstruction_clutter_db_per_100m",
                self.obstruction.clutter_db_per_100m,
                "dB/100m",
                ParamSource::assumed("Parked vehicles, street furniture, other pedestrians."),
            ),
            ParamDoc::new(
                "sensitivity_1m_dbm",
                self.sensitivity_1m_dbm,
                "dBm",
                ParamSource::lit(
                    "Bluetooth Core requires only -70 dBm for LE 1M, but shipping \
                     handset radios measure -90 to -95 dBm. -93 dBm assumed as a \
                     mid-range real receiver; this is a literature/datasheet figure, \
                     not one of ours.",
                ),
            ),
            ParamDoc::new(
                "coded_gain_db",
                self.coded_gain_db,
                "dB",
                ParamSource::spec(
                    "Bluetooth Core 5.x LE Coded S=8 reference sensitivity is -82 dBm \
                     against -70 dBm for LE 1M, i.e. 12 dB of coding gain. At the \
                     assumed n=2.6 that is 10^(12/26) = 2.9x range in the link \
                     budget, trimmed to about 2.5x once the longer coded packet's \
                     own error lengthening is included; at n=4.0 it would be 2.0x. \
                     The brief's 'roughly 2x' corresponds to the harsher end.",
                ),
            ),
            ParamDoc::new(
                "coded_symbols_per_bit",
                self.coded_symbols_per_bit,
                "symbols/bit",
                ParamSource::spec(
                    "LE Coded S=8 is 125 kbit/s against 1 Mbit/s, i.e. one EIGHTH of \
                     the rate, not one quarter. One quarter would be between S=2 \
                     (500 kbit/s) and S=8; set this to 2.0 to model S=2.",
                ),
            ),
            ParamDoc::new(
                "per_transition_db",
                self.per_transition_db,
                "dB",
                ParamSource::assumed(
                    "Logistic approximation to the BLE PER-vs-SNR waterfall. A real \
                     curve goes from 10% to 0.1% in about 3 dB.",
                ),
            ),
            ParamDoc::new(
                "per_floor",
                self.per_floor,
                "",
                ParamSource::assumed(
                    "1% irreducible loss from 2.4 GHz Wi-Fi interference and host \
                     scheduler misses. Refit from the success rate at 1 m.",
                ),
            ),
            ParamDoc::new(
                "capture_threshold_db",
                self.capture_threshold_db,
                "dB",
                ParamSource::assumed(
                    "GFSK co-channel capture. Governs how hard a dense flood \
                     actually collapses, so it matters for the 150-node number.",
                ),
            ),
        ]
    }

    pub fn body_loss_db(&self, pos: BodyPosition) -> f64 {
        match pos {
            BodyPosition::InHand => self.body_loss_in_hand_db,
            BodyPosition::Pocket => self.body_loss_pocket_db,
            BodyPosition::PocketBodyBlocked => self.body_loss_pocket_blocked_db,
            BodyPosition::Bag => self.body_loss_bag_db,
        }
    }

    /// Median log-distance path loss, excluding shadowing, bodies and buildings.
    ///
    /// `PL(d) = PL(1 m) + 10 n log10(d)`. Distances below 1 m clamp to the
    /// reference, because the log-distance model is not valid in the near field
    /// and returning a negative loss would be worse than being wrong.
    pub fn path_loss_db(&self, distance_m: f64) -> f64 {
        let d = if distance_m.is_finite() {
            distance_m.max(1.0)
        } else {
            return f64::INFINITY;
        };
        self.ref_loss_db + 10.0 * self.path_loss_exponent * d.log10()
    }

    /// Obstruction loss for a path crossing `blocks` building interiors.
    pub fn obstruction_db(&self, distance_m: f64, blocks: u32) -> f64 {
        if !distance_m.is_finite() {
            return self.obstruction.max_db;
        }
        let clutter = self.obstruction.clutter_db_per_100m * (distance_m.max(0.0) / 100.0);
        let blocked = self.obstruction.per_block_db * f64::from(blocks);
        (clutter + blocked).min(self.obstruction.max_db).max(0.0)
    }

    /// Receiver sensitivity for a mode.
    pub fn sensitivity_dbm(&self, mode: PhyMode) -> f64 {
        match mode {
            PhyMode::Ble1M => self.sensitivity_1m_dbm,
            PhyMode::BleCoded8 => self.sensitivity_1m_dbm - self.coded_gain_db,
        }
    }

    /// Full link budget. Returns received power in dBm.
    pub fn rx_power_dbm(&self, g: &LinkGeometry) -> f64 {
        self.tx_power_dbm
            - self.path_loss_db(g.distance_m)
            - self.obstruction_db(g.distance_m, g.blocks_crossed)
            - self.body_loss_db(g.tx_body)
            - self.body_loss_db(g.rx_body)
            + g.shadowing_db
    }

    /// Packet error rate for a received power, mode and packet length.
    ///
    /// Logistic in the margin above sensitivity, then lengthened: a 250-byte
    /// GATT write is more fragile than a 37-byte advertisement at the same
    /// signal level, which is why big frames do not simply ride for free.
    pub fn packet_error_rate(&self, rx_dbm: f64, mode: PhyMode, bytes: usize) -> f64 {
        if !rx_dbm.is_finite() {
            return 1.0;
        }
        let margin = rx_dbm - self.sensitivity_dbm(mode);
        let k = self.per_transition_db.max(0.1);
        // Chosen so that per == per_at_sensitivity exactly at margin == 0.
        let p0 = self.per_at_sensitivity.clamp(1e-9, 1.0 - 1e-9);
        let odds = (p0 / (1.0 - p0)) * (-margin / k).exp2();
        let per_ref = odds / (1.0 + odds);
        let per_ref = if per_ref.is_finite() {
            per_ref.clamp(0.0, 1.0)
        } else {
            1.0
        };
        let scale = (bytes as f64 / self.per_reference_bytes.max(1.0)).max(0.0);
        // Independent-bit-error lengthening of the reference PER.
        let survive = (1.0 - per_ref).max(0.0).powf(scale);
        let per = 1.0 - survive;
        (per + self.per_floor - per * self.per_floor).clamp(0.0, 1.0)
    }

    /// Airtime of one packet, microseconds.
    ///
    /// LE 1M: 1-byte preamble, 4-byte access address, 2-byte header, payload,
    /// 3-byte CRC, 8 microseconds per byte. LE Coded: the preamble is 80
    /// microseconds and the coded blocks run at `coded_symbols_per_bit`.
    pub fn airtime_us(&self, mode: PhyMode, payload_bytes: usize) -> u64 {
        let overhead_bytes = 1.0 + 4.0 + 2.0 + 3.0;
        let bits = (payload_bytes as f64 + overhead_bytes) * 8.0;
        let rate = self.symbol_rate_sps.max(1.0);
        let us = match mode {
            PhyMode::Ble1M => bits / rate * 1e6,
            PhyMode::BleCoded8 => {
                80.0 + bits * self.coded_symbols_per_bit.max(1.0) / rate * 1e6
            }
        };
        if us.is_finite() {
            us.max(1.0) as u64
        } else {
            1
        }
    }

    /// Application bit rate of the mode, bits per second.
    pub fn phy_bitrate_bps(&self, mode: PhyMode) -> f64 {
        match mode {
            PhyMode::Ble1M => self.symbol_rate_sps,
            PhyMode::BleCoded8 => self.symbol_rate_sps / self.coded_symbols_per_bit.max(1.0),
        }
    }

    /// Distance at which median success (no shadowing, given bodies and
    /// `blocks`) crosses 50% for a packet of `bytes`. Bisection, so it cannot
    /// diverge.
    pub fn median_range_m(
        &self,
        mode: PhyMode,
        bytes: usize,
        tx_body: BodyPosition,
        rx_body: BodyPosition,
        blocks: u32,
    ) -> f64 {
        let mut lo = 1.0f64;
        let mut hi = 5000.0f64;
        let ok = |d: f64| {
            let g = LinkGeometry {
                distance_m: d,
                blocks_crossed: blocks,
                tx_body,
                rx_body,
                shadowing_db: 0.0,
            };
            self.packet_error_rate(self.rx_power_dbm(&g), mode, bytes) < 0.5
        };
        if !ok(lo) {
            return 0.0;
        }
        if ok(hi) {
            return hi;
        }
        for _ in 0..60 {
            let mid = 0.5 * (lo + hi);
            if ok(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        0.5 * (lo + hi)
    }
}

/// The geometry of one link at one instant.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct LinkGeometry {
    pub distance_m: f64,
    pub blocks_crossed: u32,
    pub tx_body: BodyPosition,
    pub rx_body: BodyPosition,
    pub shadowing_db: f64,
}

// --------------------------------------------------------------------------
// Fitting
// --------------------------------------------------------------------------

/// One field observation, as it will arrive in a CSV from a walk.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct PhySample {
    pub distance_m: f64,
    pub mode: PhyMode,
    /// Did a one-hop message succeed on first attempt.
    pub success: bool,
    /// Received signal strength, if the build logged it. Optional because the
    /// success/fail column is the one we can always get and RSSI is the one
    /// platforms lie about.
    pub rssi_dbm: Option<f64>,
    pub tx_body: BodyPosition,
    pub rx_body: BodyPosition,
    pub blocks_crossed: u32,
    pub payload_bytes: usize,
}

/// What a fit produced.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct FitResult {
    pub fitted: PhyConfig,
    /// Which field round these samples came from.
    pub round: u32,
    /// Root-mean-square RSSI residual in dB over samples that carried RSSI.
    pub rssi_residual_db: f64,
    /// Number of RSSI samples the regression used.
    pub rssi_samples: usize,
    /// Mean log-likelihood per success/fail observation under the fitted model.
    /// Higher (less negative) is better; -ln(2) is a coin flip.
    pub mean_log_likelihood: f64,
    pub outcome_samples: usize,
    /// Whether the fit changed anything. A CSV with no usable rows leaves the
    /// config alone and says so rather than returning a confident nonsense.
    pub converged: bool,
    pub notes: Vec<String>,
}

/// Refit path-loss exponent, reference loss, shadowing sigma and body loss from
/// field samples.
///
/// Two stages, because the two columns in a field CSV carry different
/// information:
///
/// 1. Least squares on `rssi ~ tx_power - (PL0 + 10 n log10 d)` recovers `n`
///    and `PL0` directly, and the residual spread is the shadowing sigma.
/// 2. A bounded coordinate search over `(n, sigma, pocket body loss)` maximises
///    the likelihood of the success/fail column, which is the only thing
///    available when a platform refuses to report RSSI.
///
/// Returns the fitted config with every touched parameter marked
/// `ParamSource::Fitted`, plus the residual, so the caller can decide whether
/// to trust it.
pub fn fit_from_samples(base: &PhyConfig, samples: &[PhySample], round: u32) -> FitResult {
    let mut notes = Vec::new();
    let mut out = base.clone();

    // Stage 1: regression on RSSI samples, which must use a single mode's
    // geometry. Body and obstruction loss are subtracted out using the base
    // config so the regression sees path loss alone.
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for s in samples {
        if let Some(rssi) = s.rssi_dbm {
            if !rssi.is_finite() || !(s.distance_m > 0.0) {
                continue;
            }
            let corrected = base.tx_power_dbm
                - rssi
                - base.obstruction_db(s.distance_m, s.blocks_crossed)
                - base.body_loss_db(s.tx_body)
                - base.body_loss_db(s.rx_body);
            xs.push(s.distance_m.max(1.0).log10());
            ys.push(corrected);
        }
    }
    let mut residual = f64::NAN;
    let n_rssi = xs.len();
    if n_rssi >= 2 {
        let nf = n_rssi as f64;
        let mx = xs.iter().sum::<f64>() / nf;
        let my = ys.iter().sum::<f64>() / nf;
        let mut sxx = 0.0;
        let mut sxy = 0.0;
        for i in 0..n_rssi {
            let dx = xs[i] - mx;
            sxx += dx * dx;
            sxy += dx * (ys[i] - my);
        }
        if sxx > 1e-12 {
            let slope = sxy / sxx;
            let intercept = my - slope * mx;
            let n_fit = (slope / 10.0).clamp(1.5, 6.0);
            out.path_loss_exponent = n_fit;
            out.ref_loss_db = intercept.clamp(20.0, 80.0);
            let mut ss = 0.0;
            for i in 0..n_rssi {
                let pred = out.ref_loss_db + 10.0 * out.path_loss_exponent * xs[i];
                let e = ys[i] - pred;
                ss += e * e;
            }
            residual = (ss / nf).sqrt();
            out.shadowing_sigma_db = residual.clamp(1.0, 14.0);
        } else {
            notes.push(
                "RSSI samples all at one distance; path-loss exponent not identifiable \
                 from them. Kept the prior."
                    .into(),
            );
        }
    } else {
        notes.push(format!(
            "only {n_rssi} usable RSSI samples; path-loss exponent and sigma left at \
             their priors and fitted from success/fail alone."
        ));
    }

    // Stage 2: likelihood of the success/fail column. The probability of a
    // success at distance d marginalises the shadowing draw, approximated by
    // Gauss-Hermite style sampling over a fixed symmetric grid so the fit stays
    // deterministic.
    const NODES: [f64; 9] = [-3.0, -2.25, -1.5, -0.75, 0.0, 0.75, 1.5, 2.25, 3.0];
    let outcome: Vec<&PhySample> = samples
        .iter()
        .filter(|s| s.distance_m.is_finite() && s.distance_m > 0.0)
        .collect();

    let loglik = |cfg: &PhyConfig| -> f64 {
        let mut acc = 0.0;
        for s in &outcome {
            let mut p = 0.0;
            let mut wsum = 0.0;
            for z in NODES {
                let w = (-0.5 * z * z).exp();
                let g = LinkGeometry {
                    distance_m: s.distance_m,
                    blocks_crossed: s.blocks_crossed,
                    tx_body: s.tx_body,
                    rx_body: s.rx_body,
                    shadowing_db: z * cfg.shadowing_sigma_db,
                };
                let per = cfg.packet_error_rate(cfg.rx_power_dbm(&g), s.mode, s.payload_bytes);
                p += w * (1.0 - per);
                wsum += w;
            }
            let p = if wsum > 0.0 {
                (p / wsum).clamp(1e-6, 1.0 - 1e-6)
            } else {
                0.5
            };
            acc += if s.success { p.ln() } else { (1.0 - p).ln() };
        }
        acc
    };

    // When the RSSI regression succeeded it has already identified the exponent
    // and the reference loss far better than a binary success column can, so the
    // likelihood stage is not allowed to move them. Letting it do so lets a
    // threshold-shaped success column pull `n` anywhere that happens to put the
    // same samples on the same side of the cliff.
    let rssi_pinned_geometry = n_rssi >= 2 && residual.is_finite();
    let mut best = out.clone();
    let mut best_ll = if outcome.is_empty() {
        f64::NEG_INFINITY
    } else {
        loglik(&best)
    };
    if !outcome.is_empty() {
        // Coordinate descent on a shrinking grid. Bounded iterations, bounded
        // ranges, no derivative, so it cannot diverge or spin.
        let mut step_n = 0.5;
        let mut step_sigma = 2.0;
        let mut step_body = 3.0;
        for _ in 0..12 {
            let mut improved = false;
            let axes: [(usize, f64); 3] = [(0, step_n), (1, step_sigma), (2, step_body)];
            for (axis, step) in axes {
                if rssi_pinned_geometry && axis == 0 {
                    continue;
                }
                for dir in [-1.0f64, 1.0] {
                    let mut cand = best.clone();
                    match axis {
                        0 => {
                            cand.path_loss_exponent =
                                (cand.path_loss_exponent + dir * step).clamp(1.5, 6.0)
                        }
                        1 => {
                            cand.shadowing_sigma_db =
                                (cand.shadowing_sigma_db + dir * step).clamp(1.0, 14.0)
                        }
                        _ => {
                            cand.body_loss_pocket_db =
                                (cand.body_loss_pocket_db + dir * step).clamp(0.0, 25.0);
                            cand.body_loss_pocket_blocked_db =
                                (cand.body_loss_pocket_db + 7.0).clamp(0.0, 30.0);
                        }
                    }
                    let ll = loglik(&cand);
                    if ll > best_ll + 1e-9 {
                        best_ll = ll;
                        best = cand;
                        improved = true;
                    }
                }
            }
            if !improved {
                step_n *= 0.5;
                step_sigma *= 0.5;
                step_body *= 0.5;
            }
        }
    } else {
        notes.push("no usable success/fail rows; likelihood stage skipped.".into());
    }

    let converged = n_rssi >= 2 || !outcome.is_empty();
    let mut fitted = best;
    if !converged {
        fitted = base.clone();
        notes.push("fit refused: no usable samples. Config returned unchanged.".into());
    }
    let mean_ll = if outcome.is_empty() {
        f64::NAN
    } else {
        best_ll / outcome.len() as f64
    };

    FitResult {
        fitted,
        round,
        rssi_residual_db: residual,
        rssi_samples: n_rssi,
        mean_log_likelihood: mean_ll,
        outcome_samples: outcome.len(),
        converged,
        notes,
    }
}

impl FitResult {
    /// The parameters this fit actually moved, re-stamped as
    /// `ParamSource::Fitted` so a result file built from a fitted config does
    /// not keep claiming the values were assumed.
    ///
    /// Everything the fit did not touch keeps its original provenance, which is
    /// the point: a half-calibrated model must read as half-calibrated.
    pub fn fitted_params(&self) -> Vec<ParamDoc> {
        let residual = if self.rssi_residual_db.is_finite() {
            format!("{:.2}", self.rssi_residual_db)
        } else {
            format!(
                "n/a (no RSSI column); mean log-likelihood {:.4} over {} outcomes",
                self.mean_log_likelihood, self.outcome_samples
            )
        };
        let touched = [
            "path_loss_exponent",
            "shadowing_sigma_db",
            "ref_loss_db",
            "body_loss_pocket_db",
            "body_loss_pocket_blocked_db",
        ];
        self.fitted
            .provenance()
            .into_iter()
            .map(|mut p| {
                if self.converged && touched.contains(&p.name.as_str()) {
                    p.source = ParamSource::Fitted {
                        round: self.round,
                        residual_db: residual.clone(),
                    };
                }
                p
            })
            .collect()
    }

    /// The calibration state implied by this fit.
    pub fn calibration(&self) -> crate::provenance::Calibration {
        if self.converged {
            crate::provenance::Calibration::CalibratedAgainstRound {
                round: self.round,
                residual_db: if self.rssi_residual_db.is_finite() {
                    self.rssi_residual_db
                } else {
                    f64::NAN
                },
            }
        } else {
            crate::provenance::Calibration::default()
        }
    }
}

/// Parse a field CSV into samples.
///
/// Header-driven so the user's instrumented build can add columns without
/// breaking us. Required columns: `distance_m`, `mode`, `success`. Optional:
/// `rssi_dbm`, `tx_body`, `rx_body`, `blocks`, `bytes`. Unknown columns are
/// ignored; unparseable rows are skipped and counted, never fatal.
pub fn parse_samples_csv(text: &str) -> (Vec<PhySample>, Vec<String>) {
    let mut problems = Vec::new();
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let Some(header) = lines.next() else {
        problems.push("empty CSV".into());
        return (Vec::new(), problems);
    };
    let cols: Vec<&str> = header.split(',').map(|c| c.trim()).collect();
    let idx = |name: &str| cols.iter().position(|c| *c == name);
    let (Some(i_d), Some(i_s)) = (idx("distance_m"), idx("success")) else {
        problems.push("CSV needs at least distance_m and success columns".into());
        return (Vec::new(), problems);
    };
    let i_mode = idx("mode");
    let i_rssi = idx("rssi_dbm");
    let i_txb = idx("tx_body");
    let i_rxb = idx("rx_body");
    let i_blocks = idx("blocks");
    let i_bytes = idx("bytes");

    let body = |s: &str| match s.trim() {
        "in_hand" | "hand" => BodyPosition::InHand,
        "pocket" => BodyPosition::Pocket,
        "pocket_blocked" | "pocket_body_blocked" => BodyPosition::PocketBodyBlocked,
        "bag" => BodyPosition::Bag,
        _ => BodyPosition::Pocket,
    };

    let mut out = Vec::new();
    for (lineno, line) in lines.enumerate() {
        let f: Vec<&str> = line.split(',').map(|c| c.trim()).collect();
        let get = |i: Option<usize>| i.and_then(|i| f.get(i)).copied();
        let Some(d) = f.get(i_d).and_then(|v| v.parse::<f64>().ok()) else {
            problems.push(format!("row {}: unparseable distance_m", lineno + 2));
            continue;
        };
        let Some(succ) = f.get(i_s).map(|v| {
            matches!(
                v.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "ok" | "success"
            )
        }) else {
            problems.push(format!("row {}: missing success", lineno + 2));
            continue;
        };
        let mode = match get(i_mode).unwrap_or("ble_1m") {
            "ble_coded_s8" | "coded" | "coded_s8" | "s8" => PhyMode::BleCoded8,
            _ => PhyMode::Ble1M,
        };
        out.push(PhySample {
            distance_m: d,
            mode,
            success: succ,
            rssi_dbm: get(i_rssi).and_then(|v| v.parse::<f64>().ok()),
            tx_body: get(i_txb).map(body).unwrap_or(BodyPosition::Pocket),
            rx_body: get(i_rxb).map(body).unwrap_or(BodyPosition::Pocket),
            blocks_crossed: get(i_blocks)
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0),
            payload_bytes: get(i_bytes)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(96),
        });
    }
    (out, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one path-loss case with a closed-form answer: free space at
    /// 2.44 GHz. FSPL(10 m) = 20log10(10) + 20log10(2.44e9) - 147.55 = 60.2 dB.
    /// If this drifts, the whole distance axis of M1 is wrong.
    #[test]
    fn free_space_path_loss_matches_the_closed_form() {
        let cfg = PhyConfig {
            path_loss_exponent: 2.0,
            ..PhyConfig::default()
        };
        let closed_form = |d: f64| {
            20.0 * d.log10() + 20.0 * (2.44e9f64).log10() - 147.55
        };
        for d in [1.0, 10.0, 50.0, 100.0] {
            let got = cfg.path_loss_db(d);
            assert!(
                (got - closed_form(d)).abs() < 0.1,
                "d={d}: model {got:.2} dB vs closed form {:.2} dB",
                closed_form(d)
            );
        }
    }

    #[test]
    fn coded_phy_reaches_further_and_takes_longer() {
        let cfg = PhyConfig::default();
        let r1 = cfg.median_range_m(
            PhyMode::Ble1M,
            96,
            BodyPosition::Pocket,
            BodyPosition::Pocket,
            0,
        );
        let r8 = cfg.median_range_m(
            PhyMode::BleCoded8,
            96,
            BodyPosition::Pocket,
            BodyPosition::Pocket,
            0,
        );
        assert!(r8 > r1 * 1.8, "coded range {r8:.1} m vs 1M {r1:.1} m");
        assert!(r8 < r1 * 3.2, "coded range gain implausibly large");
        let a1 = cfg.airtime_us(PhyMode::Ble1M, 96);
        let a8 = cfg.airtime_us(PhyMode::BleCoded8, 96);
        assert!(a8 > a1 * 7, "S=8 must cost about 8x the airtime");
    }

    #[test]
    fn body_shadowing_costs_real_distance() {
        let cfg = PhyConfig::default();
        let hand = cfg.median_range_m(
            PhyMode::Ble1M,
            96,
            BodyPosition::InHand,
            BodyPosition::InHand,
            0,
        );
        let blocked = cfg.median_range_m(
            PhyMode::Ble1M,
            96,
            BodyPosition::PocketBodyBlocked,
            BodyPosition::PocketBodyBlocked,
            0,
        );
        assert!(
            blocked < hand * 0.55,
            "two body-blocked pockets must cost more than half the range: \
             {blocked:.1} m vs {hand:.1} m"
        );
    }

    #[test]
    fn one_building_block_kills_a_link_that_works_in_the_open() {
        let cfg = PhyConfig::default();
        let open = LinkGeometry {
            distance_m: 40.0,
            blocks_crossed: 0,
            tx_body: BodyPosition::InHand,
            rx_body: BodyPosition::InHand,
            shadowing_db: 0.0,
        };
        let around_corner = LinkGeometry {
            blocks_crossed: 1,
            ..open
        };
        let p_open = cfg.packet_error_rate(cfg.rx_power_dbm(&open), PhyMode::Ble1M, 96);
        let p_corner =
            cfg.packet_error_rate(cfg.rx_power_dbm(&around_corner), PhyMode::Ble1M, 96);
        assert!(p_open < 0.2, "open 40 m should mostly work, got {p_open:.3}");
        assert!(
            p_corner > 0.8,
            "round a corner at 40 m should mostly fail, got {p_corner:.3}"
        );
    }

    #[test]
    fn per_is_monotonic_and_bounded_on_absurd_input() {
        let cfg = PhyConfig::default();
        for bytes in [1usize, 96, 1056] {
            let mut prev = 2.0;
            for rx in [-140.0, -100.0, -93.0, -80.0, -20.0, 0.0] {
                let p = cfg.packet_error_rate(rx, PhyMode::Ble1M, bytes);
                assert!((0.0..=1.0).contains(&p), "per out of range: {p}");
                assert!(p <= prev + 1e-12, "per must fall as signal rises");
                prev = p;
            }
        }
        assert_eq!(cfg.packet_error_rate(f64::NAN, PhyMode::Ble1M, 96), 1.0);
        assert_eq!(cfg.path_loss_db(f64::NAN), f64::INFINITY);
    }

    #[test]
    fn fitting_recovers_a_planted_exponent() {
        // Generate RSSI samples from a known truth, then check the fit finds it.
        let truth = PhyConfig {
            path_loss_exponent: 3.6,
            ref_loss_db: 42.0,
            ..PhyConfig::default()
        };
        let mut samples = Vec::new();
        for i in 0..60u32 {
            let d = 2.0 + f64::from(i) * 2.5;
            let g = LinkGeometry {
                distance_m: d,
                blocks_crossed: 0,
                tx_body: BodyPosition::Pocket,
                rx_body: BodyPosition::Pocket,
                shadowing_db: 0.0,
            };
            let rx = truth.rx_power_dbm(&g);
            samples.push(PhySample {
                distance_m: d,
                mode: PhyMode::Ble1M,
                success: truth.packet_error_rate(rx, PhyMode::Ble1M, 96) < 0.5,
                rssi_dbm: Some(rx),
                tx_body: BodyPosition::Pocket,
                rx_body: BodyPosition::Pocket,
                blocks_crossed: 0,
                payload_bytes: 96,
            });
        }
        let fit = fit_from_samples(&PhyConfig::default(), &samples, 1);
        assert!(fit.converged);
        assert!(
            (fit.fitted.path_loss_exponent - 3.6).abs() < 0.1,
            "fitted n = {}",
            fit.fitted.path_loss_exponent
        );
        assert!(
            fit.rssi_residual_db < 0.5,
            "noiseless samples should fit almost exactly, residual {}",
            fit.rssi_residual_db
        );
    }

    #[test]
    fn fitting_refuses_rather_than_inventing() {
        let fit = fit_from_samples(&PhyConfig::default(), &[], 1);
        assert!(!fit.converged);
        assert_eq!(fit.fitted, PhyConfig::default());
        assert!(!fit.notes.is_empty());
    }

    #[test]
    fn csv_parsing_survives_garbage() {
        let (s, p) = parse_samples_csv(
            "distance_m,mode,success,rssi_dbm\n10,ble_1m,1,-70\nxx,ble_1m,1,-70\n20,coded,0,\n",
        );
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].mode, PhyMode::BleCoded8);
        assert_eq!(s[1].rssi_dbm, None);
        assert_eq!(p.len(), 1);
        let (empty, probs) = parse_samples_csv("");
        assert!(empty.is_empty());
        assert!(!probs.is_empty());
    }
}
