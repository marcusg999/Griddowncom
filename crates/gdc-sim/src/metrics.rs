//! Metric collection and the JSON report.
//!
//! Emits every metric in `docs/METRICS.md` that a simulation can legitimately
//! produce, and nothing it cannot. Anything that needs a human (onboarding
//! comprehension, sunlight legibility, one-handed reach) is absent rather than
//! faked, and the report lists what it did not measure so a reader is not left
//! to guess.
//!
//! Every report carries a [`Provenance`] block whose `provenance` field is the
//! literal string `simulated`. `BTreeMap` throughout, so key order is stable
//! and two runs of the same seed produce byte-identical JSON — which the blind
//! rig depends on.

use crate::clock::SimTime;
use crate::platform::{AppState, Platform};
use crate::provenance::Provenance;
use gdc_wire::MsgId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One message, and what happened to it.
#[derive(Clone, Debug)]
pub struct MsgRecord {
    pub source: usize,
    pub created: SimTime,
    pub body_bytes: usize,
    /// Shortest-path hop distance from the source to each node in the
    /// connectivity graph as it stood when the message was created. `None`
    /// means no radio path existed, i.e. this pair is in the carrier regime.
    pub hops: Vec<Option<u32>>,
    /// When each node's application layer first saw it.
    pub delivered: Vec<Option<SimTime>>,
    /// Receptions of this message at a node after the first.
    pub redundant: Vec<u32>,
    /// Transmissions the simulator attributes to this message.
    pub transmissions: u64,
}

impl MsgRecord {
    fn new(source: usize, created: SimTime, body_bytes: usize, nodes: usize) -> Self {
        MsgRecord {
            source,
            created,
            body_bytes,
            hops: vec![None; nodes],
            delivered: vec![None; nodes],
            redundant: vec![0; nodes],
            transmissions: 0,
        }
    }
}

/// Everything the engine records as it runs.
#[derive(Clone, Debug, Default)]
pub struct Collector {
    pub nodes: usize,
    pub msgs: BTreeMap<[u8; 16], MsgRecord>,
    pub order: Vec<[u8; 16]>,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_dup_frames: u64,
    pub collisions: u64,
    pub not_listening: u64,
    pub phy_losses: u64,
    pub queue_drops: u64,
    pub oversize_refusals: u64,
    pub links_up: u64,
    pub links_down: u64,
    pub connect_attempts: u64,
    pub name_resolutions: u64,
    /// Per node, time of first usable link. Feeds the transport metric
    /// "neighbour acquisition time from cold".
    pub first_link: Vec<Option<SimTime>>,
    pub link_lifetimes_s: Vec<f64>,
    pub links_surviving_60s: u64,
    pub links_assessed_for_survival: u64,
    pub reconnect_times_s: Vec<f64>,
    pub stack_notes: BTreeMap<String, u64>,
    pub energy_mah: Vec<f64>,
    /// Per-platform-pair one-hop attempt outcomes, for M1's three pairs.
    pub pair_attempts: BTreeMap<String, (u64, u64)>,
}

impl Collector {
    pub fn new(nodes: usize) -> Self {
        Collector {
            nodes,
            first_link: vec![None; nodes],
            energy_mah: vec![0.0; nodes],
            ..Collector::default()
        }
    }

    pub fn open_message(
        &mut self,
        id: MsgId,
        source: usize,
        created: SimTime,
        body_bytes: usize,
        hops: Vec<Option<u32>>,
    ) {
        let mut rec = MsgRecord::new(source, created, body_bytes, self.nodes);
        rec.hops = hops;
        // The source trivially has it.
        if let Some(slot) = rec.delivered.get_mut(source) {
            *slot = Some(created);
        }
        if self.msgs.insert(id.0, rec).is_none() {
            self.order.push(id.0);
        }
    }

    pub fn record_delivery(&mut self, id: MsgId, node: usize, at: SimTime) {
        if let Some(rec) = self.msgs.get_mut(&id.0) {
            match rec.delivered.get_mut(node) {
                Some(slot @ None) => *slot = Some(at),
                Some(Some(_)) => {
                    if let Some(r) = rec.redundant.get_mut(node) {
                        *r = r.saturating_add(1);
                    }
                }
                None => {}
            }
        }
    }

    pub fn record_redundant(&mut self, id: MsgId, node: usize) {
        if let Some(rec) = self.msgs.get_mut(&id.0) {
            if let Some(r) = rec.redundant.get_mut(node) {
                *r = r.saturating_add(1);
            }
        }
    }

    pub fn attribute_transmission(&mut self, id: MsgId) {
        if let Some(rec) = self.msgs.get_mut(&id.0) {
            rec.transmissions = rec.transmissions.saturating_add(1);
        }
    }

    pub fn note(&mut self, kind: &str, count: u32) {
        *self.stack_notes.entry(kind.to_string()).or_insert(0) += u64::from(count);
    }

    pub fn record_pair_attempt(
        &mut self,
        tx: (Platform, AppState),
        rx: (Platform, AppState),
        ok: bool,
    ) {
        let key = format!(
            "{}_{}__{}_{}",
            tx.0.as_str(),
            tx.1.as_str(),
            rx.0.as_str(),
            rx.1.as_str()
        );
        let e = self.pair_attempts.entry(key).or_insert((0, 0));
        e.0 = e.0.saturating_add(1);
        if ok {
            e.1 = e.1.saturating_add(1);
        }
    }
}

// --------------------------------------------------------------------------
// Report
// --------------------------------------------------------------------------

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Percentiles {
    pub n: usize,
    pub p50: Option<f64>,
    pub p90: Option<f64>,
    pub p99: Option<f64>,
    pub mean: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

impl Percentiles {
    pub fn of(mut v: Vec<f64>) -> Self {
        v.retain(|x| x.is_finite());
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = v.len();
        if n == 0 {
            return Percentiles {
                n: 0,
                p50: None,
                p90: None,
                p99: None,
                mean: None,
                min: None,
                max: None,
            };
        }
        // Nearest-rank, which is what a reader of a percentile from 30 trials
        // expects and what does not interpolate a value that never occurred.
        let pick = |p: f64| {
            let idx = ((p * n as f64).ceil() as usize).clamp(1, n) - 1;
            v.get(idx).copied()
        };
        Percentiles {
            n,
            p50: pick(0.5),
            p90: pick(0.9),
            p99: pick(0.99),
            mean: Some(v.iter().sum::<f64>() / n as f64),
            min: v.first().copied(),
            max: v.last().copied(),
        }
    }
}

/// Delivery outcome for one hop-count bucket.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HopBucket {
    /// (message, destination) pairs at this hop distance.
    pub pairs: usize,
    /// Delivery rate at each deadline, keyed by deadline in seconds.
    pub delivery_rate_by_deadline_s: BTreeMap<String, f64>,
    /// Delivered pairs at each deadline.
    pub delivered_by_deadline_s: BTreeMap<String, usize>,
    pub latency_s: Percentiles,
    pub redundant_receptions_per_delivery: Option<f64>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Totals {
    pub nodes: usize,
    pub duration_s: f64,
    pub messages_offered: usize,
    /// (message, destination) pairs, excluding the source itself.
    pub pairs_offered: usize,
    pub pairs_delivered_ever: usize,
    pub overall_delivery_rate: f64,
    pub frames_transmitted: u64,
    pub bytes_transmitted: u64,
    pub frames_received: u64,
    pub duplicate_frames_received: u64,
    pub frames_lost_to_collision: u64,
    pub frames_lost_because_receiver_not_listening: u64,
    pub frames_lost_to_path_loss: u64,
    pub frames_dropped_by_full_queue: u64,
    pub frames_refused_as_oversize_for_slot: u64,
    /// The flood-efficiency number. Bridgefy's TTL-100 degree-blind flood is
    /// the thing to beat; this is the ratio to publish.
    pub transmissions_per_delivered_message: Option<f64>,
    pub redundant_receptions_per_delivery: Option<f64>,
    pub links_established: u64,
    pub connect_attempts: u64,
    pub gatt_identity_resolutions_forced_by_missing_adv_name: u64,
    pub link_lifetime_s: Percentiles,
    pub link_survival_60s: Option<f64>,
    pub reconnect_time_s: Percentiles,
    pub neighbour_acquisition_s: Percentiles,
    pub nodes_that_never_saw_a_neighbour: usize,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CarrierRegime {
    /// (message, destination) pairs with no radio path at creation time. These
    /// are deliverable only by a human walking.
    pub pairs_with_no_radio_path: usize,
    pub delivered: usize,
    pub delivery_rate_by_deadline_s: BTreeMap<String, f64>,
    pub latency_s: Percentiles,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EnergyBlock {
    pub placeholder: bool,
    pub note: String,
    pub per_node_mah: Percentiles,
    pub mah_per_delivered_message: Option<f64>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RunReport {
    pub scenario_name: String,
    pub stack: String,
    pub seed: u64,
    /// Digest of the mobility trace. Two runs claiming the same world must
    /// agree here, which is what makes the blind rig's "identical world" claim
    /// checkable rather than asserted.
    pub world_digest: String,
    pub provenance: Provenance,
    pub totals: Totals,
    /// Keyed by hop count as a decimal string.
    pub by_hop: BTreeMap<String, HopBucket>,
    pub carrier_regime: CarrierRegime,
    /// Per-platform-pair one-hop reception rate: the three pairs M1 asks for,
    /// plus app state, because a foreground-only number is not a number.
    pub platform_pair_reception_rate: BTreeMap<String, f64>,
    pub platform_pair_attempts: BTreeMap<String, u64>,
    pub energy: EnergyBlock,
    pub stack_notes: BTreeMap<String, u64>,
    /// Metrics in `docs/METRICS.md` this run deliberately did not produce.
    pub not_measured: Vec<String>,
    /// Deadlines longer than the run, which therefore report the run's end
    /// state rather than a true deadline figure.
    pub deadlines_beyond_run_duration_s: Vec<f64>,
}

/// Build the report from a finished collector.
pub fn summarise(
    scenario_name: &str,
    stack: &str,
    seed: u64,
    world_digest: u64,
    duration: SimTime,
    deadlines: &[SimTime],
    provenance: Provenance,
    c: &Collector,
) -> RunReport {
    let dl_key = |d: SimTime| format!("{}", d.as_secs_f64() as u64);

    let mut pairs_offered = 0usize;
    let mut pairs_delivered = 0usize;
    let mut total_redundant: u64 = 0;
    let mut by_hop_raw: BTreeMap<u32, (usize, BTreeMap<String, usize>, Vec<f64>, u64, usize)> =
        BTreeMap::new();
    let mut carrier_pairs = 0usize;
    let mut carrier_delivered = 0usize;
    let mut carrier_by_dl: BTreeMap<String, usize> = BTreeMap::new();
    let mut carrier_lat: Vec<f64> = Vec::new();
    let mut delivered_msg_count = 0usize;

    for id in &c.order {
        let Some(rec) = c.msgs.get(id) else { continue };
        for node in 0..c.nodes {
            if node == rec.source {
                continue;
            }
            pairs_offered += 1;
            let delivered_at = rec.delivered.get(node).copied().flatten();
            let latency = delivered_at.map(|t| t.saturating_sub(rec.created).as_secs_f64());
            let redundant = rec.redundant.get(node).copied().unwrap_or(0);
            total_redundant += u64::from(redundant);
            if delivered_at.is_some() {
                pairs_delivered += 1;
                delivered_msg_count += 1;
            }
            match rec.hops.get(node).copied().flatten() {
                Some(h) => {
                    let e = by_hop_raw.entry(h).or_insert_with(|| {
                        (0, BTreeMap::new(), Vec::new(), 0, 0)
                    });
                    e.0 += 1;
                    for d in deadlines {
                        let k = dl_key(*d);
                        let hit = delivered_at
                            .map(|t| t.saturating_sub(rec.created) <= *d)
                            .unwrap_or(false);
                        let slot = e.1.entry(k).or_insert(0);
                        if hit {
                            *slot += 1;
                        }
                    }
                    if let Some(l) = latency {
                        e.2.push(l);
                        e.4 += 1;
                    }
                    e.3 = e.3.saturating_add(u64::from(redundant));
                }
                None => {
                    carrier_pairs += 1;
                    if delivered_at.is_some() {
                        carrier_delivered += 1;
                    }
                    for d in deadlines {
                        let k = dl_key(*d);
                        let hit = delivered_at
                            .map(|t| t.saturating_sub(rec.created) <= *d)
                            .unwrap_or(false);
                        let slot = carrier_by_dl.entry(k).or_insert(0);
                        if hit {
                            *slot += 1;
                        }
                    }
                    if let Some(l) = latency {
                        carrier_lat.push(l);
                    }
                }
            }
        }
    }

    let by_hop: BTreeMap<String, HopBucket> = by_hop_raw
        .into_iter()
        .map(|(h, (pairs, delivered, lats, redundant, ndel))| {
            let rates: BTreeMap<String, f64> = delivered
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if pairs == 0 {
                            0.0
                        } else {
                            *v as f64 / pairs as f64
                        },
                    )
                })
                .collect();
            (
                h.to_string(),
                HopBucket {
                    pairs,
                    delivery_rate_by_deadline_s: rates,
                    delivered_by_deadline_s: delivered,
                    latency_s: Percentiles::of(lats),
                    redundant_receptions_per_delivery: if ndel == 0 {
                        None
                    } else {
                        Some(redundant as f64 / ndel as f64)
                    },
                },
            )
        })
        .collect();

    let carrier = CarrierRegime {
        pairs_with_no_radio_path: carrier_pairs,
        delivered: carrier_delivered,
        delivery_rate_by_deadline_s: carrier_by_dl
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    if carrier_pairs == 0 {
                        0.0
                    } else {
                        *v as f64 / carrier_pairs as f64
                    },
                )
            })
            .collect(),
        latency_s: Percentiles::of(carrier_lat),
    };

    let pair_rate: BTreeMap<String, f64> = c
        .pair_attempts
        .iter()
        .map(|(k, (att, ok))| {
            (
                k.clone(),
                if *att == 0 {
                    0.0
                } else {
                    *ok as f64 / *att as f64
                },
            )
        })
        .collect();
    let pair_attempts: BTreeMap<String, u64> =
        c.pair_attempts.iter().map(|(k, (a, _))| (k.clone(), *a)).collect();

    let totals = Totals {
        nodes: c.nodes,
        duration_s: duration.as_secs_f64(),
        messages_offered: c.order.len(),
        pairs_offered,
        pairs_delivered_ever: pairs_delivered,
        overall_delivery_rate: if pairs_offered == 0 {
            0.0
        } else {
            pairs_delivered as f64 / pairs_offered as f64
        },
        frames_transmitted: c.tx_frames,
        bytes_transmitted: c.tx_bytes,
        frames_received: c.rx_frames,
        duplicate_frames_received: c.rx_dup_frames,
        frames_lost_to_collision: c.collisions,
        frames_lost_because_receiver_not_listening: c.not_listening,
        frames_lost_to_path_loss: c.phy_losses,
        frames_dropped_by_full_queue: c.queue_drops,
        frames_refused_as_oversize_for_slot: c.oversize_refusals,
        transmissions_per_delivered_message: if delivered_msg_count == 0 {
            None
        } else {
            Some(c.tx_frames as f64 / delivered_msg_count as f64)
        },
        redundant_receptions_per_delivery: if delivered_msg_count == 0 {
            None
        } else {
            Some(total_redundant as f64 / delivered_msg_count as f64)
        },
        links_established: c.links_up,
        connect_attempts: c.connect_attempts,
        gatt_identity_resolutions_forced_by_missing_adv_name: c.name_resolutions,
        link_lifetime_s: Percentiles::of(c.link_lifetimes_s.clone()),
        link_survival_60s: if c.links_assessed_for_survival == 0 {
            None
        } else {
            Some(c.links_surviving_60s as f64 / c.links_assessed_for_survival as f64)
        },
        reconnect_time_s: Percentiles::of(c.reconnect_times_s.clone()),
        neighbour_acquisition_s: Percentiles::of(
            c.first_link
                .iter()
                .filter_map(|t| t.map(|t| t.as_secs_f64()))
                .collect(),
        ),
        nodes_that_never_saw_a_neighbour: c.first_link.iter().filter(|t| t.is_none()).count(),
    };

    let energy = EnergyBlock {
        placeholder: true,
        note: "Energy numbers come from gdc-sim's PLACEHOLDER cost table, not from \
               gdc-power. Order of magnitude only; do not quote."
            .into(),
        per_node_mah: Percentiles::of(c.energy_mah.clone()),
        mah_per_delivered_message: if delivered_msg_count == 0 {
            None
        } else {
            Some(c.energy_mah.iter().sum::<f64>() / delivered_msg_count as f64)
        },
    };

    RunReport {
        scenario_name: scenario_name.to_string(),
        stack: stack.to_string(),
        seed,
        world_digest: format!("{world_digest:016x}"),
        provenance,
        totals,
        by_hop,
        carrier_regime: carrier,
        platform_pair_reception_rate: pair_rate,
        platform_pair_attempts: pair_attempts,
        energy,
        stack_notes: c.stack_notes.clone(),
        not_measured: vec![
            "M1 per-hop distance in metres: this run reports delivery per hop and \
             per platform pair, not a metre figure. A metre figure from an \
             uncalibrated PHY would be a fabrication; use the phy-range \
             subcommand, which labels its output as a model prediction."
                .into(),
            "Onboarding, message-screen and comprehension metrics: require humans."
                .into(),
            "Crypto metrics (wire overhead, handshake round trips, fuzz, \
             length-correlation): owned by gdc-crypto."
                .into(),
            "Battery measured on hardware: this is a placeholder model, and \
             gdc-power owns the real table."
                .into(),
            "Wi-Fi burst goodput: not modelled. BLE only."
                .into(),
        ],
        deadlines_beyond_run_duration_s: deadlines
            .iter()
            .filter(|d| **d > duration)
            .map(|d| d.as_secs_f64())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::Calibration;

    #[test]
    fn percentiles_are_nearest_rank_and_handle_emptiness() {
        let p = Percentiles::of(vec![]);
        assert_eq!(p.n, 0);
        assert!(p.p50.is_none());
        let p = Percentiles::of(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]);
        assert_eq!(p.p50, Some(5.0));
        assert_eq!(p.p90, Some(9.0));
        assert_eq!(p.max, Some(10.0));
        // NaN and infinity are dropped rather than poisoning the sort.
        let p = Percentiles::of(vec![f64::NAN, 1.0, f64::INFINITY]);
        assert_eq!(p.n, 1);
    }

    #[test]
    fn a_delivered_message_counts_once_and_the_rest_are_redundant() {
        let mut c = Collector::new(3);
        c.open_message(MsgId([1; 16]), 0, SimTime::ZERO, 10, vec![Some(0), Some(1), Some(2)]);
        c.record_delivery(MsgId([1; 16]), 1, SimTime::from_secs(5));
        c.record_delivery(MsgId([1; 16]), 1, SimTime::from_secs(6));
        c.record_delivery(MsgId([1; 16]), 1, SimTime::from_secs(7));
        c.tx_frames = 9;
        let r = summarise(
            "t",
            "s",
            1,
            0,
            SimTime::from_secs(60),
            &[SimTime::from_secs(30)],
            Provenance::new(Calibration::default(), vec![]),
            &c,
        );
        assert_eq!(r.totals.pairs_offered, 2);
        assert_eq!(r.totals.pairs_delivered_ever, 1);
        assert_eq!(r.by_hop["1"].pairs, 1);
        assert_eq!(r.by_hop["1"].delivery_rate_by_deadline_s["30"], 1.0);
        assert_eq!(r.by_hop["2"].delivery_rate_by_deadline_s["30"], 0.0);
        assert_eq!(r.totals.redundant_receptions_per_delivery, Some(2.0));
        assert_eq!(r.totals.transmissions_per_delivered_message, Some(9.0));
    }

    #[test]
    fn a_pair_with_no_radio_path_lands_in_the_carrier_regime() {
        let mut c = Collector::new(2);
        c.open_message(MsgId([2; 16]), 0, SimTime::ZERO, 10, vec![Some(0), None]);
        c.record_delivery(MsgId([2; 16]), 1, SimTime::from_secs(400));
        let r = summarise(
            "t",
            "s",
            1,
            0,
            SimTime::from_secs(600),
            &[SimTime::from_secs(30), SimTime::from_secs(600)],
            Provenance::new(Calibration::default(), vec![]),
            &c,
        );
        assert_eq!(r.carrier_regime.pairs_with_no_radio_path, 1);
        assert_eq!(r.carrier_regime.delivered, 1);
        assert_eq!(r.carrier_regime.delivery_rate_by_deadline_s["30"], 0.0);
        assert_eq!(r.carrier_regime.delivery_rate_by_deadline_s["600"], 1.0);
        assert!(r.by_hop.is_empty());
    }

    #[test]
    fn the_report_always_says_simulated_and_lists_what_it_skipped() {
        let c = Collector::new(1);
        let r = summarise(
            "t",
            "s",
            1,
            0,
            SimTime::from_secs(10),
            &[SimTime::from_secs(30), SimTime::from_secs(7200)],
            Provenance::new(Calibration::default(), vec![]),
            &c,
        );
        assert_eq!(r.provenance.provenance, "simulated");
        assert!(r.provenance.label.contains("uncalibrated"));
        assert!(!r.not_measured.is_empty());
        // A 30 s and a 2 h deadline on a 10 s run: both flagged as beyond it.
        assert_eq!(r.deadlines_beyond_run_duration_s.len(), 2);
        assert!(r.energy.placeholder);
        let json = serde_json::to_string(&r).expect("serialises");
        assert!(json.contains("\"provenance\":\"simulated\""));
    }
}
