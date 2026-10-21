//! Which links to spend a transmission on, and when to send.
//!
//! Two ideas live here and both are measured separately in the harness.
//!
//! # 1. The link that will still exist in two seconds
//!
//! A flood that ignores link quality spends most of its transmissions on links
//! that are about to break. The candidate score is a weighted sum, all terms
//! normalised to 0..=1000:
//!
//! * **survival** — `Neighbor::p_alive_in(horizon)`, which folds in the motion
//!   signal `gdc-transport` gives us. This is the term that distinguishes a
//!   stable mediocre link from a strong one that is collapsing.
//! * **quality** — present signal strength, for throughput rather than survival.
//! * **progress** — the neighbour is known to carry this channel tag, so it is
//!   closer to the destination's membership than a random link is.
//! * **relay evidence** — we have watched this neighbour actually relay
//!   traffic. A positive-only bonus, never a penalty: a peer we have no
//!   evidence about is treated as average, not as a freeloader, so a new
//!   neighbour is never starved.
//! * **noise** — a keyed pseudo-random tie-break over `(msg_id, node seed,
//!   peer)`.
//!
//! The noise term is where we differ from bitchat's subset selection. bitchat
//! derives the subset deterministically from the message id alone, so every
//! relay in the mesh orders its own neighbour list by the *same* permutation of
//! ranks; the subsets decorrelate only to the extent the lists happen to be
//! ordered differently. Mixing the local node seed in makes the subsets
//! genuinely independent across relays, which is what the coupon-collector
//! argument in [`crate::fanout`] assumes.
//!
//! # 2. Jitter as an election, not a lottery
//!
//! bitchat jitters 10–220 ms uniformly and cancels a pending relay on
//! overhearing the same frame. The staggering works, but the winner of the race
//! is random: the node that happens to draw the shortest delay relays, and the
//! best-placed node cancels.
//!
//! We make the delay a decreasing function of how much the node *adds*. A relay
//! whose candidate set is entirely inside the ingress peer's own neighbourhood
//! contributes nothing and waits the longest, so it almost always cancels. A
//! relay holding links nobody else at this hop holds goes first, and everyone
//! else cancels around it. Same mechanism, same bandwidth, but the surviving
//! transmission is the useful one.

use crate::neighbors::{Neighbor, NeighborTable, PeerId};
use crate::prng::{KeyedHash, Prng};
use gdc_wire::{ChanTag, MsgId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Weights {
    pub survival: u32,
    pub quality: u32,
    pub progress: u32,
    pub relay_evidence: u32,
    pub noise: u32,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            survival: 40,
            quality: 20,
            progress: 25,
            relay_evidence: 5,
            noise: 10,
        }
    }
}

impl Weights {
    /// Everything but the tie-break, for the ablation that turns
    /// quality-weighted selection off and leaves a uniform random subset.
    pub fn noise_only() -> Self {
        Weights {
            survival: 0,
            quality: 0,
            progress: 0,
            relay_evidence: 0,
            noise: 100,
        }
    }

    fn total(&self) -> u32 {
        (self.survival + self.quality + self.progress + self.relay_evidence + self.noise).max(1)
    }
}

/// A scored candidate link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scored {
    pub peer: PeerId,
    pub score: u32,
}

/// Positive-only relay evidence bonus, 0..=1000.
pub fn relay_evidence(n: &Neighbor) -> u32 {
    let obs = u32::from(n.relays_observed).min(8);
    obs * 1000 / 8
}

#[allow(clippy::too_many_arguments)]
fn score_one(
    n: &Neighbor,
    tag: &ChanTag,
    msg_id: &MsgId,
    hash: &KeyedHash,
    w: &Weights,
    horizon_ms: u64,
    progress_bias: bool,
) -> u32 {
    let survival = u32::from(n.p_alive_in(horizon_ms));
    let quality = u32::from(n.quality) * 1000 / 255;
    let progress = if progress_bias && n.carries(tag) { 1000 } else { 0 };
    let evidence = relay_evidence(n);
    // Keyed over (msg_id, peer): the same frame gets a different permutation at
    // every node, because the hash key is the node's own seed.
    let mut key = [0u8; 20];
    if let (Some(a), Some(b)) = (key.get_mut(..16), key.get_mut(16..20)) {
        a.copy_from_slice(&msg_id.0);
        b.copy_from_slice(&n.peer.to_le_bytes());
    }
    let noise = (hash.hash_bytes(&key) % 1001) as u32;

    (survival * w.survival
        + quality * w.quality
        + progress * w.progress
        + evidence * w.relay_evidence
        + noise * w.noise)
        / w.total()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectParams {
    pub horizon_ms: u64,
    pub progress_bias: bool,
    /// Candidates whose predicted survival is below this are not worth a
    /// transmission at all. 0 disables the floor.
    pub min_survival: u16,
}

impl Default for SelectParams {
    fn default() -> Self {
        SelectParams {
            horizon_ms: 2_000,
            progress_bias: true,
            min_survival: 120,
        }
    }
}

/// Why no candidate was usable. Drives the store handoff reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoCandidate {
    /// No fresh neighbour at all besides the excluded ones.
    None,
    /// Fresh neighbours exist but all are predicted dead within the horizon.
    AllDying,
    /// Fresh, alive neighbours exist but all already hold the frame.
    AllCovered,
}

/// Rank the links worth using for this frame.
///
/// `exclude` is the ingress peer, if any — the single largest delivery win in
/// this module and the one bitchat leaves on the table. `covered` is the
/// 32-bit sketch of peers already known to hold the frame.
#[allow(clippy::too_many_arguments)]
pub fn candidates(
    nbrs: &NeighborTable,
    now_ms: u64,
    tag: &ChanTag,
    msg_id: &MsgId,
    exclude: Option<PeerId>,
    covered: u32,
    peer_bit: &dyn Fn(PeerId) -> u32,
    hash: &KeyedHash,
    w: &Weights,
    p: &SelectParams,
) -> Result<Vec<Scored>, NoCandidate> {
    let mut any_fresh = false;
    let mut any_alive = false;
    let mut out: Vec<Scored> = Vec::new();
    for n in nbrs.fresh(now_ms) {
        if Some(n.peer) == exclude {
            continue;
        }
        any_fresh = true;
        if n.p_alive_in(p.horizon_ms) < p.min_survival {
            continue;
        }
        any_alive = true;
        if covered & peer_bit(n.peer) != 0 {
            continue;
        }
        out.push(Scored {
            peer: n.peer,
            score: score_one(n, tag, msg_id, hash, w, p.horizon_ms, p.progress_bias),
        });
    }
    if out.is_empty() {
        return Err(if !any_fresh {
            NoCandidate::None
        } else if !any_alive {
            NoCandidate::AllDying
        } else {
            NoCandidate::AllCovered
        });
    }
    // Descending by score, peer id as a deterministic final tie-break so two
    // runs with the same seed produce byte-identical plans.
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.peer.cmp(&b.peer)));
    Ok(out)
}

/// How much this node adds over the peer that handed us the frame, 0..=1000.
///
/// Fraction of our candidate links that the ingress peer does not already have.
/// Returns a neutral 500 when we have no neighbour list for the ingress peer,
/// which is the normal case for a channel we are not a member of.
pub fn unique_coverage(
    nbrs: &NeighborTable,
    ingress: Option<PeerId>,
    cands: &[Scored],
) -> u32 {
    if cands.is_empty() {
        return 0;
    }
    let theirs = match ingress.and_then(|p| nbrs.get(p)) {
        Some(n) if !n.neighbors().is_empty() => n.neighbors(),
        _ => return 500,
    };
    let unique = cands
        .iter()
        .filter(|c| !theirs.contains(&c.peer))
        .count() as u32;
    unique * 1000 / cands.len() as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitterPolicy {
    pub min_ms: u32,
    pub span_ms: u32,
    /// Span used for `Flags::URGENT`. Scheduling priority only: urgent frames
    /// pay the same rate limits and the same verification as everything else.
    pub urgent_span_ms: u32,
    pub tiebreak_ms: u32,
    /// When false, the delay is uniform over the span, which is bitchat's
    /// behaviour and the control arm for the election lever.
    pub elective: bool,
}

impl Default for JitterPolicy {
    fn default() -> Self {
        JitterPolicy {
            min_ms: 20,
            span_ms: 180,
            urgent_span_ms: 60,
            tiebreak_ms: 15,
            elective: true,
        }
    }
}

impl JitterPolicy {
    /// Delay before transmitting, in ms. Lower fitness waits longer.
    pub fn delay_ms(&self, fitness: u32, urgent: bool, prng: &mut Prng) -> u64 {
        let span = if urgent {
            self.urgent_span_ms
        } else {
            self.span_ms
        };
        let base = if self.elective {
            let f = fitness.min(1000);
            u64::from(span) * u64::from(1000 - f) / 1000
        } else {
            u64::from(prng.below(span.saturating_add(1)))
        };
        u64::from(self.min_ms) + base + u64::from(prng.below(self.tiebreak_ms.saturating_add(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighbors::LinkUpdate;

    fn table(spec: &[(PeerId, u8, i8)]) -> NeighborTable {
        let mut t = NeighborTable::new(60_000);
        for (p, q, tr) in spec {
            t.apply(LinkUpdate {
                peer: *p,
                quality: *q,
                quality_trend: *tr,
                neighbors: &[],
                tags: &[],
                now_ms: 0,
            });
        }
        t
    }

    fn bits(p: PeerId) -> u32 {
        1u32 << (p % 32)
    }

    fn pick(t: &NeighborTable, exclude: Option<PeerId>, covered: u32) -> Result<Vec<Scored>, NoCandidate> {
        candidates(
            t,
            0,
            &ChanTag([1; 8]),
            &MsgId([2; 16]),
            exclude,
            covered,
            &bits,
            &KeyedHash::from_seed(5),
            &Weights::default(),
            &SelectParams::default(),
        )
    }

    #[test]
    fn the_ingress_link_is_never_a_candidate() {
        let t = table(&[(1, 200, 0), (2, 200, 0)]);
        let c = pick(&t, Some(1), 0).expect("one left");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].peer, 2);
    }

    #[test]
    fn a_degree_two_chain_node_has_exactly_one_forward_candidate() {
        // The case M2 is graded on. With ingress exclusion this is a certainty;
        // without it, it is a coin flip.
        let t = table(&[(1, 200, 0), (2, 200, 0)]);
        assert_eq!(pick(&t, Some(1), 0).map(|c| c.len()), Ok(1));
        assert_eq!(pick(&t, None, 0).map(|c| c.len()), Ok(2));
    }

    #[test]
    fn a_leaf_whose_only_link_is_the_ingress_has_nowhere_to_go() {
        let t = table(&[(1, 200, 0)]);
        assert_eq!(pick(&t, Some(1), 0), Err(NoCandidate::None));
    }

    #[test]
    fn dying_links_are_refused_and_reported_as_such() {
        let t = table(&[(1, 40, -40), (2, 30, -30)]);
        assert_eq!(pick(&t, None, 0), Err(NoCandidate::AllDying));
    }

    #[test]
    fn covered_peers_are_skipped_and_reported_as_such() {
        let t = table(&[(1, 200, 0), (2, 200, 0)]);
        assert_eq!(pick(&t, None, bits(1) | bits(2)), Err(NoCandidate::AllCovered));
    }

    #[test]
    fn survival_outranks_raw_quality() {
        let t = table(&[(1, 250, -100), (2, 150, 0)]);
        let c = pick(&t, None, 0).expect("both");
        assert_eq!(c[0].peer, 2, "the stable link must win");
    }

    #[test]
    fn progress_bias_prefers_a_peer_known_to_carry_the_tag() {
        let tag = ChanTag([7; 8]);
        let mut t = table(&[(1, 180, 0), (2, 180, 0)]);
        t.note_tag(2, tag, 0);
        let c = candidates(
            &t, 0, &tag, &MsgId([3; 16]), None, 0, &bits,
            &KeyedHash::from_seed(1), &Weights::default(), &SelectParams::default(),
        )
        .expect("both");
        assert_eq!(c[0].peer, 2);
    }

    #[test]
    fn selection_decorrelates_across_nodes_for_the_same_frame() {
        let t = table(&[(1, 200, 0), (2, 200, 0), (3, 200, 0), (4, 200, 0), (5, 200, 0), (6, 200, 0)]);
        let id = MsgId([0xEE; 16]);
        let w = Weights::noise_only();
        let order = |seed: u64| {
            candidates(&t, 0, &ChanTag([0; 8]), &id, None, 0, &bits,
                       &KeyedHash::from_seed(seed), &w, &SelectParams::default())
                .map(|c| c.iter().map(|s| s.peer).collect::<Vec<_>>())
        };
        assert_ne!(order(1), order(2), "two nodes must not pick the same subset");
        assert_eq!(order(1), order(1), "but each node must be deterministic");
    }

    #[test]
    fn unique_coverage_is_zero_when_we_add_nothing() {
        let mut t = NeighborTable::new(60_000);
        t.apply(LinkUpdate { peer: 1, quality: 200, quality_trend: 0, neighbors: &[2, 3], tags: &[], now_ms: 0 });
        t.apply(LinkUpdate { peer: 2, quality: 200, quality_trend: 0, neighbors: &[], tags: &[], now_ms: 0 });
        t.apply(LinkUpdate { peer: 3, quality: 200, quality_trend: 0, neighbors: &[], tags: &[], now_ms: 0 });
        let cands = vec![Scored { peer: 2, score: 1 }, Scored { peer: 3, score: 1 }];
        assert_eq!(unique_coverage(&t, Some(1), &cands), 0);
        let cands = vec![Scored { peer: 2, score: 1 }, Scored { peer: 9, score: 1 }];
        assert_eq!(unique_coverage(&t, Some(1), &cands), 500);
    }

    #[test]
    fn elective_jitter_sends_the_useful_node_first() {
        let p = JitterPolicy::default();
        let mut r = Prng::from_seed(1);
        let useful = p.delay_ms(1000, false, &mut r);
        let useless = p.delay_ms(0, false, &mut r);
        assert!(useful < useless, "{useful} should precede {useless}");
        assert!(useful >= u64::from(p.min_ms));
    }

    #[test]
    fn urgent_only_shortens_the_window() {
        let p = JitterPolicy::default();
        let mut r = Prng::from_seed(2);
        let normal = p.delay_ms(0, false, &mut r);
        let urgent = p.delay_ms(0, true, &mut r);
        assert!(urgent < normal);
        assert!(urgent >= u64::from(p.min_ms), "never zero: the overhear window must exist");
    }

    #[test]
    fn uniform_jitter_control_arm_stays_in_its_window() {
        let p = JitterPolicy { elective: false, ..JitterPolicy::default() };
        let mut r = Prng::from_seed(3);
        for _ in 0..1000 {
            let d = p.delay_ms(1000, false, &mut r);
            assert!(d >= 20 && d <= 20 + 180 + 15, "{d}");
        }
    }
}
