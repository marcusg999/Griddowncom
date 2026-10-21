//! Adaptive hop limit.
//!
//! # The observation this runs on
//!
//! A constant TTL is wrong in both directions. Seven is wasteful in a room
//! where everyone can hear everyone, and fatal in a nine-hop chain along a
//! street. We can tell which we are in without any new wire field, and without
//! a topology map, from one number we already have: **the TTL a frame arrives
//! with, the first time we see it.**
//!
//! If novel frames routinely arrive with 5 of 7 hops left, the mesh is shallow
//! and the hop budget is mostly unspent — we are paying for reach we do not
//! need, and so is everyone relaying for us. If novel frames arrive with 1 hop
//! left, we are the last node that will ever see them: frames are dying in
//! flight and anyone past us is unreachable. The distribution of arrival TTL is
//! a direct measurement of how much of the hop budget the mesh is consuming.
//!
//! So the controller targets *headroom*: the low percentile of arrival TTL over
//! a window should sit a couple of hops above zero. Below that, raise the
//! origination TTL; well above it, lower it. The window is a fixed-size
//! histogram over 0..=MAX_TTL, which is 13 counters — there is nothing to
//! bound because the index space is the wire's own.
//!
//! # Cold start
//!
//! The controller needs traffic before it says anything. Until then we use the
//! structural estimate from [`crate::neighbors::TopologyEstimate`]: a node with
//! low degree and a high frontier ratio is in something long and thin and
//! should start generous; a node inside a dense blob should start tight. This
//! is the part that makes a first message in a chain work, and the controller
//! then takes over from measurement.
//!
//! # Why this cannot be driven by an attacker
//!
//! Only frames that passed the rate limiter and, where we hold the key,
//! verification are sampled. An attacker within their rate budget can bias the
//! histogram, and the worst they achieve is to push our origination TTL to
//! `ttl_max`, which the wire caps at 12 anyway. They cannot push it below
//! `ttl_min`, so they cannot use it to partition us.

use gdc_wire::MAX_TTL;

pub const BINS: usize = MAX_TTL as usize + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtlPolicy {
    pub min: u8,
    pub max: u8,
    /// Where to start before any measurement exists.
    pub initial: u8,
    /// Hops of slack we want the low percentile of arrival TTL to keep.
    pub target_headroom: u8,
    /// Samples before the controller is trusted at all.
    pub warmup: u32,
    /// Samples after which the histogram is halved, so the estimate tracks a
    /// moving mesh instead of averaging over its whole history.
    pub decay_after: u32,
    pub enabled: bool,
}

impl Default for TtlPolicy {
    fn default() -> Self {
        TtlPolicy {
            min: 4,
            max: MAX_TTL,
            initial: 7,
            target_headroom: 2,
            warmup: 12,
            decay_after: 256,
            enabled: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TtlController {
    policy: TtlPolicy,
    hist: [u32; BINS],
    samples: u32,
    /// Frames we had to drop because their TTL ran out while we still had
    /// somewhere useful to send them. The strongest possible evidence that the
    /// budget is too small, so it is weighted far above the histogram.
    clipped: u32,
    current: u8,
}

impl TtlController {
    pub fn new(policy: TtlPolicy) -> Self {
        let current = policy.initial.clamp(policy.min.max(1), policy.max.min(MAX_TTL));
        TtlController {
            policy,
            hist: [0; BINS],
            samples: 0,
            clipped: 0,
            current,
        }
    }

    pub fn policy(&self) -> TtlPolicy {
        self.policy
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    pub fn clipped(&self) -> u32 {
        self.clipped
    }

    /// Record the TTL a novel frame arrived with.
    pub fn observe_arrival(&mut self, arrival_ttl: u8) {
        let i = usize::from(arrival_ttl.min(MAX_TTL));
        if let Some(c) = self.hist.get_mut(i) {
            *c = c.saturating_add(1);
        }
        self.samples = self.samples.saturating_add(1);
        if self.samples >= self.policy.decay_after {
            for c in self.hist.iter_mut() {
                *c /= 2;
            }
            self.samples /= 2;
            self.clipped /= 2;
        }
        self.recompute();
    }

    /// Record a frame we would have relayed but could not, because its TTL was
    /// spent.
    pub fn observe_clipped(&mut self) {
        self.clipped = self.clipped.saturating_add(1);
        self.recompute();
    }

    /// The `p`-th permille percentile of observed arrival TTL.
    fn percentile(&self, p: u32) -> u8 {
        if self.samples == 0 {
            return self.policy.initial;
        }
        let want = (u64::from(self.samples) * u64::from(p) / 1000).max(1);
        let mut acc = 0u64;
        for (i, c) in self.hist.iter().enumerate() {
            acc += u64::from(*c);
            if acc >= want {
                return i as u8;
            }
        }
        MAX_TTL
    }

    fn recompute(&mut self) {
        if !self.policy.enabled {
            self.current = self
                .policy
                .initial
                .clamp(self.policy.min.max(1), self.policy.max.min(MAX_TTL));
            return;
        }
        let lo = self.policy.min.max(1);
        let hi = self.policy.max.min(MAX_TTL);
        if self.samples < self.policy.warmup {
            // Clipping alone is enough to act on even during warmup: it means
            // frames are dying with somewhere left to go.
            if self.clipped > 0 {
                self.current = self.current.saturating_add(1).clamp(lo, hi);
            }
            return;
        }
        // p10 of arrival TTL: the deepest frames we see, which are the ones
        // closest to dying.
        let p10 = self.percentile(100);
        let target = self.policy.target_headroom;
        if self.clipped > 0 || p10 < target {
            let deficit = target.saturating_sub(p10).max(1);
            self.current = self.current.saturating_add(deficit).clamp(lo, hi);
            self.clipped = 0;
        } else if p10 > target.saturating_add(2) {
            // Comfortably over-provisioned: give a hop back. One at a time, so
            // the controller cannot oscillate hard.
            self.current = self.current.saturating_sub(1).clamp(lo, hi);
        }
    }

    /// TTL to stamp on a frame we originate.
    pub fn ttl_for_origination(&self) -> u8 {
        self.current
    }

    /// TTL for a frame handed back by the store layer after being carried.
    ///
    /// Carrying is a hop: the store hands us the frame as it arrived and the
    /// relay path decrements it, so a carried frame cannot launder its way to a
    /// fresh budget. This is only consulted for frames the *store* originated
    /// re-transmission of from its own backlog with no surviving hop count.
    pub fn ttl_for_recarry(&self) -> u8 {
        // Deliberately below a fresh origination: a frame that has already been
        // carried has had more chances than a new one, and the asymmetry is
        // what stops a carried frame circulating forever.
        self.current.saturating_sub(1).max(self.policy.min.max(1))
    }

    /// Blend in the structural estimate, used while the histogram is cold.
    pub fn apply_structure(&mut self, degree: usize, frontier_ratio: u32) {
        if !self.policy.enabled || self.samples >= self.policy.warmup {
            return;
        }
        let lo = self.policy.min.max(1);
        let hi = self.policy.max.min(MAX_TTL);
        // Long and thin: few links, and most of what we can see keeps going.
        let chainish = degree > 0 && degree <= 3 && frontier_ratio >= 500;
        // Dense and closed: many links that all know each other.
        let blobish = degree >= 8 && frontier_ratio < 200;
        self.current = if chainish {
            hi
        } else if blobish {
            lo
        } else {
            self.policy.initial.clamp(lo, hi)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_the_configured_initial() {
        let c = TtlController::new(TtlPolicy::default());
        assert_eq!(c.ttl_for_origination(), 7);
    }

    #[test]
    fn never_leaves_the_wire_bounds_whatever_the_policy() {
        let mut c = TtlController::new(TtlPolicy {
            min: 0,
            max: 200,
            initial: 200,
            ..TtlPolicy::default()
        });
        assert!(c.ttl_for_origination() <= MAX_TTL);
        assert!(c.ttl_for_origination() >= 1);
        for _ in 0..1000 {
            c.observe_clipped();
        }
        assert!(c.ttl_for_origination() <= MAX_TTL);
        for _ in 0..1000 {
            c.observe_arrival(MAX_TTL);
        }
        assert!(c.ttl_for_origination() >= 1);
    }

    #[test]
    fn shallow_mesh_gives_hops_back() {
        let mut c = TtlController::new(TtlPolicy::default());
        // Every frame arrives with 6 of 7 left: one hop of travel, lots of slack.
        for _ in 0..300 {
            c.observe_arrival(6);
        }
        assert!(
            c.ttl_for_origination() < 7,
            "over-provisioned mesh should shrink, got {}",
            c.ttl_for_origination()
        );
        assert!(c.ttl_for_origination() >= c.policy().min);
    }

    #[test]
    fn deep_mesh_buys_hops() {
        let mut c = TtlController::new(TtlPolicy::default());
        for _ in 0..40 {
            c.observe_arrival(1);
        }
        assert!(
            c.ttl_for_origination() > 7,
            "frames arriving nearly dead should raise the budget, got {}",
            c.ttl_for_origination()
        );
    }

    #[test]
    fn clipping_raises_the_budget_even_before_warmup() {
        let mut c = TtlController::new(TtlPolicy::default());
        let before = c.ttl_for_origination();
        c.observe_clipped();
        assert!(c.ttl_for_origination() > before);
    }

    #[test]
    fn structural_cold_start_tells_a_chain_from_a_blob() {
        let mut chain = TtlController::new(TtlPolicy::default());
        chain.apply_structure(2, 1000);
        assert_eq!(chain.ttl_for_origination(), MAX_TTL);

        let mut blob = TtlController::new(TtlPolicy::default());
        blob.apply_structure(30, 50);
        assert_eq!(blob.ttl_for_origination(), TtlPolicy::default().min);
    }

    #[test]
    fn structure_stops_overriding_once_measurement_exists() {
        let mut c = TtlController::new(TtlPolicy::default());
        for _ in 0..40 {
            c.observe_arrival(1);
        }
        let measured = c.ttl_for_origination();
        c.apply_structure(30, 0);
        assert_eq!(c.ttl_for_origination(), measured, "measurement outranks structure");
    }

    #[test]
    fn disabled_policy_is_a_constant() {
        let mut c = TtlController::new(TtlPolicy { enabled: false, ..TtlPolicy::default() });
        for _ in 0..500 {
            c.observe_arrival(1);
            c.observe_clipped();
        }
        assert_eq!(c.ttl_for_origination(), 7);
    }

    #[test]
    fn recarry_is_never_more_generous_than_a_fresh_origination() {
        let mut c = TtlController::new(TtlPolicy::default());
        for _ in 0..40 {
            c.observe_arrival(1);
        }
        assert!(c.ttl_for_recarry() < c.ttl_for_origination());
        assert!(c.ttl_for_recarry() >= c.policy().min);
    }

    #[test]
    fn histogram_decays_so_the_estimate_tracks_a_moving_mesh() {
        let mut c = TtlController::new(TtlPolicy::default());
        for _ in 0..600 {
            c.observe_arrival(1);
        }
        let deep = c.ttl_for_origination();
        for _ in 0..2000 {
            c.observe_arrival(MAX_TTL - 1);
        }
        assert!(c.ttl_for_origination() < deep, "stale history must wash out");
    }
}
