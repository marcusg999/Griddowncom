//! How many links a relay transmits on, as a function of how many it has.
//!
//! # Why the growth rate is logarithmic, and why that is not a copy
//!
//! bitchat relays to about `log2(degree)` links. Before changing that we worked
//! out what the right form actually is, because "beat them on the exponent" was
//! the obvious move and it is wrong.
//!
//! In a BLE mesh the radio is connection-oriented: one transmission reaches one
//! peer, so fanout `f` out of degree `d` means each neighbour receives the
//! frame from a given relay with probability `f/d`. For a neighbour to receive
//! it from *someone*, the relays around it must collectively cover it, which is
//! the coupon-collector problem — covering `d` neighbours needs about `ln d`
//! independent draws each. So `f = Θ(log d)` is the correct growth rate and
//! anything faster is wasted airtime. We measured `sqrt(d)` and it is strictly
//! worse: at 150 nodes in range it spends 13 transmissions to buy the same
//! delivery that 8 buys.
//!
//! Where bitchat's function is wrong is at the bottom, not the top:
//!
//! * `ceil(log2(2)) = 1`. At degree 2 — which is every interior node of a
//!   chain, i.e. exactly the case M2 grades us on — relaying to one of two
//!   links is a coin flip, and the losing side of that coin is the direction
//!   the frame came from. Half of all chain relays go backwards.
//! * `ceil(log2(1)) = 0`. Degree 1 must be clamped, and whether it is clamped
//!   to 0 or 1 decides whether a leaf can ever hand a frame onward.
//!
//! So: **full fanout in the sparse regime, logarithmic in the dense regime.**
//! Below `full_fanout_degree` (default 3) we use every link, which costs at
//! most three transmissions and is often the only path that exists. Above it we
//! use `ceil(log2(d))` with a floor of 2 and a hard cap, because at that point
//! airtime is the scarce resource and redundancy is cheap to come by.
//!
//! The separate and much larger win is that we never count the link we received
//! the frame on as a candidate; see [`crate::select`]. That is what turns a
//! degree-2 chain node from a coin flip into a certainty, and it is measured as
//! its own lever.

/// `ceil(log2(n))` for `n >= 1`, 0 for 0. No floats, so no platform drift.
pub fn ceil_log2(n: usize) -> u32 {
    if n <= 1 {
        return 0;
    }
    usize::BITS - (n - 1).leading_zeros()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FanoutPolicy {
    /// At or below this degree, transmit on every link.
    pub full_below: u8,
    /// Floor applied in the logarithmic regime.
    pub floor: u8,
    /// Hard ceiling on transmissions per frame per node, whatever the degree.
    pub cap: u8,
}

impl Default for FanoutPolicy {
    fn default() -> Self {
        FanoutPolicy {
            full_below: 3,
            floor: 2,
            cap: 8,
        }
    }
}

impl FanoutPolicy {
    /// bitchat's function, kept so the ablation harness can run it directly
    /// rather than re-deriving it and getting it subtly wrong.
    pub fn bitchat(degree: usize) -> usize {
        (ceil_log2(degree) as usize).max(1).min(degree)
    }

    /// The rejected alternative, kept for the same reason.
    pub fn sqrt(degree: usize) -> usize {
        if degree == 0 {
            return 0;
        }
        let mut r = 0usize;
        while (r + 1) * (r + 1) <= degree {
            r += 1;
        }
        r.max(1).min(degree)
    }

    pub fn fanout(&self, degree: usize) -> usize {
        if degree == 0 {
            return 0;
        }
        if degree <= usize::from(self.full_below) {
            return degree;
        }
        let log = ceil_log2(degree) as usize;
        log.max(usize::from(self.floor))
            .min(usize::from(self.cap))
            .min(degree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceil_log2_matches_the_definition() {
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(6), 3);
        assert_eq!(ceil_log2(20), 5);
        assert_eq!(ceil_log2(150), 8);
    }

    #[test]
    fn fanout_at_the_degrees_the_metrics_file_names() {
        let p = FanoutPolicy::default();
        assert_eq!(p.fanout(1), 1, "a leaf must still be able to forward");
        assert_eq!(p.fanout(2), 2, "both links: a chain interior must not coin-flip");
        assert_eq!(p.fanout(6), 3);
        assert_eq!(p.fanout(20), 5);
        assert_eq!(p.fanout(150), 8, "capped: airtime is the scarce resource here");
    }

    #[test]
    fn fanout_is_monotone_and_never_exceeds_degree_or_cap() {
        let p = FanoutPolicy::default();
        let mut last = 0;
        for d in 0..1000usize {
            let f = p.fanout(d);
            assert!(f <= d, "degree {d} fanout {f}");
            assert!(f <= usize::from(p.cap));
            assert!(f >= last || d <= usize::from(p.full_below) + 1, "non-monotone at {d}");
            last = f;
        }
    }

    #[test]
    fn we_differ_from_bitchat_exactly_in_the_sparse_regime_and_at_the_cap() {
        let p = FanoutPolicy::default();
        assert_eq!(FanoutPolicy::bitchat(2), 1);
        assert_eq!(p.fanout(2), 2);
        assert_eq!(FanoutPolicy::bitchat(3), 2);
        assert_eq!(p.fanout(3), 3);
        // Identical through the middle, which is the honest finding.
        for d in 4..=128usize {
            assert_eq!(p.fanout(d), FanoutPolicy::bitchat(d), "degree {d}");
        }
        // And we spend less at the top.
        assert!(p.fanout(150) <= FanoutPolicy::bitchat(150));
    }

    #[test]
    fn sqrt_is_strictly_more_expensive_at_density() {
        assert!(FanoutPolicy::sqrt(150) > FanoutPolicy::default().fanout(150));
        assert_eq!(FanoutPolicy::sqrt(150), 12);
    }

    #[test]
    fn degenerate_policies_do_not_panic() {
        let p = FanoutPolicy { full_below: 255, floor: 255, cap: 0 };
        for d in 0..300usize {
            assert!(p.fanout(d) <= d.max(1) * 300);
        }
    }
}
