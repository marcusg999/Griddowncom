//! The adaptive copy budget.
//!
//! # The problem with a fixed budget
//!
//! bitchat sprays a fixed four copies, doubling-capped at eight, halved on each
//! handover. Four is a single number standing in for two opposite situations.
//!
//! In a sparse city — a stairwell, a suburban street at 3 a.m., a cordoned
//! block — a message gets handed to at most four carriers in its life, because
//! binary spray-and-wait means the copy count *is* the number of distinct
//! devices that will ever hold it. If each carrier independently has a 30 %
//! chance of walking somewhere that reaches the channel, four copies deliver
//! 76 % of the time and twelve deliver 99 %. Four leaves a quarter of the
//! messages on the floor for want of storage nobody was short of.
//!
//! In a dense crowd the same four copies are waste that lands in *other
//! people's* stores. Every copy occupies a slot in a bounded courier store, so
//! surplus copies do not merely fail to help: they evict honest mail and lower
//! the delivery rate. The dense regime wants one or two.
//!
//! # Derivation
//!
//! Take the standard two-hop spray-and-wait model. `L` copies sit on `L`
//! distinct carriers. Each carrier meets a member of the target channel as a
//! Poisson process of rate `lambda`. The message is delivered by deadline `T`
//! if any carrier does, so
//!
//! ```text
//!     P(delivered by T) = 1 - exp(-L * lambda * T)
//! ```
//!
//! Solving for the smallest `L` that reaches a target probability `p*`:
//!
//! ```text
//!     L* = ceil( -ln(1 - p*) / (lambda * T) )
//! ```
//!
//! With `p* = 0.95`, `-ln(0.05) = 2.996`, which is [`NEG_LN_MISS_X1000`].
//! `T` is [`TARGET_DEADLINE_SECS`], the 30-minute rung of `docs/METRICS.md`;
//! the 30 s and 5 min rungs are decided by whether a live path exists and no
//! copy count rescues them, and the 2 h rung is the tail of whatever the
//! 30-minute policy set in motion.
//!
//! `lambda` is the one quantity that must be measured rather than assumed, and
//! [`crate::encounter`] measures it: novel in-channel encounters per second
//! where enough have been seen, otherwise novel encounters overall discounted
//! by a prior on what fraction of strangers turn out to be members.
//!
//! The policy is therefore a division, two clamps, and an honest admission of
//! ignorance:
//!
//! ```text
//!     L = clamp( ceil(2.996 / (lambda * T)), 1, 12 )      when lambda is known
//!     L = 4                                               when it is not
//! ```
//!
//! The cold-start value is deliberately bitchat's fixed four. With no
//! observation we are in no position to claim we know better than the
//! baseline; the policy earns its divergence.
//!
//! # Why the ceiling is 12 and not higher
//!
//! The model asks for 144 copies in the sparse extreme. It cannot have them.
//! Twelve copies of a largest-bucket frame is 12 KiB spread over twelve
//! devices, which at [`crate::limits::MAX_OUTBOX_MSGS`] bounds one author's
//! total imposition on the network at about 768 KiB of other people's storage.
//! That is the number we are willing to defend. Above it, the marginal
//! delivery is small and the marginal eviction pressure on honest mail is not.
//!
//! # Why handover only ever halves
//!
//! A carrier never raises a budget. If it could, a hostile carrier would mint
//! copies and the copy budget would stop being a bound. Binary spray gives
//! `floor(L/2)` away and keeps the rest; at `L = 1` the carrier is in the wait
//! phase and hands the message only to a channel member. The *author* may
//! top up, because the author is the one entity entitled to decide how much of
//! the network its own message is worth, and even then only up to the same
//! ceiling and only counted against a monotone per-message total.

use crate::encounter::{MicroRate, RateEstimate};
use crate::limits::{
    COPY_BUDGET_DEFAULT, COPY_BUDGET_MAX, COPY_BUDGET_MIN, MEMBER_FRACTION_PRIOR_RECIP,
    NEG_LN_MISS_X1000, TARGET_DEADLINE_SECS,
};

/// A message's remaining copy allowance, plus the monotone total ever minted
/// for it so that a top-up cannot be used to exceed the ceiling by instalments.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budget {
    remaining: u8,
    minted_total: u8,
}

impl Budget {
    /// Build a budget, clamping to the ceiling rather than refusing. Callers
    /// include frames that arrived over a radio claiming a budget.
    #[must_use]
    pub fn new(copies: u8) -> Budget {
        let c = copies.clamp(COPY_BUDGET_MIN, COPY_BUDGET_MAX);
        Budget {
            remaining: c,
            minted_total: c,
        }
    }

    #[must_use]
    pub fn remaining(self) -> u8 {
        self.remaining
    }

    #[must_use]
    pub fn minted_total(self) -> u8 {
        self.minted_total
    }

    /// True when this holder is in the wait phase: it will carry the message
    /// but not pass it to another carrier, only to a channel member.
    #[must_use]
    pub fn is_waiting(self) -> bool {
        self.remaining <= 1
    }

    /// Binary spray. Returns the budget handed to the peer, or `None` in the
    /// wait phase.
    ///
    /// Total copies across the network is conserved, never increased: the
    /// halves sum to the whole.
    pub fn split(&mut self) -> Option<Budget> {
        if self.is_waiting() {
            return None;
        }
        let give = self.remaining / 2;
        self.remaining -= give;
        Some(Budget {
            remaining: give,
            minted_total: give,
        })
    }

    /// Raise the author's own remaining allowance, bounded by the ceiling on
    /// the monotone total. Returns how much was actually added.
    ///
    /// Only reachable from the outbox, never from a received frame.
    pub fn top_up(&mut self, target_total: u8) -> u8 {
        let target = target_total.min(COPY_BUDGET_MAX);
        if target <= self.minted_total {
            return 0;
        }
        let add = target - self.minted_total;
        self.remaining = self.remaining.saturating_add(add).min(COPY_BUDGET_MAX);
        self.minted_total = target;
        add
    }
}

/// The policy's answer together with why, so the numbers in a report can be
/// traced back to what the device believed at the time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BudgetDecision {
    pub copies: u8,
    pub basis: BudgetBasis,
    /// Effective in-channel encounter rate used, encounters/s scaled by 1e6.
    pub lambda: MicroRate,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BudgetBasis {
    /// Not enough observation. Fell back to the baseline's fixed value.
    ColdStart,
    /// Used directly observed in-channel encounters.
    MeasuredMember,
    /// Used overall novel encounters discounted by the member-fraction prior.
    DiscountedOverall,
    /// The model asked for more than the ceiling allows.
    ClampedSparse,
    /// The model asked for less than one copy.
    ClampedDense,
}

/// Apply the policy.
///
/// `deadline_secs` is a parameter rather than a constant so that urgent traffic
/// can solve for a nearer deadline and get a larger budget honestly, instead of
/// a priority flag quietly meaning "more copies".
#[must_use]
pub fn decide(estimate: RateEstimate, deadline_secs: u64) -> BudgetDecision {
    let lambda = match estimate {
        RateEstimate::Unknown => {
            return BudgetDecision {
                copies: COPY_BUDGET_DEFAULT,
                basis: BudgetBasis::ColdStart,
                lambda: MicroRate(0),
            }
        }
        RateEstimate::Member(r) => r,
        RateEstimate::Overall(r) => MicroRate(r.0 / MEMBER_FRACTION_PRIOR_RECIP),
    };
    let basis = match estimate {
        RateEstimate::Member(_) => BudgetBasis::MeasuredMember,
        _ => BudgetBasis::DiscountedOverall,
    };

    let t = deadline_secs.max(1);
    // lambda is scaled by 1e6, so lambda*T in model units is lambda.0*t/1e6 and
    // L = 2.996 / (lambda*T) = 2_996_000 / (lambda.0 * t).
    let denom = lambda.0.saturating_mul(t);
    if denom == 0 {
        return BudgetDecision {
            copies: COPY_BUDGET_MAX,
            basis: BudgetBasis::ClampedSparse,
            lambda,
        };
    }
    let wanted = (NEG_LN_MISS_X1000.saturating_mul(1000)).div_ceil(denom);
    let copies = wanted.clamp(COPY_BUDGET_MIN as u64, COPY_BUDGET_MAX as u64) as u8;
    let basis = if wanted > COPY_BUDGET_MAX as u64 {
        BudgetBasis::ClampedSparse
    } else if wanted < COPY_BUDGET_MIN as u64 {
        BudgetBasis::ClampedDense
    } else {
        basis
    };
    BudgetDecision {
        copies,
        basis,
        lambda,
    }
}

/// The policy's default deadline.
#[must_use]
pub fn default_deadline_secs() -> u64 {
    TARGET_DEADLINE_SECS
}
