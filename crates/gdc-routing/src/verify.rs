//! Authenticate before you relay, within a bounded work budget.
//!
//! Rule 4 of `docs/research/BRIDGEFY-FINDINGS.md`. Bridgefy's processing order
//! was receive, relay, *then* decrypt — which is why one crafted 10 KB
//! broadcast became a network-wide outage: every node forwarded the bomb before
//! discovering it was a bomb.
//!
//! # The three things that have to be true
//!
//! 1. **Nothing unparsed is ever forwarded.** Structural: the only way to
//!    obtain a [`gdc_wire::Frame`] is `Frame::decode`, which checks the version,
//!    the reserved bytes, the kind, the TTL ceiling and the exact declared
//!    length; and the only relay path in this crate takes a `Frame`. There is
//!    no byte-slice relay entry point to forget to guard.
//! 2. **Nothing is expanded at relay time at all.** A relay does not
//!    decompress, does not deserialise the body, and does not look inside it.
//!    The body is an opaque bucket-sized blob that is copied and forwarded. The
//!    decompression bomb has nowhere to detonate on the relay path, which is a
//!    stronger statement than "we check the output size".
//! 3. **Cryptographic verification is mandatory wherever it is possible**, and
//!    the work it costs is drawn from a refilled budget, so verification cannot
//!    itself become the denial of service.
//!
//! # The honest limit, stated plainly
//!
//! For a channel we hold no key for we *cannot* cryptographically verify a
//! frame. Channel-first addressing means strangers' frames must still be
//! carried — that is the whole mechanism by which a message crosses a city —
//! and `gdc-wire` is frozen with no relay-checkable MAC in the cleartext
//! header, so there is no key-free authenticator available to us.
//!
//! What we do instead, and what a critic should hold us to:
//!
//! * Member channels: full verification, no exceptions, failure means drop and
//!   a charge against the supplying peer's forgery budget.
//! * Stranger channels: structural verification only, a *separate and smaller*
//!   fanout cap, and the ordinary per-peer, per-tag and global rate limits. An
//!   unverifiable frame therefore costs the mesh a bounded and small number of
//!   transmissions no matter who minted it.
//! * Under budget exhaustion the decision is always **drop**, never
//!   relay-unverified. Running out of verification capacity must degrade reach,
//!   not integrity.
//!
//! The residual gap — a stranger frame is rate-limited rather than
//! authenticated — is listed as the crate's weakest point in the report, with
//! the wire change that would close it.

use gdc_wire::{ChanTag, Frame};

/// Work units. One unit is "verify one frame of the largest bucket", so the
/// budget is in units a scheduler can reason about without knowing the cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyBudget {
    remaining: u32,
    spent: u32,
}

impl VerifyBudget {
    pub fn new(units: u32) -> Self {
        VerifyBudget {
            remaining: units,
            spent: 0,
        }
    }

    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    pub fn spent(&self) -> u32 {
        self.spent
    }

    /// Deduct `units`, or refuse if the budget cannot cover them.
    ///
    /// Implementations of [`FrameVerifier`] must call this *before* doing the
    /// work, and must return [`Verdict::OutOfBudget`] when it refuses.
    pub fn charge(&mut self, units: u32) -> bool {
        if self.remaining >= units {
            self.remaining -= units;
            self.spent = self.spent.saturating_add(units);
            true
        } else {
            false
        }
    }

    pub fn refill_to(&mut self, units: u32) {
        self.remaining = units;
        self.spent = 0;
    }
}

/// Whether we hold the channel key for a tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Membership {
    /// We hold the key: this frame can and must be cryptographically verified.
    Member,
    /// We do not: we can carry it, under a stricter budget, but we cannot
    /// authenticate it.
    Stranger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Tag resolves to a channel we hold and the AEAD tag over
    /// `Header::aad()` and the body verified.
    Authentic,
    /// Tag resolves to a channel we hold and verification failed. Never
    /// relayed, and charged to the peer that supplied it.
    Forged,
    /// We hold no key for this tag.
    NotAMember,
    /// The verifier declined because the budget could not cover the work. The
    /// router treats this as drop, never as relay.
    OutOfBudget,
}

/// The narrow contract this crate needs from `gdc-crypto`.
///
/// Requirements on the implementation, which are part of the contract and not
/// advice:
///
/// * `verify` must charge [`VerifyBudget`] before doing work and return
///   [`Verdict::OutOfBudget`] rather than exceeding it.
/// * `verify` must not allocate proportionally to anything but the frame it was
///   given, and must not decompress or otherwise expand the body. Expansion, if
///   the payload needs it, belongs after the relay decision, in the delivery
///   path, under `gdc_wire::MAX_EXPANDED_LEN`.
/// * `verify` must not panic on any input. The frame it is handed is attacker
///   controlled in full except for its length, which `gdc-wire` has already
///   pinned to a bucket.
/// * Rule 8: the failure paths must be shaped and timed alike. `Forged` and
///   `NotAMember` must not be distinguishable by how long they take, because
///   that difference is a membership oracle — it would tell a passive attacker
///   which channels a phone belongs to.
pub trait FrameVerifier {
    /// Cheap, non-cryptographic: do we hold a key whose current-epoch tag is
    /// this? Must be constant-shape over tags.
    fn membership(&self, tag: &ChanTag) -> Membership;

    /// Full authentication of the frame under the channel key.
    fn verify(&self, frame: &Frame, budget: &mut VerifyBudget) -> Verdict;
}

/// A verifier that holds no keys at all. Every tag is a stranger's.
///
/// Useful for a relay-only node, and for tests of the stranger path.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoKeys;

impl FrameVerifier for NoKeys {
    fn membership(&self, _tag: &ChanTag) -> Membership {
        Membership::Stranger
    }

    fn verify(&self, _frame: &Frame, budget: &mut VerifyBudget) -> Verdict {
        if !budget.charge(1) {
            return Verdict::OutOfBudget;
        }
        Verdict::NotAMember
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_refuses_rather_than_underflowing() {
        let mut b = VerifyBudget::new(2);
        assert!(b.charge(1));
        assert!(b.charge(1));
        assert!(!b.charge(1));
        assert_eq!(b.remaining(), 0);
        assert_eq!(b.spent(), 2);
        assert!(!b.charge(u32::MAX));
    }

    #[test]
    fn refill_resets_both_counters() {
        let mut b = VerifyBudget::new(1);
        assert!(b.charge(1));
        b.refill_to(5);
        assert_eq!(b.remaining(), 5);
        assert_eq!(b.spent(), 0);
    }
}
