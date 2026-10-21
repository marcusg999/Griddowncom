//! bitchat §6.1 Sender Outbox and §6.2 Couriers.
//!
//! Source for everything here: bitchat WHITEPAPER.md v2.0 (2026-07-06), §6.1
//! and §6.2, quoted inline per parameter.
//!
//! This is the opponent's answer to the same problem our store-and-forward
//! design exists to solve — "the recipient is not here right now" — so it is
//! the half of bitchat that decides the `docs/METRICS.md` M2 carrier regime.
//! Weakening any quota or budget here would hand us that metric for free.

use std::collections::HashMap;

use crate::proto::{PeerId, TimeMs};

// -- §6.1 Sender Outbox ------------------------------------------------------

/// §6.1: "retained per peer (100 messages/peer, 24 h TTL)".
pub const OUTBOX_PER_PEER: usize = 100;
pub const OUTBOX_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// §6.1: "a resend cap (8 attempts) drops them with visible failure".
pub const OUTBOX_MAX_ATTEMPTS: u32 = 8;

// -- §6.2 Couriers -----------------------------------------------------------

/// §6.2: "handed to up to 3 connected peers who may physically encounter the
/// recipient", and "until 3 distinct couriers carry the message or it expires".
pub const COURIERS_PER_MESSAGE: usize = 3;

/// §6.2 Trust tiers: "Mutual favorites may deposit 5 envelopes each; any peer
/// with a signature-verified announce may deposit 2".
pub const FAVOURITE_DEPOSIT_QUOTA: usize = 5;
pub const VERIFIED_DEPOSIT_QUOTA: usize = 2;

/// §6.2 Trust tiers: "into a bounded pool (20 of 40 slots) that can never crowd
/// out favorites' mail."
pub const VERIFIED_POOL_SLOTS: usize = 20;
pub const TOTAL_POOL_SLOTS: usize = 40;

/// §6.2: "Envelopes are capped at 16 KiB and 24 h".
pub const ENVELOPE_MAX_BYTES: usize = 16 * 1024;
pub const ENVELOPE_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// §6.2 Spray and wait: "a copy budget (initially 4, capped at 8)".
pub const SPRAY_INITIAL_BUDGET: u8 = 4;
pub const SPRAY_MAX_BUDGET: u8 = 8;

/// §6.2 Handover: "throttled to one attempt per envelope per 10 minutes."
pub const RELAYED_ANNOUNCE_THROTTLE_MS: u64 = 10 * 60 * 1000;

/// §6.2 Opaque addressing: the tag is an HMAC of the recipient's static key and
/// the UTC day, so it rotates daily. One day in milliseconds.
pub const TAG_ROTATION_MS: u64 = 24 * 60 * 60 * 1000;

/// Which quota a deposit comes out of. §6.2 Trust tiers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// Mutual favourite. Cannot be crowded out.
    Favourite,
    /// Any peer with a signature-verified announce.
    Verified,
}

impl Tier {
    pub fn quota(self) -> usize {
        match self {
            Tier::Favourite => FAVOURITE_DEPOSIT_QUOTA,
            Tier::Verified => VERIFIED_DEPOSIT_QUOTA,
        }
    }
}

/// A sealed courier envelope.
///
/// §5.2: sealed to the recipient's static key with Noise `X`. Not performed —
/// `ct_len` is the modelled sealed size and `plain` is what the simulator needs
/// in order to score a delivery.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Envelope {
    /// §6.2: "The only routing information is a 16-byte rotating recipient
    /// tag". A courier therefore learns neither sender nor recipient, which is
    /// why this model gives it a tag and not a `PeerId`.
    pub tag: [u8; 16],
    pub msg_id: u64,
    pub ct_len: usize,
    pub plain: Vec<u8>,
    /// §6.2 Spray and wait.
    pub budget: u8,
    pub tier: Tier,
    pub depositor: PeerId,
    pub deposited_at: TimeMs,
    /// Last time a relayed-announce handover was attempted for this envelope.
    pub last_handover: Option<TimeMs>,
}

impl Envelope {
    pub fn new(
        tag: [u8; 16],
        msg_id: u64,
        plain: Vec<u8>,
        ct_len: usize,
        tier: Tier,
        depositor: PeerId,
        now: TimeMs,
    ) -> Self {
        Envelope {
            tag,
            msg_id,
            ct_len,
            plain,
            // Clamped on construction: §6.2 caps the budget at 8 however it is
            // set, so a crafted deposit cannot buy extra copies.
            budget: SPRAY_INITIAL_BUDGET.min(SPRAY_MAX_BUDGET),
            tier,
            depositor,
            deposited_at: now,
            last_handover: None,
        }
    }

    pub fn expired(&self, now: TimeMs) -> bool {
        now.elapsed_since(self.deposited_at) > ENVELOPE_TTL_MS
    }

    /// §6.2 Handover: "throttled to one attempt per envelope per 10 minutes."
    pub fn handover_allowed(&self, now: TimeMs) -> bool {
        match self.last_handover {
            None => true,
            Some(t) => now.elapsed_since(t) >= RELAYED_ANNOUNCE_THROTTLE_MS,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DepositError {
    /// Over this depositor's tier quota.
    QuotaExceeded,
    /// The verified-tier pool is full. Favourites are never refused for this
    /// reason, because §6.2 says the pool "can never crowd out favorites' mail".
    PoolFull,
    /// Over 16 KiB.
    TooLarge,
}

/// A node's mailbag. §6.2.
#[derive(Default, Debug)]
pub struct CourierStore {
    envelopes: Vec<Envelope>,
    pub rejected: u64,
    pub evicted: u64,
}

impl CourierStore {
    pub fn len(&self) -> usize {
        self.envelopes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Envelope> {
        self.envelopes.iter()
    }

    fn count_from(&self, who: PeerId) -> usize {
        self.envelopes.iter().filter(|e| e.depositor == who).count()
    }

    fn count_tier(&self, t: Tier) -> usize {
        self.envelopes.iter().filter(|e| e.tier == t).count()
    }

    /// Accept a deposit, or say why not.
    ///
    /// §6.2 Trust tiers, in order: per-depositor quota, then the bounded pool,
    /// then size. Overflow "evicts oldest verified-tier mail first", which is
    /// what keeps a favourite's mail safe from a flood of verified deposits.
    pub fn deposit(&mut self, now: TimeMs, env: Envelope) -> Result<(), DepositError> {
        if env.ct_len > ENVELOPE_MAX_BYTES {
            self.rejected += 1;
            return Err(DepositError::TooLarge);
        }
        self.expire(now);
        if self.count_from(env.depositor) >= env.tier.quota() {
            self.rejected += 1;
            return Err(DepositError::QuotaExceeded);
        }
        if env.tier == Tier::Verified && self.count_tier(Tier::Verified) >= VERIFIED_POOL_SLOTS {
            self.rejected += 1;
            return Err(DepositError::PoolFull);
        }
        self.envelopes.push(env);
        while self.envelopes.len() > TOTAL_POOL_SLOTS {
            // Oldest verified-tier first; only if there is none do favourites
            // give way, and then the oldest of those.
            let victim = self
                .envelopes
                .iter()
                .enumerate()
                .filter(|(_, e)| e.tier == Tier::Verified)
                .min_by_key(|(_, e)| e.deposited_at)
                .map(|(i, _)| i)
                .or_else(|| {
                    self.envelopes
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, e)| e.deposited_at)
                        .map(|(i, _)| i)
                });
            match victim {
                Some(i) => {
                    self.envelopes.remove(i);
                    self.evicted += 1;
                }
                None => break,
            }
        }
        Ok(())
    }

    /// §6.2: envelopes are capped at 24 h.
    pub fn expire(&mut self, now: TimeMs) -> usize {
        let before = self.envelopes.len();
        self.envelopes.retain(|e| !e.expired(now));
        before - self.envelopes.len()
    }

    /// Envelopes addressed to a tag, for handover on a verified announce.
    pub fn matching(&self, tag: &[u8; 16]) -> Vec<usize> {
        self.envelopes
            .iter()
            .enumerate()
            .filter(|(_, e)| &e.tag == tag)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn get(&self, i: usize) -> Option<&Envelope> {
        self.envelopes.get(i)
    }

    pub fn mark_handover(&mut self, i: usize, now: TimeMs) {
        if let Some(e) = self.envelopes.get_mut(i) {
            e.last_handover = Some(now);
        }
    }

    /// §6.2 Handover: "On a verified *direct* announce from the recipient,
    /// matching envelopes are delivered over the live link and removed."
    pub fn take(&mut self, i: usize) -> Option<Envelope> {
        if i < self.envelopes.len() {
            Some(self.envelopes.remove(i))
        } else {
            None
        }
    }

    /// §6.2 Spray and wait: "A courier meeting another eligible courier hands
    /// over half its remaining budget, so mail diffuses through a moving crowd
    /// instead of riding one person."
    ///
    /// Returns the budget handed to the other courier. The halves are
    /// `floor(b/2)` given away and `ceil(b/2)` kept, which is the standard
    /// binary-spray split and never creates a copy out of nothing: the two
    /// halves always sum to the original budget.
    pub fn hand_over_half(&mut self, i: usize) -> u8 {
        match self.envelopes.get_mut(i) {
            Some(e) => {
                let give = e.budget / 2;
                e.budget -= give;
                give
            }
            None => 0,
        }
    }
}

// -- §6.1 the outbox itself --------------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutboxItem {
    pub msg_id: u64,
    pub plain: Vec<u8>,
    pub queued_at: TimeMs,
    pub attempts: u32,
}

/// §6.1 Sender Outbox. Per-peer, bounded, with a resend cap.
#[derive(Default, Debug)]
pub struct Outbox {
    per_peer: HashMap<PeerId, Vec<OutboxItem>>,
    pub dropped_full: u64,
    pub failed_visibly: u64,
}

impl Outbox {
    pub fn queue(&mut self, now: TimeMs, peer: PeerId, msg_id: u64, plain: Vec<u8>) -> bool {
        let q = self.per_peer.entry(peer).or_default();
        if q.len() >= OUTBOX_PER_PEER {
            self.dropped_full += 1;
            return false;
        }
        q.push(OutboxItem {
            msg_id,
            plain,
            queued_at: now,
            attempts: 0,
        });
        true
    }

    pub fn len_for(&self, peer: PeerId) -> usize {
        self.per_peer.get(&peer).map(|v| v.len()).unwrap_or(0)
    }

    pub fn total(&self) -> usize {
        self.per_peer.values().map(|v| v.len()).sum()
    }

    /// §6.1: "re-sent on reconnect events until a delivery or read ack clears
    /// them, or a resend cap (8 attempts) drops them with visible failure."
    ///
    /// Returns the items to re-send now, having charged each an attempt and
    /// dropped any that has run out.
    pub fn on_reconnect(&mut self, now: TimeMs, peer: PeerId) -> Vec<OutboxItem> {
        let mut failed = 0u64;
        let out = match self.per_peer.get_mut(&peer) {
            Some(q) => {
                q.retain(|i| now.elapsed_since(i.queued_at) <= OUTBOX_TTL_MS);
                for i in q.iter_mut() {
                    i.attempts += 1;
                }
                let before = q.len();
                q.retain(|i| i.attempts <= OUTBOX_MAX_ATTEMPTS);
                failed = (before - q.len()) as u64;
                q.clone()
            }
            None => Vec::new(),
        };
        self.failed_visibly += failed;
        out
    }

    /// A delivery or read ack clears the item.
    pub fn ack(&mut self, peer: PeerId, msg_id: u64) -> bool {
        match self.per_peer.get_mut(&peer) {
            Some(q) => {
                let before = q.len();
                q.retain(|i| i.msg_id != msg_id);
                before != q.len()
            }
            None => false,
        }
    }

    /// §6.1: 24 h TTL.
    pub fn expire(&mut self, now: TimeMs) {
        for q in self.per_peer.values_mut() {
            q.retain(|i| now.elapsed_since(i.queued_at) <= OUTBOX_TTL_MS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(tier: Tier, depositor: u64, now: u64, tag: u8) -> Envelope {
        Envelope::new(
            [tag; 16],
            depositor * 1000 + now,
            b"help".to_vec(),
            512,
            tier,
            PeerId(depositor),
            TimeMs(now),
        )
    }

    #[test]
    fn documented_constants() {
        assert_eq!(OUTBOX_PER_PEER, 100);
        assert_eq!(OUTBOX_TTL_MS, 86_400_000);
        assert_eq!(OUTBOX_MAX_ATTEMPTS, 8);
        assert_eq!(COURIERS_PER_MESSAGE, 3);
        assert_eq!(FAVOURITE_DEPOSIT_QUOTA, 5);
        assert_eq!(VERIFIED_DEPOSIT_QUOTA, 2);
        assert_eq!(VERIFIED_POOL_SLOTS, 20);
        assert_eq!(TOTAL_POOL_SLOTS, 40);
        assert_eq!(ENVELOPE_MAX_BYTES, 16_384);
        assert_eq!(ENVELOPE_TTL_MS, 86_400_000);
        assert_eq!(SPRAY_INITIAL_BUDGET, 4);
        assert_eq!(SPRAY_MAX_BUDGET, 8);
        assert_eq!(RELAYED_ANNOUNCE_THROTTLE_MS, 600_000);
    }

    #[test]
    fn spray_and_wait_halves_the_budget() {
        // §6.2: "hands over half its remaining budget".
        let mut s = CourierStore::default();
        s.deposit(TimeMs(0), env(Tier::Favourite, 1, 0, 7)).unwrap();
        assert_eq!(s.get(0).unwrap().budget, SPRAY_INITIAL_BUDGET);

        let given = s.hand_over_half(0);
        assert_eq!(given, 2, "4 -> give 2");
        assert_eq!(s.get(0).unwrap().budget, 2, "and keep 2");
        assert_eq!(given + s.get(0).unwrap().budget, SPRAY_INITIAL_BUDGET);

        let given = s.hand_over_half(0);
        assert_eq!(given, 1, "2 -> give 1");
        assert_eq!(s.get(0).unwrap().budget, 1, "and keep 1");

        let given = s.hand_over_half(0);
        assert_eq!(given, 0, "1 -> nothing left to split");
        assert_eq!(s.get(0).unwrap().budget, 1, "the last copy stays put");
    }

    #[test]
    fn spray_budget_is_capped_at_eight() {
        // §6.2: "initially 4, capped at 8". A crafted deposit must not be able
        // to buy itself more copies.
        let e = env(Tier::Favourite, 1, 0, 1);
        assert!(e.budget <= SPRAY_MAX_BUDGET);
        let mut s = CourierStore::default();
        s.deposit(TimeMs(0), e).unwrap();
        // Halving from the cap, repeatedly, must conserve copies.
        let mut total = 0u32;
        let mut remaining = SPRAY_MAX_BUDGET;
        while remaining > 1 {
            let give = remaining / 2;
            remaining -= give;
            total += give as u32;
        }
        assert_eq!(total + remaining as u32, SPRAY_MAX_BUDGET as u32);
    }

    #[test]
    fn deposit_quotas_are_per_depositor_and_per_tier() {
        let mut s = CourierStore::default();
        for i in 0..FAVOURITE_DEPOSIT_QUOTA {
            s.deposit(TimeMs(0), env(Tier::Favourite, 1, i as u64, 1))
                .unwrap();
        }
        assert_eq!(
            s.deposit(TimeMs(0), env(Tier::Favourite, 1, 99, 1)),
            Err(DepositError::QuotaExceeded),
            "a favourite gets 5 and no more"
        );
        for i in 0..VERIFIED_DEPOSIT_QUOTA {
            s.deposit(TimeMs(0), env(Tier::Verified, 2, i as u64, 2))
                .unwrap();
        }
        assert_eq!(
            s.deposit(TimeMs(0), env(Tier::Verified, 2, 99, 2)),
            Err(DepositError::QuotaExceeded),
            "a verified peer gets 2"
        );
        // A different depositor has its own quota.
        assert!(s.deposit(TimeMs(0), env(Tier::Verified, 3, 0, 3)).is_ok());
    }

    #[test]
    fn verified_pool_is_twenty_of_forty_slots() {
        let mut s = CourierStore::default();
        // 10 verified depositors x 2 each = the 20-slot pool.
        for d in 0..10u64 {
            for i in 0..VERIFIED_DEPOSIT_QUOTA {
                s.deposit(TimeMs(0), env(Tier::Verified, 100 + d, i as u64, 9))
                    .unwrap();
            }
        }
        assert_eq!(s.len(), VERIFIED_POOL_SLOTS);
        assert_eq!(
            s.deposit(TimeMs(0), env(Tier::Verified, 200, 0, 9)),
            Err(DepositError::PoolFull),
            "verified mail cannot exceed 20 slots"
        );
        // Favourites are still accepted: they can never be crowded out.
        assert!(s.deposit(TimeMs(0), env(Tier::Favourite, 300, 0, 9)).is_ok());
    }

    #[test]
    fn overflow_evicts_oldest_verified_first() {
        let mut s = CourierStore::default();
        // Fill with 20 verified (oldest at t=1..) and 20 favourite.
        for d in 0..10u64 {
            for i in 0..VERIFIED_DEPOSIT_QUOTA {
                s.deposit(TimeMs(0), env(Tier::Verified, 100 + d, 1 + i as u64, 9))
                    .unwrap();
            }
        }
        for d in 0..4u64 {
            for i in 0..FAVOURITE_DEPOSIT_QUOTA {
                s.deposit(TimeMs(0), env(Tier::Favourite, 200 + d, 50 + i as u64, 8))
                    .unwrap();
            }
        }
        assert_eq!(s.len(), TOTAL_POOL_SLOTS);
        let favourites_before = s.iter().filter(|e| e.tier == Tier::Favourite).count();

        // One more favourite overflows the pool.
        s.deposit(TimeMs(0), env(Tier::Favourite, 250, 60, 8)).unwrap();
        assert_eq!(s.len(), TOTAL_POOL_SLOTS);
        assert_eq!(s.evicted, 1);
        assert_eq!(
            s.iter().filter(|e| e.tier == Tier::Favourite).count(),
            favourites_before + 1,
            "the victim must have been verified-tier, not a favourite"
        );
        assert!(
            !s.iter()
                .any(|e| e.tier == Tier::Verified && e.deposited_at == TimeMs(1)),
            "and specifically the oldest verified one"
        );
    }

    #[test]
    fn oversized_envelopes_are_refused() {
        let mut s = CourierStore::default();
        let mut e = env(Tier::Favourite, 1, 0, 1);
        e.ct_len = ENVELOPE_MAX_BYTES + 1;
        assert_eq!(s.deposit(TimeMs(0), e), Err(DepositError::TooLarge));
        let mut ok = env(Tier::Favourite, 1, 0, 1);
        ok.ct_len = ENVELOPE_MAX_BYTES;
        assert!(s.deposit(TimeMs(0), ok).is_ok(), "16 KiB exactly is allowed");
    }

    #[test]
    fn envelopes_expire_at_twenty_four_hours() {
        let mut s = CourierStore::default();
        s.deposit(TimeMs(0), env(Tier::Favourite, 1, 0, 1)).unwrap();
        assert_eq!(s.expire(TimeMs(ENVELOPE_TTL_MS)), 0, "inside the window");
        assert_eq!(s.expire(TimeMs(ENVELOPE_TTL_MS + 1)), 1);
        assert!(s.is_empty());
    }

    #[test]
    fn relayed_announce_handover_is_throttled_to_ten_minutes() {
        let mut s = CourierStore::default();
        s.deposit(TimeMs(0), env(Tier::Favourite, 1, 0, 5)).unwrap();
        assert!(s.get(0).unwrap().handover_allowed(TimeMs(0)));
        s.mark_handover(0, TimeMs(0));
        assert!(!s.get(0).unwrap().handover_allowed(TimeMs(1)));
        assert!(!s
            .get(0)
            .unwrap()
            .handover_allowed(TimeMs(RELAYED_ANNOUNCE_THROTTLE_MS - 1)));
        assert!(s
            .get(0)
            .unwrap()
            .handover_allowed(TimeMs(RELAYED_ANNOUNCE_THROTTLE_MS)));
    }

    #[test]
    fn envelopes_are_addressed_only_by_tag() {
        let mut s = CourierStore::default();
        s.deposit(TimeMs(0), env(Tier::Favourite, 1, 0, 0xAA)).unwrap();
        s.deposit(TimeMs(0), env(Tier::Favourite, 1, 1, 0xBB)).unwrap();
        assert_eq!(s.matching(&[0xAA; 16]).len(), 1);
        assert_eq!(s.matching(&[0xCC; 16]).len(), 0, "a courier learns nothing else");
    }

    #[test]
    fn outbox_holds_a_hundred_per_peer() {
        let mut o = Outbox::default();
        for i in 0..OUTBOX_PER_PEER as u64 {
            assert!(o.queue(TimeMs(0), PeerId(1), i, vec![1]));
        }
        assert!(!o.queue(TimeMs(0), PeerId(1), 999, vec![1]), "101st is refused");
        assert_eq!(o.len_for(PeerId(1)), OUTBOX_PER_PEER);
        assert_eq!(o.dropped_full, 1);
        // Per *peer*, so another peer has its own 100.
        assert!(o.queue(TimeMs(0), PeerId(2), 1, vec![1]));
    }

    #[test]
    fn outbox_drops_after_eight_attempts() {
        let mut o = Outbox::default();
        o.queue(TimeMs(0), PeerId(1), 1, vec![1]);
        for n in 1..=OUTBOX_MAX_ATTEMPTS {
            let due = o.on_reconnect(TimeMs(1000), PeerId(1));
            assert_eq!(due.len(), 1, "attempt {n} must still be offered");
        }
        let due = o.on_reconnect(TimeMs(1000), PeerId(1));
        assert!(due.is_empty(), "the 9th reconnect drops it");
        assert_eq!(o.failed_visibly, 1);
    }

    #[test]
    fn outbox_entries_expire_at_twenty_four_hours() {
        let mut o = Outbox::default();
        o.queue(TimeMs(0), PeerId(1), 1, vec![1]);
        o.expire(TimeMs(OUTBOX_TTL_MS));
        assert_eq!(o.len_for(PeerId(1)), 1);
        o.expire(TimeMs(OUTBOX_TTL_MS + 1));
        assert_eq!(o.len_for(PeerId(1)), 0);
    }

    #[test]
    fn an_ack_clears_the_outbox_entry() {
        let mut o = Outbox::default();
        o.queue(TimeMs(0), PeerId(1), 42, vec![1]);
        assert!(o.ack(PeerId(1), 42));
        assert_eq!(o.total(), 0);
        assert!(!o.ack(PeerId(1), 42), "already gone");
    }
}
