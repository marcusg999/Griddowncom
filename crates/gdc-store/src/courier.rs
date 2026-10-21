//! Courier envelopes: other people's mail, carried in a pocket.
//!
//! An envelope is a sealed frame addressed to a rotating channel tag. The
//! courier holds the channel key for exactly as many of them as it is a member
//! of, which in the interesting case is none: it cannot read the mail, cannot
//! learn which channel the mail is for, and cannot learn how old the mail is,
//! because nothing in the cleartext header says so. What it can do is match the
//! tag against its own channels on the way in, and hand the envelope on.
//!
//! # Admission
//!
//! Every offered envelope passes three gates before it occupies a byte:
//! duplicate suppression, a per-source-class token bucket, and the fairness
//! rule below. The token bucket is the one that matters against a flood: a
//! single link can place [`ADMIT_BURST`] envelopes and then one per
//! [`ADMIT_REFILL_MS`], so filling a 512-envelope store from one source takes
//! over an hour of sustained contact rather than one burst.
//!
//! # Eviction fairness
//!
//! "Oldest first" is the obvious policy and it is wrong. A hostile peer that
//! floods envelopes makes everything else the oldest thing in the store, so
//! oldest-first hands the attacker the whole store for the price of being
//! loud. bitchat's "oldest-verified-evicted-first" is worse in one way still,
//! because it spends the reputation of verified peers first.
//!
//! The rule here is max-min fair, borrowed from fair queueing:
//!
//! * Occupancy is accounted per [`SourceClass`] — a six-bit salted hash of the
//!   peer that handed the envelope over.
//! * When the store is full, evict from the *fattest* class.
//! * An arriving envelope may only displace a class strictly fatter than its
//!   own would be after admission. If its own class is already the fattest, it
//!   is refused.
//!
//! The consequence is the property that matters: **a flood can only evict
//! itself.** Once the hostile class is the fattest, its own envelopes are the
//! eviction victims and honest classes are untouchable by it.
//!
//! Within the fattest class there is a second level, because an honest peer may
//! be relaying mail for several channels and one of them should not starve the
//! rest: the victim is the oldest envelope of whichever tag is most numerous in
//! that class. Tags are attacker-chosen and unverifiable, so this is a
//! tie-break inside a class and never a fairness class of its own — otherwise
//! minting ten thousand fake tags would buy ten thousand shares.
//!
//! # A deliberate omission
//!
//! An obvious optimisation is a "this message was delivered, stop carrying it"
//! hint, which bitchat effectively has via acknowledgement. We do not implement
//! it. A courier cannot verify such a hint, because verifying it needs the
//! channel key it deliberately does not hold, so an unauthenticated hint is a
//! censorship primitive: name the message ids you dislike and every courier in
//! the city drops them. Storage is reclaimed by expiry and by fair eviction,
//! neither of which an attacker can aim at a chosen message.

use crate::error::Refused;
use crate::limits::{
    ADMIT_BURST, ADMIT_REFILL_MS, COPY_BUDGET_MAX, DELIVERY_RETRY_MS, MAX_ATTEMPTED_PEERS,
    MAX_CARRY_MS, MAX_COURIER_BYTES, MAX_COURIER_ENVELOPES, SOURCE_CLASSES,
};
use crate::tags::{ChannelId, TagDirectory};
use crate::types::{Millis, SourceClass};
use crate::Budget;
use gdc_wire::{ChanTag, Frame, Kind, MsgId};

/// One carried envelope.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub frame: Frame,
    /// Local receipt time. There is no timestamp on the wire, so this is the
    /// only age a courier can know, and expiry is measured from it.
    pub received: Millis,
    pub expires: Millis,
    pub budget: Budget,
    pub source: SourceClass,
    attempted: [Option<SourceClass>; MAX_ATTEMPTED_PEERS],
    attempted_at: [Millis; MAX_ATTEMPTED_PEERS],
    attempted_next: usize,
    pub attempts: u16,
}

impl Envelope {
    #[must_use]
    pub fn msg_id(&self) -> MsgId {
        self.frame.hdr.msg_id
    }
    #[must_use]
    pub fn tag(&self) -> ChanTag {
        self.frame.hdr.tag
    }
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.frame.wire_len()
    }

    /// Whether this envelope may be offered to `peer` now.
    ///
    /// Throttled per peer, not per envelope. bitchat allows one attempt per
    /// envelope per ten minutes regardless of who is in front of it, which
    /// means a courier walking through a cluster for two minutes delivers one
    /// envelope. Per-peer throttling lets a courier empty its bag on arrival
    /// while still refusing to pester a peer that already declined.
    fn offerable_to(&self, now: Millis, peer: SourceClass) -> bool {
        for i in 0..MAX_ATTEMPTED_PEERS {
            if self.attempted[i] == Some(peer) {
                return now.since(self.attempted_at[i]) >= DELIVERY_RETRY_MS;
            }
        }
        true
    }

    fn record_attempt(&mut self, now: Millis, peer: SourceClass) {
        self.attempts = self.attempts.saturating_add(1);
        for i in 0..MAX_ATTEMPTED_PEERS {
            if self.attempted[i] == Some(peer) {
                self.attempted_at[i] = now;
                return;
            }
        }
        let i = self.attempted_next % MAX_ATTEMPTED_PEERS;
        self.attempted[i] = Some(peer);
        self.attempted_at[i] = now;
        self.attempted_next = i + 1;
    }
}

/// What happened to an offered envelope.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admitted {
    /// Stored for onward carriage. Not for us.
    Carried,
    /// For a channel we are in, and also stored so other members can get it.
    OursAndCarried(ChannelId),
    /// For a channel we are in, offered in the wait phase, so delivered to the
    /// app but not carried onward.
    OursOnly(ChannelId),
}

/// An envelope offered to a peer, with the budget that travels with it.
///
/// `budget` is `None` in the wait phase of spray-and-wait: the peer may deliver
/// it into a channel it belongs to, and may not carry it any further. That is
/// how the wait phase survives channel-first addressing — the courier cannot
/// tell a member from a stranger, so it offers to everyone and lets the
/// receiver's own key decide, which leaks nothing about who is in what.
#[derive(Clone, Debug)]
pub struct Handover {
    pub frame: Frame,
    pub budget: Option<Budget>,
}

#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    tokens: u32,
    last: Millis,
}

impl TokenBucket {
    fn refill(&mut self, now: Millis) {
        let steps = now.since(self.last) / ADMIT_REFILL_MS;
        if steps > 0 {
            self.tokens = self
                .tokens
                .saturating_add(steps.min(u64::from(ADMIT_BURST)) as u32)
                .min(ADMIT_BURST);
            self.last = self.last.plus(steps.saturating_mul(ADMIT_REFILL_MS));
        }
    }
    fn take(&mut self, now: Millis) -> bool {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// The bag of other people's mail.
#[derive(Clone, Debug)]
pub struct CourierStore {
    envelopes: Vec<Envelope>,
    class_bytes: [usize; SOURCE_CLASSES],
    class_count: [u32; SOURCE_CLASSES],
    buckets: [TokenBucket; SOURCE_CLASSES],
    bytes: usize,
    peak_bytes: usize,
    evictions: u64,
    expired: u64,
    admitted: u64,
    refused: u64,
}

impl Default for CourierStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CourierStore {
    #[must_use]
    pub fn new() -> Self {
        CourierStore {
            envelopes: Vec::with_capacity(32),
            class_bytes: [0; SOURCE_CLASSES],
            class_count: [0; SOURCE_CLASSES],
            buckets: [TokenBucket {
                tokens: ADMIT_BURST,
                last: Millis::ZERO,
            }; SOURCE_CLASSES],
            bytes: 0,
            peak_bytes: 0,
            evictions: 0,
            expired: 0,
            admitted: 0,
            refused: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.envelopes.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    #[must_use]
    pub fn peak_bytes(&self) -> usize {
        self.peak_bytes
    }
    #[must_use]
    pub fn evictions(&self) -> u64 {
        self.evictions
    }
    #[must_use]
    pub fn expired(&self) -> u64 {
        self.expired
    }
    #[must_use]
    pub fn admitted(&self) -> u64 {
        self.admitted
    }
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused
    }
    #[must_use]
    pub fn class_bytes(&self, c: SourceClass) -> usize {
        self.class_bytes[c.index()]
    }
    #[must_use]
    pub fn class_count(&self, c: SourceClass) -> u32 {
        self.class_count[c.index()]
    }
    pub fn iter(&self) -> impl Iterator<Item = &Envelope> {
        self.envelopes.iter()
    }
    #[must_use]
    pub fn contains(&self, id: MsgId) -> bool {
        self.envelopes.iter().any(|e| e.msg_id() == id)
    }

    /// Take an offered envelope.
    ///
    /// `dedup` is the caller's seen-log decision: the store does not own
    /// duplicate suppression because the outbox shares the same log.
    pub fn offer(
        &mut self,
        now: Millis,
        from: SourceClass,
        frame: Frame,
        budget: Option<Budget>,
        dir: &TagDirectory,
    ) -> Result<Admitted, Refused> {
        // Kind gate first: a courier carries sealed channel mail and sync
        // digests are not mail. Handshakes are never relayable at all.
        if !matches!(frame.hdr.kind, Kind::Courier | Kind::ChannelMsg) {
            self.refused += 1;
            return Err(Refused::NotCarryable);
        }
        if frame.hdr.ttl == 0 {
            self.refused += 1;
            return Err(Refused::Exhausted);
        }
        let need = frame.wire_len();
        if need > MAX_COURIER_BYTES {
            self.refused += 1;
            return Err(Refused::TooLarge);
        }

        let ours = dir.match_tag(frame.hdr.tag);

        // Wait phase: deliverable, not carryable. If it is not for us we have
        // no business holding it.
        let budget = match budget {
            Some(b) if b.remaining() > COPY_BUDGET_MAX => {
                self.refused += 1;
                return Err(Refused::BudgetTooLarge);
            }
            Some(b) => b,
            None => {
                return match ours {
                    Some(ch) => Ok(Admitted::OursOnly(ch)),
                    None => {
                        self.refused += 1;
                        Err(Refused::NotCarryable)
                    }
                }
            }
        };

        if !self.buckets[from.index()].take(now) {
            self.refused += 1;
            return Err(Refused::RateLimited);
        }

        self.make_room(now, from, need)?;

        let expires = now.plus(MAX_CARRY_MS);
        self.envelopes.push(Envelope {
            frame,
            received: now,
            expires,
            budget,
            source: from,
            attempted: [None; MAX_ATTEMPTED_PEERS],
            attempted_at: [Millis::ZERO; MAX_ATTEMPTED_PEERS],
            attempted_next: 0,
            attempts: 0,
        });
        self.bytes += need;
        self.peak_bytes = self.peak_bytes.max(self.bytes);
        self.class_bytes[from.index()] += need;
        self.class_count[from.index()] += 1;
        self.admitted += 1;
        Ok(match ours {
            Some(ch) => Admitted::OursAndCarried(ch),
            None => Admitted::Carried,
        })
    }

    /// Enforce the ceilings, evicting fairly, or refuse.
    fn make_room(&mut self, now: Millis, from: SourceClass, need: usize) -> Result<(), Refused> {
        let mut guard = 0usize;
        while self.bytes + need > MAX_COURIER_BYTES
            || self.envelopes.len() + 1 > MAX_COURIER_ENVELOPES
        {
            // Expired mail is nobody's share. Reclaim it before touching
            // anything live.
            if self.drop_expired(now) > 0 {
                continue;
            }
            let incoming_after = self.class_bytes[from.index()] + need;
            let (fat, fat_bytes) = self.fattest_class();
            if fat == from.index() || fat_bytes <= incoming_after {
                self.refused += 1;
                return Err(Refused::ClassAtShare);
            }
            if !self.evict_from_class(fat) {
                self.refused += 1;
                return Err(Refused::ClassAtShare);
            }
            guard += 1;
            if guard > MAX_COURIER_ENVELOPES {
                // Unreachable while the accounting is consistent; present so a
                // bookkeeping bug degrades into a refusal rather than a hang.
                self.refused += 1;
                return Err(Refused::ClassAtShare);
            }
        }
        Ok(())
    }

    fn fattest_class(&self) -> (usize, usize) {
        let mut best = (0usize, 0usize);
        for (i, b) in self.class_bytes.iter().enumerate() {
            if *b > best.1 {
                best = (i, *b);
            }
        }
        best
    }

    /// Evict one envelope from `class`: the oldest of whichever tag is most
    /// numerous in that class.
    fn evict_from_class(&mut self, class: usize) -> bool {
        let mut worst_tag: Option<(ChanTag, usize)> = None;
        for e in self.envelopes.iter().filter(|e| e.source.index() == class) {
            let n = self
                .envelopes
                .iter()
                .filter(|o| o.source.index() == class && o.tag() == e.tag())
                .count();
            if worst_tag.is_none_or(|(_, bn)| n > bn) {
                worst_tag = Some((e.tag(), n));
            }
        }
        let Some((tag, _)) = worst_tag else {
            return false;
        };
        let mut victim: Option<usize> = None;
        for (i, e) in self.envelopes.iter().enumerate() {
            if e.source.index() == class && e.tag() == tag {
                match victim {
                    Some(v) if self.envelopes[v].received <= e.received => {}
                    _ => victim = Some(i),
                }
            }
        }
        match victim {
            Some(i) => {
                self.remove_at(i);
                self.evictions += 1;
                true
            }
            None => false,
        }
    }

    fn remove_at(&mut self, i: usize) -> Envelope {
        let e = self.envelopes.swap_remove(i);
        let n = e.bytes();
        self.bytes -= n;
        self.class_bytes[e.source.index()] -= n;
        self.class_count[e.source.index()] -= 1;
        e
    }

    /// Drop everything past its carry window. Returns how many went.
    pub fn drop_expired(&mut self, now: Millis) -> usize {
        let mut dropped = 0;
        let mut i = 0;
        while i < self.envelopes.len() {
            if self.envelopes[i].expires <= now {
                self.remove_at(i);
                dropped += 1;
                self.expired += 1;
            } else {
                i += 1;
            }
        }
        dropped
    }

    /// Choose envelopes to offer to a peer, splitting budgets as they go.
    ///
    /// `max_frames` and `max_bytes` come from the transport, which knows what
    /// the link can carry in the contact window it expects.
    pub fn plan_handover(
        &mut self,
        now: Millis,
        to: SourceClass,
        max_frames: usize,
        max_bytes: usize,
    ) -> Vec<Handover> {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        // Oldest first: mail that has been carried longest is closest to
        // expiry and has the least remaining chance of being delivered by its
        // current holder.
        let mut order: Vec<usize> = (0..self.envelopes.len()).collect();
        order.sort_by_key(|i| (self.envelopes[*i].received, self.envelopes[*i].msg_id().0));
        for i in order {
            if out.len() >= max_frames {
                break;
            }
            let (frame, need) = {
                let e = &self.envelopes[i];
                if !e.offerable_to(now, to) {
                    continue;
                }
                (e.frame.clone(), e.bytes())
            };
            if bytes + need > max_bytes {
                continue;
            }
            let split = self.envelopes[i].budget.split();
            self.envelopes[i].record_attempt(now, to);
            bytes += need;
            out.push(Handover {
                frame,
                budget: split,
            });
        }
        out
    }

    /// Forget everything. Called on panic wipe; other people's mail must not
    /// outlive the session that agreed to carry it.
    pub fn wipe(&mut self) {
        self.envelopes.clear();
        self.class_bytes = [0; SOURCE_CLASSES];
        self.class_count = [0; SOURCE_CLASSES];
        self.bytes = 0;
    }
}
