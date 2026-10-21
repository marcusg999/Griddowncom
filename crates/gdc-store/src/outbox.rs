//! The author's own outbox: what I sent and what honestly became of it.
//!
//! # Two frames per message
//!
//! `gdc-wire` authenticates the cleartext flags and the kind, and deliberately
//! does not authenticate the hop counter. A relay can therefore decrement a
//! TTL but cannot set [`Flags::WAS_CARRIED`] — which is correct, because a
//! relay that could set flags could lie about them. So the author mints two
//! frames for one message: a `ChannelMsg` for live relay, and a `Courier` frame
//! with `WAS_CARRIED` set for the pocket. Both carry the same message id, so
//! duplicate suppression and reconciliation see one message, and a recipient
//! can tell from the flag that what it is reading travelled in somebody's
//! pocket and may be stale. The honest-state machine upstream depends on that
//! distinction being authenticated rather than asserted.
//!
//! # Retry
//!
//! Exponential backoff from five seconds to a ten-minute ceiling, eight
//! attempts, twelve-hour lifetime. The jitter is a quarter of the interval and
//! exists so that a cluster of devices that all lost the same link do not retry
//! in lockstep; it is not an anonymity measure and is not sold as one.
//!
//! # Direct messages
//!
//! A direct message is addressed to an ephemeral session key. There is no
//! account behind it and no mailbox to leave anything in. When the session is
//! gone the message is reported `ExpiredUndelivered { RecipientGone }`
//! immediately — the product claim is that the user is told the truth, and
//! "sent" would be a lie we are in a position to detect.

use crate::budget::{decide, BudgetDecision};
use crate::encounter::EncounterMeter;
use crate::error::OutboxFull;
use crate::limits::{
    MAX_OUTBOX_ATTEMPTS, MAX_OUTBOX_BYTES, MAX_OUTBOX_MSGS, OUTBOX_BACKOFF_BASE_MS,
    OUTBOX_BACKOFF_CAP_MS, OUTBOX_JITTER_FRACTION, OUTBOX_LIFETIME_MS,
};
use crate::state::{DeliveryState, StateChange, UndeliveredReason};
use crate::tags::ChannelId;
use crate::types::{Millis, PeerId, Rng, SourceClass};
use crate::Budget;
use crate::courier::Handover;
use gdc_wire::{Flags, Frame, Kind, MsgId};

/// Who a message is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    /// The primary case. Deliverable to anyone in the channel.
    Channel(ChannelId),
    /// Secondary and best effort. Bound to a session that may already be gone.
    Direct(ChannelId, PeerId),
}

impl Target {
    #[must_use]
    pub fn channel(self) -> ChannelId {
        match self {
            Target::Channel(c) | Target::Direct(c, _) => c,
        }
    }
}

/// The two authored frames for one message.
#[derive(Clone, Debug)]
pub struct Outgoing {
    /// For live relay.
    pub live: Frame,
    /// For carriage, with `WAS_CARRIED` set and `Kind::Courier`.
    pub carried: Frame,
}

impl Outgoing {
    /// Reject anything inconsistent before it is stored. These are the author's
    /// own frames, but the author is a different crate and may be wrong.
    fn check(&self) -> Result<(), OutboxFull> {
        let ok = self.live.hdr.msg_id == self.carried.hdr.msg_id
            && self.live.hdr.tag == self.carried.hdr.tag
            && self.carried.hdr.kind == Kind::Courier
            && self.carried.hdr.flags.contains(Flags::WAS_CARRIED)
            && self.live.hdr.kind == Kind::ChannelMsg;
        if ok {
            Ok(())
        } else {
            Err(OutboxFull::Duplicate)
        }
    }
}

/// One message the author is still accountable for.
#[derive(Clone, Debug)]
pub struct OutboxEntry {
    pub out: Outgoing,
    pub target: Target,
    pub minted: Millis,
    pub expires: Millis,
    pub state: DeliveryState,
    pub budget: Budget,
    pub attempts: u8,
    pub next_attempt: Millis,
    pub carriers: u8,
    pub decision: BudgetDecision,
    pub urgent: bool,
}

impl OutboxEntry {
    #[must_use]
    pub fn msg_id(&self) -> MsgId {
        self.out.live.hdr.msg_id
    }
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.out.live.wire_len() + self.out.carried.wire_len()
    }
}

/// Bounded sender outbox.
#[derive(Debug)]
pub struct Outbox {
    entries: Vec<OutboxEntry>,
    bytes: usize,
    queued_total: u64,
    rejected_total: u64,
}

impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Outbox {
    #[must_use]
    pub fn new() -> Self {
        Outbox {
            entries: Vec::with_capacity(16),
            bytes: 0,
            queued_total: 0,
            rejected_total: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    #[must_use]
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total
    }
    #[must_use]
    pub fn queued_total(&self) -> u64 {
        self.queued_total
    }
    pub fn iter(&self) -> impl Iterator<Item = &OutboxEntry> {
        self.entries.iter()
    }

    #[must_use]
    pub fn state_of(&self, id: MsgId) -> Option<DeliveryState> {
        self.entries.iter().find(|e| e.msg_id() == id).map(|e| e.state)
    }

    /// Queue a message the user just sent.
    ///
    /// The budget is decided here, once, from what the device has actually
    /// observed. `deadline_secs` lets urgent traffic solve for a nearer
    /// deadline, which is a defensible reason for more copies; a bare priority
    /// flag meaning "take more of the network" is not.
    pub fn queue(
        &mut self,
        now: Millis,
        out: Outgoing,
        target: Target,
        meter: &EncounterMeter,
        deadline_secs: u64,
        rng: &mut dyn Rng,
    ) -> Result<BudgetDecision, OutboxFull> {
        out.check()?;
        let id = out.live.hdr.msg_id;
        if self.entries.iter().any(|e| e.msg_id() == id) {
            self.rejected_total += 1;
            return Err(OutboxFull::Duplicate);
        }
        if self.entries.len() >= MAX_OUTBOX_MSGS {
            self.rejected_total += 1;
            return Err(OutboxFull::Messages);
        }
        let need = out.live.wire_len() + out.carried.wire_len();
        if self.bytes + need > MAX_OUTBOX_BYTES {
            self.rejected_total += 1;
            return Err(OutboxFull::Bytes);
        }
        let decision = decide(meter.estimate(now, target.channel()), deadline_secs);
        let urgent = out.live.hdr.flags.contains(Flags::URGENT);
        self.bytes += need;
        self.queued_total += 1;
        self.entries.push(OutboxEntry {
            out,
            target,
            minted: now,
            expires: now.plus(OUTBOX_LIFETIME_MS),
            state: DeliveryState::Queued {
                attempts: 0,
                next_attempt: now,
            },
            budget: Budget::new(decision.copies),
            attempts: 0,
            next_attempt: now,
            carriers: 0,
            decision,
            urgent,
        });
        let _ = rng;
        Ok(decision)
    }

    /// Re-run the budget policy for messages still waiting.
    ///
    /// A message queued in a crowd that has since dispersed should get the
    /// sparse budget rather than being stuck with the decision made at a moment
    /// that has passed. Only the author may do this, only upward, and only up
    /// to the ceiling on the monotone per-message total — so a top-up cannot
    /// buy more than the ceiling by instalments.
    pub fn reconsider(&mut self, now: Millis, meter: &EncounterMeter, deadline_secs: u64) -> u32 {
        let mut raised = 0;
        for e in &mut self.entries {
            if e.state.is_delivered() || e.state.is_terminal() {
                continue;
            }
            let d = decide(meter.estimate(now, e.target.channel()), deadline_secs);
            if d.copies > e.budget.minted_total() && e.budget.top_up(d.copies) > 0 {
                e.decision = d;
                raised += 1;
            }
        }
        raised
    }

    /// Frames to offer a peer we have just met, newest-urgent first.
    pub fn plan_handover(
        &mut self,
        now: Millis,
        to: SourceClass,
        max_frames: usize,
        max_bytes: usize,
        rng: &mut dyn Rng,
    ) -> Vec<Handover> {
        let mut order: Vec<usize> = (0..self.entries.len())
            .filter(|i| {
                let e = &self.entries[*i];
                !e.state.is_terminal()
                    && !e.state.is_delivered()
                    && e.next_attempt <= now
                    && e.attempts < MAX_OUTBOX_ATTEMPTS
            })
            .collect();
        // Urgent first, then oldest, then message id so the order is total and
        // reproducible rather than dependent on vector layout.
        order.sort_by_key(|i| {
            let e = &self.entries[*i];
            (!e.urgent, e.minted, e.msg_id().0)
        });

        let mut out = Vec::new();
        let mut bytes = 0usize;
        for i in order {
            if out.len() >= max_frames {
                break;
            }
            let need = self.entries[i].out.carried.wire_len();
            if bytes + need > max_bytes {
                continue;
            }
            let frame = self.entries[i].out.carried.clone();
            let split = self.entries[i].budget.split();
            bytes += need;
            self.note_attempt(i, now, rng);
            let _ = to;
            out.push(Handover {
                frame,
                budget: split,
            });
        }
        out
    }

    fn note_attempt(&mut self, i: usize, now: Millis, rng: &mut dyn Rng) {
        let e = &mut self.entries[i];
        e.attempts = e.attempts.saturating_add(1);
        let shift = u32::from(e.attempts.saturating_sub(1)).min(16);
        let base = OUTBOX_BACKOFF_BASE_MS
            .saturating_mul(1u64 << shift)
            .min(OUTBOX_BACKOFF_CAP_MS);
        let jitter = rng.below(base / OUTBOX_JITTER_FRACTION + 1);
        e.next_attempt = now.plus(base + jitter);
        let s = DeliveryState::Queued {
            attempts: e.attempts,
            next_attempt: e.next_attempt,
        };
        if matches!(e.state, DeliveryState::Queued { .. }) {
            e.state = s;
        }
    }

    /// A peer confirmed it took a copy. This is the only thing we are entitled
    /// to say when a frame leaves for a pocket.
    pub fn on_carried(&mut self, id: MsgId, now: Millis) -> Option<StateChange> {
        let e = self.entries.iter_mut().find(|e| e.msg_id() == id)?;
        e.carriers = e.carriers.saturating_add(1);
        let from = e.state;
        let to = DeliveryState::Carried {
            carriers: e.carriers,
            since: now,
        };
        // `advance` re-applies Carried on each new carrier so the count climbs,
        // but will not drag a delivered message backwards.
        if from.is_delivered() || from.is_terminal() {
            return None;
        }
        e.state = to;
        Some(StateChange {
            msg_id: id,
            from,
            to,
        })
    }

    /// An acknowledgement arrived from a channel member.
    ///
    /// The caller has already verified it under the channel key; this crate
    /// never trusts an unauthenticated receipt, because a forgeable "delivered"
    /// is worse than no indicator at all.
    pub fn on_channel_ack(&mut self, id: MsgId, now: Millis) -> Option<StateChange> {
        self.transition(
            id,
            DeliveryState::DeliveredToChannel { at: now, acks: 1 },
        )
    }

    pub fn on_read(&mut self, id: MsgId, now: Millis) -> Option<StateChange> {
        self.transition(
            id,
            DeliveryState::ReadBySomeone { at: now, readers: 1 },
        )
    }

    /// The session a direct message was addressed to is gone.
    ///
    /// Reported immediately as undelivered. There is nothing to wait for.
    pub fn on_peer_gone(&mut self, peer: PeerId, now: Millis) -> Vec<StateChange> {
        let ids: Vec<MsgId> = self
            .entries
            .iter()
            .filter(|e| matches!(e.target, Target::Direct(_, p) if p == peer))
            .filter(|e| !e.state.is_delivered() && !e.state.is_terminal())
            .map(OutboxEntry::msg_id)
            .collect();
        ids.into_iter()
            .filter_map(|id| {
                self.transition(
                    id,
                    DeliveryState::ExpiredUndelivered {
                        at: now,
                        reason: UndeliveredReason::RecipientGone,
                    },
                )
            })
            .collect()
    }

    fn transition(&mut self, id: MsgId, to: DeliveryState) -> Option<StateChange> {
        let e = self.entries.iter_mut().find(|e| e.msg_id() == id)?;
        let from = e.state;
        let mut s = from;
        if s.advance(to) {
            e.state = s;
            Some(StateChange {
                msg_id: id,
                from,
                to,
            })
        } else {
            None
        }
    }

    /// Age the outbox. Messages past their lifetime or out of attempts become
    /// `ExpiredUndelivered` rather than quietly disappearing.
    pub fn tick(&mut self, now: Millis) -> Vec<StateChange> {
        let mut changes = Vec::new();
        for e in &mut self.entries {
            if e.state.is_delivered() || e.state.is_terminal() {
                continue;
            }
            let out_of_time = e.expires <= now;
            let out_of_tries = e.attempts >= MAX_OUTBOX_ATTEMPTS && e.next_attempt <= now;
            if !out_of_time && !out_of_tries {
                continue;
            }
            let reason = if e.carriers > 0 {
                UndeliveredReason::CarryWindowClosed
            } else {
                UndeliveredReason::NoCarrierFound
            };
            let from = e.state;
            let to = DeliveryState::ExpiredUndelivered { at: now, reason };
            let mut s = from;
            if s.advance(to) {
                e.state = s;
                changes.push(StateChange {
                    msg_id: e.msg_id(),
                    from,
                    to,
                });
            }
        }
        changes
    }

    /// Remove terminal entries the UI has already been told about.
    ///
    /// Kept separate from `tick` so that the expired-undelivered state is
    /// always reported at least once before the row can be reclaimed. Silently
    /// dropping a message the user believes is in flight is the failure mode
    /// this whole module exists to prevent.
    pub fn reap(&mut self, now: Millis, grace_ms: u64) -> usize {
        let before = self.entries.len();
        let mut kept = Vec::with_capacity(before);
        let mut bytes = 0usize;
        for e in self.entries.drain(..) {
            let done_at = match e.state {
                DeliveryState::ExpiredUndelivered { at, .. }
                | DeliveryState::ReadBySomeone { at, .. } => Some(at),
                _ => None,
            };
            let drop = done_at.is_some_and(|at| now.since(at) >= grace_ms);
            if !drop {
                bytes += e.bytes();
                kept.push(e);
            }
        }
        self.entries = kept;
        self.bytes = bytes;
        before - self.entries.len()
    }

    pub fn wipe(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }
}
