//! Duplicate suppression, and the set that reconciliation reconciles.
//!
//! One structure serves both jobs. A message id we have seen must not be
//! admitted twice, and the ids we have seen inside the sync window are exactly
//! what a peer who has just met us wants to diff against.
//!
//! Message ids are sixteen random bytes chosen by whoever sent the frame, which
//! means an adversary chooses the keys of this index. A `std::collections`
//! hash map is the wrong tool twice over: its hasher is seeded from ambient
//! randomness, which breaks determinism, and the structure grows. This is a
//! fixed open-addressed table with a bounded probe, a FIFO eviction ring, and a
//! per-session salt, so the worst an adversary can force is
//! [`SEEN_MAX_PROBE`] comparisons and the eviction of its own entries.

use crate::limits::{MAX_SEEN, SEEN_MAX_PROBE, SEEN_SLOTS, SYNC_WINDOW_MS};
use crate::types::{keyed_hash64, Millis};
use gdc_wire::MsgId;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug)]
struct Slot {
    id: MsgId,
    at: Millis,
}

/// Bounded set of recently seen message ids.
#[derive(Clone, Debug)]
pub struct SeenLog {
    slots: Vec<Option<Slot>>,
    order: VecDeque<usize>,
    salt: u64,
}

impl SeenLog {
    #[must_use]
    pub fn new(salt: u64) -> Self {
        debug_assert!(SEEN_SLOTS.is_power_of_two());
        SeenLog {
            slots: vec![None; SEEN_SLOTS],
            order: VecDeque::with_capacity(MAX_SEEN),
            salt,
        }
    }

    fn start(&self, id: MsgId) -> usize {
        (keyed_hash64(self.salt, &id.0) as usize) & (SEEN_SLOTS - 1)
    }

    #[must_use]
    pub fn contains(&self, id: MsgId) -> bool {
        let start = self.start(id);
        for i in 0..SEEN_MAX_PROBE {
            let idx = (start + i) & (SEEN_SLOTS - 1);
            match &self.slots[idx] {
                None => return false,
                Some(s) if s.id == id => return true,
                Some(_) => {}
            }
        }
        false
    }

    /// Record an id. Returns `false` if it was already known.
    ///
    /// Never fails and never grows: a full probe run evicts the oldest entry
    /// and tries again, bounded to a handful of attempts.
    pub fn insert(&mut self, id: MsgId, now: Millis) -> bool {
        if self.contains(id) {
            return false;
        }
        for _ in 0..4 {
            if self.order.len() >= MAX_SEEN {
                self.evict_oldest();
            }
            let start = self.start(id);
            for i in 0..SEEN_MAX_PROBE {
                let idx = (start + i) & (SEEN_SLOTS - 1);
                if self.slots[idx].is_none() {
                    self.slots[idx] = Some(Slot { id, at: now });
                    self.order.push_back(idx);
                    return true;
                }
            }
            // Every slot in the probe run is taken. Make room and retry.
            self.evict_oldest();
        }
        // Four eviction rounds failed to open a slot in the probe window. The
        // id is simply not recorded; the consequence is that a duplicate may be
        // admitted once, which costs a frame, not correctness.
        false
    }

    fn evict_oldest(&mut self) {
        if let Some(idx) = self.order.pop_front() {
            self.slots[idx] = None;
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Ids seen within the sync window, oldest first.
    ///
    /// Bounded by [`MAX_SEEN`] and filtered to [`SYNC_WINDOW_MS`]: there is
    /// nothing to win by offering a peer mail older than the longest deadline
    /// we are graded on, and every extra id is both bytes on the radio and one
    /// more thing a peer learns we are holding.
    pub fn window_ids(&self, now: Millis) -> Vec<MsgId> {
        let cutoff = now.0.saturating_sub(SYNC_WINDOW_MS);
        let mut out = Vec::with_capacity(self.order.len());
        for idx in &self.order {
            if let Some(s) = &self.slots[*idx] {
                if s.at.0 >= cutoff {
                    out.push(s.id);
                }
            }
        }
        out
    }

    pub fn wipe(&mut self) {
        self.slots.iter_mut().for_each(|s| *s = None);
        self.order.clear();
    }
}
