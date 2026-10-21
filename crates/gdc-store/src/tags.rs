//! Channel-first addressing across tag rotation.
//!
//! This is the hinge the whole crate turns on. Identity is ephemeral per
//! session, so stored mail cannot be addressed to a person who will still be
//! that person in an hour. It is addressed to a *channel*, named on the wire by
//! an eight-byte tag that the crypto layer derives as a MAC over the current
//! epoch under the channel key. On arrival, the envelope is deliverable to
//! anyone holding that key.
//!
//! The tag rotates hourly (`gdc_wire::TAG_EPOCH_SECS`) so that a passive
//! observer cannot link a channel's traffic across epochs. That creates the one
//! real problem in this module: a frame carried in a pocket for forty minutes
//! may cross a boundary, and the tag in its header is immutable — the courier
//! has no key and so *cannot* re-tag it, which is exactly the property we want.
//!
//! The resolution is that matching is a local operation on the receiving side,
//! where the key does live. A member derives tags for a window of epochs and
//! matches an arriving tag against the whole window:
//!
//! ```text
//!   epoch:   n-13 ... n-1   n   n+1
//!            └── carried ──┘  │   └─ clock skew tolerance
//!                            now
//! ```
//!
//! Sizing the window is a real cost decision, not a free parameter:
//!
//! * Back: `MAX_CARRY_MS / TAG_EPOCH_SECS` = 12 epochs, plus one for a frame
//!   minted a second before a boundary. Thirteen.
//! * Forward: one epoch, so a peer whose wall clock runs minutes fast near a
//!   boundary is still understood. More than one would widen the window a
//!   dishonest client could aim at for free.
//! * Cost: 15 tags x 8 bytes = 120 bytes per channel, 3.8 KiB at
//!   `MAX_CHANNELS`; and 15 MACs per channel per hour, which is 480 MACs an
//!   hour on a fully loaded device. Both are rounding errors. Widening the
//!   window to cover bitchat's 24 h carry would cost 25 tags, which is also
//!   affordable — the binding constraint on the carry window is the copy budget
//!   and storage, not the tag ring.
//!
//! Matching runs over the whole ring with no early exit and accumulates with
//! bitwise operations. Rule 8 of the findings file forbids oracles from timing,
//! and "how long did that device take to decide it was not interested" is a
//! membership oracle if the loop short-circuits.

use crate::limits::{MAX_CHANNELS, TAG_RING_BACK, TAG_RING_FWD, TAG_RING_LEN};
use crate::types::Millis;
use gdc_wire::{ChanTag, TAG_EPOCH_SECS};

/// A local handle for a joined channel. Never on the wire; the wire carries
/// only the rotating tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct ChannelId(pub u16);

/// The narrow slice of the crypto layer this crate needs.
///
/// `gdc-crypto` owns the derivation. The only thing asked of it is: given a
/// channel and an epoch number, produce that epoch's tag. Deriving a *past*
/// epoch's tag must be possible, which rules out a ratchet that cannot be
/// rewound; that constraint is in the report.
pub trait ChannelTags {
    /// Tag for `channel` in `epoch`, or `None` if we hold no key for it.
    fn tag_for_epoch(&self, channel: ChannelId, epoch: u64) -> Option<ChanTag>;

    /// Current epoch number, from the crypto layer's view of wall-clock time.
    ///
    /// Epoch numbers, rather than timestamps, are the only wall-clock quantity
    /// that crosses into this crate, and they cross through this one call.
    fn current_epoch(&self) -> u64;
}

/// The tags one channel is currently matchable under.
#[derive(Clone, Debug)]
struct TagRing {
    channel: ChannelId,
    base_epoch: u64,
    tags: [Option<ChanTag>; TAG_RING_LEN],
}

impl TagRing {
    fn rebuild(&mut self, now_epoch: u64, src: &dyn ChannelTags) {
        let base = now_epoch.saturating_sub(TAG_RING_BACK as u64);
        self.base_epoch = base;
        for (i, slot) in self.tags.iter_mut().enumerate() {
            *slot = src.tag_for_epoch(self.channel, base.saturating_add(i as u64));
        }
    }

    /// Constant-work match over the whole ring.
    fn matches(&self, tag: ChanTag) -> bool {
        let mut hit = 0u8;
        for slot in &self.tags {
            // A vacant slot must behave exactly like a non-matching one, so it
            // is compared against a value a tag can never equal rather than
            // skipped.
            let candidate = slot.unwrap_or(ChanTag([0xFF; 8]));
            let mut diff = 0u8;
            for k in 0..8 {
                diff |= candidate.0[k] ^ tag.0[k];
            }
            let eq = ((diff as u16).wrapping_sub(1) >> 8) as u8 & 1;
            let present = u8::from(slot.is_some());
            hit |= eq & present;
        }
        hit != 0
    }

    fn age_epochs(&self, tag: ChanTag, now_epoch: u64) -> Option<u64> {
        let mut found: Option<u64> = None;
        for (i, slot) in self.tags.iter().enumerate() {
            if let Some(t) = slot {
                if *t == tag {
                    found = Some(now_epoch.saturating_sub(self.base_epoch + i as u64));
                }
            }
        }
        found
    }
}

/// Every channel we hold a key for, with its matchable tag window.
///
/// Bounded at [`MAX_CHANNELS`] by construction: joining past the limit is
/// refused rather than growing the table.
#[derive(Clone, Debug, Default)]
pub struct TagDirectory {
    rings: Vec<TagRing>,
    epoch: u64,
    /// Epoch at which the rings were last rebuilt, so `refresh` is idempotent
    /// and cheap when called on every tick.
    built_epoch: Option<u64>,
}

impl TagDirectory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rings.is_empty()
    }

    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Join a channel. Returns `false` if the table is full.
    pub fn join(&mut self, channel: ChannelId, src: &dyn ChannelTags) -> bool {
        if self.rings.iter().any(|r| r.channel == channel) {
            return true;
        }
        if self.rings.len() >= MAX_CHANNELS {
            return false;
        }
        let mut ring = TagRing {
            channel,
            base_epoch: 0,
            tags: [None; TAG_RING_LEN],
        };
        let epoch = src.current_epoch();
        self.epoch = epoch;
        ring.rebuild(epoch, src);
        self.rings.push(ring);
        self.built_epoch = Some(epoch);
        true
    }

    pub fn leave(&mut self, channel: ChannelId) {
        self.rings.retain(|r| r.channel != channel);
    }

    /// Re-derive every ring if the epoch moved. Call on each tick; it does
    /// nothing until the hour turns.
    pub fn refresh(&mut self, src: &dyn ChannelTags) -> bool {
        let epoch = src.current_epoch();
        self.epoch = epoch;
        if self.built_epoch == Some(epoch) {
            return false;
        }
        for ring in &mut self.rings {
            ring.rebuild(epoch, src);
        }
        self.built_epoch = Some(epoch);
        true
    }

    /// Which channel, if any, an arriving tag is for.
    ///
    /// Scans every ring without early exit; see the module note on timing.
    #[must_use]
    pub fn match_tag(&self, tag: ChanTag) -> Option<ChannelId> {
        let mut found = None;
        for ring in &self.rings {
            if ring.matches(tag) {
                found = Some(ring.channel);
            }
        }
        found
    }

    /// How many epochs ago the tag was minted, if we can tell.
    ///
    /// Only a channel member can answer this, which is the point: a courier
    /// cannot learn the age of the mail it carries, and therefore cannot sort
    /// its bag by how urgent somebody else's business is.
    #[must_use]
    pub fn tag_age_epochs(&self, tag: ChanTag) -> Option<u64> {
        let mut found = None;
        for ring in &self.rings {
            if let Some(age) = ring.age_epochs(tag, self.epoch) {
                found = Some(age);
            }
        }
        found
    }

    /// The tag to mint new traffic under.
    #[must_use]
    pub fn current_tag(&self, channel: ChannelId) -> Option<ChanTag> {
        let ring = self.rings.iter().find(|r| r.channel == channel)?;
        let idx = TAG_RING_BACK as usize;
        ring.tags[idx]
    }

    /// Forget every tag. Called on panic wipe; nothing survives it.
    pub fn wipe(&mut self) {
        self.rings.clear();
        self.built_epoch = None;
    }
}

/// Epoch number for a monotonic offset from a known starting epoch.
///
/// Used only by the deterministic harness and by tests, which is why it takes
/// the starting epoch rather than consulting anything.
#[must_use]
pub fn epoch_at(start_epoch: u64, since_start: Millis) -> u64 {
    start_epoch.saturating_add(since_start.0 / (TAG_EPOCH_SECS * 1000))
}

/// Deterministic stand-in for the crypto layer's tag derivation.
///
/// Available outside tests so the harness and, later, `gdc-sim` can drive the
/// store without a crypto dependency. It is not a security construction and
/// says so.
#[derive(Clone, Debug)]
pub struct MockTags {
    pub keys: Vec<(ChannelId, u64)>,
    pub epoch: u64,
}

impl MockTags {
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        MockTags {
            keys: Vec::new(),
            epoch,
        }
    }

    pub fn with_key(mut self, channel: ChannelId, key: u64) -> Self {
        self.keys.push((channel, key));
        self
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }
}

impl ChannelTags for MockTags {
    fn tag_for_epoch(&self, channel: ChannelId, epoch: u64) -> Option<ChanTag> {
        let key = self.keys.iter().find(|(c, _)| *c == channel)?.1;
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&key.to_le_bytes());
        buf[8..].copy_from_slice(&epoch.to_le_bytes());
        let h = crate::types::keyed_hash64(key, &buf);
        Some(ChanTag(h.to_le_bytes()))
    }

    fn current_epoch(&self) -> u64 {
        self.epoch
    }
}
