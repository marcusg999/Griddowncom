//! Rotating channel tags, and what an 8-byte truncation actually costs.
//!
//! A tag is `HMAC-SHA256(tag_key, "gdc/v1/tag" || epoch_be)` truncated to
//! 8 bytes. A relay compares an incoming tag against the tags of the channels
//! it holds. It learns one bit — "mine or not" — and nothing else: the tag is a
//! PRF output, so it names no channel, and it changes every epoch, so two
//! epochs of one channel's traffic cannot be linked by anyone without the tag
//! key. That is what replaces the cleartext sender/receiver pair that handed
//! Bridgefy's observers a social graph.
//!
//! # The epoch boundary
//!
//! A frame can be built at 10:59:59 and arrive at 11:00:01, and a frame carried
//! in a pocket can arrive an hour late. Clocks also disagree. So the matcher
//! holds three epochs at once — `e-1`, `e`, `e+1` — and a frame matching any of
//! them is a candidate. That costs 3x the table size and buys an hour of skew
//! and rollover tolerance in both directions.
//!
//! # Truncation collisions
//!
//! Eight bytes is 2^64. For a device holding `n` channels there are `3n` live
//! tags.
//!
//! * A random (or attacker-chosen, since the attacker cannot compute our tags)
//!   incoming tag hits one of them with probability `3n / 2^64`. At `n = 32`
//!   that is about `5 x 10^-18`.
//! * Two channels *we hold* collide in the same epoch with probability about
//!   `C(3n, 2) / 2^64`. At `n = 32` that is about `2 x 10^-16`.
//!
//! A collision must therefore cost nothing but work, and it does: a matching
//! tag selects a *candidate*, and the candidate is then asked to open the frame
//! under its own key. The AEAD refuses, and the frame moves to the next
//! candidate or is rejected with the one error this crate has. No state is
//! created, no receipt is emitted, and the error is byte-identical to a MAC
//! failure. `candidates` is capped at [`MAX_TAG_CANDIDATES`], so even a
//! deliberately engineered pile-up cannot turn one frame into unbounded work.
//! The cap is a liveness limit, not a security one: were three of our own
//! channels ever to collide in one epoch, the third would simply not be tried.

use std::collections::HashMap;

use gdc_wire::ChanTag;

use crate::channel::{ChannelId, ChannelKeys};
use crate::kdf::{mac, M_TAG};

/// How many colliding channels one tag may select.
///
/// Two is already unreachable in practice (see the module note); the constant
/// exists so that the work an incoming frame can cause is a stated number.
pub const MAX_TAG_CANDIDATES: usize = 2;

/// Tag epoch containing `unix_secs`.
pub fn epoch_of(unix_secs: u64) -> u64 {
    unix_secs / gdc_wire::TAG_EPOCH_SECS
}

/// The channel tag for `epoch` under `tag_key`.
pub fn tag_for_epoch(tag_key: &[u8; 32], epoch: u64) -> ChanTag {
    ChanTag(mac::<8>(tag_key, M_TAG, &epoch.to_be_bytes()))
}

/// Maps the tags of the channels a device holds, for three epochs at a time.
#[derive(Default, Debug)]
pub struct TagMatcher {
    epoch: u64,
    by_tag: HashMap<[u8; 8], Vec<(ChannelId, u64)>>,
}

impl TagMatcher {
    /// An empty matcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// The epoch this matcher was last refreshed for.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Rebuild the table for `epoch` and its two neighbours.
    pub fn refresh<'a>(&mut self, channels: impl Iterator<Item = &'a ChannelKeys>, epoch: u64) {
        self.by_tag.clear();
        self.epoch = epoch;
        for keys in channels {
            for e in [epoch.saturating_sub(1), epoch, epoch + 1] {
                if keys.expired(e) {
                    continue;
                }
                self.insert_raw(keys.tag_for(e), keys.id(), e);
            }
        }
    }

    /// Insert a tag directly.
    ///
    /// Public so that a test can engineer a truncation collision, which cannot
    /// be found by search at 2^64. Production code goes through
    /// [`TagMatcher::refresh`].
    pub fn insert_raw(&mut self, tag: ChanTag, id: ChannelId, epoch: u64) {
        let slot = self.by_tag.entry(tag.0).or_default();
        if slot.len() < MAX_TAG_CANDIDATES && !slot.contains(&(id, epoch)) {
            slot.push((id, epoch));
        }
    }

    /// Candidate `(channel, epoch)` pairs for `tag`, at most
    /// [`MAX_TAG_CANDIDATES`] of them.
    pub fn candidates(&self, tag: &ChanTag) -> &[(ChannelId, u64)] {
        self.by_tag.get(&tag.0).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Whether any channel this device holds matches `tag`.
    pub fn holds(&self, tag: &ChanTag) -> bool {
        self.by_tag.contains_key(&tag.0)
    }

    /// Drop the table.
    pub fn clear(&mut self) {
        self.by_tag.clear();
    }
}
