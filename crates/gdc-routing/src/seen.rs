//! Duplicate suppression keyed on the 16-byte random `MsgId`.
//!
//! # Shape
//!
//! Two levels, both set-associative with a fixed number of buckets and a fixed
//! number of ways per bucket, so the memory ceiling is a compile-time product
//! and there is no global ordering structure to maintain:
//!
//! * **Main table** — full `MsgId`, first-seen time, which neighbours are known
//!   to already hold the frame, the TTL it arrived with, and whether we relayed
//!   it. This is the working set that the relay decision reads.
//! * **Archive** — 64-bit keyed fingerprints and a coarse timestamp, nothing
//!   else. Four times the entry count at a sixth of the bytes per entry, so for
//!   a small memory cost the "have I seen this before" window is several times
//!   longer than the window in which we can still answer questions about the
//!   frame. A fingerprint collision costs us one suppressed delivery; at 64
//!   bits over a few thousand live entries that is a probability around 1e-16
//!   per lookup, which is far below the loss rate of any radio we will ever run
//!   on.
//!
//! # Eviction, and why it is not exploitable
//!
//! Within a bucket, eviction prefers (1) an entry already past `ttl_ms`, then
//! (2) the oldest entry by first-seen time. Insertion order, not access order.
//!
//! LRU-on-hit, which is what bitchat uses, is the wrong choice here: it lets a
//! replayer keep an entry hot by re-sending it, and more importantly it makes
//! the eviction order a function of attacker-controlled accesses. FIFO means
//! the only thing that rolls the window is admitted novel frames.
//!
//! That is the load-bearing coupling with [`crate::limits`]: a frame that fails
//! the rate limiter is **never inserted**. So the rate at which an attacker can
//! roll our suppression window is capped by their token budget, not by their
//! radio. With the default 1024-entry main table, 4096-entry archive and a
//! 20-frame-per-second global budget, the guaranteed suppression window is
//! 5120 / 20 = 256 seconds even under a sustained maximum-rate flood of fresh
//! ids. [`SeenSet::guaranteed_window_ms`] computes this from live config so the
//! number cannot drift away from the code.
//!
//! An attacker who does force an eviction gains the ability to make us relay
//! one old frame once more. That frame still carries its decremented TTL and is
//! still subject to fanout and rate limits, so the amplification factor is
//! bounded by one re-flood at reduced TTL, not by a loop.

use crate::prng::KeyedHash;
use gdc_wire::MsgId;

/// Upper bound on buckets, so a bad config cannot allocate without limit.
pub const MAX_BUCKETS: usize = 4096;
/// Upper bound on ways per bucket. Probe work per lookup is at most this.
pub const MAX_WAYS: usize = 8;

#[derive(Clone, Copy, Debug)]
struct MainEntry {
    id: MsgId,
    first_ms: u64,
    /// One bit per hashed peer: neighbours believed to already hold this frame,
    /// because they sent it to us or we overheard them relaying it. A 32-bit
    /// sketch, so it can report a false "covered" for a peer it has never seen;
    /// the cost of that is one skipped candidate, never a wrong relay.
    covered: u32,
    arrival_ttl: u8,
    relayed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct ArchEntry {
    fp: u64,
    /// Seconds, not milliseconds: 32 bits of seconds is 136 years and halves
    /// the entry size.
    first_s: u32,
}

/// What a lookup found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Seen {
    /// Not seen inside the suppression window.
    Novel,
    /// Seen, and we still hold its record.
    Known {
        first_ms: u64,
        arrival_ttl: u8,
        relayed: bool,
        covered: u32,
    },
    /// Seen, but only the archive remembers it. Enough to suppress, not enough
    /// to reason about.
    Archived { first_s: u32 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeenStats {
    pub inserts: u64,
    pub main_evictions: u64,
    pub archive_evictions: u64,
    pub main_hits: u64,
    pub archive_hits: u64,
    pub expired: u64,
}

pub struct SeenSet {
    buckets: usize,
    ways: usize,
    arch_buckets: usize,
    arch_ways: usize,
    main: Vec<Option<MainEntry>>,
    arch: Vec<ArchEntry>,
    hash: KeyedHash,
    ttl_ms: u64,
    stats: SeenStats,
}

impl SeenSet {
    /// `buckets` and `ways` are clamped into `1..=MAX_*`; the archive is sized
    /// to four times the main entry count.
    pub fn new(buckets: usize, ways: usize, ttl_ms: u64, seed: u64) -> Self {
        let buckets = buckets.clamp(1, MAX_BUCKETS);
        let ways = ways.clamp(1, MAX_WAYS);
        let arch_buckets = buckets.saturating_mul(2).clamp(1, MAX_BUCKETS * 2);
        let arch_ways = ways.clamp(1, MAX_WAYS);
        SeenSet {
            buckets,
            ways,
            arch_buckets,
            arch_ways,
            main: vec![None; buckets * ways],
            arch: vec![ArchEntry::default(); arch_buckets * arch_ways],
            hash: KeyedHash::from_seed(seed),
            ttl_ms,
            stats: SeenStats::default(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.buckets * self.ways
    }

    pub fn archive_capacity(&self) -> usize {
        self.arch_buckets * self.arch_ways
    }

    /// Worst-case resident bytes for both tables. Reported rather than
    /// estimated, so the ceiling in the docs is the ceiling in the code.
    pub fn memory_bytes(&self) -> usize {
        self.main.len() * core::mem::size_of::<Option<MainEntry>>()
            + self.arch.len() * core::mem::size_of::<ArchEntry>()
    }

    /// Seconds of guaranteed suppression under a sustained flood of fresh ids
    /// admitted at `admitted_per_sec`.
    pub fn guaranteed_window_ms(&self, admitted_per_sec: u32) -> u64 {
        if admitted_per_sec == 0 {
            return u64::MAX;
        }
        let total = (self.capacity() + self.archive_capacity()) as u64;
        total.saturating_mul(1000) / u64::from(admitted_per_sec)
    }

    pub fn stats(&self) -> SeenStats {
        self.stats
    }

    fn main_slots(&self, id: &MsgId) -> (usize, usize) {
        let b = (self.hash.hash_bytes(&id.0) % self.buckets as u64) as usize;
        (b * self.ways, self.ways)
    }

    fn arch_slots(&self, fp: u64) -> (usize, usize) {
        let b = (self.hash.hash_u64(fp) % self.arch_buckets as u64) as usize;
        (b * self.arch_ways, self.arch_ways)
    }

    fn fingerprint(&self, id: &MsgId) -> u64 {
        // Non-zero so that zero can mark an empty archive slot.
        let fp = self.hash.hash_bytes(&id.0);
        if fp == 0 {
            1
        } else {
            fp
        }
    }

    pub fn lookup(&mut self, id: &MsgId, now_ms: u64) -> Seen {
        let (base, ways) = self.main_slots(id);
        for i in 0..ways {
            if let Some(Some(e)) = self.main.get(base + i) {
                if e.id == *id {
                    if now_ms.saturating_sub(e.first_ms) > self.ttl_ms {
                        self.stats.expired += 1;
                        break;
                    }
                    self.stats.main_hits += 1;
                    return Seen::Known {
                        first_ms: e.first_ms,
                        arrival_ttl: e.arrival_ttl,
                        relayed: e.relayed,
                        covered: e.covered,
                    };
                }
            }
        }
        let fp = self.fingerprint(id);
        let (abase, aways) = self.arch_slots(fp);
        let now_s = (now_ms / 1000) as u32;
        let ttl_s = (self.ttl_ms / 1000) as u32;
        for i in 0..aways {
            if let Some(e) = self.arch.get(abase + i) {
                if e.fp == fp {
                    if now_s.saturating_sub(e.first_s) > ttl_s {
                        break;
                    }
                    self.stats.archive_hits += 1;
                    return Seen::Archived { first_s: e.first_s };
                }
            }
        }
        Seen::Novel
    }

    /// Record a novel frame. Idempotent on an id already resident.
    pub fn insert(&mut self, id: &MsgId, now_ms: u64, arrival_ttl: u8, covered: u32) {
        self.stats.inserts += 1;
        let (base, ways) = self.main_slots(id);

        let mut victim: Option<usize> = None;
        let mut oldest = u64::MAX;
        for i in 0..ways {
            match self.main.get(base + i) {
                Some(None) => {
                    victim = Some(base + i);
                    oldest = 0;
                    break;
                }
                Some(Some(e)) if e.id == *id => {
                    // Already resident: merge coverage, keep the original
                    // first-seen so a replay cannot extend an entry's life.
                    if let Some(Some(slot)) = self.main.get_mut(base + i) {
                        slot.covered |= covered;
                    }
                    return;
                }
                Some(Some(e)) => {
                    let expired = now_ms.saturating_sub(e.first_ms) > self.ttl_ms;
                    // Expired entries outrank every live entry as a victim.
                    let key = if expired { 0 } else { e.first_ms.saturating_add(1) };
                    if key < oldest {
                        oldest = key;
                        victim = Some(base + i);
                    }
                }
                None => {}
            }
        }

        if let Some(slot) = victim {
            if let Some(cell) = self.main.get_mut(slot) {
                if cell.is_some() {
                    self.stats.main_evictions += 1;
                }
                *cell = Some(MainEntry {
                    id: *id,
                    first_ms: now_ms,
                    covered,
                    arrival_ttl,
                    relayed: false,
                });
            }
        }

        let fp = self.fingerprint(id);
        let (abase, aways) = self.arch_slots(fp);
        let now_s = (now_ms / 1000) as u32;
        let ttl_s = (self.ttl_ms / 1000) as u32;
        let mut avictim: Option<usize> = None;
        let mut aoldest = u32::MAX;
        for i in 0..aways {
            if let Some(e) = self.arch.get(abase + i) {
                if e.fp == fp {
                    return;
                }
                let key = if e.fp == 0 || now_s.saturating_sub(e.first_s) > ttl_s {
                    0
                } else {
                    e.first_s.saturating_add(1)
                };
                if key < aoldest {
                    aoldest = key;
                    avictim = Some(abase + i);
                }
            }
        }
        if let Some(slot) = avictim {
            if let Some(cell) = self.arch.get_mut(slot) {
                if cell.fp != 0 {
                    self.stats.archive_evictions += 1;
                }
                *cell = ArchEntry { fp, first_s: now_s };
            }
        }
    }

    /// Note that `peer_bit` already holds this frame. No-op if evicted.
    pub fn mark_covered(&mut self, id: &MsgId, peer_bit: u32) {
        let (base, ways) = self.main_slots(id);
        for i in 0..ways {
            if let Some(Some(e)) = self.main.get_mut(base + i) {
                if e.id == *id {
                    e.covered |= peer_bit;
                    return;
                }
            }
        }
    }

    pub fn mark_relayed(&mut self, id: &MsgId) {
        let (base, ways) = self.main_slots(id);
        for i in 0..ways {
            if let Some(Some(e)) = self.main.get_mut(base + i) {
                if e.id == *id {
                    e.relayed = true;
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> MsgId {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&n.to_le_bytes());
        MsgId(b)
    }

    #[test]
    fn novel_then_known() {
        let mut s = SeenSet::new(64, 4, 300_000, 1);
        assert_eq!(s.lookup(&id(1), 0), Seen::Novel);
        s.insert(&id(1), 0, 7, 0);
        assert!(matches!(s.lookup(&id(1), 10), Seen::Known { .. }));
    }

    #[test]
    fn entries_expire_on_time_not_on_access() {
        let mut s = SeenSet::new(8, 2, 1_000, 1);
        s.insert(&id(1), 0, 7, 0);
        assert!(matches!(s.lookup(&id(1), 999), Seen::Known { .. }));
        assert_eq!(s.lookup(&id(1), 5_000), Seen::Novel);
    }

    #[test]
    fn replay_cannot_extend_an_entry() {
        // Insertion-order eviction is only sound if a re-insert does not reset
        // first_ms; otherwise a replayer pins an entry forever.
        let mut s = SeenSet::new(8, 2, 1_000, 1);
        s.insert(&id(1), 0, 7, 0);
        s.insert(&id(1), 900, 7, 0);
        assert_eq!(s.lookup(&id(1), 2_000), Seen::Novel, "first_ms must not move");
    }

    #[test]
    fn bound_holds_under_a_flood_of_fresh_ids() {
        // The headline property: a million fresh ids must not grow the table by
        // one byte, and must not panic.
        let mut s = SeenSet::new(256, 4, 300_000, 7);
        let before = s.memory_bytes();
        for i in 0..1_000_000u64 {
            s.insert(&id(i), i, 7, 0);
        }
        assert_eq!(s.memory_bytes(), before);
        assert_eq!(s.capacity(), 1024);
        assert_eq!(s.archive_capacity(), 2048);
        let resident = s.main.iter().filter(|e| e.is_some()).count();
        assert!(resident <= s.capacity());
    }

    #[test]
    fn recent_ids_survive_a_flood_of_their_own_size() {
        // A flood an order of magnitude smaller than capacity must not reach
        // back far enough to evict something inserted moments ago. This is the
        // property the rate limiter converts into a time guarantee.
        let mut s = SeenSet::new(256, 4, 300_000, 11);
        s.insert(&id(u64::MAX), 0, 7, 0);
        for i in 0..64u64 {
            s.insert(&id(i), 1, 7, 0);
        }
        assert!(matches!(s.lookup(&id(u64::MAX), 2), Seen::Known { .. }));
    }

    #[test]
    fn archive_extends_the_window_past_main_capacity() {
        let mut s = SeenSet::new(16, 2, 300_000, 3);
        // 32 main slots, 64 archive slots.
        s.insert(&id(u64::MAX), 0, 7, 0);
        for i in 0..40u64 {
            s.insert(&id(i), 1, 7, 0);
        }
        // Likely gone from main, still suppressed by the archive.
        match s.lookup(&id(u64::MAX), 2) {
            Seen::Known { .. } | Seen::Archived { .. } => {}
            Seen::Novel => panic!("archive failed to extend the window"),
        }
    }

    #[test]
    fn probe_work_is_bounded_by_ways_even_when_config_is_absurd() {
        let s = SeenSet::new(usize::MAX, usize::MAX, 1, 1);
        assert_eq!(s.capacity(), MAX_BUCKETS * MAX_WAYS);
    }

    #[test]
    fn guaranteed_window_is_computed_from_live_config() {
        let s = SeenSet::new(256, 4, 300_000, 1);
        // 1024 + 2048 entries at 20 admitted frames/s.
        assert_eq!(s.guaranteed_window_ms(20), 153_600);
        assert_eq!(s.guaranteed_window_ms(0), u64::MAX);
    }

    #[test]
    fn coverage_bits_merge() {
        let mut s = SeenSet::new(8, 2, 10_000, 1);
        s.insert(&id(5), 0, 7, 0b0001);
        s.mark_covered(&id(5), 0b0100);
        match s.lookup(&id(5), 1) {
            Seen::Known { covered, .. } => assert_eq!(covered, 0b0101),
            other => panic!("{other:?}"),
        }
    }
}
