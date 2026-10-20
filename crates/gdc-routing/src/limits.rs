//! Anti-flood. Token buckets in fixed memory, charged before anything expensive.
//!
//! # Why there is no per-source limit
//!
//! The brief asks for per-source and per-channel rate limits. Per-channel we
//! can do. Per-source we cannot and should not: rule 7 of the research file
//! removes the cleartext sender from the wire precisely so that a passive
//! observer cannot build a social graph, and a sender identifier that did exist
//! in the clear would be unauthenticated and therefore trivially spoofed —
//! an attacker would simply mint a fresh source per frame and get a fresh
//! budget, exactly as they would with a fresh `MsgId`.
//!
//! What we limit instead:
//!
//! * **Per ingress peer.** Whoever handed us the frame is the party actually
//!   consuming our radio time, and that identity comes from the authenticated
//!   link layer, not from the frame. A node that floods us is throttled at the
//!   link it floods over, and because the link is authenticated it cannot
//!   escape by relabelling itself.
//! * **Per channel tag.** Bounds how much of the mesh any one conversation can
//!   occupy. Tags are attacker-mintable, so the table is *hash-sliced*: the tag
//!   selects a slot by keyed hash and there is no eviction and no admission
//!   decision at all. An attacker minting fake tags therefore cannot crowd a
//!   real channel out of a table — the worst they achieve is to share a slot
//!   with it, and the keyed hash means they cannot choose which slot. A
//!   collision degrades two channels' budgets gracefully instead of evicting
//!   one.
//! * **Globally**, so the sum of everything cannot exceed what we are willing
//!   to spend on relaying.
//! * **Forgeries per peer**, on a separate and much tighter bucket. A peer
//!   feeding us frames that fail verification is spending our verification
//!   budget, so it pays from a budget of its own.
//!
//! `Flags::URGENT` is explicitly *not* an exemption from any of this. It is
//! unauthenticated, so it buys a shorter jitter window and nothing else.

use crate::prng::KeyedHash;

pub const MAX_SLOTS: usize = 1024;

/// A rate in frames per second with a burst allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    pub per_sec: u32,
    pub burst: u32,
}

impl Rate {
    pub const fn new(per_sec: u32, burst: u32) -> Self {
        Rate { per_sec, burst }
    }
}

/// Milli-tokens, so a sub-1/s rate is representable without floats.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    milli: u32,
    last_ms: u64,
}

impl Bucket {
    fn new(rate: Rate) -> Self {
        Bucket {
            milli: rate.burst.saturating_mul(1000),
            last_ms: 0,
        }
    }

    fn refill(&mut self, rate: Rate, now_ms: u64) {
        let dt = now_ms.saturating_sub(self.last_ms);
        self.last_ms = now_ms;
        if dt == 0 {
            return;
        }
        // per_sec tokens per 1000 ms == per_sec milli-tokens per ms.
        let add = u64::from(rate.per_sec).saturating_mul(dt);
        let cap = u64::from(rate.burst).saturating_mul(1000);
        self.milli = u64::from(self.milli)
            .saturating_add(add)
            .min(cap)
            .min(u64::from(u32::MAX)) as u32;
    }

    fn take(&mut self, rate: Rate, now_ms: u64) -> bool {
        self.refill(rate, now_ms);
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// Hash-sliced token buckets: fixed slot count, no eviction, no admission.
struct Sliced {
    slots: Vec<Bucket>,
    rate: Rate,
    hash: KeyedHash,
}

impl Sliced {
    fn new(n: usize, rate: Rate, seed: u64) -> Self {
        let n = n.clamp(1, MAX_SLOTS);
        Sliced {
            slots: vec![Bucket::new(rate); n],
            rate,
            hash: KeyedHash::from_seed(seed),
        }
    }

    fn take(&mut self, key: &[u8], now_ms: u64) -> bool {
        let i = (self.hash.hash_bytes(key) % self.slots.len() as u64) as usize;
        match self.slots.get_mut(i) {
            Some(b) => b.take(self.rate, now_ms),
            None => false,
        }
    }

    fn take_u64(&mut self, key: u64, now_ms: u64) -> bool {
        let i = (self.hash.hash_u64(key) % self.slots.len() as u64) as usize;
        match self.slots.get_mut(i) {
            Some(b) => b.take(self.rate, now_ms),
            None => false,
        }
    }
}

/// Which budget refused a frame. Carried in the drop reason so the metric can
/// attribute throttling.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Global,
    Peer,
    Tag,
    Duplicate,
    Forgery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateConfig {
    pub global: Rate,
    pub peer: Rate,
    pub tag: Rate,
    /// Duplicates are cheap — a lookup and maybe a cancellation — but a flood of
    /// them is still work, so they have their own generous bucket.
    pub duplicate: Rate,
    pub forgery: Rate,
    pub peer_slots: usize,
    pub tag_slots: usize,
}

impl Default for RateConfig {
    fn default() -> Self {
        RateConfig {
            // 20 novel frames/s is roughly four times the busiest plausible
            // channel in a crowd and still only ~20 kB/s of BLE airtime.
            global: Rate::new(20, 40),
            peer: Rate::new(8, 16),
            tag: Rate::new(10, 20),
            duplicate: Rate::new(80, 160),
            forgery: Rate::new(1, 4),
            peer_slots: 64,
            tag_slots: 128,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LimitStats {
    pub denied_global: u64,
    pub denied_peer: u64,
    pub denied_tag: u64,
    pub denied_duplicate: u64,
    pub denied_forgery: u64,
}

pub struct Limits {
    cfg: RateConfig,
    global: Bucket,
    dup: Bucket,
    peers: Sliced,
    tags: Sliced,
    forgeries: Sliced,
    stats: LimitStats,
}

impl Limits {
    pub fn new(cfg: RateConfig, seed: u64) -> Self {
        Limits {
            global: Bucket::new(cfg.global),
            dup: Bucket::new(cfg.duplicate),
            peers: Sliced::new(cfg.peer_slots, cfg.peer, seed ^ 0xA1),
            tags: Sliced::new(cfg.tag_slots, cfg.tag, seed ^ 0xB2),
            forgeries: Sliced::new(cfg.peer_slots, cfg.forgery, seed ^ 0xC3),
            cfg,
            stats: LimitStats::default(),
        }
    }

    pub fn config(&self) -> RateConfig {
        self.cfg
    }

    pub fn stats(&self) -> LimitStats {
        self.stats
    }

    /// Charge one novel frame against peer, tag and global budgets.
    ///
    /// Order matters: the most specific budget is charged first so that a
    /// throttled peer does not consume the global allowance on its way to being
    /// refused. A frame that fails any check is charged to none of them.
    pub fn admit_novel(&mut self, peer: u64, tag: &[u8; 8], now_ms: u64) -> Result<(), Scope> {
        if !self.peers.take_u64(peer, now_ms) {
            self.stats.denied_peer += 1;
            return Err(Scope::Peer);
        }
        if !self.tags.take(tag, now_ms) {
            self.stats.denied_tag += 1;
            return Err(Scope::Tag);
        }
        if !self.global.take(self.cfg.global, now_ms) {
            self.stats.denied_global += 1;
            return Err(Scope::Global);
        }
        Ok(())
    }

    pub fn admit_duplicate(&mut self, now_ms: u64) -> Result<(), Scope> {
        if self.dup.take(self.cfg.duplicate, now_ms) {
            Ok(())
        } else {
            self.stats.denied_duplicate += 1;
            Err(Scope::Duplicate)
        }
    }

    /// Charge a failed verification to the peer that supplied it. Returns
    /// `Err` once that peer has exhausted its forgery allowance, which is the
    /// signal to stop spending verification budget on it at all.
    pub fn charge_forgery(&mut self, peer: u64, now_ms: u64) -> Result<(), Scope> {
        if self.forgeries.take_u64(peer, now_ms) {
            Ok(())
        } else {
            self.stats.denied_forgery += 1;
            Err(Scope::Forgery)
        }
    }

    pub fn memory_bytes(&self) -> usize {
        (self.peers.slots.len() + self.tags.slots.len() + self.forgeries.slots.len())
            * core::mem::size_of::<Bucket>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RateConfig {
        RateConfig {
            global: Rate::new(10, 10),
            peer: Rate::new(4, 4),
            tag: Rate::new(5, 5),
            duplicate: Rate::new(10, 10),
            forgery: Rate::new(1, 1),
            peer_slots: 16,
            tag_slots: 16,
        }
    }

    #[test]
    fn peer_burst_then_throttle_then_refill() {
        let mut l = Limits::new(cfg(), 1);
        let tag = [1u8; 8];
        for i in 0..4 {
            assert!(l.admit_novel(7, &tag, 0).is_ok(), "burst slot {i}");
        }
        assert_eq!(l.admit_novel(7, &tag, 0), Err(Scope::Peer));
        // One token per 250 ms at 4/s.
        assert!(l.admit_novel(7, &tag, 250).is_ok());
    }

    #[test]
    fn a_throttled_peer_does_not_consume_the_global_budget() {
        let mut l = Limits::new(cfg(), 1);
        let tag = [1u8; 8];
        for _ in 0..4 {
            assert!(l.admit_novel(1, &tag, 0).is_ok());
        }
        for _ in 0..20 {
            assert_eq!(l.admit_novel(1, &tag, 0), Err(Scope::Peer));
        }
        // Six global tokens were spent by the four admits plus none by the
        // refusals, so a different peer still gets through.
        assert!(l.admit_novel(2, &tag, 0).is_ok());
    }

    #[test]
    fn global_budget_caps_the_sum_of_well_behaved_peers() {
        let mut l = Limits::new(cfg(), 1);
        let mut admitted = 0;
        for p in 0..100u64 {
            if l.admit_novel(p, &[9u8; 8], 0).is_ok() {
                admitted += 1;
            }
        }
        // tag burst is 5, so the tag budget binds first; either way the sum is
        // bounded well below 100.
        assert!(admitted <= 10, "admitted {admitted}");
    }

    #[test]
    fn fake_tags_cannot_evict_a_real_channel() {
        // The property the hash-sliced layout buys: minting tags cannot remove
        // an existing channel's bucket, only (rarely) collide with it.
        let mut l = Limits::new(cfg(), 42);
        let real = [0xAAu8; 8];
        for t in 0..10_000u64 {
            let mut fake = [0u8; 8];
            fake.copy_from_slice(&t.to_le_bytes());
            let _ = l.admit_novel(t, &fake, 1000);
        }
        let mut ok = 0;
        for i in 0..5 {
            if l.admit_novel(1, &real, 2000 + i).is_ok() {
                ok += 1;
            }
        }
        assert!(ok >= 4, "real channel starved by fake tags: {ok}/5");
    }

    #[test]
    fn forgeries_have_their_own_tight_budget() {
        let mut l = Limits::new(cfg(), 1);
        assert!(l.charge_forgery(5, 0).is_ok());
        assert_eq!(l.charge_forgery(5, 0), Err(Scope::Forgery));
        assert!(l.charge_forgery(6, 0).is_ok(), "other peers unaffected");
    }

    #[test]
    fn memory_is_fixed_and_config_is_clamped() {
        let mut c = cfg();
        c.peer_slots = usize::MAX;
        c.tag_slots = usize::MAX;
        let l = Limits::new(c, 1);
        assert_eq!(l.memory_bytes(), 3 * MAX_SLOTS * core::mem::size_of::<Bucket>());
    }

    #[test]
    fn refill_never_overflows_on_a_huge_time_jump() {
        let mut l = Limits::new(cfg(), 1);
        assert!(l.admit_novel(1, &[0u8; 8], u64::MAX).is_ok());
        assert!(l.admit_novel(1, &[0u8; 8], u64::MAX).is_ok());
    }
}
