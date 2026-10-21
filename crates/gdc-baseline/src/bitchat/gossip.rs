//! bitchat §6.3 Public History (Gossip Sync).
//!
//! Source: bitchat WHITEPAPER.md v2.0 (2026-07-06), §6.3, quoted inline.
//!
//! "Public broadcast messages are cached (1000 packets) and reconciled between
//! peers every ~15 s using compact GCS filters: each side advertises what it
//! holds, the other returns what is missing. Messages stay sync-able for
//! **6 hours** ... Fragments and file transfers keep a short 15-minute window."
//!
//! This is the mechanism that lets a bitchat device "walk between two
//! partitions" and serve history on arrival, so it is a direct competitor to
//! our backlog sync and must not be understated.

use std::collections::VecDeque;

use crate::proto::TimeMs;

/// §6.3: "cached (1000 packets)".
pub const CACHE_PACKETS: usize = 1000;

/// §6.3: "reconciled between peers every ~15 s".
pub const SYNC_INTERVAL_MS: u64 = 15_000;

/// §6.3: "Messages stay sync-able for **6 hours**".
pub const SYNC_WINDOW_MS: u64 = 6 * 60 * 60 * 1000;

/// §6.3: "Fragments and file transfers keep a short 15-minute window."
pub const FRAGMENT_WINDOW_MS: u64 = 15 * 60 * 1000;

/// False-positive rate of the Golomb-coded set, as `1/2^GCS_FP_BITS`.
///
/// ASSUMPTION: §6.3 says "compact GCS filters" and gives no false-positive
/// rate. 1-in-64 is the usual neighbourhood for a set-reconciliation filter.
/// The choice is close to neutral and the direction is stated so a critic can
/// check it: a lower rate makes the filter bigger, costing bitchat airtime but
/// missing fewer messages; a higher rate is cheaper but leaves gaps. The size
/// formula is exposed in [`gcs_filter_bytes`] so `gdc-sim` can substitute its
/// own figure without touching the protocol logic.
pub const GCS_FP_BITS: u64 = 6;

/// Modelled size of a GCS filter advertising `n` entries, in bytes.
///
/// A Golomb-coded set storing `n` elements with false-positive probability
/// `1/2^b` costs about `n * (b + 1/ln 2)` bits, i.e. `b + 1.4427` bits per
/// element, plus a short header. Integer-only so a run replays exactly:
/// `1/ln 2` is carried as the fraction 1443/1000.
pub fn gcs_filter_bytes(n: usize) -> usize {
    if n == 0 {
        return 2;
    }
    let bits = (n as u64) * (GCS_FP_BITS * 1000 + 1443) / 1000;
    // 2-byte count header, then the coded bits rounded up to a byte.
    2 + ((bits + 7) / 8) as usize
}

/// One cached public broadcast.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CachedPacket {
    /// The dedup identity, so a reconciliation can name what it holds without
    /// carrying the payload.
    pub digest: u64,
    pub at: TimeMs,
    /// Modelled on-air size, so the harness can charge for serving history.
    pub wire_len: usize,
    /// Fragments and file transfers have the shorter window.
    pub is_fragment: bool,
}

/// The 1000-packet broadcast cache and its reconciliation schedule.
#[derive(Default, Debug)]
pub struct GossipCache {
    packets: VecDeque<CachedPacket>,
    last_sync: Option<TimeMs>,
    pub served: u64,
    pub evicted: u64,
}

impl GossipCache {
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn insert(&mut self, p: CachedPacket) {
        if self.packets.iter().any(|q| q.digest == p.digest) {
            return;
        }
        self.packets.push_back(p);
        while self.packets.len() > CACHE_PACKETS {
            self.packets.pop_front();
            self.evicted += 1;
        }
    }

    /// Drop anything outside its window: 6 hours for broadcasts, 15 minutes for
    /// fragments and file transfers (§6.3).
    pub fn expire(&mut self, now: TimeMs) {
        self.packets.retain(|p| {
            let window = if p.is_fragment {
                FRAGMENT_WINDOW_MS
            } else {
                SYNC_WINDOW_MS
            };
            now.elapsed_since(p.at) <= window
        });
    }

    pub fn due_for_sync(&self, now: TimeMs) -> bool {
        match self.last_sync {
            None => true,
            Some(t) => now.elapsed_since(t) >= SYNC_INTERVAL_MS,
        }
    }

    pub fn mark_synced(&mut self, now: TimeMs) {
        self.last_sync = Some(now);
    }

    /// What this node would advertise: the digests inside the sync window, and
    /// the modelled filter size.
    pub fn advertise(&self, now: TimeMs) -> (Vec<u64>, usize) {
        let digests: Vec<u64> = self
            .packets
            .iter()
            .filter(|p| {
                let window = if p.is_fragment {
                    FRAGMENT_WINDOW_MS
                } else {
                    SYNC_WINDOW_MS
                };
                now.elapsed_since(p.at) <= window
            })
            .map(|p| p.digest)
            .collect();
        let bytes = gcs_filter_bytes(digests.len());
        (digests, bytes)
    }

    /// "each side advertises what it holds, the other returns what is missing."
    pub fn missing_from(&self, theirs: &[u64], now: TimeMs) -> Vec<CachedPacket> {
        self.packets
            .iter()
            .filter(|p| {
                let window = if p.is_fragment {
                    FRAGMENT_WINDOW_MS
                } else {
                    SYNC_WINDOW_MS
                };
                now.elapsed_since(p.at) <= window && !theirs.contains(&p.digest)
            })
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(d: u64, at: u64) -> CachedPacket {
        CachedPacket {
            digest: d,
            at: TimeMs(at),
            wire_len: 120,
            is_fragment: false,
        }
    }

    #[test]
    fn documented_constants() {
        assert_eq!(CACHE_PACKETS, 1000);
        assert_eq!(SYNC_INTERVAL_MS, 15_000);
        assert_eq!(SYNC_WINDOW_MS, 21_600_000, "6 hours");
        assert_eq!(FRAGMENT_WINDOW_MS, 900_000, "15 minutes");
    }

    #[test]
    fn cache_holds_a_thousand_packets_and_evicts_oldest() {
        let mut c = GossipCache::default();
        for i in 0..CACHE_PACKETS as u64 + 10 {
            c.insert(pkt(i, 0));
        }
        assert_eq!(c.len(), CACHE_PACKETS);
        assert_eq!(c.evicted, 10);
        let (d, _) = c.advertise(TimeMs(0));
        assert!(!d.contains(&0), "the first ten are gone");
        assert!(d.contains(&(CACHE_PACKETS as u64 + 9)));
    }

    #[test]
    fn duplicates_are_not_cached_twice() {
        let mut c = GossipCache::default();
        c.insert(pkt(1, 0));
        c.insert(pkt(1, 5));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn broadcasts_stay_syncable_for_six_hours() {
        let mut c = GossipCache::default();
        c.insert(pkt(1, 0));
        c.expire(TimeMs(SYNC_WINDOW_MS));
        assert_eq!(c.len(), 1, "still inside 6 h");
        c.expire(TimeMs(SYNC_WINDOW_MS + 1));
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn fragments_keep_only_fifteen_minutes() {
        let mut c = GossipCache::default();
        let mut f = pkt(2, 0);
        f.is_fragment = true;
        c.insert(f);
        c.expire(TimeMs(FRAGMENT_WINDOW_MS));
        assert_eq!(c.len(), 1);
        c.expire(TimeMs(FRAGMENT_WINDOW_MS + 1));
        assert_eq!(c.len(), 0, "a fragment is not kept for 6 h");
    }

    #[test]
    fn reconciliation_is_due_every_fifteen_seconds() {
        let mut c = GossipCache::default();
        assert!(c.due_for_sync(TimeMs(0)), "the first sync is immediate");
        c.mark_synced(TimeMs(0));
        assert!(!c.due_for_sync(TimeMs(SYNC_INTERVAL_MS - 1)));
        assert!(c.due_for_sync(TimeMs(SYNC_INTERVAL_MS)));
    }

    #[test]
    fn reconciliation_returns_only_what_the_peer_lacks() {
        let mut c = GossipCache::default();
        for i in 1..=5u64 {
            c.insert(pkt(i, 0));
        }
        let missing = c.missing_from(&[1, 2, 3], TimeMs(0));
        assert_eq!(missing.len(), 2);
        assert!(missing.iter().all(|p| p.digest == 4 || p.digest == 5));
        assert!(c.missing_from(&[1, 2, 3, 4, 5], TimeMs(0)).is_empty());
    }

    #[test]
    fn gcs_filter_is_compact_and_grows_linearly() {
        // ~7.44 bits per entry at a 1-in-64 false-positive rate.
        assert_eq!(gcs_filter_bytes(0), 2);
        let one_k = gcs_filter_bytes(1000);
        assert!(
            (900..=1000).contains(&one_k),
            "1000 digests should cost about 930 bytes, got {one_k}"
        );
        assert!(gcs_filter_bytes(2000) > one_k);
        // Far cheaper than sending the digests themselves (8 bytes each).
        assert!(one_k < 1000 * 8);
    }
}
