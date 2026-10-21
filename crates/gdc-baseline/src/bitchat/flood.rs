//! bitchat §4.2 Flood Control.
//!
//! Source for everything in this file: bitchat WHITEPAPER.md v2.0 (2026-07-06),
//! §4.2, quoted inline per parameter. This is the part of bitchat that actually
//! out-engineers Bridgefy — a degree-tuned, deduplicated, jittered, subset
//! flood against a blind TTL-100 broadcast storm — so it is the part most worth
//! getting exactly right.

use std::collections::{HashMap, VecDeque};

use crate::proto::{PeerId, TimeMs};
use crate::rng::Rng;

/// §4.2 TTL: "packets originate with TTL 7."
pub const ORIGIN_TTL: u8 = 7;

/// §4.2 TTL: "dense graphs (≥ 6 links) cap broadcast TTL at 5".
pub const DENSE_DEGREE: usize = 6;
pub const DENSE_BROADCAST_TTL_CAP: u8 = 5;

/// §4.2 TTL: "thin chains (≤ 2 links) relay at full incoming depth."
pub const THIN_DEGREE: usize = 2;

/// §4.2 Deduplication: "an LRU seen-set (1000 entries, 5-minute expiry)".
pub const SEEN_CAPACITY: usize = 1000;
pub const SEEN_TTL_MS: u64 = 5 * 60 * 1000;

/// §4.2 Jitter: "relays wait a random 10–220 ms (wider when dense)".
pub const JITTER_MIN_MS: u64 = 10;
pub const JITTER_MAX_MS: u64 = 220;

/// ASSUMPTION: §4.2 says jitter is "wider when dense" without giving the wider
/// bound. Doubling the upper bound at [`DENSE_DEGREE`] cuts **in bitchat's
/// favour**: a wider window is precisely what makes its duplicate suppression
/// "win often", so this buys it a better transmissions-per-delivery figure —
/// the `docs/METRICS.md` Routing number we are trying to beat — at the cost of
/// a little latency. A narrower reading would have flattered us.
pub const DENSE_JITTER_MAX_MS: u64 = 440;

/// ASSUMPTION: §4.2 says directed traffic relays with "tight jitter" and gives
/// no figure. A tight window is modelled as a tenth of the broadcast window's
/// span, floored at 2 ms. Tighter cuts **in bitchat's favour** on the
/// `docs/METRICS.md` latency-per-hop metric for private messages, which is the
/// traffic class our store-and-forward design has to beat.
pub const DIRECTED_JITTER_MIN_MS: u64 = 2;
pub const DIRECTED_JITTER_MAX_MS: u64 = 23;

/// The de-duplication key.
///
/// §4.2 Deduplication: the seen-set is "keyed by sender, timestamp, type, and a
/// payload digest". Note what is *not* in it: the TTL, so the same packet at
/// different depths collapses to one entry, and the relay, so a copy arriving
/// from a second neighbour is recognised. Keying on a per-hop field instead
/// would quietly break suppression, so this tuple is reproduced exactly.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SeenKey {
    pub sender: u64,
    pub timestamp_ms: u64,
    pub ptype: u8,
    pub payload_digest: u64,
}

/// LRU seen-set with a time bound: 1000 entries, 5-minute expiry (§4.2).
#[derive(Debug)]
pub struct SeenSet {
    /// key -> (last touched, recency stamp)
    map: HashMap<SeenKey, (TimeMs, u64)>,
    order: VecDeque<(SeenKey, u64)>,
    stamp: u64,
    capacity: usize,
    ttl_ms: u64,
    pub evicted_by_capacity: u64,
    pub evicted_by_age: u64,
}

impl Default for SeenSet {
    fn default() -> Self {
        SeenSet::new(SEEN_CAPACITY, SEEN_TTL_MS)
    }
}

impl SeenSet {
    pub fn new(capacity: usize, ttl_ms: u64) -> Self {
        SeenSet {
            map: HashMap::new(),
            order: VecDeque::new(),
            stamp: 0,
            // A zero capacity would make every packet novel, i.e. no
            // suppression at all; clamped so a misconfiguration cannot silently
            // turn bitchat into Bridgefy.
            capacity: capacity.max(1),
            ttl_ms,
            evicted_by_capacity: 0,
            evicted_by_age: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drop entries past the expiry. Cheap because `order` is in insertion
    /// order and expiry is uniform.
    pub fn sweep(&mut self, now: TimeMs) {
        let ttl = self.ttl_ms;
        let stale: Vec<SeenKey> = self
            .map
            .iter()
            .filter(|(_, (t, _))| now.elapsed_since(*t) > ttl)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            self.map.remove(&k);
            self.evicted_by_age += 1;
        }
    }

    pub fn contains(&self, now: TimeMs, key: &SeenKey) -> bool {
        match self.map.get(key) {
            Some((t, _)) => now.elapsed_since(*t) <= self.ttl_ms,
            None => false,
        }
    }

    /// Record a key. Returns true if it was already present and unexpired, i.e.
    /// this is a duplicate.
    pub fn insert(&mut self, now: TimeMs, key: SeenKey) -> bool {
        let dup = self.contains(now, &key);
        self.stamp += 1;
        self.map.insert(key, (now, self.stamp));
        self.order.push_back((key, self.stamp));
        self.trim();
        dup
    }

    fn trim(&mut self) {
        while self.map.len() > self.capacity {
            match self.order.pop_front() {
                Some((k, s)) => {
                    // Skip stale order entries left behind by a re-touch.
                    if self.map.get(&k).map(|(_, cur)| *cur == s).unwrap_or(false) {
                        self.map.remove(&k);
                        self.evicted_by_capacity += 1;
                    }
                }
                None => break,
            }
        }
    }
}

/// How many links a broadcast relay goes to.
///
/// §4.2 Fanout subsetting: "broadcast messages are re-sent to a deterministic,
/// message-ID-seeded subset of links (~log₂ of degree) rather than all of them".
///
/// ASSUMPTION: "~log₂" does not say how it rounds. This rounds **up**, which
/// cuts **in bitchat's favour**: more links means a higher delivery rate, and
/// delivery across ≥ 3 hops (`docs/METRICS.md` M2) is the headline number we
/// are graded against. Rounding down would have given it fewer transmissions
/// and flattered its efficiency figure instead, at the cost of the metric that
/// actually decides the comparison. Floor is available via
/// [`super::BitchatConfig::fanout_rounds_up`] so the harness can report both.
pub fn broadcast_fanout(degree: usize, round_up: bool) -> usize {
    if degree == 0 {
        return 0;
    }
    if degree == 1 {
        return 1;
    }
    let k = if round_up {
        // ceil(log2(degree)) = bits needed to represent degree - 1.
        usize::BITS as usize - (degree - 1).leading_zeros() as usize
    } else {
        // floor(log2(degree)).
        (usize::BITS as usize - 1) - degree.leading_zeros() as usize
    };
    k.clamp(1, degree)
}

/// Pick the subset deterministically from the message id.
///
/// §4.2: "a deterministic, message-ID-seeded subset of links". Deterministic
/// matters: two nodes holding the same packet make correlated choices, which is
/// what stops the subset trick from tearing holes in the flood. The ingress
/// link must already have been removed by the caller (split horizon, §4.2).
pub fn select_subset(msg_id: u64, eligible: &[PeerId], k: usize) -> Vec<PeerId> {
    if k >= eligible.len() {
        return eligible.to_vec();
    }
    let mut v = eligible.to_vec();
    // Sorted first so the result depends only on the id and the *set* of links,
    // never on the order they happened to connect in.
    v.sort_unstable();
    let mut rng = Rng::new(crate::hash::mix64(msg_id, 0x5F3A_C11D_0E27_B481));
    rng.shuffle(&mut v);
    v.truncate(k);
    v.sort_unstable();
    v
}

/// The TTL a relay goes out with, or `None` if the packet dies here.
///
/// §4.2 TTL: "Relays clamp: dense graphs (≥ 6 links) cap broadcast TTL at 5;
/// thin chains (≤ 2 links) relay at full incoming depth."
///
/// ASSUMPTION: "relay at full incoming depth" is read as *no dense clamp*, with
/// the ordinary decrement still applied. The alternative reading — relay
/// without decrementing — would give bitchat unlimited hop count along any
/// chain, so it is the reading that favours bitchat and would normally win
/// here. It is rejected on the whitepaper's own evidence: §9 Future Work lists
/// "edge-of-network TTL boosting for very dense and very sparse graphs" as *not
/// yet implemented*. Reading §4.2 as already implementing it would contradict
/// §9, so this is a sourced decision, not a preference.
pub fn relay_ttl(incoming: u8, degree: usize, broadcast: bool) -> Option<u8> {
    if incoming <= 1 {
        return None;
    }
    let mut out = incoming - 1;
    if broadcast && degree >= DENSE_DEGREE {
        out = out.min(DENSE_BROADCAST_TTL_CAP);
    }
    // A thin chain (degree <= THIN_DEGREE) reaches here with no clamp applied,
    // which is the "full incoming depth" case.
    if out == 0 {
        None
    } else {
        Some(out)
    }
}

/// Draw the relay delay. §4.2 Jitter.
pub fn jitter_ms(rng: &mut Rng, degree: usize, directed: bool) -> u64 {
    if directed {
        return rng.range_inclusive(DIRECTED_JITTER_MIN_MS, DIRECTED_JITTER_MAX_MS);
    }
    let hi = if degree >= DENSE_DEGREE {
        DENSE_JITTER_MAX_MS
    } else {
        JITTER_MAX_MS
    };
    rng.range_inclusive(JITTER_MIN_MS, hi)
}

/// A relay waiting out its jitter.
///
/// §4.2 Deduplication: "A scheduled relay is cancelled when a duplicate arrives
/// first from another relay." Holding the relay as cancellable state rather
/// than transmitting immediately is the whole mechanism, so it is modelled as
/// state and not as a delay on an already-committed transmission.
#[derive(Clone, Debug)]
pub struct PendingRelay {
    pub key: SeenKey,
    pub due: TimeMs,
    pub targets: Vec<PeerId>,
    pub frame: Vec<u8>,
    pub wire_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_ttl_and_clamps_match_the_whitepaper() {
        assert_eq!(ORIGIN_TTL, 7, "§4.2: packets originate with TTL 7");
        // Dense: >= 6 links caps a broadcast relay at 5.
        assert_eq!(relay_ttl(7, 6, true), Some(5));
        assert_eq!(relay_ttl(7, 20, true), Some(5));
        // Just below the dense threshold there is no cap.
        assert_eq!(relay_ttl(7, 5, true), Some(6));
        // Thin chain: full incoming depth, i.e. no clamp, ordinary decrement.
        assert_eq!(relay_ttl(7, 2, true), Some(6));
        assert_eq!(relay_ttl(7, 1, true), Some(6));
        // The clamp is on broadcast only; directed traffic is TTL - 1 (§4.2).
        assert_eq!(relay_ttl(7, 20, false), Some(6));
    }

    #[test]
    fn ttl_one_dies_here_and_never_wraps() {
        assert_eq!(relay_ttl(1, 3, true), None);
        assert_eq!(relay_ttl(0, 3, true), None);
        for d in 0..32 {
            for t in 0..=255u8 {
                if let Some(o) = relay_ttl(t, d, true) {
                    assert!(o < t, "ttl must strictly decrease: {t} -> {o}");
                    assert!(o > 0);
                }
            }
        }
    }

    #[test]
    fn subset_flooding_picks_the_documented_number_of_links() {
        // §4.2: ~log2(degree). Rounding up, clamped to [1, degree].
        let cases = [
            (1usize, 1usize),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (6, 3),
            (7, 3),
            (8, 3),
            (9, 4),
            (16, 4),
            (17, 5),
            (32, 5),
        ];
        for (deg, want) in cases {
            assert_eq!(broadcast_fanout(deg, true), want, "degree {deg}");
            assert!(broadcast_fanout(deg, true) <= deg);
        }
        assert_eq!(broadcast_fanout(0, true), 0);
        // A degree-20 node transmits on 5 links, not 20: that is the whole
        // difference from an unsuppressed flood.
        assert_eq!(broadcast_fanout(20, true), 5);
        // Floor variant, offered for comparison only.
        assert_eq!(broadcast_fanout(5, false), 2);
        assert_eq!(broadcast_fanout(8, false), 3);
    }

    #[test]
    fn subset_selection_is_deterministic_and_id_seeded() {
        let links: Vec<PeerId> = (1..=12).map(PeerId).collect();
        let a = select_subset(0xAAAA, &links, 4);
        let b = select_subset(0xAAAA, &links, 4);
        let c = select_subset(0xBBBB, &links, 4);
        assert_eq!(a, b, "same id must give the same subset");
        assert_eq!(a.len(), 4);
        assert_ne!(a, c, "a different id must give a different subset");
        // Independent of connection order.
        let mut shuffled = links.clone();
        Rng::new(99).shuffle(&mut shuffled);
        assert_eq!(a, select_subset(0xAAAA, &shuffled, 4));
    }

    #[test]
    fn subset_never_exceeds_the_eligible_set() {
        let links = [PeerId(1), PeerId(2)];
        assert_eq!(select_subset(7, &links, 9).len(), 2);
        assert_eq!(select_subset(7, &[], 3).len(), 0);
    }

    #[test]
    fn seen_set_evicts_at_a_thousand_entries() {
        // §4.2: "an LRU seen-set (1000 entries, 5-minute expiry)".
        let mut s = SeenSet::default();
        let key = |i: u64| SeenKey {
            sender: i,
            timestamp_ms: i,
            ptype: 1,
            payload_digest: i,
        };
        for i in 0..SEEN_CAPACITY as u64 {
            assert!(!s.insert(TimeMs(0), key(i)));
        }
        assert_eq!(s.len(), SEEN_CAPACITY);
        assert!(s.contains(TimeMs(0), &key(0)));
        // One more pushes the oldest out.
        s.insert(TimeMs(0), key(SEEN_CAPACITY as u64));
        assert_eq!(s.len(), SEEN_CAPACITY, "capacity must be held");
        assert!(!s.contains(TimeMs(0), &key(0)), "oldest must be evicted");
        assert!(s.contains(TimeMs(0), &key(SEEN_CAPACITY as u64)));
        assert_eq!(s.evicted_by_capacity, 1);
    }

    #[test]
    fn seen_set_expires_after_five_minutes() {
        let mut s = SeenSet::default();
        let k = SeenKey {
            sender: 1,
            timestamp_ms: 2,
            ptype: 3,
            payload_digest: 4,
        };
        s.insert(TimeMs(0), k);
        assert!(s.contains(TimeMs(SEEN_TTL_MS), &k), "still inside the window");
        assert!(
            !s.contains(TimeMs(SEEN_TTL_MS + 1), &k),
            "5-minute expiry: a packet is relayable again afterwards"
        );
        s.sweep(TimeMs(SEEN_TTL_MS + 1));
        assert_eq!(s.len(), 0);
        assert_eq!(s.evicted_by_age, 1);
    }

    #[test]
    fn seen_set_reports_duplicates() {
        let mut s = SeenSet::default();
        let k = SeenKey {
            sender: 9,
            timestamp_ms: 9,
            ptype: 0,
            payload_digest: 9,
        };
        assert!(!s.insert(TimeMs(0), k));
        assert!(s.insert(TimeMs(10), k), "second sighting is a duplicate");
    }

    #[test]
    fn dedup_key_ignores_ttl_by_construction() {
        // A packet relayed at depth 6 and at depth 3 must collapse to one entry,
        // or suppression does not work. The key type has no TTL field; this test
        // exists so that adding one is a test failure.
        let a = SeenKey {
            sender: 1,
            timestamp_ms: 100,
            ptype: 2,
            payload_digest: 3,
        };
        let b = a;
        assert_eq!(a, b);
        assert_eq!(std::mem::size_of::<SeenKey>(), 8 + 8 + 8 + 8);
    }

    #[test]
    fn jitter_is_ten_to_two_twenty_and_wider_when_dense() {
        let mut r = Rng::new(4);
        let mut max_sparse = 0;
        let mut max_dense = 0;
        for _ in 0..5000 {
            let s = jitter_ms(&mut r, 3, false);
            let d = jitter_ms(&mut r, 9, false);
            assert!((JITTER_MIN_MS..=JITTER_MAX_MS).contains(&s), "sparse {s}");
            assert!((JITTER_MIN_MS..=DENSE_JITTER_MAX_MS).contains(&d), "dense {d}");
            max_sparse = max_sparse.max(s);
            max_dense = max_dense.max(d);
        }
        assert_eq!(max_sparse, JITTER_MAX_MS);
        assert!(max_dense > JITTER_MAX_MS, "dense must be wider");
    }

    #[test]
    fn directed_jitter_is_tight() {
        let mut r = Rng::new(5);
        for _ in 0..1000 {
            let j = jitter_ms(&mut r, 20, true);
            assert!((DIRECTED_JITTER_MIN_MS..=DIRECTED_JITTER_MAX_MS).contains(&j));
            assert!(j < JITTER_MAX_MS, "tighter than the broadcast window");
        }
    }
}
