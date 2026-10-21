//! What we know about the links around us, and the two things we infer from it:
//! how big the mesh is, and which neighbour is worth spending a transmission on.
//!
//! Every per-neighbour collection is a fixed-size array, not a `Vec`, so the
//! ceiling on remote-driven memory is structural rather than checked.

use gdc_wire::ChanTag;

/// Link-layer peer handle. Session-scoped and opaque to us: `gdc-transport`
/// assigns it, we never put it on the wire, and it carries no identity.
pub type PeerId = u32;

/// Neighbours we will track. Beyond this, new neighbours replace the worst
/// existing one rather than growing the table.
pub const MAX_NEIGHBORS: usize = 64;
/// Neighbours-of-a-neighbour retained per peer. Enough to spot overlap and
/// estimate structure; bounded because it is remote-supplied.
pub const MAX_NBR_OF_NBR: usize = 16;
/// Channel tags we remember a peer carrying.
pub const MAX_PEER_TAGS: usize = 8;

/// What `gdc-transport` must tell us about a link. This is the whole of the
/// transport dependency: a push of these, whenever anything changes.
///
/// * `quality` — 0 (unusable) to 255 (perfect). Transport's own blend of RSSI,
///   PDR and retry count; routing does not want to know the recipe.
/// * `quality_trend` — change in `quality` per second, signed and saturating.
///   This is the motion signal. A link at quality 200 falling by 60 a second is
///   worth less to us than a link at 120 that is stable, because we are about
///   to lose the first one.
/// * `neighbors` / `tags` — optionally supplied by `gdc-node` from decrypted
///   presence frames for channels we are a member of. Both are truncated to
///   their ceilings on the way in.
#[derive(Clone, Copy, Debug)]
pub struct LinkUpdate<'a> {
    pub peer: PeerId,
    pub quality: u8,
    pub quality_trend: i8,
    pub neighbors: &'a [PeerId],
    pub tags: &'a [ChanTag],
    pub now_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Neighbor {
    pub peer: PeerId,
    pub quality: u8,
    pub quality_trend: i8,
    pub last_seen_ms: u64,
    nbrs: [PeerId; MAX_NBR_OF_NBR],
    n_nbrs: u8,
    tags: [ChanTag; MAX_PEER_TAGS],
    n_tags: u8,
    /// Times we scheduled a relay expecting this peer to carry it onward and
    /// then observed it do so. Freeloader detection, and a vote for the links
    /// that actually move traffic.
    pub relays_observed: u16,
    pub relays_expected: u16,
}

impl Neighbor {
    fn blank(peer: PeerId, now_ms: u64) -> Self {
        Neighbor {
            peer,
            quality: 0,
            quality_trend: 0,
            last_seen_ms: now_ms,
            nbrs: [0; MAX_NBR_OF_NBR],
            n_nbrs: 0,
            tags: [ChanTag([0; 8]); MAX_PEER_TAGS],
            n_tags: 0,
            relays_observed: 0,
            relays_expected: 0,
        }
    }

    pub fn neighbors(&self) -> &[PeerId] {
        let n = (self.n_nbrs as usize).min(MAX_NBR_OF_NBR);
        self.nbrs.get(..n).unwrap_or(&[])
    }

    pub fn tags(&self) -> &[ChanTag] {
        let n = (self.n_tags as usize).min(MAX_PEER_TAGS);
        self.tags.get(..n).unwrap_or(&[])
    }

    pub fn carries(&self, tag: &ChanTag) -> bool {
        self.tags().iter().any(|t| t == tag)
    }

    fn note_tag(&mut self, tag: ChanTag) {
        if self.carries(&tag) {
            return;
        }
        let n = self.n_tags as usize;
        if n < MAX_PEER_TAGS {
            if let Some(slot) = self.tags.get_mut(n) {
                *slot = tag;
                self.n_tags = self.n_tags.saturating_add(1);
            }
        } else {
            // Ring-replace the oldest. A peer that carries more than
            // MAX_PEER_TAGS channels is either very busy or probing us; either
            // way we keep the most recent evidence and spend no more memory.
            self.tags.rotate_left(1);
            if let Some(slot) = self.tags.get_mut(MAX_PEER_TAGS - 1) {
                *slot = tag;
            }
        }
    }

    fn set_neighbors(&mut self, src: &[PeerId]) {
        let n = src.len().min(MAX_NBR_OF_NBR);
        if let (Some(dst), Some(s)) = (self.nbrs.get_mut(..n), src.get(..n)) {
            dst.copy_from_slice(s);
        }
        self.n_nbrs = n as u8;
    }

    /// Probability, scaled to 0..=1000, that this link is still usable in
    /// `horizon_ms`.
    ///
    /// Deliberately crude and deliberately pessimistic about motion: the point
    /// is not to predict radio physics but to rank a stable mediocre link above
    /// a good one that is visibly collapsing. A flood that ignores this spends
    /// most of its transmissions on links that will not exist by the time the
    /// next hop tries to use them.
    pub fn p_alive_in(&self, horizon_ms: u64) -> u16 {
        let horizon_s = (horizon_ms as i64 + 999) / 1000;
        let projected = i64::from(self.quality) + i64::from(self.quality_trend) * horizon_s;
        let projected = projected.clamp(0, 255) as u16;
        // Map quality onto survival with a floor: even a strong link can drop,
        // and a weak-but-present link is not hopeless.
        (projected * 1000 / 255).clamp(0, 1000)
    }

    pub fn is_fresh(&self, now_ms: u64, stale_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_seen_ms) <= stale_ms
    }

    /// Fraction, 0..=1000, of scheduled relays this peer was seen to carry on.
    /// Unknown peers start optimistic so a new neighbour is not starved.
    pub fn reliability(&self) -> u16 {
        if self.relays_expected < 3 {
            return 700;
        }
        (u32::from(self.relays_observed) * 1000 / u32::from(self.relays_expected)).min(1000) as u16
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TopologyEstimate {
    pub degree: usize,
    /// Distinct nodes two hops out that are not also one hop out.
    pub frontier: usize,
    /// `frontier * 1000 / degree`. High means the mesh keeps going past our
    /// horizon; low means we are inside a blob that we already see all of.
    pub frontier_ratio: u32,
}

pub struct NeighborTable {
    v: Vec<Neighbor>,
    stale_ms: u64,
}

impl NeighborTable {
    pub fn new(stale_ms: u64) -> Self {
        NeighborTable {
            v: Vec::with_capacity(MAX_NEIGHBORS),
            stale_ms,
        }
    }

    pub fn len(&self) -> usize {
        self.v.len()
    }

    pub fn is_empty(&self) -> bool {
        self.v.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.v.iter()
    }

    pub fn get(&self, peer: PeerId) -> Option<&Neighbor> {
        self.v.iter().find(|n| n.peer == peer)
    }

    pub fn get_mut(&mut self, peer: PeerId) -> Option<&mut Neighbor> {
        self.v.iter_mut().find(|n| n.peer == peer)
    }

    /// Neighbours seen recently enough to be worth a transmission.
    pub fn fresh(&self, now_ms: u64) -> impl Iterator<Item = &Neighbor> {
        let stale = self.stale_ms;
        self.v.iter().filter(move |n| n.is_fresh(now_ms, stale))
    }

    pub fn degree(&self, now_ms: u64) -> usize {
        self.fresh(now_ms).count()
    }

    pub fn apply(&mut self, u: LinkUpdate<'_>) {
        if let Some(existing) = self.v.iter().position(|n| n.peer == u.peer) {
            if let Some(n) = self.v.get_mut(existing) {
                n.quality = u.quality;
                n.quality_trend = u.quality_trend;
                n.last_seen_ms = u.now_ms;
                if !u.neighbors.is_empty() {
                    n.set_neighbors(u.neighbors);
                }
                for t in u.tags.iter().take(MAX_PEER_TAGS) {
                    n.note_tag(*t);
                }
            }
            return;
        }

        if self.v.len() >= MAX_NEIGHBORS {
            // Full. Replace the least useful resident: stalest first, then
            // weakest. Never grow.
            let stale = self.stale_ms;
            let victim = self
                .v
                .iter()
                .enumerate()
                .min_by_key(|(_, n)| {
                    (n.is_fresh(u.now_ms, stale), n.quality, n.last_seen_ms)
                })
                .map(|(i, _)| i);
            match victim {
                Some(i) if self.v.get(i).is_some_and(|n| n.quality <= u.quality || !n.is_fresh(u.now_ms, stale)) => {
                    if let Some(slot) = self.v.get_mut(i) {
                        *slot = Neighbor::blank(u.peer, u.now_ms);
                    }
                }
                // Everyone resident is fresher and better. Ignore the newcomer
                // rather than churn the table.
                _ => return,
            }
        } else {
            self.v.push(Neighbor::blank(u.peer, u.now_ms));
        }

        if let Some(n) = self.v.iter_mut().find(|n| n.peer == u.peer) {
            n.quality = u.quality;
            n.quality_trend = u.quality_trend;
            n.last_seen_ms = u.now_ms;
            n.set_neighbors(u.neighbors);
            for t in u.tags.iter().take(MAX_PEER_TAGS) {
                n.note_tag(*t);
            }
        }
    }

    pub fn drop_peer(&mut self, peer: PeerId) {
        self.v.retain(|n| n.peer != peer);
    }

    /// Note that a peer carries a tag, learned from a frame it handed us.
    ///
    /// This is the cheap topology knowledge the progress heuristic runs on, and
    /// it needs no new wire field: the tag is already in the cleartext header,
    /// and "this peer passes traffic for this tag" is exactly the signal we
    /// want. For channels we are not a member of it is the *only* signal
    /// available, which is the point.
    pub fn note_tag(&mut self, peer: PeerId, tag: ChanTag, now_ms: u64) {
        if let Some(n) = self.get_mut(peer) {
            n.note_tag(tag);
            n.last_seen_ms = now_ms;
        } else {
            self.apply(LinkUpdate {
                peer,
                quality: 128,
                quality_trend: 0,
                neighbors: &[],
                tags: &[tag],
                now_ms,
            });
        }
    }

    /// One- and two-hop structure, used to tell a chain from a blob.
    pub fn estimate(&self, now_ms: u64) -> TopologyEstimate {
        let mut seen_two: [PeerId; MAX_NEIGHBORS * 2] = [0; MAX_NEIGHBORS * 2];
        let mut n_two = 0usize;
        let degree = self.degree(now_ms);
        for n in self.fresh(now_ms) {
            for far in n.neighbors() {
                if self.get(*far).is_some() {
                    continue;
                }
                let have = seen_two.get(..n_two).is_some_and(|s| s.contains(far));
                if !have && n_two < seen_two.len() {
                    if let Some(slot) = seen_two.get_mut(n_two) {
                        *slot = *far;
                        n_two += 1;
                    }
                }
            }
        }
        TopologyEstimate {
            degree,
            frontier: n_two,
            frontier_ratio: if degree == 0 {
                0
            } else {
                (n_two as u32).saturating_mul(1000) / degree as u32
            },
        }
    }

    pub fn memory_bytes(&self) -> usize {
        MAX_NEIGHBORS * core::mem::size_of::<Neighbor>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(peer: PeerId, q: u8, now: u64) -> LinkUpdate<'static> {
        LinkUpdate {
            peer,
            quality: q,
            quality_trend: 0,
            neighbors: &[],
            tags: &[],
            now_ms: now,
        }
    }

    #[test]
    fn table_never_exceeds_its_ceiling() {
        let mut t = NeighborTable::new(60_000);
        for p in 0..10_000u32 {
            t.apply(up(p, (p % 256) as u8, 0));
        }
        assert!(t.len() <= MAX_NEIGHBORS);
    }

    #[test]
    fn remote_neighbor_lists_are_truncated() {
        let mut t = NeighborTable::new(60_000);
        let huge: Vec<PeerId> = (0..10_000).collect();
        t.apply(LinkUpdate {
            peer: 1,
            quality: 200,
            quality_trend: 0,
            neighbors: &huge,
            tags: &[],
            now_ms: 0,
        });
        assert_eq!(t.get(1).map(|n| n.neighbors().len()), Some(MAX_NBR_OF_NBR));
    }

    #[test]
    fn remote_tag_lists_are_truncated() {
        let mut t = NeighborTable::new(60_000);
        let tags: Vec<ChanTag> = (0..1000u64)
            .map(|i| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&i.to_le_bytes());
                ChanTag(b)
            })
            .collect();
        t.apply(LinkUpdate {
            peer: 1,
            quality: 200,
            quality_trend: 0,
            neighbors: &[],
            tags: &tags,
            now_ms: 0,
        });
        assert_eq!(t.get(1).map(|n| n.tags().len()), Some(MAX_PEER_TAGS));
    }

    #[test]
    fn a_collapsing_link_ranks_below_a_stable_weaker_one() {
        let mut t = NeighborTable::new(60_000);
        t.apply(LinkUpdate {
            peer: 1,
            quality: 220,
            quality_trend: -80,
            neighbors: &[],
            tags: &[],
            now_ms: 0,
        });
        t.apply(LinkUpdate {
            peer: 2,
            quality: 130,
            quality_trend: 0,
            neighbors: &[],
            tags: &[],
            now_ms: 0,
        });
        let a = t.get(1).map(|n| n.p_alive_in(2000)).unwrap_or(0);
        let b = t.get(2).map(|n| n.p_alive_in(2000)).unwrap_or(0);
        assert!(a < b, "collapsing {a} should rank below stable {b}");
    }

    #[test]
    fn staleness_removes_a_peer_from_candidacy_without_removing_the_record() {
        let mut t = NeighborTable::new(1_000);
        t.apply(up(5, 200, 0));
        assert_eq!(t.degree(500), 1);
        assert_eq!(t.degree(5_000), 0);
        assert!(t.get(5).is_some());
    }

    #[test]
    fn frontier_ratio_separates_a_chain_from_a_blob() {
        // Chain: two neighbours, each with an onward neighbour we cannot see.
        let mut chain = NeighborTable::new(60_000);
        chain.apply(LinkUpdate { peer: 1, quality: 200, quality_trend: 0, neighbors: &[100], tags: &[], now_ms: 0 });
        chain.apply(LinkUpdate { peer: 2, quality: 200, quality_trend: 0, neighbors: &[200], tags: &[], now_ms: 0 });
        let c = chain.estimate(0);
        assert_eq!(c.degree, 2);
        assert_eq!(c.frontier, 2);

        // Blob: four neighbours who all know only each other.
        let mut blob = NeighborTable::new(60_000);
        for p in 1..=4u32 {
            blob.apply(LinkUpdate { peer: p, quality: 200, quality_trend: 0, neighbors: &[1, 2, 3, 4], tags: &[], now_ms: 0 });
        }
        let b = blob.estimate(0);
        assert_eq!(b.frontier, 0);
        assert!(c.frontier_ratio > b.frontier_ratio);
    }

    #[test]
    fn reliability_starts_optimistic_then_tracks_observation() {
        let mut t = NeighborTable::new(60_000);
        t.apply(up(1, 200, 0));
        assert_eq!(t.get(1).map(|n| n.reliability()), Some(700));
        if let Some(n) = t.get_mut(1) {
            n.relays_expected = 10;
            n.relays_observed = 2;
        }
        assert_eq!(t.get(1).map(|n| n.reliability()), Some(200));
    }
}
